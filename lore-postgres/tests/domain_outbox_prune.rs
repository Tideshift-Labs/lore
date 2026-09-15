// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step C: bounded retention pruning
//! (`lore-postgres/src/domain/outbox/prune.rs`).
//!
//! Real Postgres only, `#[ignore]`. Every case acquires its own
//! [`case_namespace::CaseNamespace`] schema, matching every other Step C real-
//! Postgres file in this crate.
//!
//! Rows in the states `prune_consumer_safe`/`prune_dead_letters` are meant to
//! delete are seeded directly by SQL rather than produced through the real
//! evaluator or relay pipeline. `consumer_safe` is a terminal state only
//! `evaluator.rs` can produce in production, and that path (and its
//! `broker_accepted`-vs-`consumer_safe` discrimination) is
//! `domain_outbox_checkpoints.rs`'s responsibility; this file only needs rows
//! already shaped like what that path would have left behind, at a controlled
//! `created_at`/`disposition_at` age the production clock cannot be told to
//! fast-forward to.

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::time::Duration;

use case_namespace::CaseNamespace;
use lore_postgres::domain::DomainError;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::CapturedPosition;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::SafetyBlock;
use lore_postgres::domain::outbox::SupersededPruneOutcome;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::prune::MAX_PRUNE_BATCH;
use lore_postgres::domain::outbox::prune::MIN_DEAD_LETTER_RETENTION;
use lore_postgres::domain::outbox::prune::MIN_RETENTION_AGE;
use lore_postgres::domain::outbox::prune_consumer_safe;
use lore_postgres::domain::outbox::prune_dead_letters;
use lore_postgres::domain::outbox::prune_superseded_epochs;
use lore_postgres::domain::outbox::report_checkpoint;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn ensure_schema_bootstrapped(url: &str) {
    let _ = PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap the domain schema (including outbox tables) for this namespace");
}

async fn pg_client(url: &str) -> Client {
    ensure_schema_bootstrapped(url).await;
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test access");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

async fn deadpool_client(url: &str) -> deadpool_postgres::Client {
    let pool = build_pool(url, 8, &TlsConfig::default()).expect("build pool");
    pool.get().await.expect("checkout deadpool connection")
}

fn rand_cell_id() -> String {
    format!("cell-{:016x}", rand::random::<u64>())
}

fn rand_repository_id() -> [u8; 16] {
    rand::random()
}

async fn current_membership_version(raw: &Client, cell_id: &str) -> i64 {
    membership::read_membership_state(raw, cell_id)
        .await
        .expect("read membership state")
        .expect("membership state row present")
        .membership_version
}

/// Join, capture, baseline, checkpoint, and readiness-CAS one receiver.
/// Duplicated from `domain_outbox_checkpoints.rs` -- `tests/*.rs` files are
/// independent binaries with no shared lib target to put this in besides
/// `common/case_namespace.rs`, which is deliberately scoped to namespacing
/// alone.
async fn join_ready_receiver(
    raw: &Client,
    deadpool: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    stream_identity: &str,
    stream_epoch: i64,
    frontier: i64,
) -> i64 {
    let version = current_membership_version(raw, cell_id).await;
    let joined = membership::join_receiver(deadpool, cell_id, receiver_identity, version)
        .await
        .expect("join receiver");
    let MembershipCas::Applied {
        membership_generation: generation_id,
        ..
    } = joined
    else {
        panic!("unexpected {joined:?}");
    };
    let captured = CapturedPosition {
        stream_identity: stream_identity.to_string(),
        stream_epoch,
        start_sequence: 0,
    };
    membership::record_capture(raw, cell_id, receiver_identity, generation_id, &captured)
        .await
        .expect("record capture");
    membership::record_baseline(raw, cell_id, receiver_identity, generation_id)
        .await
        .expect("record baseline");
    let version = current_membership_version(raw, cell_id).await;
    let report = CheckpointReport {
        stream_identity: stream_identity.to_string(),
        stream_epoch,
        receiver_identity: receiver_identity.to_string(),
        membership_generation: generation_id,
        membership_version: version,
        contiguous_frontier: frontier,
        gaps: Vec::new(),
        poison: Vec::new(),
    };
    let outcome = report_checkpoint(deadpool, cell_id, &report)
        .await
        .expect("report checkpoint before readiness");
    assert_eq!(
        outcome,
        CheckpointOutcome::Applied {
            contiguous_frontier: frontier
        }
    );
    let ready = membership::readiness_cas(deadpool, cell_id, receiver_identity, generation_id)
        .await
        .expect("readiness cas");
    assert!(
        matches!(ready, MembershipCas::Applied { .. }),
        "expected the receiver to become ready, got {ready:?}"
    );
    generation_id
}

/// Install a reset fence directly by SQL. `event_relay_reset.rs` owns proving
/// the receipt transaction itself.
async fn install_reset_fence(raw: &Client, cell_id: &str, old_epoch: i64, new_epoch: i64) {
    raw.execute(
        "INSERT INTO lore_outbox_reset_generations \
             (cell_id, reset_generation, detection_id, reset_fingerprint, \
              broker_reset_identity, old_stream_identity, old_stream_epoch, \
              new_stream_identity, new_stream_epoch, reason_code, placement_revision, \
              detected_at_unix_ms, emitter_identity, evidence_id, ack_bytes, state, \
              persisted_at) \
         VALUES ($1, 1, 'test-detection', $2, 'broker-x', 'DURABLE-x', $3, 'DURABLE-x', $4, 2, 0, \
                 0, 'spiffe://test/cell/test/wp110', 'ev-1', $5, 'reset_in_progress', \
                 clock_timestamp())",
        &[
            &cell_id,
            &vec![0x11u8; 32],
            &old_epoch,
            &new_epoch,
            &vec![1u8, 2, 3],
        ],
    )
    .await
    .expect("install a reset fence row");
}

/// Install one reset-generation transition row directly by SQL, at a chosen
/// `state` ("cleared" or "reset_in_progress") and generation. Unlike
/// [`install_reset_fence`] (fixed generation 1, always `reset_in_progress`),
/// this lets a test build a multi-hop chain with a mix of cleared and
/// in-progress hops. `reset.rs`'s `accept_reset` owns proving the receipt
/// transaction itself; `prune_superseded_epochs`'s backward walk is what these
/// tests exercise, so a directly-seeded row shaped like what `accept_reset`
/// would have left behind is sufficient.
#[allow(clippy::too_many_arguments)]
async fn insert_reset_transition(
    raw: &Client,
    cell_id: &str,
    stream_identity: &str,
    reset_generation: i64,
    old_epoch: i64,
    new_epoch: i64,
    state: &str,
) {
    let mut fingerprint = vec![0u8; 32];
    fingerprint[24..].copy_from_slice(&reset_generation.to_be_bytes());
    let detection_id = format!("test-detection-{reset_generation}");
    let evidence_id = format!("ev-{reset_generation}");
    let ack_bytes = vec![1u8, 2, 3];
    let cleared_at_expr = if state == "cleared" {
        "clock_timestamp()"
    } else {
        "NULL"
    };
    let sql = format!(
        "INSERT INTO lore_outbox_reset_generations \
             (cell_id, reset_generation, detection_id, reset_fingerprint, \
              broker_reset_identity, old_stream_identity, old_stream_epoch, \
              new_stream_identity, new_stream_epoch, reason_code, placement_revision, \
              detected_at_unix_ms, emitter_identity, evidence_id, ack_bytes, state, \
              persisted_at, cleared_at) \
         VALUES ($1, $2, $3, $4, 'broker-x', $5, $6, $5, $7, 2, 0, \
                 0, 'spiffe://test/cell/test/wp110', $8, $9, $10, \
                 clock_timestamp(), {cleared_at_expr})"
    );
    raw.execute(
        &sql,
        &[
            &cell_id,
            &reset_generation,
            &detection_id,
            &fingerprint,
            &stream_identity,
            &old_epoch,
            &new_epoch,
            &evidence_id,
            &ack_bytes,
            &state,
        ],
    )
    .await
    .unwrap_or_else(|error| panic!("insert a {state} reset transition: {error}"));
}

/// One directly-seeded outbox row, at a controlled `state` and age. Every
/// field the production writers would have set is filled in with a
/// syntactically valid placeholder; only `state`, `broker_sequence`, and
/// `created_at`/`stream_identity`/`stream_epoch` (when applicable) vary by
/// caller intent.
#[allow(clippy::too_many_arguments)]
async fn seed_event_row(
    client: &Client,
    cell_id: &str,
    repository_id: &[u8],
    state: &str,
    stream_identity: Option<&str>,
    stream_epoch: Option<i64>,
    broker_sequence: Option<i64>,
    age_days: f64,
) -> Uuid {
    let event_id = Uuid::now_v7();
    let seed: i64 = rand::random::<u32>().into();
    let mut idempotency_key = [0u8; 32];
    idempotency_key[24..].copy_from_slice(&seed.to_be_bytes());
    let mut aggregate_id = [0u8; 16];
    aggregate_id[8..].copy_from_slice(&seed.to_be_bytes());
    let aggregate_version = vec![0u8; 8];
    // `publication_shape` requires all six of these NOT NULL together, or all
    // six NULL together (exactly the `pending` case).
    let (gateway_response_id, publisher_contract_version, broker_accepted_at_expr): (
        Option<String>,
        Option<i32>,
        &str,
    ) = if state == "pending" {
        (None, None, "NULL")
    } else {
        (
            Some(format!("gw-{seed}")),
            Some(1),
            "clock_timestamp() - ($8 * interval '1 day')",
        )
    };
    let sql = format!(
        "INSERT INTO lore_outbox_events \
             (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
              event_kind, aggregate_kind, aggregate_id, aggregate_version, \
              payload_schema_version, payload, state, created_at, available_at, \
              stream_identity, stream_epoch, broker_sequence, gateway_response_id, \
              publisher_contract_version, broker_accepted_at) \
         VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{{}}', $7, \
                 clock_timestamp() - ($8 * interval '1 day'), clock_timestamp(), \
                 $9, $10, $11, $12, $13, {broker_accepted_at_expr})"
    );
    client
        .execute(
            &sql,
            &[
                &event_id,
                &cell_id,
                &idempotency_key.as_slice(),
                &repository_id,
                &aggregate_id.as_slice(),
                &aggregate_version,
                &state,
                &age_days,
                &stream_identity,
                &stream_epoch,
                &broker_sequence,
                &gateway_response_id,
                &publisher_contract_version,
            ],
        )
        .await
        .unwrap_or_else(|error| panic!("seed a {state} row: {error}"));
    event_id
}

async fn event_state(raw: &Client, event_id: Uuid) -> String {
    raw.query_one(
        "SELECT state FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("read event state")
    .get("state")
}

async fn event_exists(raw: &Client, event_id: Uuid) -> bool {
    raw.query_opt(
        "SELECT 1 FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("probe event existence")
    .is_some()
}

async fn count_state(raw: &Client, cell_id: &str, state: &str) -> i64 {
    raw.query_one(
        "SELECT count(*) AS n FROM lore_outbox_events WHERE cell_id = $1 AND state = $2",
        &[&cell_id, &state],
    )
    .await
    .expect("count rows by state")
    .get("n")
}

async fn seed_consumer_safe_rows_bulk(
    client: &mut Client,
    cell_id: &str,
    repository_id: &[u8],
    stream_identity: &str,
    stream_epoch: i64,
    count: i64,
    age_days: f64,
) {
    let tx = client.transaction().await.expect("begin bulk seed tx");
    let aggregate_version = vec![0u8; 8];
    for seq in 1..=count {
        let event_id = Uuid::now_v7();
        let mut idempotency_key = [0u8; 32];
        idempotency_key[24..].copy_from_slice(&seq.to_be_bytes());
        let mut aggregate_id = [0u8; 16];
        aggregate_id[8..].copy_from_slice(&seq.to_be_bytes());
        tx.execute(
            "INSERT INTO lore_outbox_events \
                 (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                  event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                  payload_schema_version, payload, state, created_at, available_at, \
                  stream_identity, stream_epoch, broker_sequence, gateway_response_id, \
                  publisher_contract_version, broker_accepted_at) \
             VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', \
                     'consumer_safe', clock_timestamp() - ($7 * interval '1 day'), \
                     clock_timestamp(), $8, $9, $10, $11, 1, clock_timestamp())",
            &[
                &event_id,
                &cell_id,
                &idempotency_key.as_slice(),
                &repository_id,
                &aggregate_id.as_slice(),
                &aggregate_version,
                &age_days,
                &stream_identity,
                &stream_epoch,
                &seq,
                &format!("gw-bulk-{seq}"),
            ],
        )
        .await
        .expect("seed one consumer_safe row");
    }
    tx.commit().await.expect("commit bulk seed");
}

async fn insert_dead_letter(
    client: &Client,
    cell_id: &str,
    disposition: &str,
    disposition_age_days: Option<f64>,
    last_failed_age_days: f64,
) -> Uuid {
    let event_id = Uuid::now_v7();
    let idempotency_key: [u8; 32] = rand::random();
    let repository_id: [u8; 16] = rand::random();
    let aggregate_id: [u8; 16] = rand::random();
    let aggregate_version = vec![0u8; 8];
    client
        .execute(
            "INSERT INTO lore_outbox_dead_letters \
                 (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                  event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                  payload_schema_version, payload, created_at, attempt_count, terminal_class, \
                  first_failed_at, last_failed_at, disposition, disposition_at, \
                  disposition_actor) \
             VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', \
                     clock_timestamp() - ($7 * interval '1 day'), 5, 'PERMANENT_REJECTION', \
                     clock_timestamp() - ($7 * interval '1 day'), \
                     clock_timestamp() - ($7 * interval '1 day'), \
                     $8, \
                     CASE WHEN $9::double precision IS NULL THEN NULL \
                          ELSE clock_timestamp() - ($9 * interval '1 day') END, \
                     CASE WHEN $9::double precision IS NULL THEN NULL ELSE 'ops' END)",
            &[
                &event_id,
                &cell_id,
                &idempotency_key.as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
                &aggregate_version,
                &last_failed_age_days,
                &disposition,
                &disposition_age_days,
            ],
        )
        .await
        .unwrap_or_else(|error| panic!("insert a {disposition} dead letter: {error}"));
    event_id
}

async fn dead_letter_exists(raw: &Client, event_id: Uuid) -> bool {
    raw.query_opt(
        "SELECT 1 FROM lore_outbox_dead_letters WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("probe dead letter existence")
    .is_some()
}

// ---------------------------------------------------------------------------
// consumer_safe pruning
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn old_consumer_safe_rows_are_reaped_and_pending_broker_accepted_and_young_rows_are_not() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-safe").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        stream_epoch,
        10_000,
    )
    .await;

    let old_safe = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(stream_epoch),
        Some(1),
        9.0,
    )
    .await;
    let young_safe = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(stream_epoch),
        Some(2),
        0.5,
    )
    .await;
    let pending = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "pending",
        None,
        None,
        None,
        9.0,
    )
    .await;
    let accepted = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "broker_accepted",
        Some(stream_identity),
        Some(stream_epoch),
        Some(3),
        9.0,
    )
    .await;

    let outcome = prune_consumer_safe(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
        .await
        .expect("prune consumer-safe rows");
    assert_eq!(
        outcome.deleted, 1,
        "only the old consumer_safe row is reapable"
    );
    assert!(outcome.block.is_none());

    assert!(
        !event_exists(&raw, old_safe).await,
        "the old row must be gone"
    );
    assert_eq!(event_state(&raw, young_safe).await, "consumer_safe");
    assert_eq!(event_state(&raw, pending).await, "pending");
    assert_eq!(event_state(&raw, accepted).await, "broker_accepted");

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn an_unready_required_member_blocks_pruning_of_old_rows_it_would_otherwise_release() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-block").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    // Joined but never captured/baselined/readiness-CAS'd -- stays "joining".
    let version = current_membership_version(&raw, &cell_id).await;
    membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version)
        .await
        .expect("join without ever becoming ready");

    let old_safe = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(stream_epoch),
        Some(1),
        9.0,
    )
    .await;

    let outcome = prune_consumer_safe(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
        .await
        .expect("prune call itself must not error");
    assert_eq!(outcome.deleted, 0);
    assert!(matches!(
        outcome.block,
        Some(EvaluationBlock::Membership(
            SafetyBlock::MemberNotReady { .. }
        ))
    ));
    assert!(
        event_exists(&raw, old_safe).await,
        "the row must be retained"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_reset_fence_blocks_pruning_of_old_rows_it_would_otherwise_release() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-reset").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        stream_epoch,
        10_000,
    )
    .await;
    let old_safe = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(stream_epoch),
        Some(1),
        9.0,
    )
    .await;

    install_reset_fence(&raw, &cell_id, stream_epoch, stream_epoch + 1).await;

    let outcome = prune_consumer_safe(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
        .await
        .expect("prune call itself must not error");
    assert_eq!(outcome.deleted, 0);
    assert_eq!(
        outcome.block,
        Some(EvaluationBlock::Membership(SafetyBlock::ResetInProgress))
    );
    assert!(
        event_exists(&raw, old_safe).await,
        "the row must be retained"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn consumer_safe_prune_transactions_are_bounded_at_the_thousand_row_batch() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-batch").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        stream_epoch,
        1_000_000,
    )
    .await;

    let mut seed_client = pg_client(&url).await;
    seed_consumer_safe_rows_bulk(
        &mut seed_client,
        &cell_id,
        &repository_id,
        stream_identity,
        stream_epoch,
        1_200,
        9.0,
    )
    .await;
    assert_eq!(count_state(&raw, &cell_id, "consumer_safe").await, 1_200);

    let first = prune_consumer_safe(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
        .await
        .expect("first prune");
    assert_eq!(first.deleted, MAX_PRUNE_BATCH as u64);

    let second = prune_consumer_safe(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
        .await
        .expect("second prune");
    assert_eq!(second.deleted, 200);

    assert_eq!(count_state(&raw, &cell_id, "consumer_safe").await, 0);

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Dead-letter pruning
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn dead_letters_are_pruned_only_when_disposed_and_past_the_thirty_day_floor() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-dl").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    // No membership/placement setup needed -- `prune_dead_letters` does not
    // consult the checkpoint vector at all.
    membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state (harmless for this path, matches other cells' setup)");

    let old_disposed = insert_dead_letter(&raw, &cell_id, "obsolete", Some(31.0), 40.0).await;
    let young_disposed = insert_dead_letter(&raw, &cell_id, "requeued", Some(1.0), 2.0).await;
    let old_parked = insert_dead_letter(&raw, &cell_id, "parked", None, 40.0).await;

    let deleted = prune_dead_letters(
        &mut deadpool,
        &cell_id,
        MIN_DEAD_LETTER_RETENTION,
        MAX_PRUNE_BATCH,
    )
    .await
    .expect("prune dead letters");
    assert_eq!(deleted, 1, "only the old disposed row qualifies");

    assert!(
        !dead_letter_exists(&raw, old_disposed).await,
        "old + disposed must be gone"
    );
    assert!(
        dead_letter_exists(&raw, young_disposed).await,
        "young rows are retained even when disposed"
    );
    assert!(
        dead_letter_exists(&raw, old_parked).await,
        "a parked row is never deleted without an operator disposition, however old"
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Superseded-epoch pruning (prune_superseded_epochs)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_cleared_reset_reaps_the_superseded_placement_but_leaves_current_pending_broker_accepted_young_and_stray_rows()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-basic").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let old_epoch = 1; // A: superseded
    let current_epoch = 2; // B: current
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        current_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place at the current epoch");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        current_epoch,
        10_000,
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        old_epoch,
        current_epoch,
        "cleared",
    )
    .await;

    let old_at_superseded = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(old_epoch),
        Some(1),
        9.0,
    )
    .await;
    let young_at_superseded = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(old_epoch),
        Some(2),
        0.5,
    )
    .await;
    let broker_accepted_at_superseded = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "broker_accepted",
        Some(stream_identity),
        Some(old_epoch),
        Some(3),
        9.0,
    )
    .await;
    let old_at_current = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(current_epoch),
        Some(1),
        9.0,
    )
    .await;
    let pending = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "pending",
        None,
        None,
        None,
        9.0,
    )
    .await;
    // A stray epoch that appears in no transition at all.
    let stray = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(99),
        Some(1),
        9.0,
    )
    .await;

    let outcome =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune superseded-epoch rows");
    assert_eq!(
        outcome.deleted, 1,
        "only the old row at the superseded placement is reapable"
    );
    assert_eq!(outcome.superseded_placements, 1);
    assert!(outcome.block.is_none());
    let current = outcome.current.expect("a proven current placement");
    assert_eq!(current.stream_identity, stream_identity);
    assert_eq!(current.stream_epoch, current_epoch);

    assert!(
        !event_exists(&raw, old_at_superseded).await,
        "the old superseded-placement row must be gone"
    );
    assert_eq!(
        event_state(&raw, young_at_superseded).await,
        "consumer_safe",
        "younger than the floor survives even at an admitted tuple"
    );
    assert_eq!(
        event_state(&raw, broker_accepted_at_superseded).await,
        "broker_accepted",
        "only consumer_safe rows are matched, however old"
    );
    assert_eq!(
        event_state(&raw, old_at_current).await,
        "consumer_safe",
        "the current placement belongs to prune_consumer_safe, not this function"
    );
    assert_eq!(event_state(&raw, pending).await, "pending");
    assert_eq!(
        event_state(&raw, stray).await,
        "consumer_safe",
        "a tuple nothing leads from is never admitted, however old"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_reset_still_in_progress_blocks_the_superseded_walk_entirely() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-fence").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let old_epoch = 1;
    let current_epoch = 2;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        current_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        current_epoch,
        10_000,
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        old_epoch,
        current_epoch,
        "reset_in_progress",
    )
    .await;

    let old_at_superseded = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(old_epoch),
        Some(1),
        9.0,
    )
    .await;

    let outcome =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune call itself must not error");
    assert_eq!(
        outcome,
        SupersededPruneOutcome {
            deleted: 0,
            current: None,
            superseded_placements: 0,
            block: Some(EvaluationBlock::Membership(SafetyBlock::ResetInProgress)),
        },
        "an in-progress fence is a block, distinct from a proven zero-placement answer"
    );
    assert!(
        event_exists(&raw, old_at_superseded).await,
        "the row must be retained while the fence stands"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_two_hop_cleared_chain_reaps_rows_at_both_superseded_placements() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-chain").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let epoch_a = 1;
    let epoch_b = 2;
    let epoch_c = 3; // current
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        epoch_c,
        0,
        state.membership_version,
    )
    .await
    .expect("place at C");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        epoch_c,
        10_000,
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        epoch_a,
        epoch_b,
        "cleared",
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        2,
        epoch_b,
        epoch_c,
        "cleared",
    )
    .await;

    let at_a = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_a),
        Some(1),
        9.0,
    )
    .await;
    let at_b = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_b),
        Some(1),
        9.0,
    )
    .await;
    let at_c = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_c),
        Some(1),
        9.0,
    )
    .await;

    let outcome =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune superseded-epoch rows");
    assert_eq!(outcome.deleted, 2, "both A and B are admitted");
    assert_eq!(outcome.superseded_placements, 2);
    assert!(outcome.block.is_none());

    assert!(!event_exists(&raw, at_a).await, "A must be reaped");
    assert!(!event_exists(&raw, at_b).await, "B must be reaped");
    assert_eq!(
        event_state(&raw, at_c).await,
        "consumer_safe",
        "the current placement C is untouched by this function"
    );

    namespace.release().await;
}

/// `prove_safe_vector`'s fence check (`MembershipSnapshot::reset_in_progress`)
/// is a **cell-wide** `EXISTS` over every reset-generation row, not a
/// per-tuple predicate scoped to the hop the walk would otherwise reach --
/// see `membership.rs`'s `read_membership_snapshot`, which queries
/// `WHERE cell_id = $1 AND state = 'reset_in_progress'` with no
/// `old_stream_*`/`new_stream_*` filter at all. So an in-progress row
/// ANYWHERE in the cell's reset history blocks the entire evaluation --
/// including proving a current placement at all -- before the backward chain
/// walk ever runs, not merely the specific hop it sits on and whatever is
/// behind it. `A -> B` in progress with `B -> C` cleared is exactly the shape
/// CR-032's own module doc uses to say "a hop still reset_in_progress ...
/// blocks the whole chain behind it"; the discriminating fact this test pins
/// is that "the whole chain" means literally everything reachable from
/// current, including a hop nominally AHEAD of the break (B), not just what
/// sits behind the broken hop (A).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_reset_in_progress_anywhere_in_the_cells_history_blocks_the_entire_walk_not_only_the_broken_hop()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-fence-mid").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let epoch_a = 1;
    let epoch_b = 2;
    let epoch_c = 3; // current
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        epoch_c,
        0,
        state.membership_version,
    )
    .await
    .expect("place at C");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        epoch_c,
        10_000,
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        epoch_a,
        epoch_b,
        "reset_in_progress",
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        2,
        epoch_b,
        epoch_c,
        "cleared",
    )
    .await;

    let at_a = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_a),
        Some(1),
        9.0,
    )
    .await;
    let at_b = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_b),
        Some(1),
        9.0,
    )
    .await;
    let at_c = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_c),
        Some(1),
        9.0,
    )
    .await;

    let outcome =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune call itself must not error");
    assert_eq!(
        outcome,
        SupersededPruneOutcome {
            deleted: 0,
            current: None,
            superseded_placements: 0,
            block: Some(EvaluationBlock::Membership(SafetyBlock::ResetInProgress)),
        },
        "any open fence blocks the whole evaluation, not just the hop it sits on"
    );

    assert_eq!(
        event_state(&raw, at_a).await,
        "consumer_safe",
        "A must be retained"
    );
    assert_eq!(
        event_state(&raw, at_b).await,
        "consumer_safe",
        "B is retained too -- the fence blocks proving anything, so it is never reached"
    );
    assert_eq!(
        event_state(&raw, at_c).await,
        "consumer_safe",
        "the current placement is untouched by this function in any case"
    );

    namespace.release().await;
}

/// The complement of the fence case above: no row anywhere is
/// `reset_in_progress`, so `prove_safe_vector` proves a current placement and
/// the backward walk runs -- but the walk itself requires an unbroken run of
/// `cleared` transitions, not merely "an admitted tuple exists somewhere
/// closer to current." `A -> B` has no row at all (a genuine missing link,
/// not an in-progress one), so the walk reaches B through the cleared
/// `B -> C` hop and stops there: nothing leads to A, so A is never admitted,
/// exactly as a stray/forged epoch never is.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_missing_link_in_the_walk_is_never_bridged_so_only_what_it_reaches_is_admitted() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-gap").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let epoch_a = 1;
    let epoch_b = 2;
    let epoch_c = 3; // current
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        epoch_c,
        0,
        state.membership_version,
    )
    .await
    .expect("place at C");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        epoch_c,
        10_000,
    )
    .await;
    // Only B -> C is recorded. No row of any state connects A to B.
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        epoch_b,
        epoch_c,
        "cleared",
    )
    .await;

    let at_a = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_a),
        Some(1),
        9.0,
    )
    .await;
    let at_b = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_b),
        Some(1),
        9.0,
    )
    .await;
    let at_c = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_c),
        Some(1),
        9.0,
    )
    .await;

    let outcome =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune superseded-epoch rows");
    assert_eq!(
        outcome.deleted, 1,
        "only B is reachable through a cleared hop"
    );
    assert_eq!(outcome.superseded_placements, 1);
    assert!(outcome.block.is_none());

    assert_eq!(
        event_state(&raw, at_a).await,
        "consumer_safe",
        "nothing leads to A, so it is never admitted, exactly like a stray epoch"
    );
    assert!(!event_exists(&raw, at_b).await, "B must be reaped");
    assert_eq!(event_state(&raw, at_c).await, "consumer_safe");

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_never_reset_cell_proves_zero_superseded_placements_without_a_block() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-never").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let epoch = 1;

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        epoch,
        10_000,
    )
    .await;

    let outcome =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune superseded-epoch rows");
    assert_eq!(outcome.deleted, 0);
    assert_eq!(
        outcome.superseded_placements, 0,
        "a proven answer that admits nothing, not a block"
    );
    assert!(outcome.block.is_none());
    let current = outcome.current.expect("a proven current placement");
    assert_eq!(current.stream_identity, stream_identity);
    assert_eq!(current.stream_epoch, epoch);

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn superseded_epoch_prune_transactions_are_bounded_at_the_thousand_row_batch() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-batch").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let old_epoch = 1;
    let current_epoch = 2;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        current_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        current_epoch,
        1_000_000,
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        old_epoch,
        current_epoch,
        "cleared",
    )
    .await;

    let mut seed_client = pg_client(&url).await;
    seed_consumer_safe_rows_bulk(
        &mut seed_client,
        &cell_id,
        &repository_id,
        stream_identity,
        old_epoch,
        1_200,
        9.0,
    )
    .await;
    assert_eq!(count_state(&raw, &cell_id, "consumer_safe").await, 1_200);

    let first =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("first prune");
    assert_eq!(first.deleted, MAX_PRUNE_BATCH as u64);
    assert_eq!(first.superseded_placements, 1);

    let second =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("second prune");
    assert_eq!(second.deleted, 200);

    assert_eq!(count_state(&raw, &cell_id, "consumer_safe").await, 0);

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn superseded_epoch_prune_rejects_a_sub_floor_age_and_a_zero_batch() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-args").await;
    let url = namespace.pg_url().to_owned();
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let sub_floor = prune_superseded_epochs(
        &mut deadpool,
        &cell_id,
        MIN_RETENTION_AGE - Duration::from_secs(1),
        MAX_PRUNE_BATCH,
    )
    .await;
    assert!(
        matches!(sub_floor, Err(DomainError::InvalidInput(_))),
        "a sub-floor retention age must be refused, not clamped: got {sub_floor:?}"
    );

    let zero_batch = prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, 0).await;
    assert!(
        matches!(zero_batch, Err(DomainError::InvalidInput(_))),
        "a zero batch must be refused: got {zero_batch:?}"
    );

    namespace.release().await;
}

/// Nothing in the schema forbids a cycle across a whole chain -- the per-row
/// successor check (`accept_reset`'s own business logic, bypassed here by a
/// direct SQL seed) only refuses a successor equal to its OWN predecessor, not
/// one reachable several hops back. `A -> B -> C -> A`, all `cleared`, with
/// current placed at A: every node has exactly one predecessor, so nothing
/// short of the `MAX_RESET_CHAIN_DEPTH` bound stops the walk from circling
/// forever, and the walk's own `UNION` (not `UNION ALL`) plus final
/// `SELECT DISTINCT` is what turns that bounded, repeating traversal into the
/// correct two-element admitted set rather than a blown-up multiset or a hang.
/// Wrapped in a generous `tokio::time::timeout` so a future accidental
/// `UNION ALL` (which would keep expanding at the depth bound's full width,
/// not merely revisit a small set) fails this test rather than hanging the
/// whole suite.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_cycle_in_the_reset_chain_terminates_promptly_and_admits_only_the_reachable_set() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-cycle").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let epoch_a = 1; // current
    let epoch_b = 2;
    let epoch_c = 3;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        epoch_a,
        0,
        state.membership_version,
    )
    .await
    .expect("place at A");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        epoch_a,
        10_000,
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        epoch_a,
        epoch_b,
        "cleared",
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        2,
        epoch_b,
        epoch_c,
        "cleared",
    )
    .await;
    // Closes the cycle: C's successor is A, the current placement itself.
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        3,
        epoch_c,
        epoch_a,
        "cleared",
    )
    .await;

    let at_a = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_a),
        Some(1),
        9.0,
    )
    .await;
    let at_b = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_b),
        Some(1),
        9.0,
    )
    .await;
    let at_c = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(epoch_c),
        Some(1),
        9.0,
    )
    .await;

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH),
    )
    .await
    .expect("a cycle must not hang the walk")
    .expect("prune superseded-epoch rows");

    assert_eq!(
        outcome.deleted, 2,
        "B and C are both reachable through the cycle; A is current and untouched"
    );
    assert_eq!(
        outcome.superseded_placements, 2,
        "DISTINCT collapses repeated visits around the cycle to the two real placements"
    );
    assert!(outcome.block.is_none());
    let current = outcome.current.expect("a proven current placement");
    assert_eq!(current.stream_identity, stream_identity);
    assert_eq!(current.stream_epoch, epoch_a);

    assert_eq!(
        event_state(&raw, at_a).await,
        "consumer_safe",
        "the current placement is untouched by this function"
    );
    assert!(!event_exists(&raw, at_b).await, "B must be reaped");
    assert!(!event_exists(&raw, at_c).await, "C must be reaped");

    namespace.release().await;
}

/// Stream identities are not globally unique, so "the walk and delete are
/// scoped by `cell_id`" is worth an executed proof, not a read of the `WHERE`
/// clause. Cell B has its own cleared chain and admits its old placement;
/// cell A has rows at the EXACT same `(stream_identity, stream_epoch)` tuple
/// but no reset chain of its own. Pruning cell A must never touch cell B's
/// rows (or its own, since cell A's chain admits nothing); pruning cell B
/// must reap only cell B's rows, never cell A's coincidentally-matching ones.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_prune_is_scoped_to_its_own_cell_even_when_another_cell_shares_the_same_stream_tuple() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-cellscope").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let stream_identity = "DURABLE-x";
    let shared_old_epoch = 1;
    let repository_id = rand_repository_id();

    // Cell B: a real cleared chain admitting `shared_old_epoch`.
    let cell_b = rand_cell_id();
    let current_epoch_b = 2;
    let state_b = membership::ensure_membership_state(&raw, &cell_b)
        .await
        .expect("ensure membership state for B");
    membership::set_current_placement(
        &raw,
        &cell_b,
        stream_identity,
        current_epoch_b,
        0,
        state_b.membership_version,
    )
    .await
    .expect("place B");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_b,
        "loreserver-1",
        stream_identity,
        current_epoch_b,
        10_000,
    )
    .await;
    insert_reset_transition(
        &raw,
        &cell_b,
        stream_identity,
        1,
        shared_old_epoch,
        current_epoch_b,
        "cleared",
    )
    .await;

    // Cell A: its own valid membership and placement (so a prune of it is a
    // real proven answer, not a `CellUnknown` short-circuit), but NO reset
    // chain of its own -- only a row that happens to sit at the same
    // (stream_identity, epoch) tuple cell B's chain admits.
    let cell_a = rand_cell_id();
    let current_epoch_a = 5;
    let state_a = membership::ensure_membership_state(&raw, &cell_a)
        .await
        .expect("ensure membership state for A");
    membership::set_current_placement(
        &raw,
        &cell_a,
        stream_identity,
        current_epoch_a,
        0,
        state_a.membership_version,
    )
    .await
    .expect("place A");
    join_ready_receiver(
        &raw,
        &mut deadpool,
        &cell_a,
        "loreserver-1",
        stream_identity,
        current_epoch_a,
        10_000,
    )
    .await;

    let row_b = seed_event_row(
        &raw,
        &cell_b,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(shared_old_epoch),
        Some(1),
        9.0,
    )
    .await;
    let row_a = seed_event_row(
        &raw,
        &cell_a,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(shared_old_epoch),
        Some(1),
        9.0,
    )
    .await;

    let outcome_a =
        prune_superseded_epochs(&mut deadpool, &cell_a, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune cell A");
    assert_eq!(
        outcome_a.deleted, 0,
        "cell A has no reset chain of its own, so nothing is admitted for it"
    );
    assert_eq!(outcome_a.superseded_placements, 0);
    assert!(outcome_a.block.is_none());
    assert_eq!(
        event_state(&raw, row_a).await,
        "consumer_safe",
        "cell A's row must survive pruning cell A"
    );
    assert_eq!(
        event_state(&raw, row_b).await,
        "consumer_safe",
        "cell B's row must be untouched by pruning cell A"
    );

    let outcome_b =
        prune_superseded_epochs(&mut deadpool, &cell_b, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune cell B");
    assert_eq!(outcome_b.deleted, 1, "only cell B's own row is reapable");
    assert_eq!(outcome_b.superseded_placements, 1);
    assert!(outcome_b.block.is_none());
    assert!(
        !event_exists(&raw, row_b).await,
        "cell B's row must be reaped"
    );
    assert_eq!(
        event_state(&raw, row_a).await,
        "consumer_safe",
        "cell A's row at the SAME tuple must survive pruning cell B -- cell_id scopes the delete"
    );

    namespace.release().await;
}

/// The seam where the two proofs meet. The reset fence has been CLEARED, so
/// the chain walk itself would admit the predecessor placement -- but a
/// required member is `joining`, with no checkpoint at the CURRENT placement,
/// so `prove_safe_vector` cannot prove the vector at all. `cleared` alone
/// does not carry reapability; `prove_safe_vector` supplies the rest. If this
/// ever goes green by deleting the old row, the two-proof design in this
/// module's own doc comment is broken.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_cleared_chain_still_defers_to_an_unready_required_member_at_the_current_placement() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-superseded-joining").await;
    let url = namespace.pg_url().to_owned();
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let stream_identity = "DURABLE-x";
    let old_epoch = 1;
    let current_epoch = 2;
    let repository_id = rand_repository_id();

    let state = membership::ensure_membership_state(&raw, &cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        &raw,
        &cell_id,
        stream_identity,
        current_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");
    insert_reset_transition(
        &raw,
        &cell_id,
        stream_identity,
        1,
        old_epoch,
        current_epoch,
        "cleared",
    )
    .await;
    // Joined but never captured/baselined/readiness-CAS'd -- stays "joining",
    // with no checkpoint at the current placement.
    let version = current_membership_version(&raw, &cell_id).await;
    membership::join_receiver(&mut deadpool, &cell_id, "loreserver-1", version)
        .await
        .expect("join without ever becoming ready");

    let old_at_superseded = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some(stream_identity),
        Some(old_epoch),
        Some(1),
        9.0,
    )
    .await;

    let outcome =
        prune_superseded_epochs(&mut deadpool, &cell_id, MIN_RETENTION_AGE, MAX_PRUNE_BATCH)
            .await
            .expect("prune call itself must not error");
    assert_eq!(outcome.deleted, 0);
    assert_eq!(outcome.current, None);
    assert_eq!(outcome.superseded_placements, 0);
    assert!(
        matches!(
            outcome.block,
            Some(EvaluationBlock::Membership(
                SafetyBlock::MemberNotReady { .. }
            ))
        ),
        "a cleared chain does not bypass the checkpoint-vector proof: got {:?}",
        outcome.block
    );
    assert!(
        event_exists(&raw, old_at_superseded).await,
        "the row must be retained -- a cleared chain alone never proves reapability"
    );

    namespace.release().await;
}

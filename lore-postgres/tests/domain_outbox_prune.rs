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

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::CapturedPosition;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::SafetyBlock;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::prune::MAX_PRUNE_BATCH;
use lore_postgres::domain::outbox::prune::MIN_DEAD_LETTER_RETENTION;
use lore_postgres::domain::outbox::prune::MIN_RETENTION_AGE;
use lore_postgres::domain::outbox::prune_consumer_safe;
use lore_postgres::domain::outbox::prune_dead_letters;
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

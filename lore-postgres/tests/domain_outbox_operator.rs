// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Phase 8: the bounded operator recovery surface
//! (`lore-postgres/src/domain/outbox/operator.rs`, CR-032's "Retention,
//! replay, and operator recovery" section).
//!
//! Real Postgres only, `#[ignore]`. Every case acquires its own
//! [`case_namespace::CaseNamespace`] schema, matching every other WP-119
//! real-Postgres file in this crate.
//!
//! This file proves the **operator module's own contract**, not the store
//! primitives it composes:
//!
//! * [`operator::requeue_dead_letter`] and [`operator::mark_obsolete`] add a
//!   cell scope in front of [`relay::requeue_dead_letter`] and
//!   [`relay::mark_obsolete`], whose own compare-and-set/audit correctness is
//!   already pinned by `domain_outbox_relay.rs`. This file proves the added
//!   cell scope and the composed obsolete-proof text, not the CAS again.
//! * [`operator::status`] and the inspection functions are new reads with no
//!   prior coverage; this file is their only proof.
//! * [`operator::replay`] is a new write with no prior coverage.
//!
//! `operator::status`'s own module documentation is explicit that
//! [`operator::OperatorStatus::backlog`] is **cell-wide by design** (the same
//! query the relay's own readiness probe uses), while
//! [`operator::OperatorStatus::parked_dead_letters`] is genuinely cell-scoped.
//! Tests here assert that contrast directly rather than assuming every field
//! on the status struct is cell-scoped.

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::time::Duration;
use std::time::SystemTime;

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::AdmissionLimits;
use lore_postgres::domain::outbox::AdmissionVerdict;
use lore_postgres::domain::outbox::CapturedPosition;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::operator;
use lore_postgres::domain::outbox::operator::MAX_INSPECT_ROWS;
use lore_postgres::domain::outbox::operator::MAX_REPLAY_ROWS;
use lore_postgres::domain::outbox::operator::MAX_REPLAY_WINDOW;
use lore_postgres::domain::outbox::operator::OBSOLETE_PROOF_MARKER;
use lore_postgres::domain::outbox::relay;
use lore_postgres::domain::outbox::relay::BrokerAcceptanceRecord;
use lore_postgres::domain::outbox::relay::CasOutcome;
use lore_postgres::domain::outbox::relay::DeadLetterOutcome;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_postgres::domain::outbox::relay::dead_letter;
use lore_postgres::domain::outbox::relay::record_broker_accepted;
use lore_postgres::domain::outbox::relay::release_for_retry;
use lore_postgres::domain::outbox::relay::requeue_unsafe_for_epoch_reset;
use lore_postgres::domain::outbox::report_checkpoint;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn connect_domain_store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

/// A raw `NoTls` connection, for functions bound on `tokio_postgres::GenericClient`.
async fn pg_client(url: &str) -> Client {
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

/// A `deadpool_postgres::Client`, for functions that open their own internal
/// transaction (`claim_batch`, `dead_letter`, `operator::status`,
/// `operator::replay`, `operator::requeue_dead_letter`).
async fn deadpool_client(url: &str) -> deadpool_postgres::Client {
    let pool = build_pool(url, 8, &TlsConfig::default()).expect("build deadpool pool");
    pool.get().await.expect("checkout deadpool connection")
}

fn rand_repository_id() -> [u8; 16] {
    rand::random()
}

fn rand_cell_id() -> String {
    format!("cell-{:016x}", rand::random::<u64>())
}

/// Append one pending row via the real production `append()` path so every
/// case here exercises the actual write path, not a hand-poked row.
async fn append_pending(
    client: &mut Client,
    cell_id: &str,
    repository_id: &[u8],
    ordinal: u64,
) -> Uuid {
    let version = AggregateVersion::ordinal_only(ordinal).encode();
    let aggregate_id: [u8; 16] = rand::random();
    let tx = client.transaction().await.expect("begin append tx");
    let event = OutboxEvent {
        cell_id,
        repository_id,
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id: &aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(&tx, &event).await.expect("append pending event");
    tx.commit().await.expect("commit append");
    appended.event_id
}

/// Claim `event_id` (among whatever else is claimable in the namespace) and
/// record a broker acceptance for it, via the real production path.
async fn claim_and_accept(
    raw: &Client,
    pool_client: &mut deadpool_postgres::Client,
    event_id: Uuid,
    stream_identity: &str,
    stream_epoch: i64,
    broker_sequence: i64,
) -> i64 {
    let claimed = claim_batch(
        pool_client,
        &format!("worker-{:016x}", rand::random::<u64>()),
        50,
        Duration::from_secs(30),
    )
    .await
    .expect("claim");
    let claim = claimed
        .iter()
        .find(|c| c.event.event_id == event_id)
        .unwrap_or_else(|| panic!("{event_id} was not among the claimed rows"));
    let generation = claim.claim_generation;
    let acceptance = BrokerAcceptanceRecord {
        stream_identity: stream_identity.to_owned(),
        stream_epoch,
        broker_sequence,
        gateway_response_id: format!("resp-{:016x}", rand::random::<u64>()),
        publisher_contract_version: 1,
    };
    let outcome = record_broker_accepted(raw, event_id, generation, &acceptance)
        .await
        .expect("record broker acceptance");
    assert_eq!(outcome, CasOutcome::Applied);
    generation
}

/// Claim `event_id` and dead-letter it, via the real production path.
async fn claim_and_dead_letter(
    pool_client: &mut deadpool_postgres::Client,
    event_id: Uuid,
    terminal_class: &str,
) {
    let claimed = claim_batch(
        pool_client,
        &format!("worker-dl-{:016x}", rand::random::<u64>()),
        50,
        Duration::from_secs(30),
    )
    .await
    .expect("claim");
    let claim = claimed
        .iter()
        .find(|c| c.event.event_id == event_id)
        .unwrap_or_else(|| panic!("{event_id} was not among the claimed rows"));
    let outcome = dead_letter(
        pool_client,
        event_id,
        claim.claim_generation,
        terminal_class,
    )
    .await
    .expect("dead letter");
    assert_eq!(outcome, CasOutcome::Applied);
}

/// One directly-seeded outbox row at a controlled `state`, for the states no
/// public write path produces (`consumer_safe`) or for controlling
/// `broker_accepted_at` precisely. Adapted from `domain_outbox_prune.rs`'s
/// helper of the same shape -- `tests/*.rs` files are independent binaries
/// with no shared lib target to put this in besides `common/case_namespace.rs`,
/// which stays scoped to namespacing alone.
#[allow(clippy::too_many_arguments)]
async fn seed_event_row(
    client: &Client,
    cell_id: &str,
    repository_id: &[u8],
    state: &str,
    stream_identity: Option<&str>,
    stream_epoch: Option<i64>,
    broker_sequence: Option<i64>,
    broker_accepted_age_hours: f64,
) -> Uuid {
    let event_id = Uuid::now_v7();
    let seed: i64 = rand::random::<u32>().into();
    let mut idempotency_key = [0u8; 32];
    idempotency_key[24..].copy_from_slice(&seed.to_be_bytes());
    let mut aggregate_id = [0u8; 16];
    aggregate_id[8..].copy_from_slice(&seed.to_be_bytes());
    let aggregate_version = vec![0u8; 8];
    let (gateway_response_id, publisher_contract_version): (Option<String>, Option<i32>) =
        if state == "pending" {
            (None, None)
        } else {
            (Some(format!("gw-{seed}")), Some(1))
        };
    let broker_accepted_at_expr = if state == "pending" {
        "NULL"
    } else {
        "clock_timestamp() - ($8 * interval '1 hour')"
    };
    let sql = format!(
        "INSERT INTO lore_outbox_events \
             (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
              event_kind, aggregate_kind, aggregate_id, aggregate_version, \
              payload_schema_version, payload, state, created_at, available_at, \
              stream_identity, stream_epoch, broker_sequence, gateway_response_id, \
              publisher_contract_version, broker_accepted_at) \
         VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{{}}', $7, \
                 clock_timestamp() - ($8 * interval '1 hour'), clock_timestamp(), \
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
                &broker_accepted_age_hours,
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

struct EventFacts {
    state: String,
    claim_generation: i64,
    replay_count: i32,
    replayed_at: Option<SystemTime>,
    replay_actor: Option<String>,
    replay_reason: Option<String>,
    idempotency_key: Vec<u8>,
    stream_identity: Option<String>,
    broker_accepted_at: Option<SystemTime>,
    unpublished_since: SystemTime,
}

async fn event_facts(raw: &Client, event_id: Uuid) -> Option<EventFacts> {
    let row = raw
        .query_opt(
            "SELECT state, claim_generation, replay_count, replayed_at, replay_actor, \
                    replay_reason, idempotency_key, stream_identity, broker_accepted_at, \
                    unpublished_since \
             FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("event facts query");
    row.map(|r| EventFacts {
        state: r.get("state"),
        claim_generation: r.get("claim_generation"),
        replay_count: r.get("replay_count"),
        replayed_at: r.get("replayed_at"),
        replay_actor: r.get("replay_actor"),
        replay_reason: r.get("replay_reason"),
        idempotency_key: r.get("idempotency_key"),
        stream_identity: r.get("stream_identity"),
        broker_accepted_at: r.get("broker_accepted_at"),
        unpublished_since: r.get("unpublished_since"),
    })
}

/// The dead-letter table's own replay audit columns, which
/// [`operator::DeadLetterRecord`] does not decode (they are `relay::
/// dead_letter`'s/`requeue_dead_letter`'s internal carry-through, not part of
/// the operator procedure's own read model). Read directly for the regression
/// this proves: the audit a replay wrote on the live row must survive a
/// terminal failure into the dead-letter table's copy.
struct DeadLetterReplayFacts {
    replay_count: i32,
    replay_actor: Option<String>,
    replay_reason: Option<String>,
}

async fn dead_letter_replay_facts(raw: &Client, event_id: Uuid) -> DeadLetterReplayFacts {
    let row = raw
        .query_one(
            "SELECT replay_count, replay_actor, replay_reason \
             FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("dead letter replay facts query");
    DeadLetterReplayFacts {
        replay_count: row.get("replay_count"),
        replay_actor: row.get("replay_actor"),
        replay_reason: row.get("replay_reason"),
    }
}

/// Seed one `broker_accepted` row with `created_at` AND `unpublished_since`
/// both backdated by `age_days`, and `broker_accepted_at` backdated
/// separately by `broker_accepted_age_hours`. [`seed_event_row`] omits
/// `unpublished_since` deliberately (its `DEFAULT clock_timestamp()` is the
/// right choice for every case that does not measure age), so a case that
/// needs an old, unpublished-looking row -- reproducing a defect where the
/// age probe read the wrong column -- needs its own seed with the column set
/// explicitly.
///
/// The two ages are independent on purpose: this is the exact shape of the
/// defect under test. A row created a week ago that was accepted by the
/// broker only recently still has a week-old `created_at`/`unpublished_since`
/// (never touched between creation and acceptance) but a recent
/// `broker_accepted_at` -- which is what keeps it inside
/// [`operator::replay`]'s own 24-hour window (`replay` matches on
/// `broker_accepted_at`, not `created_at`/`unpublished_since`; a caller that
/// backdates all three together makes its own seeded row invisible to
/// `replay`'s window, not a replay defect).
#[allow(clippy::too_many_arguments)]
async fn seed_broker_accepted_with_backdated_unpublished_since(
    client: &Client,
    cell_id: &str,
    repository_id: &[u8],
    stream_identity: &str,
    stream_epoch: i64,
    broker_sequence: i64,
    age_days: f64,
    broker_accepted_age_hours: f64,
) -> Uuid {
    let event_id = Uuid::now_v7();
    let seed: i64 = rand::random::<u32>().into();
    let mut idempotency_key = [0u8; 32];
    idempotency_key[24..].copy_from_slice(&seed.to_be_bytes());
    let mut aggregate_id = [0u8; 16];
    aggregate_id[8..].copy_from_slice(&seed.to_be_bytes());
    let aggregate_version = vec![0u8; 8];
    client
        .execute(
            "INSERT INTO lore_outbox_events \
                 (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                  event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                  payload_schema_version, payload, state, created_at, available_at, \
                  unpublished_since, \
                  stream_identity, stream_epoch, broker_sequence, gateway_response_id, \
                  publisher_contract_version, broker_accepted_at) \
             VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', \
                     'broker_accepted', clock_timestamp() - ($7 * interval '1 day'), \
                     clock_timestamp(), clock_timestamp() - ($7 * interval '1 day'), \
                     $8, $9, $10, $11, 1, clock_timestamp() - ($12 * interval '1 hour'))",
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
                &broker_sequence,
                &format!("gw-{seed}"),
                &broker_accepted_age_hours,
            ],
        )
        .await
        .unwrap_or_else(|error| panic!("seed a backdated broker_accepted row: {error}"));
    event_id
}

/// Seed one `pending` row with `created_at` AND `unpublished_since` both
/// backdated by `age_days`, for `release_for_retry`'s negative control: unlike
/// [`operator::replay`] and `relay::requeue_unsafe_for_epoch_reset`,
/// `release_for_retry` must NOT reset `unpublished_since` -- a row failing
/// repeatedly must keep accruing visible age, or a stuck backlog hides.
async fn seed_pending_with_backdated_unpublished_since(
    client: &Client,
    cell_id: &str,
    repository_id: &[u8],
    age_days: f64,
) -> Uuid {
    let event_id = Uuid::now_v7();
    let seed: i64 = rand::random::<u32>().into();
    let mut idempotency_key = [0u8; 32];
    idempotency_key[24..].copy_from_slice(&seed.to_be_bytes());
    let mut aggregate_id = [0u8; 16];
    aggregate_id[8..].copy_from_slice(&seed.to_be_bytes());
    let aggregate_version = vec![0u8; 8];
    client
        .execute(
            "INSERT INTO lore_outbox_events \
                 (event_id, cell_id, idempotency_key, repository_id, repository_generation, \
                  event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                  payload_schema_version, payload, state, created_at, available_at, \
                  unpublished_since) \
             VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', \
                     'pending', clock_timestamp() - ($7 * interval '1 day'), \
                     clock_timestamp(), clock_timestamp() - ($7 * interval '1 day'))",
            &[
                &event_id,
                &cell_id,
                &idempotency_key.as_slice(),
                &repository_id,
                &aggregate_id.as_slice(),
                &aggregate_version,
                &age_days,
            ],
        )
        .await
        .unwrap_or_else(|error| panic!("seed a backdated pending row: {error}"));
    event_id
}

async fn event_state(raw: &Client, event_id: Uuid) -> Option<String> {
    raw.query_opt(
        "SELECT state FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("event state query")
    .map(|r| r.get("state"))
}

async fn dead_letter_idempotency_key(raw: &Client, event_id: Uuid) -> Vec<u8> {
    raw.query_one(
        "SELECT idempotency_key FROM lore_outbox_dead_letters WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("dead letter idempotency key")
    .get("idempotency_key")
}

/// Join, capture, baseline, checkpoint, and readiness-CAS one receiver, after
/// placing the cell's authoritative current stream. Duplicated from
/// `domain_outbox_prune.rs` for the same reason as `seed_event_row`.
async fn set_up_ready_cell(
    raw: &Client,
    deadpool: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    stream_identity: &str,
    stream_epoch: i64,
    frontier: i64,
) -> i64 {
    let state = membership::ensure_membership_state(raw, cell_id)
        .await
        .expect("ensure membership state");
    membership::set_current_placement(
        raw,
        cell_id,
        stream_identity,
        stream_epoch,
        0,
        state.membership_version,
    )
    .await
    .expect("place");

    let version = membership::read_membership_state(raw, cell_id)
        .await
        .expect("read membership state")
        .expect("membership state row present")
        .membership_version;
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
    let version = membership::read_membership_state(raw, cell_id)
        .await
        .expect("read membership state")
        .expect("membership state row present")
        .membership_version;
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

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// `operator::status` against a database with no outbox schema at all -- the
/// first thing an operator points this command at when they are not sure
/// whether cutover ever ran. `CaseNamespace::acquire` alone gives a fresh
/// schema with no DDL applied (see its own module docs), so this is the one
/// test in this file that deliberately skips `connect_domain_store`/
/// `PostgresDomainStore::connect`: bootstrapping first would defeat the case.
///
/// Must return the empty-but-typed report `operator.rs`'s own doc comment
/// describes (`schema_state: None`, an empty `backlog`, `CellUnknown`) rather
/// than surfacing the raw SQLSTATE 42P01 a `relay::backlog`/membership probe
/// would hit against tables that do not exist.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn status_against_a_database_with_no_outbox_schema_reports_the_empty_typed_shape() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "status-no-schema").await;
    let url = namespace.pg_url().to_owned();
    // Deliberately no `connect_domain_store(&url).await` here.
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let status = operator::status(&mut pool_client, &cell_id)
        .await
        .expect("status against a schema-less database must not error");

    assert!(status.schema_state.is_none());
    assert_eq!(status.backlog.pending_count, 0);
    assert_eq!(status.backlog.pending_bytes, 0);
    assert!(status.backlog.oldest_pending_age.is_none());
    assert_eq!(status.backlog.claimed_count, 0);
    assert_eq!(status.backlog.dead_letter_count, 0);
    assert_eq!(status.parked_dead_letters, 0);
    assert!(status.safe_vector.is_none());
    assert_eq!(status.evaluation_block, Some(EvaluationBlock::CellUnknown));
    assert!(status.membership.is_none());

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn status_backlog_is_cell_wide_while_parked_dead_letters_and_schema_state_are_scoped_and_present()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "status-backlog").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_a = rand_cell_id();
    let cell_b = rand_cell_id();
    let repository_a = rand_repository_id();
    let repository_b = rand_repository_id();

    // Cell A: two pending, one dead-lettered -> one pending, one parked.
    let a1 = append_pending(&mut raw, &cell_a, &repository_a, 1).await;
    let _a2 = append_pending(&mut raw, &cell_a, &repository_a, 2).await;
    claim_and_dead_letter(&mut pool_client, a1, "UNSUPPORTED_SCHEMA_V1").await;

    // Cell B: three pending, one dead-lettered -> two pending, one parked.
    let b1 = append_pending(&mut raw, &cell_b, &repository_b, 1).await;
    let _b2 = append_pending(&mut raw, &cell_b, &repository_b, 2).await;
    let _b3 = append_pending(&mut raw, &cell_b, &repository_b, 3).await;
    claim_and_dead_letter(&mut pool_client, b1, "UNSUPPORTED_SCHEMA_V1").await;

    let status = operator::status(&mut pool_client, &cell_a)
        .await
        .expect("status for cell A");

    assert_eq!(status.cell_id, cell_a);
    assert!(
        status.schema_state.is_some(),
        "a bootstrapped database must report a schema state row"
    );

    // Table-wide: cell A's one remaining pending row PLUS cell B's two.
    assert_eq!(
        status.backlog.pending_count, 3,
        "OperatorStatus::backlog is documented cell-wide, not cell-scoped"
    );
    assert_eq!(
        status.backlog.dead_letter_count, 2,
        "relay::backlog's own dead-letter probe carries no cell_id predicate either"
    );

    // Cell-scoped: only cell A's own parked dead letter.
    assert_eq!(
        status.parked_dead_letters, 1,
        "OperatorStatus::parked_dead_letters must not count cell B's dead letter"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn status_before_cutover_reports_no_membership_and_cell_unknown() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "status-precutover").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let status = operator::status(&mut pool_client, &cell_id)
        .await
        .expect("status for a cell that never cut over");

    assert!(status.membership.is_none());
    assert!(status.safe_vector.is_none());
    assert_eq!(status.evaluation_block, Some(EvaluationBlock::CellUnknown));

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn status_after_cutover_with_a_ready_receiver_reports_membership_and_a_proven_safe_vector() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "status-ready").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let generation = set_up_ready_cell(
        &raw,
        &mut pool_client,
        &cell_id,
        "loreserver-1",
        "DURABLE-x",
        7,
        10_000,
    )
    .await;

    let status = operator::status(&mut pool_client, &cell_id)
        .await
        .expect("status for a ready cell");

    let membership = status.membership.expect("membership must be reported");
    assert_eq!(
        membership.current_stream_identity.as_deref(),
        Some("DURABLE-x")
    );
    assert_eq!(membership.current_stream_epoch, Some(7));
    assert!(!membership.reset_in_progress);
    assert_eq!(membership.required_members.len(), 1);
    let member = &membership.required_members[0];
    assert_eq!(member.receiver_identity, "loreserver-1");
    assert_eq!(member.membership_generation, generation);
    assert_eq!(member.state, "ready");
    assert!(member.ready_at.is_some());
    assert!(member.baseline_at.is_some());

    let safe_vector = status.safe_vector.expect("a proven safe vector");
    assert_eq!(safe_vector.stream_identity, "DURABLE-x");
    assert_eq!(safe_vector.stream_epoch, 7);
    assert_eq!(safe_vector.safe_sequence, 10_000);
    assert_eq!(safe_vector.required_members, 1);
    assert!(status.evaluation_block.is_none());

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// inspect_event
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn inspect_event_resolves_the_live_half_and_is_invisible_from_another_cell() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "inspect-event-live").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let other_cell = rand_cell_id();
    let repository_id = rand_repository_id();
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;

    let inspected = operator::inspect_event(&pool_client, &cell_id, event_id)
        .await
        .expect("inspect within the owning cell");
    assert!(inspected.live.is_some());
    assert!(inspected.dead_letter.is_none());
    assert!(!inspected.is_empty());

    let invisible = operator::inspect_event(&pool_client, &other_cell, event_id)
        .await
        .expect("inspect from a different cell");
    assert!(
        invisible.is_empty(),
        "an event ID from another cell must resolve to nothing, indistinguishable from unknown"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn inspect_event_shows_both_halves_once_a_dead_letter_has_been_requeued() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "inspect-event-both").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;

    let dead_only = operator::inspect_event(&pool_client, &cell_id, event_id)
        .await
        .expect("inspect a parked dead letter");
    assert!(dead_only.live.is_none());
    assert!(dead_only.dead_letter.is_some());
    assert_eq!(
        dead_only.dead_letter.as_ref().unwrap().disposition,
        "parked"
    );

    let outcome =
        operator::requeue_dead_letter(&mut pool_client, &cell_id, event_id, "kv", "operator retry")
            .await
            .expect("requeue");
    assert_eq!(outcome, DeadLetterOutcome::Applied);

    let both = operator::inspect_event(&pool_client, &cell_id, event_id)
        .await
        .expect("inspect after requeue");
    assert!(
        both.live.is_some(),
        "the reinstated row must be visible again"
    );
    assert!(!both.is_empty());
    let dead_letter = both
        .dead_letter
        .expect("the evidence row must survive a requeue");
    assert_eq!(dead_letter.disposition, "requeued");

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// inspect_repository
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn inspect_repository_returns_only_this_repository_in_this_cell_capped_at_the_limit() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "inspect-repo").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let other_cell = rand_cell_id();
    let repository_r = rand_repository_id();
    let repository_other = rand_repository_id();

    let mut r_ids = Vec::new();
    for ordinal in 1..=3 {
        r_ids.push(append_pending(&mut raw, &cell_id, &repository_r, ordinal).await);
    }
    // Noise: a different repository in the same cell, and the same repository
    // ID bytes in a different cell.
    let _other_repo = append_pending(&mut raw, &cell_id, &repository_other, 1).await;
    let _other_cell_same_repo = append_pending(&mut raw, &other_cell, &repository_r, 1).await;

    let full = operator::inspect_repository(&pool_client, &cell_id, &repository_r, 10)
        .await
        .expect("inspect the repository with room to spare");
    assert_eq!(full.len(), 3);
    for row in &full {
        assert_eq!(row.event.repository_id, repository_r);
    }
    let full_ids: std::collections::HashSet<Uuid> =
        full.iter().map(|row| row.event.event_id).collect();
    assert_eq!(full_ids, r_ids.into_iter().collect());

    let capped = operator::inspect_repository(&pool_client, &cell_id, &repository_r, 2)
        .await
        .expect("inspect capped at 2");
    assert_eq!(
        capped.len(),
        2,
        "the cap must be honoured even though 3 rows exist"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn inspect_repository_refuses_a_limit_outside_cr_032s_bound_or_a_short_repository_id() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "inspect-repo-bounds").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();

    assert!(
        operator::inspect_repository(&pool_client, &cell_id, &repository_id, 0)
            .await
            .is_err()
    );
    assert!(
        operator::inspect_repository(&pool_client, &cell_id, &repository_id, MAX_INSPECT_ROWS + 1)
            .await
            .is_err()
    );
    assert!(
        operator::inspect_repository(&pool_client, &cell_id, &repository_id[..15], 10)
            .await
            .is_err(),
        "a 15-byte repository id must be refused, not silently truncate-matched"
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// inspect_dead_letters
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn inspect_dead_letters_lists_only_this_cells_parked_rows() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "inspect-dead-letters").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let other_cell = rand_cell_id();
    let repository_id = rand_repository_id();

    // This cell: one still parked, one requeued (must not be listed).
    let parked = append_pending(&mut raw, &cell_id, &repository_id, 1).await;
    claim_and_dead_letter(&mut pool_client, parked, "UNSUPPORTED_SCHEMA_V1").await;
    let requeued = append_pending(&mut raw, &cell_id, &repository_id, 2).await;
    claim_and_dead_letter(&mut pool_client, requeued, "UNSUPPORTED_SCHEMA_V1").await;
    operator::requeue_dead_letter(&mut pool_client, &cell_id, requeued, "kv", "retry")
        .await
        .expect("requeue")
        .eq(&DeadLetterOutcome::Applied)
        .then_some(())
        .expect("requeue applied");

    // Another cell: also parked, must never appear in this cell's listing.
    let other_parked = append_pending(&mut raw, &other_cell, &repository_id, 1).await;
    claim_and_dead_letter(&mut pool_client, other_parked, "UNSUPPORTED_SCHEMA_V1").await;

    let listed = operator::inspect_dead_letters(&pool_client, &cell_id, 10)
        .await
        .expect("inspect dead letters");
    let listed_ids: Vec<Uuid> = listed.iter().map(|d| d.event.event_id).collect();
    assert_eq!(listed_ids, vec![parked]);
    assert_eq!(listed[0].disposition, "parked");

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn replay_returns_broker_accepted_rows_in_window_to_pending_with_original_keys_and_audit() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "replay-happy").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;

    let before = event_facts(&raw, event_id)
        .await
        .expect("row before replay");
    let before_generation =
        claim_and_accept(&raw, &mut pool_client, event_id, "DURABLE-x", 3, 100).await;
    let before_key = before.idempotency_key.clone();

    let outcome = operator::replay(
        &mut pool_client,
        &cell_id,
        None,
        Duration::from_secs(3600),
        10,
        "kv",
        "gateway incident 2026-09-04",
    )
    .await
    .expect("replay");
    assert_eq!(outcome.replayed, 1);
    assert_eq!(outcome.repository_id, None);

    let after = event_facts(&raw, event_id)
        .await
        .expect("row must still exist after replay");
    assert_eq!(after.state, "pending");
    assert_eq!(
        after.idempotency_key, before_key,
        "replay must reuse the original idempotency key"
    );
    assert_eq!(
        after.claim_generation,
        before_generation + 1,
        "the fence must advance, never reset"
    );
    assert_eq!(after.replay_count, 1);
    assert!(after.replayed_at.is_some());
    assert_eq!(after.replay_actor.as_deref(), Some("kv"));
    assert_eq!(
        after.replay_reason.as_deref(),
        Some("gateway incident 2026-09-04")
    );
    assert!(
        after.stream_identity.is_none() && after.broker_accepted_at.is_none(),
        "the publication result must be cleared, or the publication-shape CHECK would reject this"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn replay_never_touches_consumer_safe_or_pending_rows() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "replay-untouched").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();

    let safe = seed_event_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        Some("DURABLE-x"),
        Some(1),
        Some(1),
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
        0.5,
    )
    .await;

    let outcome = operator::replay(
        &mut pool_client,
        &cell_id,
        None,
        MAX_REPLAY_WINDOW,
        MAX_REPLAY_ROWS,
        "kv",
        "sweep",
    )
    .await
    .expect("replay over the whole window");
    assert_eq!(
        outcome.replayed, 0,
        "neither seeded row is broker_accepted, so nothing is eligible"
    );

    assert_eq!(
        event_state(&raw, safe).await.as_deref(),
        Some("consumer_safe")
    );
    assert_eq!(event_state(&raw, pending).await.as_deref(), Some("pending"));

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn replay_scoped_to_one_repository_leaves_the_others_broker_accepted_rows_alone() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "replay-repo-scope").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_target = rand_repository_id();
    let repository_other = rand_repository_id();

    let target = append_pending(&mut raw, &cell_id, &repository_target, 1).await;
    claim_and_accept(&raw, &mut pool_client, target, "DURABLE-x", 1, 10).await;
    let other = append_pending(&mut raw, &cell_id, &repository_other, 1).await;
    claim_and_accept(&raw, &mut pool_client, other, "DURABLE-x", 1, 11).await;

    let outcome = operator::replay(
        &mut pool_client,
        &cell_id,
        Some(&repository_target),
        MAX_REPLAY_WINDOW,
        MAX_REPLAY_ROWS,
        "kv",
        "targeted replay",
    )
    .await
    .expect("scoped replay");
    assert_eq!(outcome.replayed, 1);
    assert_eq!(
        outcome.repository_id.as_deref(),
        Some(repository_target.as_slice())
    );

    assert_eq!(event_state(&raw, target).await.as_deref(), Some("pending"));
    assert_eq!(
        event_state(&raw, other).await.as_deref(),
        Some("broker_accepted"),
        "an unrelated repository's broker_accepted row must be untouched"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn replay_refuses_a_window_over_a_day_or_a_row_bound_over_a_thousand() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "replay-bounds").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();

    let over_window = operator::replay(
        &mut pool_client,
        &cell_id,
        None,
        MAX_REPLAY_WINDOW + Duration::from_secs(1),
        10,
        "kv",
        "reason",
    )
    .await;
    assert!(over_window.is_err(), "a >24h window must be refused");

    let over_rows = operator::replay(
        &mut pool_client,
        &cell_id,
        None,
        Duration::from_secs(60),
        MAX_REPLAY_ROWS + 1,
        "kv",
        "reason",
    )
    .await;
    assert!(over_rows.is_err(), "a >1000-row bound must be refused");

    let empty_actor = operator::replay(
        &mut pool_client,
        &cell_id,
        None,
        Duration::from_secs(60),
        10,
        "",
        "reason",
    )
    .await;
    assert!(empty_actor.is_err(), "an empty actor must be refused");

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// unpublished_since: a recovered row must not report stale relay lag
//
// Regression for a cold-review defect: `oldest_pending_age` used to be
// measured from `created_at`, so recovering (replaying, or epoch-reset-
// requeueing) a row that had been published a week ago reported a week of
// relay lag the moment the recovery command succeeded -- above both
// `max_oldest_unpublished` (30s) and admission's `max_oldest_pending_age`
// (300s default), closing the cell's own write admission as a side effect of
// the recovery meant to fix it. The fix is `unpublished_since`, reset by
// `operator::replay` and `relay::requeue_unsafe_for_epoch_reset` (and by
// `relay::requeue_dead_letter`, already proven by
// `operator_requeue_dead_letter_reinstates_with_original_keys_and_refuses_a_second_requeue`'s
// `EventStillPresent`/CAS path -- not repeated here) -- and deliberately NOT
// by `release_for_retry`, whose whole job is to keep a repeatedly-failing
// row's age visible so a stuck backlog cannot hide.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn replay_resets_unpublished_since_so_a_week_old_publication_does_not_close_admission() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "unpub-since-replay").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();

    seed_broker_accepted_with_backdated_unpublished_since(
        &raw,
        &cell_id,
        &repository_id,
        "DURABLE-x",
        1,
        1,
        7.0,
        1.0,
    )
    .await;

    operator::replay(
        &mut pool_client,
        &cell_id,
        None,
        MAX_REPLAY_WINDOW,
        MAX_REPLAY_ROWS,
        "kv",
        "unpublished_since regression (INV: cold review)",
    )
    .await
    .expect("replay the week-old published row");

    let backlog = relay::backlog(&raw).await.expect("backlog after replay");
    let oldest = backlog
        .oldest_pending_age
        .expect("the replayed row is pending, so there is an oldest age");
    assert!(
        oldest < Duration::from_secs(30),
        "a just-replayed row must report a fresh age, not the week it sat published; got \
         {oldest:?}"
    );

    let verdict = relay::admission_check(&raw, &AdmissionLimits::default())
        .await
        .expect("admission check after replay");
    assert_eq!(
        verdict,
        AdmissionVerdict::Admit,
        "a successful replay must not close the cell's own write admission"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn epoch_reset_requeue_resets_unpublished_since_so_a_week_old_publication_does_not_close_admission()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "unpub-since-epoch-reset").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let stream_identity = "DURABLE-x";
    let old_epoch = 3;

    seed_broker_accepted_with_backdated_unpublished_since(
        &raw,
        &cell_id,
        &repository_id,
        stream_identity,
        old_epoch,
        1,
        7.0,
        7.0 * 24.0,
    )
    .await;

    let requeued = requeue_unsafe_for_epoch_reset(&mut pool_client, stream_identity, old_epoch)
        .await
        .expect("epoch reset requeue");
    assert_eq!(requeued, 1);

    let backlog = relay::backlog(&raw)
        .await
        .expect("backlog after epoch reset");
    let oldest = backlog
        .oldest_pending_age
        .expect("the requeued row is pending, so there is an oldest age");
    assert!(
        oldest < Duration::from_secs(30),
        "a just-epoch-reset row must report a fresh age, not the week it sat published; got \
         {oldest:?}"
    );

    let verdict = relay::admission_check(&raw, &AdmissionLimits::default())
        .await
        .expect("admission check after epoch reset requeue");
    assert_eq!(
        verdict,
        AdmissionVerdict::Admit,
        "a broker epoch reset's requeue must not close the cell's own write admission"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn release_for_retry_leaves_unpublished_since_alone_so_a_stuck_row_keeps_accruing_age() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "unpub-since-retry").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();

    let event_id =
        seed_pending_with_backdated_unpublished_since(&raw, &cell_id, &repository_id, 1.0).await;
    let before = event_facts(&raw, event_id)
        .await
        .expect("row before release_for_retry");

    let claimed = claim_batch(
        &mut pool_client,
        "worker-retry",
        10,
        Duration::from_secs(30),
    )
    .await
    .expect("claim");
    let claim = claimed
        .iter()
        .find(|c| c.event.event_id == event_id)
        .expect("claimed the seeded row");

    let outcome = release_for_retry(
        &raw,
        event_id,
        claim.claim_generation,
        "TRANSIENT_TRANSPORT_ERROR",
        std::time::SystemTime::now(),
    )
    .await
    .expect("release for retry");
    assert_eq!(outcome, CasOutcome::Applied);

    let after = event_facts(&raw, event_id)
        .await
        .expect("row after release_for_retry");
    assert_eq!(
        after.unpublished_since, before.unpublished_since,
        "release_for_retry must not touch unpublished_since: a repeatedly-failing row must \
         keep accruing visible age"
    );

    let backlog = relay::backlog(&raw)
        .await
        .expect("backlog after release_for_retry");
    let oldest = backlog
        .oldest_pending_age
        .expect("the row is pending, so there is an oldest age");
    assert!(
        oldest >= Duration::from_secs(23 * 60 * 60),
        "the row's age must still read close to its original 1-day backdate, not reset to \
         fresh; got {oldest:?}"
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// requeue_dead_letter / mark_obsolete (cell-scoped operator wrappers)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn operator_requeue_dead_letter_reinstates_with_original_keys_and_refuses_a_second_requeue() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "operator-requeue").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;
    let before_key = dead_letter_idempotency_key(&raw, event_id).await;

    let applied = operator::requeue_dead_letter(
        &mut pool_client,
        &cell_id,
        event_id,
        "kv",
        "authoritative fix landed",
    )
    .await
    .expect("first requeue");
    assert_eq!(applied, DeadLetterOutcome::Applied);
    let after = event_facts(&raw, event_id)
        .await
        .expect("reinstated row must exist");
    assert_eq!(after.state, "pending");
    assert_eq!(after.idempotency_key, before_key);

    let second =
        operator::requeue_dead_letter(&mut pool_client, &cell_id, event_id, "kv", "second attempt")
            .await
            .expect("second requeue call");
    assert!(
        matches!(second, DeadLetterOutcome::NotParked { .. }),
        "a second requeue of the same dead letter must be refused, got {second:?}"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn operator_dead_letter_dispositions_are_invisible_across_cells() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "operator-cross-cell").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let other_cell = rand_cell_id();
    let repository_id = rand_repository_id();
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;

    let requeue_from_wrong_cell =
        operator::requeue_dead_letter(&mut pool_client, &other_cell, event_id, "kv", "reason")
            .await
            .expect("requeue call from another cell");
    assert_eq!(requeue_from_wrong_cell, DeadLetterOutcome::NotFound);

    let obsolete_from_wrong_cell =
        operator::mark_obsolete(&pool_client, &other_cell, event_id, "kv", "reason", "proof")
            .await
            .expect("obsolete call from another cell");
    assert_eq!(obsolete_from_wrong_cell, DeadLetterOutcome::NotFound);

    // Prove the row is genuinely untouched, not merely reported not-found.
    let still_parked = operator::inspect_event(&pool_client, &cell_id, event_id)
        .await
        .expect("inspect from the owning cell");
    assert_eq!(
        still_parked.dead_letter.expect("still parked").disposition,
        "parked"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn operator_mark_obsolete_composes_reason_and_proof_and_never_deletes_the_dead_letter_row() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "operator-obsolete").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;

    let outcome = operator::mark_obsolete(
        &pool_client,
        &cell_id,
        event_id,
        "kv",
        "repository was deleted",
        "repository_get returned NotFound for repo 0x0a.. at generation 9",
    )
    .await
    .expect("mark obsolete");
    assert_eq!(outcome, DeadLetterOutcome::Applied);

    let inspected = operator::inspect_event(&pool_client, &cell_id, event_id)
        .await
        .expect("inspect after obsolete");
    let dead_letter = inspected
        .dead_letter
        .expect("the evidence row must survive an obsolete disposition");
    assert_eq!(dead_letter.disposition, "obsolete");
    let reason = dead_letter
        .disposition_reason
        .expect("a reason must be recorded");
    assert!(reason.starts_with("repository was deleted"));
    assert!(reason.contains(OBSOLETE_PROOF_MARKER));
    assert!(reason.contains("repo 0x0a.."));
    assert!(
        inspected.live.is_none(),
        "obsolete never reinstates the row"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn operator_mark_obsolete_requires_a_non_empty_proof() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "operator-obsolete-proof-required").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;

    let refused =
        operator::mark_obsolete(&pool_client, &cell_id, event_id, "kv", "reason", "").await;
    assert!(
        refused.is_err(),
        "an empty proof must be refused rather than silently treated as absent"
    );

    let inspected = operator::inspect_event(&pool_client, &cell_id, event_id)
        .await
        .expect("inspect after refusal");
    assert_eq!(
        inspected.dead_letter.expect("row untouched").disposition,
        "parked",
        "a refused obsolete call must not have mutated the disposition"
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// The replay audit must survive a dead-letter cycle
//
// Regression for a cold-review defect: `lore_outbox_dead_letters` had no
// `replay_*` columns, so replay -> terminal failure -> requeue reinstated the
// row with `replay_count = 0` and a null actor/reason -- CR-032's audit lost
// on exactly the path ("identify the terminal class... monitor the original
// stable key through acknowledgement") an incident review asks about. The fix
// carries the four columns on both the dead-letter INSERT/`ON CONFLICT`
// update and the requeue reinstatement.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_replay_audit_survives_a_dead_letter_and_requeue_cycle() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "replay-audit-dl-cycle").await;
    let url = namespace.pg_url().to_owned();
    connect_domain_store(&url).await;
    let mut raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();

    // Publish, then replay it -- this is what writes the audit under test.
    let event_id = append_pending(&mut raw, &cell_id, &repository_id, 1).await;
    claim_and_accept(&raw, &mut pool_client, event_id, "DURABLE-x", 1, 1).await;
    operator::replay(
        &mut pool_client,
        &cell_id,
        None,
        MAX_REPLAY_WINDOW,
        MAX_REPLAY_ROWS,
        "kv",
        "incident-1: gateway flapped",
    )
    .await
    .expect("replay");
    let after_replay = event_facts(&raw, event_id).await.expect("row after replay");
    assert_eq!(after_replay.replay_count, 1);
    assert_eq!(after_replay.replay_actor.as_deref(), Some("kv"));
    assert_eq!(
        after_replay.replay_reason.as_deref(),
        Some("incident-1: gateway flapped")
    );

    // Terminal failure: the replayed row goes to the dead-letter table. The
    // audit must be copied, not dropped, by dead_letter's INSERT.
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;
    let dl_after_park = dead_letter_replay_facts(&raw, event_id).await;
    assert_eq!(
        dl_after_park.replay_count, 1,
        "the replay audit must be copied onto the dead-letter evidence row"
    );
    assert_eq!(dl_after_park.replay_actor.as_deref(), Some("kv"));
    assert_eq!(
        dl_after_park.replay_reason.as_deref(),
        Some("incident-1: gateway flapped")
    );

    // Requeue: a *different* actor/reason for the disposition decision itself
    // (recorded on disposition_actor/disposition_reason, asserted elsewhere) --
    // it must not overwrite the original replay audit on either copy.
    let outcome = operator::requeue_dead_letter(
        &mut pool_client,
        &cell_id,
        event_id,
        "ops",
        "bring back after schema fix",
    )
    .await
    .expect("requeue");
    assert_eq!(outcome, DeadLetterOutcome::Applied);

    let live_after_requeue = event_facts(&raw, event_id)
        .await
        .expect("live row after requeue");
    assert_eq!(
        live_after_requeue.replay_count, 1,
        "the reinstated live row must keep the original replay audit"
    );
    assert_eq!(live_after_requeue.replay_actor.as_deref(), Some("kv"));
    assert_eq!(
        live_after_requeue.replay_reason.as_deref(),
        Some("incident-1: gateway flapped")
    );

    let dl_after_requeue = dead_letter_replay_facts(&raw, event_id).await;
    assert_eq!(
        dl_after_requeue.replay_count, 1,
        "the evidence row's replay audit must survive the requeue too"
    );
    assert_eq!(dl_after_requeue.replay_actor.as_deref(), Some("kv"));
    assert_eq!(
        dl_after_requeue.replay_reason.as_deref(),
        Some("incident-1: gateway flapped")
    );

    namespace.release().await;
}

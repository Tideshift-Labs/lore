// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Phase 8: the `loreserver outbox` maintenance command
//! (`lore-server/src/event_relay/operator.rs`) and the retention schedule
//! (`lore-server/src/event_relay/prune_task.rs`), plus confirming checks on
//! `admission::ADMISSION_RETRY_DELAY` and `reset_budget::ReportBudget`'s
//! shipped defaults (both already pinned by their own crates' module tests,
//! which this file cross-checks from outside the crate rather than
//! re-deriving).
//!
//! # `reset_budget`'s wiring into `reset_service.rs` is source-reviewed here,
//! # not test-driven
//!
//! `StreamResetHandler::note_rejection`/`note_success` are private, and its
//! only public entry point (`report_stream_reset`) needs a real mTLS peer
//! certificate that `tonic::transport::TlsConnectInfo` has no public
//! constructor for outside a genuine TLS handshake -- the same limitation
//! `event_relay_reset.rs`'s own module docs record for the wider
//! authenticate/authorize/derive gate. Confirmed by reading
//! `reset_service.rs`'s `serve`/`receipt`: every one of the six
//! `ResetAcceptance` rejection arms plus the unauthenticated and unauthorized
//! failures calls `note_rejection(principal_or_shared_key, ...)`, and both
//! success arms (`ExactReplay`, `Applied`) call `note_success(&principal)`
//! before returning -- so a caller's status is decided independent of, and
//! before, the budget charge in every arm. `reset_budget.rs`'s own tests never
//! exercise `ReportBudget::default()` (they build small custom budgets), so
//! this file's own `reset_budget` test below is the only proof the *shipped*
//! `REJECTION_BUDGET`/`REJECTION_REFILL_INTERVAL` constants behave as the spec
//! requires.
//!
//! Real Postgres only where noted, `#[ignore]`. `RetentionTask` and the
//! `MaintenanceCommand::run` cases each acquire their own
//! [`case_namespace::CaseNamespace`] schema.
//!
//! # What this file proves, and what it deliberately does not
//!
//! `event_relay::operator`'s dispatch (`OperatorContext::open`/`run`) is thin:
//! it resolves settings, opens one connection, and calls straight into
//! `lore_postgres::domain::outbox::operator`, whose own correctness is already
//! proven by `lore-postgres/tests/domain_outbox_operator.rs`. This file proves
//! the **wiring** — that a `MaintenanceCommand` built the way `clap` would
//! build it actually reaches the right store function against a real
//! database and produces the right persisted effect — and the **settings
//! preconditions** (`mutable_store.mode = postgres`, `[plugins.remote]`
//! present), which are unique to this layer. It does not re-derive the store
//! semantics, and it does not capture stdout: `run()` prints for a human and
//! returns `Result<()>`, so correctness here is asserted against the
//! database, the same way an operator's own follow-up `inspect` would confirm
//! it.

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::sync::Arc;
use std::time::Duration;

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::relay::BrokerAcceptanceRecord;
use lore_postgres::domain::outbox::relay::CasOutcome;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_postgres::domain::outbox::relay::dead_letter;
use lore_postgres::domain::outbox::relay::record_broker_accepted;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_server::event_relay::EventRelayReadiness;
use lore_server::event_relay::RetentionConfig;
use lore_server::event_relay::RetentionTask;
use lore_server::event_relay::admission;
use lore_server::event_relay::operator::MaintenanceCommand;
use lore_server::event_relay::operator::OutboxCommand;
use lore_server::event_relay::retry_info;
use lore_server::settings::Settings;
use tokio_postgres::Client;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

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

async fn deadpool_client(url: &str) -> lore_postgres::pool::Client {
    let pool = build_pool(url, 8, &TlsConfig::default()).expect("build deadpool pool");
    pool.get().await.expect("checkout deadpool connection")
}

fn rand_repository_id() -> [u8; 16] {
    rand::random()
}

fn rand_cell_id() -> String {
    format!("cell-{:016x}", rand::random::<u64>())
}

async fn append_pending(client: &mut Client, cell_id: &str, repository_id: &[u8]) -> Uuid {
    let version = AggregateVersion::ordinal_only(1).encode();
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

async fn claim_and_dead_letter(
    pool_client: &mut lore_postgres::pool::Client,
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

async fn claim_and_accept(
    raw: &Client,
    pool_client: &mut lore_postgres::pool::Client,
    event_id: Uuid,
    stream_identity: &str,
    stream_epoch: i64,
) {
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
    let acceptance = BrokerAcceptanceRecord {
        stream_identity: stream_identity.to_owned(),
        stream_epoch,
        broker_sequence: 1,
        gateway_response_id: format!("resp-{:016x}", rand::random::<u64>()),
        publisher_contract_version: 1,
    };
    let outcome = record_broker_accepted(raw, event_id, claim.claim_generation, &acceptance)
        .await
        .expect("record broker acceptance");
    assert_eq!(outcome, CasOutcome::Applied);
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

async fn dead_letter_disposition(raw: &Client, event_id: Uuid) -> String {
    raw.query_one(
        "SELECT disposition FROM lore_outbox_dead_letters WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("dead letter disposition query")
    .get("disposition")
}

async fn dead_letter_reason(raw: &Client, event_id: Uuid) -> Option<String> {
    raw.query_one(
        "SELECT disposition_reason FROM lore_outbox_dead_letters WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("dead letter reason query")
    .get("disposition_reason")
}

/// A minimal `Settings` document with a real, cell-scoped Postgres mutable
/// store and a parseable `[plugins.remote]`, matching
/// `event_relay_wiring.rs`'s own minimal-fixture convention. `[outbox_relay]`
/// stays disabled -- these tests drive the operator surface, never the relay
/// worker, and `OperatorContext::open`'s own module docs say the surface must
/// work even when the relay is off.
fn operator_settings(pg_url: &str, cell_id: &str) -> Settings {
    let toml_text = format!(
        r#"
        [server]
        runtime_shutdown_timeout_seconds = 0

        [server.http]
        enabled = false
        host = "127.0.0.1"
        max_file_size = 1024
        port = 8080
        request_timeout_seconds = 30
        request_body_timeout_seconds = 30
        available_interval_seconds = 5
        available_timeout_seconds = 30
        store_health_check = false

        [immutable_store]
        mode = "local"

        [immutable_store.local]
        path = "/tmp/immutable"
        flush_delay_seconds = 5

        [mutable_store]
        mode = "postgres"

        [plugins.postgres]
        url = {pg_url:?}

        [notification]
        mode = "remote"

        [plugins.remote]
        gateway_uri = "http://127.0.0.1:1"
        cell_id = {cell_id:?}
        placement_epoch = 1
        producer_instance_id = "outbox-operator-cli-test"
        allow_insecure_transport_for_test = true

        [outbox_relay]
        enabled = false
        "#
    );
    // `Settings` borrows string fields from its source (see
    // `event_relay_wiring.rs`'s own comment on this), so a per-test
    // interpolated document -- unlike the crate's `const &str` fixtures --
    // needs its backing string promoted to `'static` before `Settings` can
    // borrow from it and cross this function's return boundary. Leaking is
    // deliberate and bounded: one short-lived test process, one document.
    let leaked: &'static str = Box::leak(toml_text.into_boxed_str());
    toml::from_str(leaked).expect("operator Settings TOML must parse")
}

// ---------------------------------------------------------------------------
// Precondition refusals (offline: no real Postgres needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_maintenance_command_refuses_when_mutable_store_is_not_postgres_mode() {
    let toml_text = r#"
        [server]
        runtime_shutdown_timeout_seconds = 0

        [server.http]
        enabled = false
        host = "127.0.0.1"
        max_file_size = 1024
        port = 8080
        request_timeout_seconds = 30
        request_body_timeout_seconds = 30
        available_interval_seconds = 5
        available_timeout_seconds = 30
        store_health_check = false

        [immutable_store]
        mode = "local"

        [immutable_store.local]
        path = "/tmp/immutable"
        flush_delay_seconds = 5

        [mutable_store]
        mode = "local"

        [mutable_store.local]
        path = "/tmp/mutable"
        flush_delay_seconds = 5

        [outbox_relay]
        enabled = false
    "#;
    let settings: Settings = toml::from_str(toml_text).expect("valid Settings TOML");
    let command = MaintenanceCommand::Outbox {
        command: OutboxCommand::Status { json: true },
    };
    let error = lore_server::event_relay::operator::run(&command, &settings)
        .await
        .expect_err("a non-Postgres mutable store must refuse before touching anything");
    assert!(
        format!("{error:#}").contains("postgres"),
        "the refusal must name the postgres precondition, got: {error:#}"
    );
}

#[tokio::test]
async fn the_maintenance_command_refuses_when_plugins_remote_is_absent() {
    let toml_text = r#"
        [server]
        runtime_shutdown_timeout_seconds = 0

        [server.http]
        enabled = false
        host = "127.0.0.1"
        max_file_size = 1024
        port = 8080
        request_timeout_seconds = 30
        request_body_timeout_seconds = 30
        available_interval_seconds = 5
        available_timeout_seconds = 30
        store_health_check = false

        [immutable_store]
        mode = "local"

        [immutable_store.local]
        path = "/tmp/immutable"
        flush_delay_seconds = 5

        [mutable_store]
        mode = "postgres"

        [plugins.postgres]
        url = "postgresql://unused:unused@127.0.0.1:1/unused"

        [outbox_relay]
        enabled = false
    "#;
    let settings: Settings = toml::from_str(toml_text).expect("valid Settings TOML");
    let command = MaintenanceCommand::Outbox {
        command: OutboxCommand::Status { json: false },
    };
    let error = lore_server::event_relay::operator::run(&command, &settings)
        .await
        .expect_err("a missing [plugins.remote] must refuse before opening a connection");
    assert!(
        format!("{error:#}").contains("plugins.remote"),
        "the refusal must name the missing section, got: {error:#}"
    );
}

// ---------------------------------------------------------------------------
// Dead-letter dispositions, through the real CLI dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn cli_requeue_dead_letter_reinstates_the_row_and_refuses_a_second_requeue() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "cli-requeue").await;
    let url = namespace.pg_url().to_owned();
    PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap schema");
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let mut raw_mut = pg_client(&url).await;
    let event_id = append_pending(&mut raw_mut, &cell_id, &repository_id).await;
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;

    let settings = operator_settings(&url, &cell_id);
    let command = MaintenanceCommand::Outbox {
        command: OutboxCommand::RequeueDeadLetter {
            event: event_id,
            actor: "kv".to_owned(),
            reason: "authoritative fix landed".to_owned(),
        },
    };
    lore_server::event_relay::operator::run(&command, &settings)
        .await
        .expect("the CLI requeue must apply");

    assert_eq!(
        event_state(&raw, event_id).await.as_deref(),
        Some("pending")
    );
    assert_eq!(dead_letter_disposition(&raw, event_id).await, "requeued");

    let second = MaintenanceCommand::Outbox {
        command: OutboxCommand::RequeueDeadLetter {
            event: event_id,
            actor: "kv".to_owned(),
            reason: "second attempt".to_owned(),
        },
    };
    let error = lore_server::event_relay::operator::run(&second, &settings)
        .await
        .expect_err("a second requeue of an already-requeued dead letter must fail the process");
    assert!(
        format!("{error:#}").contains("requeued"),
        "the refusal must name the current disposition, got: {error:#}"
    );

    namespace.release().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn cli_obsolete_records_the_composed_reason_and_never_deletes_the_row() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "cli-obsolete").await;
    let url = namespace.pg_url().to_owned();
    PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap schema");
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let mut raw_mut = pg_client(&url).await;
    let event_id = append_pending(&mut raw_mut, &cell_id, &repository_id).await;
    claim_and_dead_letter(&mut pool_client, event_id, "UNSUPPORTED_SCHEMA_V1").await;

    let settings = operator_settings(&url, &cell_id);
    let command = MaintenanceCommand::Outbox {
        command: OutboxCommand::Obsolete {
            event: event_id,
            actor: "kv".to_owned(),
            reason: "repository was deleted".to_owned(),
            proof: "repository_get returned NotFound".to_owned(),
        },
    };
    lore_server::event_relay::operator::run(&command, &settings)
        .await
        .expect("the CLI obsolete disposition must apply");

    assert_eq!(dead_letter_disposition(&raw, event_id).await, "obsolete");
    let reason = dead_letter_reason(&raw, event_id)
        .await
        .expect("a reason must be recorded");
    assert!(reason.contains("repository was deleted"));
    assert!(reason.contains("repository_get returned NotFound"));

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Replay, through the real CLI dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn cli_replay_moves_broker_accepted_rows_to_pending_within_the_window() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "cli-replay").await;
    let url = namespace.pg_url().to_owned();
    PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap schema");
    let raw = pg_client(&url).await;
    let mut pool_client = deadpool_client(&url).await;

    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let mut raw_mut = pg_client(&url).await;
    let event_id = append_pending(&mut raw_mut, &cell_id, &repository_id).await;
    claim_and_accept(&raw, &mut pool_client, event_id, "DURABLE-x", 1).await;

    let settings = operator_settings(&url, &cell_id);
    let command = MaintenanceCommand::Outbox {
        command: OutboxCommand::Replay {
            repository: None,
            window_hours: 24,
            limit: 10,
            actor: "kv".to_owned(),
            reason: "cli replay test".to_owned(),
            json: false,
        },
    };
    lore_server::event_relay::operator::run(&command, &settings)
        .await
        .expect("the CLI replay must apply");

    assert_eq!(
        event_state(&raw, event_id).await.as_deref(),
        Some("pending")
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Status, through the real CLI dispatch (reachability; content is
// `lore_postgres::domain::outbox::operator::status`'s own proof)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn cli_status_reaches_the_configured_cell_without_erroring_in_json_or_text_mode() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "cli-status").await;
    let url = namespace.pg_url().to_owned();
    PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap schema");
    let cell_id = rand_cell_id();
    let settings = operator_settings(&url, &cell_id);

    let json_command = MaintenanceCommand::Outbox {
        command: OutboxCommand::Status { json: true },
    };
    lore_server::event_relay::operator::run(&json_command, &settings)
        .await
        .expect("status --json must succeed against a bootstrapped, empty cell");

    let text_command = MaintenanceCommand::Outbox {
        command: OutboxCommand::Status { json: false },
    };
    lore_server::event_relay::operator::run(&text_command, &settings)
        .await
        .expect("status (human) must succeed against a bootstrapped, empty cell");

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// The Phase 8 retention schedule (RetentionTask), driven with a tiny
// sweep_interval. Ages stay at CR-032's real floors -- the store refuses
// anything below them -- so rows are seeded already past the floor by direct
// SQL, matching lore-postgres/tests/domain_outbox_prune.rs's own pattern.
// ---------------------------------------------------------------------------

async fn set_up_ready_cell(
    raw: &Client,
    deadpool: &mut lore_postgres::pool::Client,
    cell_id: &str,
    receiver_identity: &str,
    stream_identity: &str,
    stream_epoch: i64,
    frontier: i64,
) {
    use lore_postgres::domain::outbox::CapturedPosition;
    use lore_postgres::domain::outbox::CheckpointOutcome;
    use lore_postgres::domain::outbox::CheckpointReport;
    use lore_postgres::domain::outbox::MembershipCas;
    use lore_postgres::domain::outbox::membership;
    use lore_postgres::domain::outbox::report_checkpoint;

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
}

/// One directly-seeded outbox row at a controlled `state`/age. `prune_task`'s
/// own re-proof needs `consumer_safe` rows already shaped like what the real
/// evaluator would have left, which no public write path here produces --
/// same reason `domain_outbox_prune.rs` seeds by SQL.
#[allow(clippy::too_many_arguments)]
async fn seed_outbox_row(
    client: &Client,
    cell_id: &str,
    repository_id: &[u8],
    state: &str,
    stream_identity: &str,
    stream_epoch: i64,
    broker_sequence: i64,
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
                  stream_identity, stream_epoch, broker_sequence, gateway_response_id, \
                  publisher_contract_version, broker_accepted_at) \
             VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', $7, \
                     clock_timestamp() - ($8 * interval '1 day'), clock_timestamp(), \
                     $9, $10, $11, $12, 1, clock_timestamp())",
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
                &format!("gw-{seed}"),
            ],
        )
        .await
        .unwrap_or_else(|error| panic!("seed a {state} row: {error}"));
    event_id
}

async fn insert_dead_letter_disposed(
    client: &Client,
    cell_id: &str,
    disposition_age_days: f64,
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
                  payload_schema_version, payload, created_at, attempt_count, claim_generation, \
                  terminal_class, first_failed_at, last_failed_at, disposition, \
                  disposition_reason, disposition_at, disposition_actor) \
             VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}', \
                     clock_timestamp(), 1, 1, 'UNSUPPORTED_SCHEMA_V1', clock_timestamp(), \
                     clock_timestamp(), 'obsolete', 'no longer needed', \
                     clock_timestamp() - ($7 * interval '1 day'), 'kv')",
            &[
                &event_id,
                &cell_id,
                &idempotency_key.as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
                &aggregate_version,
                &disposition_age_days,
            ],
        )
        .await
        .expect("seed a disposed dead letter");
    event_id
}

async fn dead_letter_row_exists(raw: &Client, event_id: Uuid) -> bool {
    raw.query_opt(
        "SELECT 1 FROM lore_outbox_dead_letters WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .expect("dead letter existence probe")
    .is_some()
}

async fn wait_until<F, Fut>(deadline: Duration, mut probe: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if probe().await {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_retention_schedule_reaps_old_rows_past_the_floor_and_retains_everything_else() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "prune-tick").await;
    let url = namespace.pg_url().to_owned();
    PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap schema");
    let raw = pg_client(&url).await;
    let mut deadpool = deadpool_client(&url).await;
    let cell_id = rand_cell_id();
    let repository_id = rand_repository_id();
    let stream_identity = "DURABLE-x";
    let stream_epoch = 1;

    // A ready receiver whose frontier proves every seeded broker_sequence
    // safe, so the only thing standing between a consumer_safe row and reap
    // is age.
    set_up_ready_cell(
        &raw,
        &mut deadpool,
        &cell_id,
        "loreserver-1",
        stream_identity,
        stream_epoch,
        10_000,
    )
    .await;

    // Reapable: consumer_safe, well past the 7-day floor.
    let old_safe = seed_outbox_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        stream_identity,
        stream_epoch,
        1,
        9.0,
    )
    .await;
    // Retained: consumer_safe but younger than the floor.
    let young_safe = seed_outbox_row(
        &raw,
        &cell_id,
        &repository_id,
        "consumer_safe",
        stream_identity,
        stream_epoch,
        2,
        0.1,
    )
    .await;
    // Retained: broker_accepted is never consumer_safe's business.
    let accepted = seed_outbox_row(
        &raw,
        &cell_id,
        &repository_id,
        "broker_accepted",
        stream_identity,
        stream_epoch,
        3,
        9.0,
    )
    .await;
    // Reapable dead letter: obsolete, well past the 30-day floor.
    let old_dead = insert_dead_letter_disposed(&raw, &cell_id, 31.0).await;
    // Retained dead letter: obsolete but younger than the floor.
    let young_dead = insert_dead_letter_disposed(&raw, &cell_id, 1.0).await;

    let pool = build_pool(&url, 4, &TlsConfig::default()).expect("build relay pool");
    let readiness = Arc::new(EventRelayReadiness::new(
        Duration::from_secs(30),
        Duration::from_secs(5),
        Duration::from_secs(10),
    ));
    let retention = RetentionConfig {
        sweep_interval: Duration::from_millis(20),
        ..RetentionConfig::default()
    };
    let task = RetentionTask::new(pool, cell_id.clone(), retention, readiness);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = lore_base::lore_spawn!(task.run(shutdown_rx));

    let reaped = wait_until(Duration::from_secs(10), || {
        let raw = &raw;
        async move { event_state(raw, old_safe).await.is_none() }
    })
    .await;
    assert!(
        reaped,
        "the old consumer_safe row must be reaped by the retention schedule within 10s"
    );
    let dead_reaped = wait_until(Duration::from_secs(10), || {
        let raw = &raw;
        async move { !dead_letter_row_exists(raw, old_dead).await }
    })
    .await;
    assert!(
        dead_reaped,
        "the old disposed dead letter must be reaped within 10s"
    );

    shutdown_tx.send(true).expect("signal shutdown");
    handle.await.expect("task join").expect("task returns Ok");

    assert_eq!(
        event_state(&raw, young_safe).await.as_deref(),
        Some("consumer_safe"),
        "a consumer_safe row younger than the floor must be retained"
    );
    assert_eq!(
        event_state(&raw, accepted).await.as_deref(),
        Some("broker_accepted"),
        "a broker_accepted row is never consumer_safe's to reap"
    );
    assert!(
        dead_letter_row_exists(&raw, young_dead).await,
        "a disposed dead letter younger than the 30-day floor must be retained"
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// ADMISSION_RETRY_DELAY: a confirming cross-check, not a re-derivation of
// admission.rs's own module tests (which already pin the RetryInfo shape).
// ---------------------------------------------------------------------------

/// CR-032: "One documented maximum elapsed/attempt budget covers the real
/// Lore client policy and server transaction retries." This does not re-pin
/// the exact retry-count/backoff table (that is a client-side policy this
/// crate does not own); it pins the invariant the module's own doc comment
/// states -- the delay is bounded and positive -- so a future change that
/// zeroes or removes the bound fails here even if `admission.rs`'s own
/// `rejection_status_always_carries_a_retryinfo` test were ever weakened.
#[test]
fn admission_retry_delay_is_bounded_and_positive() {
    assert!(admission::ADMISSION_RETRY_DELAY > Duration::ZERO);
    // CR-032's own admission budget: readiness degrades above 30s and required-
    // event admission closes above five minutes. A retry hint at or above that
    // ceiling would tell a client to wait past the point admission itself
    // would already have escalated.
    assert!(admission::ADMISSION_RETRY_DELAY < Duration::from_secs(5 * 60));
}

/// The value the relay actually carries in `RetryInfo`, cross-checked through
/// the wire-decode helper `admission.rs`'s own tests already use, so this
/// file and that one cannot silently drift to different numbers while both
/// stay green.
#[test]
fn admission_rejection_status_carries_exactly_the_pinned_delay() {
    use lore_postgres::domain::outbox::relay::AdmissionRejection;

    let status = admission::rejection_status(&AdmissionRejection::PendingRows {
        observed: 2_000_000,
        limit: 1_000_000,
    });
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    assert_eq!(
        retry_info::decode_retry_delay(status.details()),
        Some(admission::ADMISSION_RETRY_DELAY)
    );
}

// ---------------------------------------------------------------------------
// reset_budget: the per-emitter diagnostic rate limit on rejected stream
// reset reports, exercised against the SHIPPED defaults (`ReportBudget::
// default()`), which `reset_budget.rs`'s own tests never construct.
// ---------------------------------------------------------------------------

/// `REJECTION_BUDGET` reports from one emitter are `Charge::Report`; the next
/// is the one-time `Quarantining` transition, and every one after that is
/// `Charge::Quarantined` -- all without mutating anything, since `Charge` only
/// ever governs how loudly `reset_service.rs` logs a rejection it has already
/// decided. A different emitter, charged against the SAME shared budget
/// instance, still gets `Charge::Report` on its first call: one emitter's
/// flood cannot spend another's budget, which is the whole reason the type is
/// keyed per principal rather than per cell.
#[test]
fn the_shipped_default_budget_quarantines_one_flooding_emitter_without_affecting_another() {
    use lore_server::event_relay::reset_budget::Charge;
    use lore_server::event_relay::reset_budget::REJECTION_BUDGET;
    use lore_server::event_relay::reset_budget::ReportBudget;

    let budget = ReportBudget::default();
    let now = std::time::Instant::now();
    let flooding_emitter = "spiffe://commit0/ns/notification/sa/gateway-flooding";
    let quiet_emitter = "spiffe://commit0/ns/notification/sa/gateway-quiet";

    for attempt in 0..REJECTION_BUDGET {
        assert_eq!(
            budget.charge(flooding_emitter, now),
            Charge::Report,
            "attempt {attempt} is inside the shipped budget of {REJECTION_BUDGET}"
        );
    }
    assert_eq!(
        budget.charge(flooding_emitter, now),
        Charge::Quarantining,
        "the ({REJECTION_BUDGET} + 1)th rejection from the same emitter is the quarantine \
         transition, reported once"
    );
    assert_eq!(
        budget.charge(flooding_emitter, now),
        Charge::Quarantined,
        "every further rejection from the same emitter within the window is quarantined"
    );

    assert_eq!(
        budget.charge(quiet_emitter, now),
        Charge::Report,
        "a different emitter's first rejection must still be reported in full"
    );
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! CR-027 / WP-111 Phase 3: the durable invalidation receiver's ordered
//! bootstrap, steady-state outcomes, and generation regeneration, proven
//! against WP-119 Step C's REAL Postgres membership/checkpoint projection
//! (`PostgresReceiverStore`) rather than the in-process `InMemoryReceiverStore`
//! `lore-server/src/plugins/remote_notification/receiver.rs`'s own co-located
//! tests use.
//!
//! `receiver.rs`'s own unit tests already exhaustively pin the ordering of
//! store calls (`the_bootstrap_runs_the_contracts_order_and_reaches_readiness`),
//! every `StepOutcome` classification
//! (`the_steady_state_disposes_each_outcome_class`), and the pure
//! retire/store-failure mappings, all against `InMemoryReceiverStore`. This
//! file does not duplicate those. What it adds: the SAME bootstrap and
//! steady-state contract, driven through the real `PostgresReceiverStore`
//! (Step C's actual schema, CHECK constraints, and compare-and-set SQL), plus
//! a real regeneration across two Postgres membership rows.
//!
//! Real Postgres only, `#[ignore]`. One throwaway database per run, e.g.:
//! `docker exec lorehub-dataplane-test-postgres-1 psql -U lorehub -d postgres
//! -c "CREATE DATABASE wp111_p3_tests_<runid>;"` (lowercase names only --
//! Postgres folds unquoted identifiers). Each case below acquires its own
//! schema inside it via `common::case_namespace::CaseNamespace`, matching
//! `lore-postgres/tests/domain_outbox_checkpoints.rs`'s own isolation
//! rationale: `evaluate_consumer_safe` and every membership/checkpoint
//! function scan by `cell_id` alone.
//!
//! The durable stream is `FakeDurableStream`, an in-process double satisfying
//! `receiver.rs`'s own `stream::DurableStreamSource` seam -- see that
//! module's `BLOCKED(WP-111)` note: no receiver-side gateway RPC is pinned
//! yet, so there is no real transport to drive here regardless.

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "common/relay_harness.rs"]
mod relay_harness;

use std::sync::Arc;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use case_namespace::CaseNamespace;
use lore_base::types::RepositoryId;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::checkpoint;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::membership::CapturedPosition;
use lore_postgres::pool::Pool;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_server::plugins::remote_notification::AggregateVersion;
use lore_server::plugins::remote_notification::DurableEnvelopeV1;
use lore_server::plugins::remote_notification::DurableInvalidationBody;
use lore_server::plugins::remote_notification::DurableReceiver;
use lore_server::plugins::remote_notification::EnvelopeCommon;
use lore_server::plugins::remote_notification::EventId;
use lore_server::plugins::remote_notification::FakeDurableStream;
use lore_server::plugins::remote_notification::PostgresReceiverStore;
use lore_server::plugins::remote_notification::ReceiverRuntime;
use lore_server::plugins::remote_notification::ReceiverStore;
use lore_server::plugins::remote_notification::RecordingInvalidationTarget;
use lore_server::plugins::remote_notification::RemoteNotificationConfig;
use lore_server::plugins::remote_notification::StepOutcome;
use lore_server::plugins::remote_notification::StreamError;
use lore_server::plugins::remote_notification::StreamPlacement;
use lore_server::plugins::remote_notification::apply::TargetCall;
use lore_server::plugins::remote_notification::receiver::REASON_POISON_PARKED;
use lore_server::plugins::remote_notification::receiver::REASON_STREAM_UNAVAILABLE;

const CELL: &str = "sfo3-cell-a";
const IDENTITY: &str = "loreserver-sfo3-cell-a-2";

const TEST_CONFIG: &str = r#"
    gateway_uri = "http://127.0.0.1:1"
    cell_id = "sfo3-cell-a"
    placement_epoch = 12
    producer_instance_id = "loreserver-sfo3-cell-a-2"
    allow_insecure_transport_for_test = true

    [retry]
    initial_backoff_ms = 1
    max_backoff_ms = 2
    max_attempts = 2

    [receiver]
    membership_identity = "loreserver-sfo3-cell-a-2"
    lifecycle_generation = 1
    lag_readiness_threshold = 5000
    checkpoint_interval_ms = 50
    checkpoint_every_events = 1
    idle_poll_ms = 5
"#;

/// Same as [`TEST_CONFIG`] except the receiver backoff is slow enough (300ms)
/// that a single scripted transient stream failure produces an observable
/// window: a bounded poll can reliably see the receiver's lag-readiness facet
/// go false without racing a sub-millisecond retry.
const TEST_CONFIG_SLOW_BACKOFF: &str = r#"
    gateway_uri = "http://127.0.0.1:1"
    cell_id = "sfo3-cell-a"
    placement_epoch = 12
    producer_instance_id = "loreserver-sfo3-cell-a-2"
    allow_insecure_transport_for_test = true

    [retry]
    initial_backoff_ms = 300
    max_backoff_ms = 300
    max_attempts = 2

    [receiver]
    membership_identity = "loreserver-sfo3-cell-a-2"
    lifecycle_generation = 1
    lag_readiness_threshold = 5000
    checkpoint_interval_ms = 50
    checkpoint_every_events = 1
    idle_poll_ms = 5
"#;

fn config() -> RemoteNotificationConfig {
    let value: toml::Value = toml::from_str(TEST_CONFIG).expect("test config parses");
    RemoteNotificationConfig::parse(&value).expect("test config validates")
}

fn config_slow_backoff() -> RemoteNotificationConfig {
    let value: toml::Value = toml::from_str(TEST_CONFIG_SLOW_BACKOFF).expect("test config parses");
    RemoteNotificationConfig::parse(&value).expect("test config validates")
}

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

fn repository(byte: u8) -> RepositoryId {
    let mut id = RepositoryId::default();
    *id.data_mut() = [byte; 16];
    id
}

/// One valid durable envelope for `repository_byte`, at `ordinal`. Mirrors
/// `receiver.rs`'s own private test helper of the same shape, rebuilt here
/// against the public envelope API since this file is a separate crate.
fn durable(
    repository_byte: u8,
    ordinal: u64,
    identity: Option<&str>,
) -> lore_server::plugins::remote_notification::wire::PrivateEnvelopeV1 {
    DurableEnvelopeV1 {
        common: EnvelopeCommon {
            cell_id: CELL.to_string(),
            placement_epoch: 12,
            event_id: EventId::from_bytes([ordinal as u8; 16]),
            repository: repository(repository_byte),
            producer_instance_id: IDENTITY.to_string(),
            produced_at: UNIX_EPOCH,
        },
        body: DurableInvalidationBody {
            payload_version: 1,
            idempotency_key: [7; 32],
            event_kind: "branch.pushed".to_string(),
            repository_generation: 1,
            aggregate_kind: "branch".to_string(),
            aggregate_identity: "0123456789abcdef".to_string(),
            aggregate_version: AggregateVersion {
                ordinal,
                identity: identity.map(str::to_string),
            },
            payload: Bytes::new(),
            committed_at: UNIX_EPOCH,
            actor: None,
        },
    }
    .encode(1..=1)
    .expect("the test envelope is inside every contract bound")
}

/// Create the cell's membership-state row and record its initial
/// authoritative placement. Returns the membership version after the
/// placement write, which is what the first `join` must compare against.
async fn bootstrap_cell(
    pool: &Pool,
    cell_id: &str,
    stream_identity: &str,
    stream_epoch: i64,
) -> i64 {
    let client = pool.get().await.expect("checkout pool client");
    membership::ensure_membership_state(&**client, cell_id)
        .await
        .expect("ensure membership state row");
    match membership::set_current_placement(&**client, cell_id, stream_identity, stream_epoch, 1, 1)
        .await
        .expect("set current placement")
    {
        MembershipCas::Applied {
            membership_version, ..
        } => membership_version,
        other => panic!("unexpected placement CAS outcome: {other:?}"),
    }
}

/// Poll `predicate` on a bounded real-time budget. Used only for the two
/// assertions here that need to observe a live `steady_state()` loop's
/// readiness transitions -- there is no other way to read
/// `ReceiverReadiness` except from the running receiver itself.
async fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// 1. Bootstrap order, against the real projection
// ---------------------------------------------------------------------------

/// The full ordered bootstrap -- join, capture, baseline, drain, checkpoint,
/// readiness CAS -- run against a real `PostgresReceiverStore`, with the
/// resulting row independently read back from Postgres rather than trusted
/// from the receiver's own belief.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_bootstrap_reaches_readiness_with_a_real_postgres_projection() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "bootstrap").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let target = RecordingInvalidationTarget::new();
    let receiver = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream.clone()),
            target: Arc::new(target.clone()),
        },
    )
    .expect("the test config declares a required receiver");

    stream.push_envelope(900, durable(0x9f, 1, None));

    let session = receiver
        .bootstrap()
        .await
        .expect("the happy-path bootstrap reaches readiness against real Postgres");
    assert!(session.ready);
    assert_eq!(session.membership_generation, 1);
    assert_eq!(
        session.contiguous_frontier(),
        900,
        "the drained event advances the frontier to the captured start"
    );
    assert!(receiver.readiness().is_ready());

    // The fake stream's own call log: captured exactly once, and the drained
    // event was acknowledged.
    assert_eq!(stream.captures(), vec![(IDENTITY.to_string(), 1)]);
    assert_eq!(stream.acked(), vec![900]);
    assert_eq!(target.baselines(), 1);

    // Independent proof against the REAL projection: not the receiver's own
    // belief, but what Step C actually persisted.
    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("the cell has a membership row");
    assert_eq!(snapshot.members.len(), 1);
    let member = &snapshot.members[0];
    assert_eq!(member.receiver_identity, IDENTITY);
    assert_eq!(member.membership_generation, 1);
    assert_eq!(member.state, "ready");
    let captured = member
        .captured
        .as_ref()
        .expect("a ready row carries its captured position");
    assert_eq!(captured.stream_identity, "DURABLE-sfo3-cell-a");
    assert_eq!(captured.stream_epoch, 8);
    assert_eq!(captured.start_sequence, 900);
    assert!(member.baseline_at.is_some());
    assert!(member.ready_at.is_some());

    let client = pool.get().await.expect("checkout pool client");
    let record = checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, 1)
        .await
        .expect("read checkpoint")
        .expect("the bootstrap persisted a checkpoint before claiming readiness");
    assert_eq!(record.contiguous_frontier, 900);
    assert!(record.gaps.is_empty());
    assert!(record.poison.is_empty());
}

// ---------------------------------------------------------------------------
// 2. Steady-state disposed outcomes, checkpointed to the real projection
// ---------------------------------------------------------------------------

/// Applied, duplicate, stale, and refetched -- each acknowledged -- with the
/// resulting frontier reported through the real `report_checkpoint` and read
/// back from Postgres.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn steady_state_applied_duplicate_stale_and_refetch_persist_the_real_checkpoint() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "steady-state").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let target = RecordingInvalidationTarget::new();
    let receiver = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream.clone()),
            target: Arc::new(target.clone()),
        },
    )
    .expect("the test config declares a required receiver");

    let mut session = receiver
        .bootstrap()
        .await
        .expect("bootstraps against real Postgres");
    assert_eq!(session.contiguous_frontier(), 899);

    // Next version: applied.
    stream.push_envelope(900, durable(0x9f, 5, None));
    assert_eq!(receiver.step(&mut session).await, StepOutcome::Applied);

    // The same version again: an acknowledged no-op, with no repeated effect.
    stream.push_envelope(901, durable(0x9f, 5, None));
    assert_eq!(receiver.step(&mut session).await, StepOutcome::Duplicate);

    // A lower ordinal: an acknowledged no-op.
    stream.push_envelope(902, durable(0x9f, 4, None));
    assert_eq!(receiver.step(&mut session).await, StepOutcome::Stale);

    // A skipped ordinal: an authoritative refetch before the acknowledgement.
    stream.push_envelope(903, durable(0x9f, 9, None));
    assert_eq!(receiver.step(&mut session).await, StepOutcome::Refetched);

    assert_eq!(stream.acked(), vec![900, 901, 902, 903]);
    assert_eq!(session.contiguous_frontier(), 903);
    assert_eq!(
        target
            .calls()
            .iter()
            .filter(|call| matches!(call, TargetCall::Apply { .. }))
            .count(),
        1,
        "the duplicate must not repeat the applied effect"
    );
    assert!(
        target
            .calls()
            .iter()
            .any(|call| matches!(call, TargetCall::Refetch(repo) if *repo == repository(0x9f))),
        "a gap must be resolved by an authoritative refetch, not by picking an order"
    );

    // Persist the frontier to the REAL Postgres projection, exactly as the
    // running receiver's own checkpoint cadence would, and prove Step C's
    // real `report_checkpoint` accepted it.
    let outcome = store
        .report_checkpoint(&session.checkpoint_report(IDENTITY))
        .await
        .expect("checkpoint report succeeds");
    assert_eq!(
        outcome,
        CheckpointOutcome::Applied {
            contiguous_frontier: 903
        }
    );

    let client = pool.get().await.expect("checkout pool client");
    let record = checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, 1)
        .await
        .expect("read checkpoint")
        .expect("a checkpoint was persisted");
    assert_eq!(record.contiguous_frontier, 903);
}

/// A transient stream failure and a poison (malformed) event, each driven
/// through the REAL running `steady_state()` loop -- the only place
/// `ReceiverReadiness` is ever updated -- and each acknowledging nothing.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn steady_state_transient_and_poison_fail_readiness_without_acknowledging() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "transient-poison").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let target = RecordingInvalidationTarget::new();
    let receiver = DurableReceiver::new(
        &config_slow_backoff(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream.clone()),
            target: Arc::new(target.clone()),
        },
    )
    .expect("the test config declares a required receiver");
    let readiness = receiver.readiness();
    let cancel = receiver.cancellation_token();
    let handle = tokio::spawn(receiver.run());

    assert!(
        wait_until(|| readiness.is_ready(), Duration::from_secs(10)).await,
        "the bootstrap must reach readiness before the steady-state cases run"
    );

    // Transient: a stream error must fail the lag-readiness facet and
    // acknowledge nothing. The slow-backoff config keeps this attempt's
    // retry window open long enough for a bounded poll to observe it
    // reliably rather than racing a sub-millisecond retry.
    stream.push_error(StreamError::Transient("broker down".into()));
    let saw_transient = wait_until(
        || readiness.snapshot().reason == Some(REASON_STREAM_UNAVAILABLE),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        saw_transient,
        "a transient stream failure must fail the receiver's readiness facet"
    );
    assert!(
        stream.acked().is_empty(),
        "a transient failure must not acknowledge anything"
    );

    assert!(
        wait_until(|| readiness.is_ready(), Duration::from_secs(10)).await,
        "readiness must recover once the stream stops erroring"
    );

    // Poison: a malformed envelope. Permanent once parked, so there is no
    // time pressure observing it -- it can only ever appear and stay.
    let mut malformed = durable(0x9f, 10, None);
    malformed.transport_version = 99;
    stream.push_envelope(901, malformed);
    let saw_poison = wait_until(
        || readiness.snapshot().reason == Some(REASON_POISON_PARKED),
        Duration::from_secs(10),
    )
    .await;
    assert!(saw_poison, "a malformed event must park and fail readiness");
    assert!(
        !stream.acked().contains(&901),
        "a parked event must never be acknowledged"
    );

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("the receiver task stops after cancellation")
        .expect("the receiver task does not panic")
        .expect("run() never returns an Err");
}

// ---------------------------------------------------------------------------
// 3. Regeneration after a placement move observed at the readiness CAS
// ---------------------------------------------------------------------------

/// Generation 1 is driven manually through join/capture/baseline/checkpoint
/// via the real `PostgresReceiverStore` -- exactly what the receiver's own
/// `bootstrap()` does -- so the cell's authoritative placement can be moved
/// deterministically between the checkpoint and the readiness compare-and-set
/// (the one boundary a running `bootstrap()` call cannot be paused mid-flight
/// to hit without racing it). The CAS then observes the mismatch, retires
/// generation 1, and a real `DurableReceiver` bootstraps generation 2 fresh
/// against the new placement.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_placement_move_observed_at_the_readiness_cas_retires_and_a_fresh_generation_bootstraps()
{
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "regeneration").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    let v0 = bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);

    let MembershipCas::Applied {
        membership_version: v1,
        membership_generation: gen1,
    } = store.join(IDENTITY, v0).await.expect("join answers")
    else {
        panic!("expected the join to apply");
    };
    assert_eq!(gen1, 1);
    store
        .record_capture(
            IDENTITY,
            gen1,
            &CapturedPosition {
                stream_identity: "DURABLE-sfo3-cell-a".to_string(),
                stream_epoch: 8,
                start_sequence: 900,
            },
        )
        .await
        .expect("capture answers");
    store
        .record_baseline(IDENTITY, gen1)
        .await
        .expect("baseline answers");
    store
        .report_checkpoint(&CheckpointReport {
            stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            stream_epoch: 8,
            receiver_identity: IDENTITY.to_string(),
            membership_generation: gen1,
            membership_version: v1,
            contiguous_frontier: 899,
            gaps: Vec::new(),
            poison: Vec::new(),
        })
        .await
        .expect("checkpoint answers");

    // Move the cell's authoritative placement while generation 1 is still
    // `joining` -- captured, baselined, and checkpointed, but not yet
    // compare-and-set to ready.
    let client = pool.get().await.expect("checkout pool client");
    let moved =
        membership::set_current_placement(&**client, CELL, "DURABLE-sfo3-cell-a-r2", 9, 2, v1)
            .await
            .expect("placement moves");
    assert!(matches!(moved, MembershipCas::Applied { .. }));
    drop(client);

    // The readiness compare-and-set now observes the moved placement.
    match store
        .readiness_cas(IDENTITY, gen1)
        .await
        .expect("readiness cas answers")
    {
        MembershipCas::PlacementMoved {
            current_stream_identity,
            current_stream_epoch,
        } => {
            assert_eq!(
                current_stream_identity.as_deref(),
                Some("DURABLE-sfo3-cell-a-r2")
            );
            assert_eq!(current_stream_epoch, Some(9));
        }
        other => panic!("expected PlacementMoved, got {other:?}"),
    }

    // Real projection: generation 1 is retired.
    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("membership row present");
    let gen1_row = snapshot
        .members
        .iter()
        .find(|member| member.membership_generation == gen1)
        .expect("generation 1's row is present");
    assert_eq!(gen1_row.state, "retired");

    // A fresh receiver, pointed at the NEW placement, bootstraps generation 2
    // from a fresh capture -- never resuming the retired epoch.
    let stream2 = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a-r2", 9), 1);
    let receiver2 = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream2.clone()),
            target: Arc::new(RecordingInvalidationTarget::new()),
        },
    )
    .expect("the test config declares a required receiver");
    let session2 = receiver2
        .bootstrap()
        .await
        .expect("the replacement generation bootstraps fresh");
    assert!(session2.ready);
    assert_eq!(session2.membership_generation, gen1 + 1);
    assert_eq!(
        session2.captured.placement.stream_identity,
        "DURABLE-sfo3-cell-a-r2"
    );
    assert_eq!(session2.captured.placement.stream_epoch, 9);
    assert_eq!(
        stream2.captures(),
        vec![(IDENTITY.to_string(), gen1 + 1)],
        "generation 2 must capture its OWN fresh position, never resume generation 1's"
    );

    // Real projection: two rows, first retired, second ready.
    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("membership row present");
    assert_eq!(snapshot.members.len(), 2);
    let retired = snapshot
        .members
        .iter()
        .find(|member| member.membership_generation == gen1)
        .expect("generation 1's row is present");
    let ready = snapshot
        .members
        .iter()
        .find(|member| member.membership_generation == gen1 + 1)
        .expect("generation 2's row is present");
    assert_eq!(retired.state, "retired");
    assert_eq!(ready.state, "ready");
}

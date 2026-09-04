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
    let handle = lore_base::lore_spawn!(receiver.run());

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

// ---------------------------------------------------------------------------
// 4. Resume from a captured/checkpointed position (WP-111 resume)
// ---------------------------------------------------------------------------
//
// These four cases prove the receiver-side resume path this file's module
// docs describe as still `TODO(WP-111)` at `03c7454`: a restart that finds
// this identity's own generation already captured (and possibly baselined or
// ready) must resume it -- never allocate a fresh generation and never
// replay what a persisted checkpoint already proved -- while a placement
// that moved out from under a stale generation must still retire it and
// bootstrap a fresh one, exactly as a first-ever bootstrap does.
//
// Every discriminator below is deliberately picked so a plausible wrong
// implementation fails a *specific* assertion rather than the suite merely
// erroring:
//   - the fresh `FakeDurableStream` in every case here is built with a
//     `start_sequence` that disagrees with the correct resume position (900,
//     6, or 3 below), so a resume that silently fell back to `capture_new`
//     would be caught by `captured.start_sequence` alone, without needing to
//     inspect `resume_from` directly;
//   - case 4's gap sits strictly below `highest_seen`, so a resume that used
//     `highest_seen + 1` instead of the checkpoint's own
//     `contiguous_frontier + 1` would silently and permanently skip the gap
//     rather than erroring -- the two candidate positions are chosen to
//     differ (3 vs 5) so that bug is visible as a wrong `start_sequence`
//     rather than a hang.

/// A restart that finds its own generation already `ready`, with a real
/// checkpoint behind it, must resume the SAME generation at the checkpoint's
/// `contiguous_frontier + 1` -- never re-baseline, never re-apply the
/// already-acknowledged range, and never allocate a new generation.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_restart_after_readiness_resumes_the_same_generation_past_the_checkpointed_frontier() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "resume-ready").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);

    // The first receiver: a real bootstrap and a live steady-state loop that
    // drains, applies, and acknowledges five events before this "process"
    // stops.
    let stream1 = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 1);
    for ordinal in 1..=5u64 {
        stream1.push_envelope(
            i64::try_from(ordinal).unwrap(),
            durable(0x9f, ordinal, None),
        );
    }
    let target1 = RecordingInvalidationTarget::new();
    let receiver1 = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream1.clone()),
            target: Arc::new(target1.clone()),
        },
    )
    .expect("the test config declares a required receiver");
    let readiness1 = receiver1.readiness();
    let cancel1 = receiver1.cancellation_token();
    let handle1 = lore_base::lore_spawn!(receiver1.run());

    assert!(
        wait_until(|| readiness1.is_ready(), Duration::from_secs(10)).await,
        "the first generation must reach readiness having drained all five events"
    );
    cancel1.cancel();
    tokio::time::timeout(Duration::from_secs(10), handle1)
        .await
        .expect("the first receiver task stops after cancellation")
        .expect("the first receiver task does not panic")
        .expect("run() never returns an Err");

    assert_eq!(
        target1
            .calls()
            .iter()
            .filter(|call| matches!(call, TargetCall::Apply { .. }))
            .count(),
        5,
        "all five events were applied exactly once by the first generation"
    );

    // Independent proof: the real projection shows one ready generation with
    // its frontier checkpointed at 5.
    {
        let client = pool.get().await.expect("checkout pool client");
        let record = checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, 1)
            .await
            .expect("read checkpoint")
            .expect("the first generation persisted a checkpoint before stopping");
        assert_eq!(record.contiguous_frontier, 5);
    }
    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("membership row present");
    assert_eq!(snapshot.members.len(), 1);
    assert_eq!(snapshot.members[0].state, "ready");

    // The second "process": a fresh receiver over the SAME store and cell.
    // The fake stream's own default start (999) deliberately disagrees with
    // the correct resume position (6), so a resume that fell back to
    // `capture_new` would be caught here rather than by inspecting the
    // capture request directly.
    let stream2 = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 999);
    let target2 = RecordingInvalidationTarget::new();
    let receiver2 = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream2.clone()),
            target: Arc::new(target2.clone()),
        },
    )
    .expect("the test config declares a required receiver");

    let mut session2 = receiver2
        .bootstrap()
        .await
        .expect("a restart resumes the same generation rather than failing");

    assert!(session2.ready);
    assert_eq!(
        session2.membership_generation, 1,
        "the restart must resume generation 1, never allocate a new one"
    );
    assert_eq!(
        session2.captured.start_sequence, 6,
        "the resumed capture must start at the checkpointed frontier plus one, not the stream's \
         own default and not the original capture position"
    );
    assert_eq!(
        session2.contiguous_frontier(),
        5,
        "the resumed session's frontier must reconstruct exactly what was persisted"
    );
    assert_eq!(
        stream2.captures(),
        vec![(IDENTITY.to_string(), 1)],
        "exactly one capture call, for the resumed generation"
    );
    assert!(
        target2
            .calls()
            .iter()
            .filter(|call| matches!(call, TargetCall::Apply { .. }))
            .count()
            .eq(&0),
        "sequences 1..=5 must never be re-applied across the resume boundary"
    );

    // Deliver the next event and prove the resumed session picks up exactly
    // where the checkpoint left off.
    stream2.push_envelope(6, durable(0x9f, 6, None));
    assert_eq!(
        receiver2.step(&mut session2).await,
        StepOutcome::Applied,
        "delivery resumes at 6"
    );
    assert_eq!(stream2.acked(), vec![6], "1..=5 are never re-acknowledged");
    assert_eq!(
        target2
            .calls()
            .iter()
            .filter(|call| matches!(call, TargetCall::Apply { .. }))
            .count(),
        1
    );

    let outcome = store
        .report_checkpoint(&session2.checkpoint_report(IDENTITY))
        .await
        .expect("checkpoint report succeeds");
    assert_eq!(
        outcome,
        CheckpointOutcome::Applied {
            contiguous_frontier: 6
        }
    );

    let client = pool.get().await.expect("checkout pool client");
    let record = checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, 1)
        .await
        .expect("read checkpoint")
        .expect("a checkpoint was persisted");
    assert_eq!(record.contiguous_frontier, 6);

    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("membership row present");
    assert_eq!(
        snapshot.members.len(),
        1,
        "the resume must never create a second membership row for this identity"
    );
    assert_eq!(snapshot.members[0].state, "ready");
}

/// A restart that finds its own generation captured but never baselined (a
/// crash between `record_capture` and `record_baseline`) must resume the
/// SAME generation from the persisted captured position -- there is no
/// checkpoint yet to derive a later one from -- and complete the remaining
/// baseline, drain, and readiness steps fresh.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_restart_after_capture_but_before_baseline_resumes_from_the_captured_position() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "resume-captured").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    let v0 = bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);

    // Manually drive Step C exactly up through `record_capture`, simulating
    // a crash before this generation ever took its baseline.
    let MembershipCas::Applied {
        membership_generation: gen1,
        ..
    } = store.join(IDENTITY, v0).await.expect("join answers")
    else {
        panic!("expected the join to apply");
    };
    match store
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
        .expect("capture answers")
    {
        MembershipCas::Applied { .. } => {}
        other => panic!("expected the capture to apply: {other:?}"),
    }

    // The fake stream's own default (1) deliberately disagrees with the
    // persisted captured position (900).
    let stream2 = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 1);
    let target2 = RecordingInvalidationTarget::new();
    let receiver2 = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream2.clone()),
            target: Arc::new(target2.clone()),
        },
    )
    .expect("the test config declares a required receiver");

    let session2 = receiver2
        .bootstrap()
        .await
        .expect("a restart resumes the captured-but-unbaselined generation");

    assert!(session2.ready);
    assert_eq!(
        session2.membership_generation, gen1,
        "the restart must reuse the generation that already captured, not allocate a new one"
    );
    assert_eq!(
        session2.captured.start_sequence, 900,
        "with no checkpoint yet, resume must use the persisted captured position, not the \
         stream's own default"
    );
    assert_eq!(
        session2.contiguous_frontier(),
        899,
        "nothing was ever drained before the crash, so the frontier starts one below the capture"
    );
    assert_eq!(
        stream2.captures(),
        vec![(IDENTITY.to_string(), gen1)],
        "exactly one capture call for the resumed generation"
    );
    assert_eq!(
        target2.baselines(),
        1,
        "the baseline was never taken before the crash and must be taken now"
    );

    // Independent proof against the real projection.
    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("membership row present");
    assert_eq!(
        snapshot.members.len(),
        1,
        "the resume must never leave a second row for this identity"
    );
    let member = &snapshot.members[0];
    assert_eq!(member.membership_generation, gen1);
    assert_eq!(member.state, "ready");
    assert!(member.baseline_at.is_some());
    let captured = member
        .captured
        .as_ref()
        .expect("captured position is present");
    assert_eq!(captured.start_sequence, 900);

    let client = pool.get().await.expect("checkout pool client");
    let record = checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, gen1)
        .await
        .expect("read checkpoint")
        .expect("the resumed bootstrap persisted a checkpoint before claiming readiness");
    assert_eq!(record.contiguous_frontier, 899);
}

/// A restart whose own captured generation's placement no longer matches the
/// cell's current authoritative placement must not resume it -- a fresh
/// generation captures anew at the current placement instead, exactly as a
/// first-ever bootstrap into a moved placement does.
///
/// The stale generation is deliberately left as-is (`"joining"`, never
/// touched again), not actively retired: `resumable_generation`'s epoch check
/// (`receiver.rs`) returns `None` without calling any store method on it, and
/// `receiver_store.rs`'s own module docs are explicit that retirement is
/// Step C's affair via `readiness_cas` on a *live bootstrap attempt* for that
/// generation or WP-119's separate hard-dead-member path -- never this
/// receiver reaching back to tombstone a generation it decided not to touch.
/// A bootstrap that resumed a placement-mismatched generation to explicitly
/// retire it would need to attempt a capture and a drain against the WRONG
/// broker to discover that, which is exactly the risk resuming exists to
/// avoid.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_captured_generation_whose_placement_moved_is_not_resumed_and_a_fresh_generation_bootstraps()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "resume-moved").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    let v0 = bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);

    // Generation 1: captured and baselined at the OLD placement, but never
    // reached readiness -- a resumable candidate under the same shape as the
    // previous case.
    let MembershipCas::Applied {
        membership_generation: gen1,
        membership_version: v1,
    } = store.join(IDENTITY, v0).await.expect("join answers")
    else {
        panic!("expected the join to apply");
    };
    match store
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
        .expect("capture answers")
    {
        MembershipCas::Applied { .. } => {}
        other => panic!("expected the capture to apply: {other:?}"),
    }
    match store
        .record_baseline(IDENTITY, gen1)
        .await
        .expect("baseline answers")
    {
        MembershipCas::Applied { .. } => {}
        other => panic!("expected the baseline to apply: {other:?}"),
    }

    // The placement moves before any restart is attempted.
    let client = pool.get().await.expect("checkout pool client");
    let moved =
        membership::set_current_placement(&**client, CELL, "DURABLE-sfo3-cell-a-r2", 9, 2, v1)
            .await
            .expect("placement moves");
    assert!(matches!(moved, MembershipCas::Applied { .. }));
    drop(client);

    // A fresh receiver, at the NEW placement. `resumable_generation` refuses
    // generation 1 on the epoch check alone, so ONE bootstrap() call is
    // enough to fall all the way through to a fresh join -- there is no
    // failed attempt to retry here, unlike a genuine mid-bootstrap CAS race.
    let stream2 = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a-r2", 9), 1);
    let target2 = RecordingInvalidationTarget::new();
    let receiver2 = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream2.clone()),
            target: Arc::new(target2.clone()),
        },
    )
    .expect("the test config declares a required receiver");

    let session2 = receiver2
        .bootstrap()
        .await
        .expect("a fresh generation bootstraps despite the stale one's placement mismatch");

    assert!(session2.ready);
    assert_eq!(
        session2.membership_generation,
        gen1 + 1,
        "a fresh generation bootstraps; the stale one is never resumed"
    );
    assert_eq!(
        session2.captured.placement.stream_identity,
        "DURABLE-sfo3-cell-a-r2"
    );
    assert_eq!(session2.captured.placement.stream_epoch, 9);
    assert_eq!(
        session2.captured.start_sequence, 1,
        "the fresh generation captures new at the current placement's edge, never the stale \
         generation's old position"
    );
    assert_eq!(
        stream2.captures(),
        vec![(IDENTITY.to_string(), gen1 + 1)],
        "the stale generation is never asked to capture again"
    );
    assert_eq!(
        target2.baselines(),
        1,
        "the fresh generation takes its own baseline"
    );

    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("membership row present");
    assert_eq!(snapshot.members.len(), 2);
    let stale = snapshot
        .members
        .iter()
        .find(|member| member.membership_generation == gen1)
        .expect("generation 1's row is present");
    let ready = snapshot
        .members
        .iter()
        .find(|member| member.membership_generation == gen1 + 1)
        .expect("generation 2's row is present");
    assert_eq!(
        stale.state, "joining",
        "the mismatched generation is left exactly as it was -- captured and baselined but never \
         reached; retiring it is not this receiver's job (see the test's own doc comment)"
    );
    assert_eq!(ready.state, "ready");
}

/// A checkpoint left with an unresolved broker-sequence gap must refuse the
/// resume, even though the generation is otherwise eligible (captured, own
/// identity, matching placement): a fresh generation captures anew instead,
/// and the stale generation's own checkpoint record is left untouched.
///
/// `resumable_generation`'s own doc comment (`receiver.rs`) explains why: the
/// projection records the frontier and the blockers, not the out-of-order
/// acknowledgements above them, so a resumed frontier seeded at
/// `contiguous_frontier + 1` would never see 4 acknowledged again (the broker
/// does not redeliver an already-acknowledged sequence) and would stall at
/// the gap forever. Starting a new generation is one generation more
/// expensive and actually recovers.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_persisted_checkpoint_with_a_blocker_is_not_resumed_and_a_fresh_generation_bootstraps() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "resume-gap").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let pool = build_pool(&url, 8, &TlsConfig::default()).expect("build pool");
    bootstrap_cell(&pool, CELL, "DURABLE-sfo3-cell-a", 8).await;

    let store = PostgresReceiverStore::new(pool.clone(), CELL);

    // Generation 1 reaches readiness first (with an empty, blocker-free
    // checkpoint from its own bootstrap), then its OWN steady-state
    // processing hits a broker-sequence gap it never resolves before the
    // process stops -- a live receiver that is ready can still carry an
    // unresolved blocker; `readiness_cas` only requires SOME checkpoint to
    // exist at the current placement, not a blocker-free one.
    let stream1 = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 1);
    let target1 = RecordingInvalidationTarget::new();
    let receiver1 = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream1.clone()),
            target: Arc::new(target1.clone()),
        },
    )
    .expect("the test config declares a required receiver");
    let mut session1 = receiver1.bootstrap().await.expect("bootstraps");
    assert!(session1.ready);
    assert_eq!(session1.contiguous_frontier(), 0);

    // Ack 1 and 2 in order.
    stream1.push_envelope(1, durable(0x9f, 1, None));
    assert_eq!(receiver1.step(&mut session1).await, StepOutcome::Applied);
    stream1.push_envelope(2, durable(0x9f, 2, None));
    assert_eq!(receiver1.step(&mut session1).await, StepOutcome::Applied);
    assert_eq!(session1.contiguous_frontier(), 2);

    // Broker sequence 3 is never delivered before the crash; broker sequence
    // 4 arrives and is acknowledged, but the frontier cannot advance past the
    // gap at 3.
    stream1.push_envelope(4, durable(0x9f, 3, None));
    assert_eq!(receiver1.step(&mut session1).await, StepOutcome::Applied);
    assert_eq!(
        session1.contiguous_frontier(),
        2,
        "an acknowledgement above a gap must not advance the frontier"
    );
    assert!(session1.has_blockers());

    let outcome = store
        .report_checkpoint(&session1.checkpoint_report(IDENTITY))
        .await
        .expect("checkpoint report succeeds");
    assert_eq!(
        outcome,
        CheckpointOutcome::Applied {
            contiguous_frontier: 2
        }
    );
    {
        let client = pool.get().await.expect("checkout pool client");
        let record = checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, 1)
            .await
            .expect("read checkpoint")
            .expect("a checkpoint with the unresolved gap was persisted");
        assert_eq!(record.contiguous_frontier, 2);
        assert_eq!(
            record.gaps,
            vec![lore_postgres::domain::outbox::SequenceGap { from: 3, to: 3 }]
        );
        assert!(record.has_blockers());
    }

    // The fake stream's own default (1) is what a fresh `capture_new` would
    // actually return, deliberately distinct from either candidate resume
    // position (3, the gap, or 5, `highest_seen + 1`) so a wrong
    // implementation that resumed anyway is caught by `start_sequence` alone.
    let stream2 = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 1);
    let target2 = RecordingInvalidationTarget::new();
    let receiver2 = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(stream2.clone()),
            target: Arc::new(target2.clone()),
        },
    )
    .expect("the test config declares a required receiver");

    let session2 = receiver2
        .bootstrap()
        .await
        .expect("a fresh generation bootstraps despite the stale one's unresolved gap");

    assert!(session2.ready);
    assert_eq!(
        session2.membership_generation, 2,
        "the gap-carrying generation is never resumed; a fresh one bootstraps"
    );
    assert_eq!(
        session2.captured.start_sequence, 1,
        "the fresh generation captures new, not at the gap and not at highest_seen + 1"
    );
    assert_eq!(session2.contiguous_frontier(), 0);
    assert_eq!(
        stream2.captures(),
        vec![(IDENTITY.to_string(), 2)],
        "the stale generation is never asked to capture again"
    );
    assert_eq!(
        target2.baselines(),
        1,
        "the fresh generation takes its own baseline"
    );

    // Independent proof: generation 1's checkpoint is untouched (still
    // carrying its gap), and generation 2 has its own clean one.
    let client = pool.get().await.expect("checkout pool client");
    let stale_record =
        checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, 1)
            .await
            .expect("read checkpoint")
            .expect("generation 1's checkpoint is untouched");
    assert_eq!(stale_record.contiguous_frontier, 2);
    assert_eq!(
        stale_record.gaps,
        vec![lore_postgres::domain::outbox::SequenceGap { from: 3, to: 3 }]
    );
    let fresh_record =
        checkpoint::read_checkpoint(&**client, "DURABLE-sfo3-cell-a", 8, IDENTITY, 2)
            .await
            .expect("read checkpoint")
            .expect("generation 2 persisted its own checkpoint before claiming readiness");
    assert_eq!(fresh_record.contiguous_frontier, 0);
    assert!(fresh_record.gaps.is_empty());

    let snapshot = store
        .read_membership()
        .await
        .expect("read membership")
        .expect("membership row present");
    assert_eq!(snapshot.members.len(), 2);
    let stale = snapshot
        .members
        .iter()
        .find(|member| member.membership_generation == 1)
        .expect("generation 1's row is present");
    let ready = snapshot
        .members
        .iter()
        .find(|member| member.membership_generation == 2)
        .expect("generation 2's row is present");
    assert_eq!(
        stale.state, "ready",
        "generation 1's own membership state is unaffected -- only its checkpoint carried the \
         gap, and the resume decision never wrote to this row"
    );
    assert_eq!(ready.state, "ready");
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use lore_base::types::RepositoryId;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::membership::CapturedPosition;
use lore_postgres::domain::outbox::schema::MAX_CHECKPOINT_BLOCKERS;
use lore_server::plugins::remote_notification::apply::POISON_CLASS_UNSUPPORTED_SCHEMA;
use lore_server::plugins::remote_notification::apply::RecordingInvalidationTarget;
use lore_server::plugins::remote_notification::apply::TargetCall;
use lore_server::plugins::remote_notification::config::RemoteNotificationConfig;
use lore_server::plugins::remote_notification::envelope::AggregateVersion;
use lore_server::plugins::remote_notification::envelope::DurableEnvelopeV1;
use lore_server::plugins::remote_notification::envelope::DurableInvalidationBody;
use lore_server::plugins::remote_notification::envelope::EnvelopeCommon;
use lore_server::plugins::remote_notification::envelope::EventId;
use lore_server::plugins::remote_notification::receiver::*;
use lore_server::plugins::remote_notification::receiver_store::InMemoryReceiverStore;
use lore_server::plugins::remote_notification::receiver_store::ReceiverStore;
use lore_server::plugins::remote_notification::receiver_store::ReceiverStoreError;
use lore_server::plugins::remote_notification::receiver_store::StoreCall;
use lore_server::plugins::remote_notification::stream::CaptureRequest;
use lore_server::plugins::remote_notification::stream::CapturedStreamPosition;
use lore_server::plugins::remote_notification::stream::DurableStreamSource;
use lore_server::plugins::remote_notification::stream::FakeDurableStream;
use lore_server::plugins::remote_notification::stream::StreamDelivery;
use lore_server::plugins::remote_notification::stream::StreamError;
use lore_server::plugins::remote_notification::stream::StreamPlacement;
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
    checkpoint_interval_ms = 100
    checkpoint_every_events = 2
    idle_poll_ms = 10
"#;

fn config() -> RemoteNotificationConfig {
    let value: toml::Value = toml::from_str(TEST_CONFIG).expect("test config parses");
    RemoteNotificationConfig::parse(&value).expect("test config validates")
}

fn repository(byte: u8) -> RepositoryId {
    let mut id = RepositoryId::default();
    *id.data_mut() = [byte; 16];
    id
}

/// One valid durable envelope for `repository`, at `ordinal`.
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

/// One durable envelope whose `payload_version` is inside the producer's
/// own encode bound (so it encodes cleanly) but outside this receiver's
/// contract-pinned decode range (`[1, 1]` under [`TEST_CONFIG`]). The
/// decoder must refuse it with `DeliveryViolation::UnsupportedPayloadVersion`,
/// which is exactly the case the two decode paths in
/// [`DurableReceiver::dispose`] must classify under
/// [`POISON_CLASS_UNSUPPORTED_SCHEMA`] and park.
fn durable_with_unsupported_payload_version(
    repository_byte: u8,
    ordinal: u64,
) -> lore_server::plugins::remote_notification::wire::PrivateEnvelopeV1 {
    let payload_version = 2;
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
            payload_version,
            idempotency_key: [7; 32],
            event_kind: "branch.pushed".to_string(),
            repository_generation: 1,
            aggregate_kind: "branch".to_string(),
            aggregate_identity: "0123456789abcdef".to_string(),
            aggregate_version: AggregateVersion {
                ordinal,
                identity: None,
            },
            payload: Bytes::new(),
            committed_at: UNIX_EPOCH,
            actor: None,
        },
    }
    .encode(payload_version..=payload_version)
    .expect("the producer's own contract permits the version it sent")
}

struct Harness {
    receiver: DurableReceiver,
    store: InMemoryReceiverStore,
    stream: FakeDurableStream,
    target: RecordingInvalidationTarget,
}

fn harness(start_sequence: i64) -> Harness {
    let store = InMemoryReceiverStore::new(CELL);
    let stream = FakeDurableStream::at(
        StreamPlacement::new("DURABLE-sfo3-cell-a", 8),
        start_sequence,
    );
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
    Harness {
        receiver,
        store,
        stream,
        target,
    }
}

/// The whole happy path, executed: join, capture, baseline, drain,
/// checkpoint, readiness CAS — in that order — then steady-state
/// consumption of the four disposed outcomes.
#[tokio::test]
async fn the_bootstrap_runs_the_contracts_order_and_reaches_readiness() {
    let harness = harness(900);
    harness.stream.push_envelope(900, durable(0x9f, 1, None));

    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("the happy-path bootstrap reaches readiness");

    assert!(session.ready);
    assert_eq!(session.membership_generation, 1);
    assert_eq!(
        session.contiguous_frontier(),
        900,
        "the drained event advances the frontier to the captured start"
    );

    // The store saw the contract's order, and nothing else.
    let kinds: Vec<&'static str> = harness
        .store
        .calls()
        .iter()
        .map(|call| match call {
            StoreCall::ReadMembership => "read",
            StoreCall::Join { .. } => "join",
            StoreCall::Capture { .. } => "capture",
            StoreCall::Baseline { .. } => "baseline",
            StoreCall::Checkpoint(_) => "checkpoint",
            StoreCall::DrainingCheckpoint(_) => "draining_checkpoint",
            StoreCall::Readiness { .. } => "readiness",
            StoreCall::ReadCheckpoint { .. } => "read_checkpoint",
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "read",
            "join",
            "capture",
            "baseline",
            "checkpoint",
            "readiness"
        ],
        "the capture must precede the baseline, and the checkpoint must precede the readiness \
         compare-and-set"
    );

    // Exactly one baseline, taken before the drained event was applied.
    assert_eq!(harness.target.baselines(), 1);
    assert!(matches!(
        harness.target.calls().first(),
        Some(TargetCall::Baseline)
    ));
    assert!(harness.receiver.readiness().is_ready());
    assert_eq!(harness.stream.acked(), vec![900]);
}

/// The four disposed outcomes, each acknowledged, and the two undisposed
/// ones, neither acknowledged.
#[tokio::test]
async fn the_steady_state_disposes_each_outcome_class() {
    let harness = harness(900);
    let mut session = harness.receiver.bootstrap().await.expect("bootstraps");
    assert_eq!(session.contiguous_frontier(), 899);

    // Next version: applied.
    harness.stream.push_envelope(900, durable(0x9f, 5, None));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Applied
    );

    // The same version again: an acknowledged no-op.
    harness.stream.push_envelope(901, durable(0x9f, 5, None));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Duplicate
    );

    // A lower ordinal: an acknowledged no-op.
    harness.stream.push_envelope(902, durable(0x9f, 4, None));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Stale
    );

    // A skipped ordinal: an authoritative refetch before the acknowledgement.
    harness.stream.push_envelope(903, durable(0x9f, 9, None));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Refetched
    );
    assert!(
        harness
            .target
            .calls()
            .iter()
            .any(|call| matches!(call, TargetCall::Refetch(_))),
        "a gap must be resolved by refetch, not by picking an order"
    );

    assert_eq!(harness.stream.acked(), vec![900, 901, 902, 903]);
    assert_eq!(session.contiguous_frontier(), 903);
    assert!(!session.has_blockers());

    // Poison: parked, unacknowledged, and the frontier stops below it.
    let mut malformed = durable(0x9f, 10, None);
    malformed.transport_version = 99;
    harness.stream.push_envelope(904, malformed);
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Parked("UNSUPPORTED_SCHEMA")
    );
    assert_eq!(harness.stream.acked(), vec![900, 901, 902, 903]);
    assert_eq!(session.contiguous_frontier(), 903);
    assert!(session.has_blockers());

    // A later event acknowledges but cannot skip the park.
    harness.stream.push_envelope(905, durable(0x9f, 10, None));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Applied
    );
    assert_eq!(
        session.contiguous_frontier(),
        903,
        "an acknowledgement above an unresolved park must never advance the frontier"
    );

    // Transient: unacknowledged, and nothing is applied.
    harness
        .stream
        .push_error(StreamError::Transient("broker down".into()));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Transient(REASON_STREAM_UNAVAILABLE)
    );

    // Caught up.
    assert_eq!(harness.receiver.step(&mut session).await, StepOutcome::Idle);
}

/// A single park must be enough to make the *next steady-state cadence
/// tick* report a checkpoint, not only the best-effort one at shutdown.
///
/// Regression pin for [`ReceiverSession::park`]: recording the poison in
/// the in-process frontier alone left `events_since_checkpoint` at zero,
/// so [`ReceiverSession::needs_checkpoint`]'s short circuit
/// (`reported_frontier == contiguous_frontier && events_since_checkpoint
/// == 0`) held forever — a parked generation would never trip the cadence,
/// however much wall-clock time passed.
#[tokio::test]
async fn a_single_park_makes_the_next_cadence_checkpoint_due() {
    let mut harness = harness(900);
    // One event is enough to cross the threshold, so this pins the count
    // itself rather than a coincidence of the default's `2`.
    harness.receiver.receiver.checkpoint_every_events = 1;
    let mut session = harness.receiver.bootstrap().await.expect("bootstraps");
    assert_eq!(session.contiguous_frontier(), 899);

    harness
        .stream
        .push_envelope(900, durable_with_unsupported_payload_version(0x9f, 1));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Parked(POISON_CLASS_UNSUPPORTED_SCHEMA)
    );
    assert!(harness.stream.acked().is_empty());
    assert_eq!(
        session.contiguous_frontier(),
        899,
        "a park never advances the frontier"
    );

    assert!(
        session.needs_checkpoint(&harness.receiver.receiver),
        "a park that acknowledges nothing must still count toward the checkpoint cadence, or \
         the durable projection never learns the generation is blocked"
    );
}

/// A broker redelivers an unacknowledged parked sequence.
/// [`AckFrontier::record_poison`] deliberately deduplicates the poison
/// entry itself, and deliberately NOT [`ReceiverSession::park`] — each
/// protects something different. This pins both halves: the poison list
/// must not grow on the redelivery, and the checkpoint must still be
/// re-armed by it, because `park` increments
/// `events_since_checkpoint` unconditionally. A `park` that skipped the
/// increment for an already-known sequence would pass the first half and
/// silently restore the original defect for every redelivery.
#[tokio::test]
async fn a_redelivered_park_does_not_duplicate_the_poison_entry_but_still_rearms_the_checkpoint() {
    let mut harness = harness(900);
    harness.receiver.receiver.checkpoint_every_events = 1;
    let mut session = harness.receiver.bootstrap().await.expect("bootstraps");
    assert_eq!(session.contiguous_frontier(), 899);

    // First delivery: parked.
    harness
        .stream
        .push_envelope(900, durable_with_unsupported_payload_version(0x9f, 1));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Parked(POISON_CLASS_UNSUPPORTED_SCHEMA)
    );
    assert_eq!(
        session.checkpoint_report(IDENTITY).poison.len(),
        1,
        "the first park records one blocker"
    );
    assert!(session.needs_checkpoint(&harness.receiver.receiver));

    // Model a checkpoint having already been sent for the first park, so
    // the second delivery's own effect on the cadence can be isolated
    // from the first's.
    session.reported_frontier = Some(session.contiguous_frontier());
    session.events_since_checkpoint = 0;
    assert!(
        !session.needs_checkpoint(&harness.receiver.receiver),
        "sanity: nothing pending immediately after the modeled checkpoint"
    );

    // The broker redelivers the same unacknowledged sequence.
    harness
        .stream
        .push_envelope(900, durable_with_unsupported_payload_version(0x9f, 1));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Parked(POISON_CLASS_UNSUPPORTED_SCHEMA)
    );

    assert_eq!(
        session.checkpoint_report(IDENTITY).poison.len(),
        1,
        "a redelivered park must not duplicate the poison entry"
    );
    assert!(
        session.needs_checkpoint(&harness.receiver.receiver),
        "a redelivered park must still re-arm the checkpoint even though \
         AckFrontier::record_poison deduplicated it, or a redelivery leaves the durable \
         projection unaware the generation is still blocked"
    );
}

/// Once the poison tracker saturates, [`AckFrontier::record_poison`]
/// early-returns without pushing a new entry — the caller cannot tell a
/// saturated park from a no-op by watching the poison list. The
/// checkpoint must still be armed regardless, because the synthetic
/// `POISON_CLASS_TRACKER_SATURATED` entry [`AckFrontier::poison`] appends
/// only reaches the durable projection if a checkpoint is actually sent.
/// Drives saturation directly on the frontier rather than pushing
/// [`MAX_CHECKPOINT_BLOCKERS`] real deliveries through the stream: the
/// tests module has direct field access to [`ReceiverSession::frontier`]
/// and [`AckFrontier::record_poison`] is public, so this is the cheapest
/// way to reach the state under test.
#[tokio::test]
async fn a_park_while_the_poison_tracker_is_saturated_still_arms_the_checkpoint() {
    let mut harness = harness(900);
    harness.receiver.receiver.checkpoint_every_events = 1;
    let mut session = harness.receiver.bootstrap().await.expect("bootstraps");

    // Fill the tracker to exactly its cap with distinct sequences.
    for offset in 1..=(MAX_CHECKPOINT_BLOCKERS as i64) {
        session
            .frontier
            .record_poison(1_000 + offset, "SATURATION_FILL");
    }
    assert!(
        !session.frontier.is_saturated(),
        "filling exactly to the cap must not itself saturate the tracker"
    );

    // One more distinct sequence pushes it over.
    session.frontier.record_poison(
        1_000 + MAX_CHECKPOINT_BLOCKERS as i64 + 1,
        "SATURATION_TRIGGER",
    );
    assert!(
        session.frontier.is_saturated(),
        "one more distinct park past the cap must saturate the tracker"
    );

    // Establish a clean checkpoint baseline so the assertion below
    // isolates park's own contribution.
    session.reported_frontier = Some(session.frontier.contiguous_frontier());
    session.events_since_checkpoint = 0;
    assert!(
        !session.needs_checkpoint(&harness.receiver.receiver),
        "sanity: nothing pending before the park under test"
    );

    // A further park while saturated: record_poison itself pushes
    // nothing new (it early-returns once saturated).
    session.park(1_000 + MAX_CHECKPOINT_BLOCKERS as i64 + 2, "NEW_POISON");

    assert!(
        session.needs_checkpoint(&harness.receiver.receiver),
        "a park must arm the checkpoint even when the tracker is saturated and \
         record_poison itself pushed nothing new, or the synthetic \
         FRONTIER_TRACKER_SATURATED entry never reaches the durable projection"
    );
}

/// A membership-version conflict is a checkpoint attempt, so it spends the
/// cadence tick it was sent on. Before this, the conflict reset neither
/// `last_checkpoint` nor `events_since_checkpoint`, so a generation parked
/// under a persistent conflict stayed due and re-sent a store write on
/// every idle poll rather than on the next cadence tick. The unreported
/// work must survive the conflict, or the park never reaches the row.
#[tokio::test]
async fn a_membership_version_conflict_waits_for_the_next_cadence_tick() {
    let mut harness = harness(900);
    harness.receiver.receiver.checkpoint_every_events = 1;
    harness.receiver.receiver.checkpoint_interval = Duration::from_secs(60);
    let mut session = harness.receiver.bootstrap().await.expect("bootstraps");

    harness
        .stream
        .push_envelope(900, durable_with_unsupported_payload_version(0x9f, 1));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Parked(POISON_CLASS_UNSUPPORTED_SCHEMA)
    );
    assert!(session.needs_checkpoint(&harness.receiver.receiver));

    let current = harness.store.membership_version() + 1;
    harness
        .store
        .next_checkpoint(Ok(CheckpointOutcome::MembershipVersionConflict {
            current_membership_version: current,
        }));
    assert!(matches!(
        harness.receiver.checkpoint(&mut session).await,
        Err(BootstrapFailure::Transient(REASON_BOOTSTRAPPING))
    ));
    assert_eq!(session.membership_version, current);

    assert!(
        !session.needs_checkpoint(&harness.receiver.receiver),
        "a conflicted report must wait for the next cadence tick, not retry every idle poll"
    );
    harness.receiver.receiver.checkpoint_interval = Duration::ZERO;
    assert!(
        session.needs_checkpoint(&harness.receiver.receiver),
        "the park is still unreported, so the next cadence tick must resend it"
    );
}

/// The conflict above clears `events_since_checkpoint`, so after it only
/// the cleared `reported_frontier` keeps [`DurableReceiver::final_checkpoint`]
/// from reading the park as reported. The frontier was already reported
/// before the park, and a park does not move it, so without that reset the
/// shutdown report is skipped and the park never reaches the durable row.
#[tokio::test]
async fn the_final_checkpoint_still_sends_a_park_after_a_membership_version_conflict() {
    let mut harness = harness(900);
    harness.receiver.receiver.checkpoint_every_events = 1;
    harness.receiver.receiver.checkpoint_interval = Duration::from_secs(60);
    let mut session = harness.receiver.bootstrap().await.expect("bootstraps");

    // Report the frontier first, so it reads as reported before the park.
    assert!(harness.receiver.checkpoint(&mut session).await.is_ok());
    assert_eq!(session.reported_frontier, Some(899));

    harness
        .stream
        .push_envelope(900, durable_with_unsupported_payload_version(0x9f, 1));
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Parked(POISON_CLASS_UNSUPPORTED_SCHEMA)
    );
    assert_eq!(session.contiguous_frontier(), 899);

    // A concurrent join moves the cell's version, so the next report conflicts.
    let current = harness.store.membership_version() + 1;
    harness.store.set_membership_version(current);
    assert!(matches!(
        harness.receiver.checkpoint(&mut session).await,
        Err(BootstrapFailure::Transient(REASON_BOOTSTRAPPING))
    ));
    assert_eq!(session.events_since_checkpoint, 0);

    let checkpoints = |harness: &Harness| -> Vec<CheckpointReport> {
        harness
            .store
            .calls()
            .iter()
            .filter_map(|call| match call {
                StoreCall::Checkpoint(report) => Some((**report).clone()),
                _ => None,
            })
            .collect()
    };
    let before = checkpoints(&harness).len();
    harness.receiver.final_checkpoint(&mut session).await;
    let sent = checkpoints(&harness);
    assert_eq!(
        sent.len(),
        before + 1,
        "the shutdown report must still carry the park after a conflict"
    );
    let last = sent.last().expect("one final report");
    assert_eq!(last.membership_version, current);
    assert_eq!(last.poison.len(), 1);
    assert_eq!(session.reported_frontier, Some(899));
}

/// The finding an executed live two-process run caught: a parked delivery
/// acknowledges nothing, so nothing else makes a checkpoint due, and
/// without [`ReceiverSession::park`] counting the park itself neither the
/// steady-state cadence nor [`DurableReceiver::final_checkpoint`] at
/// shutdown ever reports one — the durable `lore_outbox_checkpoints`
/// projection shows an unblocked row forever while this process's own
/// readiness correctly reports `poison_parked`.
///
/// This drives the real, unmodified shutdown path (mirroring
/// `shutdown_checkpoints_an_applied_event_before_returning`) rather than
/// calling the checkpoint machinery directly, so it fails exactly when the
/// automatic trigger is broken, not only when the report's own content is
/// wrong.
#[tokio::test]
async fn shutdown_checkpoints_a_parked_deliverys_poison_class_before_returning() {
    let mut harness = harness(900);
    harness.receiver.receiver.checkpoint_interval = Duration::from_secs(60);
    let readiness = harness.receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run = harness.receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                result = &mut run => panic!("receiver stopped before shutdown: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
            if readiness.is_ready() {
                break;
            }
        }
        harness
            .stream
            .push_envelope(900, durable_with_unsupported_payload_version(0x9f, 1));
        loop {
            tokio::select! {
                result = &mut run => panic!("receiver stopped before parking: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
            if readiness.snapshot().reason == Some(REASON_POISON_PARKED) {
                break;
            }
        }
    })
    .await
    .expect("receiver must park the unsupported-schema delivery");

    assert!(
        harness.stream.acked().is_empty(),
        "a parked delivery must never be acknowledged"
    );
    let before_shutdown = harness.store.calls().len();
    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("receiver must finish promptly")
        .expect("shutdown succeeds");

    // A ready generation's graceful stop sends its final report as the
    // draining write (WP-115 row 68), so both kinds count here.
    let checkpoints: Vec<CheckpointReport> = harness.store.calls()[before_shutdown..]
        .iter()
        .filter_map(|call| match call {
            StoreCall::Checkpoint(report) | StoreCall::DrainingCheckpoint(report) => {
                Some((**report).clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        checkpoints.len(),
        1,
        "shutdown must report exactly one checkpoint once a park is outstanding"
    );
    assert_eq!(
        checkpoints[0].poison,
        vec![lore_postgres::domain::outbox::PoisonEntry {
            broker_sequence: 900,
            class: POISON_CLASS_UNSUPPORTED_SCHEMA.to_string(),
        }],
        "the parked sequence and its bounded poison class must reach the durable checkpoint \
         projection, keyed by the same constant apply.rs classifies it under"
    );
    assert_eq!(readiness.snapshot().reason, Some(REASON_STOPPED));
}

/// A message served from an epoch this generation did not capture retires
/// the generation. It is not parked: a park would record a blocker against
/// a generation that is about to be replaced.
#[tokio::test]
async fn an_event_from_another_epoch_retires_rather_than_parking() {
    let harness = harness(900);
    let mut session = harness.receiver.bootstrap().await.expect("bootstraps");
    harness.stream.push_envelope_at(
        900,
        StreamPlacement::new("DURABLE-sfo3-cell-a-r2", 1),
        durable(0x9f, 1, None),
    );
    assert_eq!(
        harness.receiver.step(&mut session).await,
        StepOutcome::Retired(REASON_PLACEMENT_MOVED)
    );
    assert!(harness.stream.acked().is_empty());
}

/// The four reset boundaries the contract names collapse to one response:
/// retire the generation. This exercises the last of them, the readiness
/// CAS race, which is the only one the receiver cannot see coming.
#[tokio::test]
async fn a_placement_that_moved_during_the_bootstrap_fails_the_readiness_cas() {
    let harness = harness(900);
    harness
        .store
        .next_readiness(Ok(MembershipCas::PlacementMoved {
            current_stream_identity: Some("DURABLE-sfo3-cell-a-r2".to_string()),
            current_stream_epoch: Some(1),
        }));
    assert_eq!(
        harness.receiver.bootstrap().await.err(),
        Some(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
    );
}

/// Step C refuses a readiness CAS with no checkpoint at the current
/// placement. A receiver that read that as retryable would spin claiming
/// readiness it never proved.
#[tokio::test]
async fn a_baseline_alone_cannot_reach_readiness() {
    let harness = harness(900);
    harness
        .store
        .next_readiness(Ok(MembershipCas::NoCheckpointAtCurrentPlacement));
    assert_eq!(
        harness.receiver.bootstrap().await.err(),
        Some(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
    );
}

/// A capture failure never leaves a baseline recorded against a position
/// nothing pinned.
#[tokio::test]
async fn a_failed_capture_stops_before_the_baseline() {
    let harness = harness(900);
    harness
        .stream
        .fail_next_capture_with(StreamError::Transient("broker down".into()));
    assert_eq!(
        harness.receiver.bootstrap().await.err(),
        Some(BootstrapFailure::Transient(REASON_STREAM_UNAVAILABLE))
    );
    assert_eq!(harness.target.baselines(), 0);
    assert!(
        !harness
            .store
            .calls()
            .iter()
            .any(|call| matches!(call, StoreCall::Baseline { .. })),
        "no baseline may be recorded for a generation whose position was never captured"
    );
}

/// A reset fence is not a reason to refuse to bootstrap: the fence stands
/// because a replacement generation is required, and this is it.
#[tokio::test]
async fn a_generation_still_bootstraps_while_a_reset_fence_stands() {
    let harness = harness(900);
    harness.store.set_reset_in_progress(true);
    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("the replacement generation bootstraps under the fence");
    assert!(
        session.ready,
        "the fence stands because a replacement generation is required; refusing to \
         bootstrap under it would make the fence permanent"
    );
}

// -----------------------------------------------------------------
// Resuming a captured generation
//
// The live-Postgres suite in `tests/remote_notification_receiver.rs`
// proves the same behaviours against the real projection, but it is
// `#[ignore]`d. These run in the default tier, so a regression in the
// resume decision is caught by `cargo test -p lore-server` rather than
// only by someone who has a database.
// -----------------------------------------------------------------

/// One member row as a previous process would have left it.
fn seeded_member(
    state: &str,
    membership_generation: i64,
    captured: Option<(&str, i64, i64)>,
    baselined: bool,
) -> lore_postgres::domain::outbox::MembershipMember {
    lore_postgres::domain::outbox::MembershipMember {
        receiver_identity: IDENTITY.to_string(),
        membership_generation,
        state: state.to_string(),
        membership_version: 1,
        captured: captured.map(|(stream_identity, stream_epoch, start_sequence)| {
            CapturedPosition {
                stream_identity: stream_identity.to_string(),
                stream_epoch,
                start_sequence,
            }
        }),
        baseline_at: baselined.then_some(std::time::SystemTime::UNIX_EPOCH),
        ready_at: (state == "ready").then_some(std::time::SystemTime::UNIX_EPOCH),
    }
}

/// One persisted checkpoint as a previous process would have left it.
fn seeded_checkpoint(
    membership_generation: i64,
    contiguous_frontier: i64,
    gaps: Vec<lore_postgres::domain::outbox::SequenceGap>,
) -> lore_postgres::domain::outbox::CheckpointRecord {
    lore_postgres::domain::outbox::CheckpointRecord {
        cell_id: CELL.to_string(),
        stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        stream_epoch: 8,
        receiver_identity: IDENTITY.to_string(),
        membership_generation,
        membership_version: 1,
        contiguous_frontier,
        gaps,
        poison: Vec::new(),
        reported_at: std::time::SystemTime::UNIX_EPOCH,
        projection_at: std::time::SystemTime::UNIX_EPOCH,
    }
}

fn joined(store: &InMemoryReceiverStore) -> usize {
    store
        .calls()
        .iter()
        .filter(|call| matches!(call, StoreCall::Join { .. }))
        .count()
}

/// Resume binds the original capture while the local frontier preserves
/// progress made since that capture.
#[tokio::test]
async fn a_restart_resumes_its_captured_generation_past_the_persisted_frontier() {
    // 999 is deliberately not a plausible resume position, so a fallback
    // to `capture_new` is caught here rather than by reading the request.
    let harness = harness(999);
    harness
        .store
        .seed_member(seeded_member(
            "ready",
            1,
            Some(("DURABLE-sfo3-cell-a", 8, 900)),
            true,
        ))
        .seed_checkpoint(seeded_checkpoint(1, 905, Vec::new()));

    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("a restart resumes rather than failing");

    assert_eq!(session.membership_generation, 1);
    assert_eq!(session.captured.start_sequence, 900);
    assert_eq!(session.contiguous_frontier(), 905);
    assert!(session.ready);
    assert_eq!(joined(&harness.store), 0, "a resume never joins");
    assert_eq!(harness.stream.captures(), vec![(IDENTITY.to_string(), 1)]);
    assert!(
        !harness
            .store
            .calls()
            .iter()
            .any(|call| matches!(call, StoreCall::Capture { .. })),
        "a resume never re-records a capture it did not take"
    );
}

/// Model the gateway's immutable durable-consumer `opt_start_seq` check.
/// Delivery state survives reconnects, as it does at the broker.
#[derive(Debug)]
struct StrictCapturedStream {
    stream: FakeDurableStream,
    requests: std::sync::Mutex<Vec<CaptureRequest>>,
}

#[async_trait::async_trait]
impl DurableStreamSource for StrictCapturedStream {
    async fn capture(
        &self,
        request: &CaptureRequest,
    ) -> Result<CapturedStreamPosition, StreamError> {
        {
            let mut requests = self.requests.lock().expect("test request log");
            let expected = (!requests.is_empty()).then_some(900);
            requests.push(request.clone());
            if request.resume_from != expected {
                return Err(
                    lore_server::plugins::remote_notification::stream::status_to_stream_error(
                        &tonic::Status::failed_precondition("UNKNOWN_DURABLE_CONSUMER_V1"),
                        &request.placement,
                    ),
                );
            }
        }
        self.stream.capture(request).await
    }

    async fn next(&self) -> Result<StreamDelivery, StreamError> {
        self.stream.next().await
    }

    async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError> {
        self.stream.ack(broker_sequence).await
    }
}

#[tokio::test]
async fn progressed_restarts_keep_the_gateway_capture_and_advance_the_local_checkpoint() {
    let store = InMemoryReceiverStore::new(CELL);
    let stream = Arc::new(StrictCapturedStream {
        stream: FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900),
        requests: std::sync::Mutex::new(Vec::new()),
    });
    let make_receiver = |target: RecordingInvalidationTarget| {
        DurableReceiver::new(
            &config(),
            ReceiverRuntime {
                store: Arc::new(store.clone()),
                stream: stream.clone(),
                target: Arc::new(target),
            },
        )
        .expect("receiver config")
    };
    let first = make_receiver(RecordingInvalidationTarget::new());
    let mut session = first.bootstrap().await.expect("fresh capture succeeds");
    assert_eq!(session.captured.start_sequence, 900);
    assert_eq!(session.contiguous_frontier(), 899);
    for sequence in 900..=905 {
        stream
            .stream
            .push_envelope(sequence, durable(0x9f, (sequence - 899) as u64, None));
        assert_eq!(first.step(&mut session).await, StepOutcome::Applied);
    }
    store
        .report_checkpoint(&session.checkpoint_report(IDENTITY))
        .await
        .expect("persist progress");
    drop(session);
    drop(first);

    // Recreate receiver and baseline cache twice. The broker retains its
    // consumer, while each local checkpoint advances beyond the capture.
    for next in [906, 907] {
        let target = RecordingInvalidationTarget::new();
        let restarted = make_receiver(target.clone());
        let mut session = restarted
            .bootstrap()
            .await
            .expect("strict gateway accepts original capture");
        assert!(session.ready);
        assert_eq!(session.membership_generation, 1);
        assert_eq!(session.captured.start_sequence, 900);
        assert_eq!(session.contiguous_frontier(), next - 1);
        assert_eq!(target.baselines(), 1);
        assert!(
            !target
                .calls()
                .iter()
                .any(|call| matches!(call, TargetCall::Apply { .. }))
        );
        let checkpoint = store
            .read_checkpoint("DURABLE-sfo3-cell-a", 8, IDENTITY, 1)
            .await
            .expect("read checkpoint")
            .expect("checkpoint exists");
        assert_eq!(
            checkpoint.contiguous_frontier,
            next - 1,
            "empty reconnect drain must not regress persisted progress"
        );
        stream
            .stream
            .push_envelope(next, durable(0x9f, (next - 899) as u64, None));
        assert_eq!(restarted.step(&mut session).await, StepOutcome::Applied);
        assert_eq!(session.contiguous_frontier(), next);
        assert!(
            !session.has_blockers(),
            "no artificial gap back to the original capture"
        );
        assert_eq!(
            target
                .calls()
                .iter()
                .filter(|call| matches!(call, TargetCall::Apply { .. }))
                .count(),
            1
        );
        store
            .report_checkpoint(&session.checkpoint_report(IDENTITY))
            .await
            .expect("persist resumed progress");
    }
    assert_eq!(stream.stream.acked(), (900..=907).collect::<Vec<_>>());
    assert_eq!(joined(&store), 1, "restarts keep the original membership");
    assert_eq!(
        stream
            .requests
            .lock()
            .expect("request log")
            .iter()
            .map(|request| request.resume_from)
            .collect::<Vec<_>>(),
        vec![None, Some(900), Some(900)]
    );
}

/// A crash between `record_capture` and `record_baseline` leaves no
/// checkpoint to derive a later position from, so the captured position is
/// still the first sequence this generation owes.
#[tokio::test]
async fn a_restart_with_no_checkpoint_resumes_at_the_captured_position() {
    let harness = harness(999);
    harness.store.seed_member(seeded_member(
        "joining",
        1,
        Some(("DURABLE-sfo3-cell-a", 8, 900)),
        false,
    ));

    let session = harness.receiver.bootstrap().await.expect("resumes");

    assert_eq!(session.membership_generation, 1);
    assert_eq!(session.captured.start_sequence, 900);
    assert_eq!(session.contiguous_frontier(), 899);
    assert_eq!(joined(&harness.store), 0);
    assert!(
        harness
            .target
            .calls()
            .iter()
            .any(|call| matches!(call, TargetCall::Baseline)),
        "a restarted process holds no belief a baseline established, so it takes one"
    );
}

/// The finding the whole blocker rule exists for: the projection does not
/// record the acknowledgements above a gap, so resuming would stall the
/// frontier at it forever. A new generation is one generation more
/// expensive and actually recovers.
#[tokio::test]
async fn a_persisted_blocker_refuses_the_resume_and_a_new_generation_joins() {
    let harness = harness(900);
    harness
        .store
        .seed_member(seeded_member(
            "ready",
            1,
            Some(("DURABLE-sfo3-cell-a", 8, 1)),
            true,
        ))
        .seed_checkpoint(seeded_checkpoint(
            1,
            2,
            vec![lore_postgres::domain::outbox::SequenceGap { from: 3, to: 3 }],
        ));

    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("bootstraps fresh");

    assert_eq!(joined(&harness.store), 1, "a refused resume joins instead");
    assert_ne!(session.membership_generation, 1);
    assert_eq!(session.captured.start_sequence, 900);
}

/// The contract's own condition: a crash resumes the same generation only
/// while the authoritative identity and epoch still match.
#[tokio::test]
async fn a_captured_generation_whose_epoch_moved_is_not_resumed() {
    let harness = harness(900);
    harness.store.seed_member(seeded_member(
        "ready",
        1,
        Some(("DURABLE-sfo3-cell-a", 7, 100)),
        true,
    ));

    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("bootstraps fresh");

    assert_eq!(joined(&harness.store), 1);
    assert_ne!(session.membership_generation, 1);
}

/// A standing reset fence requires a replacement generation with a newly
/// captured identity, epoch, and position. Resuming would deny it one.
#[tokio::test]
async fn a_standing_reset_fence_refuses_the_resume() {
    let harness = harness(900);
    harness.store.set_reset_in_progress(true);
    harness
        .store
        .seed_member(seeded_member(
            "ready",
            1,
            Some(("DURABLE-sfo3-cell-a", 8, 900)),
            true,
        ))
        .seed_checkpoint(seeded_checkpoint(1, 905, Vec::new()));

    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("bootstraps fresh");

    assert_eq!(joined(&harness.store), 1);
    assert_ne!(session.membership_generation, 1);
}

/// A retired generation is never resumed, however complete its checkpoint.
#[tokio::test]
async fn a_retired_generation_is_not_resumed() {
    let harness = harness(900);
    harness
        .store
        .seed_member(seeded_member(
            "retired",
            1,
            Some(("DURABLE-sfo3-cell-a", 8, 900)),
            true,
        ))
        .seed_checkpoint(seeded_checkpoint(1, 905, Vec::new()));

    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("bootstraps fresh");

    assert_eq!(joined(&harness.store), 1);
    assert_ne!(session.membership_generation, 1);
}

/// The frontier this session reports is seeded from what the source
/// answered, so a source that answers a resume with a HIGHER position
/// would have this generation claim sequences nobody acknowledged and
/// WP-119's reaper would delete rows nobody read. The receiver refuses it
/// rather than trusting one transport to have checked.
#[tokio::test]
async fn a_resume_position_the_stream_does_not_echo_retires() {
    let harness = harness(900);
    harness
        .store
        .seed_member(seeded_member(
            "ready",
            1,
            Some(("DURABLE-sfo3-cell-a", 8, 900)),
            true,
        ))
        .seed_checkpoint(seeded_checkpoint(1, 905, Vec::new()));
    harness.stream.force_capture_start(4_000);

    assert_eq!(
        harness.receiver.bootstrap().await.err(),
        Some(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED))
    );
}

/// A checkpoint refused for any reason other than a version conflict must
/// fail the bootstrap. `readiness_cas` answers `AlreadyRecorded` for a row
/// that is already ready BEFORE it rereads the placement, so a swallowed
/// refusal would let a resumed generation claim readiness while every
/// checkpoint it goes on to send is refused.
#[tokio::test]
async fn a_checkpoint_refused_as_stale_fails_the_resume_rather_than_reaching_readiness() {
    let harness = harness(900);
    harness
        .store
        .seed_member(seeded_member(
            "ready",
            1,
            Some(("DURABLE-sfo3-cell-a", 8, 900)),
            true,
        ))
        .seed_checkpoint(seeded_checkpoint(1, 905, Vec::new()));
    harness
        .store
        .next_checkpoint(Ok(CheckpointOutcome::StaleGeneration {
            current_membership_generation: 4,
        }));

    assert_eq!(
        harness.receiver.bootstrap().await.err(),
        Some(BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)),
        "a stale generation must not reach readiness through AlreadyRecorded"
    );
}

/// A bootstrap that fails after joining must not cost a generation on the
/// next attempt. Nothing retires an uncaptured `joining` row, so joining
/// again per backoff tick would grow the membership table without bound
/// for as long as the broker is down.
#[tokio::test]
async fn a_retried_bootstrap_reuses_its_uncaptured_generation() {
    let harness = harness(900);
    harness
        .stream
        .fail_next_capture_with(StreamError::Transient("broker down".into()));
    assert!(harness.receiver.bootstrap().await.is_err());

    let joins_after_first = harness
        .store
        .calls()
        .iter()
        .filter(|call| matches!(call, StoreCall::Join { .. }))
        .count();
    assert_eq!(joins_after_first, 1);

    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("the retry bootstraps");
    assert_eq!(
        session.membership_generation, 1,
        "the retry must reuse the uncaptured generation the failed attempt left behind"
    );
    assert_eq!(
        harness
            .store
            .calls()
            .iter()
            .filter(|call| matches!(call, StoreCall::Join { .. }))
            .count(),
        1,
        "a second join would leak a generation and bump the cell version again"
    );
}

/// A concurrent join moves the cell's membership version under the
/// bootstrap's checkpoint. That costs one resend, not a whole generation
/// that had already captured, baselined, and drained.
#[tokio::test]
async fn a_membership_version_conflict_during_bootstrap_resends_in_place() {
    let harness = harness(900);
    harness.store.advance_membership_version_after_join(7);
    let session = harness
        .receiver
        .bootstrap()
        .await
        .expect("the conflicting report is resent, not abandoned");
    assert!(session.ready);
    assert_eq!(session.membership_generation, 1);

    let reports: Vec<i64> = harness
        .store
        .calls()
        .iter()
        .filter_map(|call| match call {
            StoreCall::Checkpoint(report) => Some(report.membership_version),
            _ => None,
        })
        .collect();
    assert_eq!(
        reports.len(),
        2,
        "the conflict costs exactly one extra report"
    );
    assert_eq!(reports[0], 2, "the first report carries the joined version");
    assert_eq!(
        reports[1], 9,
        "the resend must carry the version the conflict reported"
    );
}

/// The checkpoint report carries the version the JOIN returned, which is
/// the cell counter after the join's own bump — not the version read
/// before it, and not the member row's join-stamped column. Either of
/// those would make the bootstrap's own report conflict every time.
#[tokio::test]
async fn the_checkpoint_report_carries_the_post_join_cell_version() {
    let harness = harness(900);
    let session = harness.receiver.bootstrap().await.expect("bootstraps");
    let reports: Vec<i64> = harness
        .store
        .calls()
        .iter()
        .filter_map(|call| match call {
            StoreCall::Checkpoint(report) => Some(report.membership_version),
            _ => None,
        })
        .collect();
    assert_eq!(
        reports,
        vec![2],
        "one accepted report, at the version the join returned"
    );
    let report = session.checkpoint_report(IDENTITY);
    assert_eq!(report.stream_identity, "DURABLE-sfo3-cell-a");
    assert_eq!(report.stream_epoch, 8);
    assert_eq!(report.membership_generation, 1);
}

/// A cell whose `SCHEMA-119` install never ran is a configuration fault,
/// not a transient one. Reading it as transient would spin a backoff loop
/// against a database that is never going to grow the row.
#[tokio::test]
async fn a_cell_with_no_membership_state_is_a_rejection_not_a_retry() {
    let harness = harness(900);
    harness.store.uninstalled();
    let failure = harness
        .receiver
        .bootstrap()
        .await
        .expect_err("an uninstalled cell cannot bootstrap");
    assert!(matches!(failure, BootstrapFailure::Rejected(_)));
    assert_eq!(failure.reason(), REASON_CONFIGURATION_REJECTED);
    assert_eq!(harness.target.baselines(), 0);
}

/// A cancelled receiver stops and reports the closed stopped reason rather
/// than an error, because an unreachable broker is a false readiness facet
/// and not a failed plugin task.
#[tokio::test]
async fn cancellation_stops_the_loop_without_returning_an_error() {
    let harness = harness(900);
    let readiness = harness.receiver.readiness();
    let cancel = harness.receiver.cancellation_token();
    cancel.cancel();
    assert!(harness.receiver.run().await.is_ok());
    assert_eq!(readiness.snapshot().reason, Some(REASON_STOPPED));
}

#[tokio::test]
async fn shutdown_checkpoints_an_applied_event_before_returning() {
    let mut harness = harness(900);
    harness.receiver.receiver.checkpoint_interval = Duration::from_secs(60);
    let readiness = harness.receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run = harness.receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                result = &mut run => panic!("receiver stopped before shutdown: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
            if readiness.is_ready() {
                break;
            }
        }
        harness.stream.push_envelope(900, durable(0x9f, 1, None));
        while harness.stream.acked().is_empty() {
            tokio::select! {
                result = &mut run => panic!("receiver stopped before application: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
    })
    .await
    .expect("receiver must apply the event");
    let before_shutdown = harness.store.calls().len();
    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("receiver must finish promptly")
        .expect("shutdown succeeds");
    assert_eq!(harness.stream.acked(), vec![900]);
    assert!(
        harness.store.calls()[before_shutdown..]
            .iter()
            .any(|call| matches!(
                call, StoreCall::DrainingCheckpoint(report) if report.contiguous_frontier == 900
            )),
        "shutdown must persist the accepted frontier, with the draining marker, before \
         returning"
    );
    assert_eq!(
        harness.store.member_state(IDENTITY, 1).as_deref(),
        Some("draining")
    );
    assert_eq!(readiness.snapshot().reason, Some(REASON_STOPPED));
}

/// A real gateway sends one `CaughtUp` on an idle durable consumer and then
/// nothing. `FakeDurableStream` answers `CaughtUp` forever instead, which
/// returns at once and so hides a read that cannot be cancelled. After its
/// first `CaughtUp`, this stream's `next` blocks until dropped.
#[derive(Debug)]
struct IdleBlockingStream {
    stream: FakeDurableStream,
    caught_up: std::sync::atomic::AtomicBool,
    /// Notified each time a read starts to block.
    blocked: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl DurableStreamSource for IdleBlockingStream {
    async fn capture(
        &self,
        request: &CaptureRequest,
    ) -> Result<CapturedStreamPosition, StreamError> {
        self.stream.capture(request).await
    }

    async fn next(&self) -> Result<StreamDelivery, StreamError> {
        if self.caught_up.load(std::sync::atomic::Ordering::SeqCst) {
            self.blocked.notify_one();
            std::future::pending::<()>().await;
        }
        let delivery = self.stream.next().await?;
        if matches!(delivery, StreamDelivery::CaughtUp) {
            self.caught_up
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(delivery)
    }

    async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError> {
        self.stream.ack(broker_sequence).await
    }
}

/// Shutdown reaches a receiver whose steady-state read is blocked on an idle
/// stream. The read used to be uncancellable, so the run never returned and the
/// server waited for its force-close deadline.
#[tokio::test]
async fn shutdown_interrupts_a_read_blocked_on_an_idle_stream() {
    let store = InMemoryReceiverStore::new(CELL);
    let target = RecordingInvalidationTarget::new();
    let blocked = Arc::new(tokio::sync::Notify::new());
    let receiver = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream: Arc::new(IdleBlockingStream {
                stream: FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900),
                caught_up: std::sync::atomic::AtomicBool::new(false),
                blocked: blocked.clone(),
            }),
            target: Arc::new(target),
        },
    )
    .expect("the test config declares a required receiver");
    let readiness = receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run = receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);
    // The signal goes only once the ready loop is blocked in its read;
    // otherwise the loop could see the cancellation before reading.
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = &mut run => panic!("receiver stopped before shutdown: {result:?}"),
            () = blocked.notified() => {}
        }
    })
    .await
    .expect("receiver must reach its blocked read");
    assert!(
        readiness.is_ready(),
        "the blocked read is the ready steady state"
    );
    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("shutdown must not wait for a read the idle stream never completes")
        .expect("shutdown succeeds");
    assert_eq!(store.member_state(IDENTITY, 1).as_deref(), Some("draining"));
    assert_eq!(readiness.snapshot().reason, Some(REASON_STOPPED));
}

/// The gateway's idle shape: one `CaughtUp` once nothing is pending, then
/// silence until the next push. `FakeDurableStream` answers `CaughtUp` at
/// once on every read, which re-runs the idle cadence check and hides a
/// checkpoint that only an idle step could send.
#[derive(Debug)]
struct QuietAfterCaughtUpStream {
    stream: FakeDurableStream,
    quiet: std::sync::atomic::AtomicBool,
    pushed: Arc<tokio::sync::Notify>,
}

impl QuietAfterCaughtUpStream {
    fn new(stream: FakeDurableStream) -> Self {
        Self {
            stream,
            quiet: std::sync::atomic::AtomicBool::new(false),
            pushed: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

#[async_trait::async_trait]
impl DurableStreamSource for QuietAfterCaughtUpStream {
    async fn capture(
        &self,
        request: &CaptureRequest,
    ) -> Result<CapturedStreamPosition, StreamError> {
        self.stream.capture(request).await
    }

    async fn next(&self) -> Result<StreamDelivery, StreamError> {
        loop {
            let delivery = self.stream.next().await?;
            if !matches!(delivery, StreamDelivery::CaughtUp) {
                self.quiet.store(false, std::sync::atomic::Ordering::SeqCst);
                return Ok(delivery);
            }
            if !self.quiet.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Ok(delivery);
            }
            // A stored permit survives a dropped wait, so a push is not lost.
            self.pushed.notified().await;
        }
    }

    async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError> {
        self.stream.ack(broker_sequence).await
    }
}

/// A receiver over [`QuietAfterCaughtUpStream`] whose checkpoints come due by
/// the interval alone.
fn quiet_receiver(
    store: &InMemoryReceiverStore,
    stream: Arc<QuietAfterCaughtUpStream>,
) -> DurableReceiver {
    let mut receiver = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(store.clone()),
            stream,
            target: Arc::new(RecordingInvalidationTarget::new()),
        },
    )
    .expect("the test config declares a required receiver");
    receiver.receiver.checkpoint_interval = Duration::from_millis(300);
    receiver.receiver.checkpoint_every_events = 10_000;
    receiver
}

fn checkpoint_reports(store: &InMemoryReceiverStore) -> Vec<CheckpointReport> {
    store
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            StoreCall::Checkpoint(report) => Some(*report),
            _ => None,
        })
        .collect()
}

/// Drive `run` until `condition` holds, failing if the run returns first.
async fn drive_until<F, R>(
    run: &mut std::pin::Pin<&mut F>,
    within: Duration,
    what: &str,
    mut condition: impl FnMut() -> bool,
) where
    F: std::future::Future<Output = R>,
    R: std::fmt::Debug,
{
    tokio::time::timeout(within, async {
        while !condition() {
            tokio::select! {
                result = run.as_mut() => panic!("receiver stopped early: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_elapsed| panic!("timed out waiting for {what}"));
}

/// Keep `run` going for `window`, failing if it returns.
async fn drive_for<F, R>(run: &mut std::pin::Pin<&mut F>, window: Duration)
where
    F: std::future::Future<Output = R>,
    R: std::fmt::Debug,
{
    tokio::select! {
        result = run.as_mut() => panic!("receiver stopped early: {result:?}"),
        () = tokio::time::sleep(window) => {}
    }
}

/// WP-115 ledger row 64. The last acknowledgements of a burst used to stay
/// unreported while the stream was idle: the interval was checked only on an
/// idle step, and the read after it blocks until the next delivery.
#[tokio::test]
async fn an_idle_stream_still_reports_a_burst_once_the_interval_passes() {
    let store = InMemoryReceiverStore::new(CELL);
    let fake = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let stream = Arc::new(QuietAfterCaughtUpStream::new(fake.clone()));
    let receiver = quiet_receiver(&store, stream.clone());
    let readiness = receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run = receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);

    drive_until(&mut run, Duration::from_secs(2), "readiness", || {
        readiness.is_ready()
    })
    .await;
    for (offset, ordinal) in (0..3).zip(1..) {
        fake.push_envelope(900 + offset, durable(0x9f, ordinal, None));
    }
    stream.pushed.notify_one();
    drive_until(&mut run, Duration::from_secs(2), "the burst's acks", || {
        fake.acked().len() == 3
    })
    .await;
    // Nothing more is delivered. Only the interval can report the burst.
    drive_until(
        &mut run,
        Duration::from_secs(2),
        "the idle checkpoint",
        || store.projected_frontier() == Some(902),
    )
    .await;
    assert_eq!(fake.acked(), vec![900, 901, 902]);

    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("receiver must finish promptly")
        .expect("shutdown succeeds");
}

/// A deadline exists only while something is unreported, so a reported idle
/// receiver neither re-sends nor wakes on a timer.
#[tokio::test]
async fn a_reported_idle_receiver_sends_no_further_checkpoint() {
    let store = InMemoryReceiverStore::new(CELL);
    let fake = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let stream = Arc::new(QuietAfterCaughtUpStream::new(fake.clone()));
    let receiver = quiet_receiver(&store, stream.clone());
    let readiness = receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run = receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);

    drive_until(&mut run, Duration::from_secs(2), "readiness", || {
        readiness.is_ready()
    })
    .await;
    fake.push_envelope(900, durable(0x9f, 1, None));
    stream.pushed.notify_one();
    drive_until(
        &mut run,
        Duration::from_secs(2),
        "the idle checkpoint",
        || store.projected_frontier() == Some(900),
    )
    .await;
    let reported = checkpoint_reports(&store).len();
    drive_for(&mut run, Duration::from_millis(1_000)).await;
    assert_eq!(
        checkpoint_reports(&store).len(),
        reported,
        "three idle intervals with nothing unreported must send nothing"
    );

    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("receiver must finish promptly")
        .expect("shutdown succeeds");
}

/// Cancellation wins over a pending checkpoint deadline, and the draining
/// write still reports what the deadline had not yet sent.
#[tokio::test]
async fn shutdown_wins_over_a_pending_checkpoint_deadline() {
    let store = InMemoryReceiverStore::new(CELL);
    let fake = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let stream = Arc::new(QuietAfterCaughtUpStream::new(fake.clone()));
    let mut receiver = quiet_receiver(&store, stream.clone());
    receiver.receiver.checkpoint_interval = Duration::from_secs(60);
    let readiness = receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run = receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);

    drive_until(&mut run, Duration::from_secs(2), "readiness", || {
        readiness.is_ready()
    })
    .await;
    fake.push_envelope(900, durable(0x9f, 1, None));
    stream.pushed.notify_one();
    drive_until(&mut run, Duration::from_secs(2), "the ack", || {
        fake.acked().len() == 1
    })
    .await;
    let before_shutdown = store.calls().len();
    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("shutdown must not wait for the 60 s checkpoint deadline")
        .expect("shutdown succeeds");
    let after: Vec<StoreCall> = store.calls()[before_shutdown..].to_vec();
    assert!(
        !after
            .iter()
            .any(|call| matches!(call, StoreCall::Checkpoint(_))),
        "the deadline must not fire an ordinary checkpoint on the way out: {after:?}"
    );
    assert!(after.iter().any(|call| matches!(
        call,
        StoreCall::DrainingCheckpoint(report) if report.contiguous_frontier == 900
    )));
    assert_eq!(store.member_state(IDENTITY, 1).as_deref(), Some("draining"));
}

/// A refused idle checkpoint leaves its deadline in the past. The retry
/// backs off instead of spinning on the store.
#[tokio::test]
async fn a_failing_idle_checkpoint_backs_off_rather_than_spinning() {
    let store = InMemoryReceiverStore::new(CELL);
    let fake = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let stream = Arc::new(QuietAfterCaughtUpStream::new(fake.clone()));
    let mut receiver = quiet_receiver(&store, stream.clone());
    receiver.receiver.checkpoint_interval = Duration::from_millis(50);
    receiver.backoff_initial = Duration::from_millis(100);
    receiver.backoff_max = Duration::from_millis(100);
    let readiness = receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let run = receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);

    drive_until(&mut run, Duration::from_secs(2), "readiness", || {
        readiness.is_ready()
    })
    .await;
    for _ in 0..1_000 {
        store.next_checkpoint(Err(ReceiverStoreError::Unavailable(
            "store down".to_string(),
        )));
    }
    let before = checkpoint_reports(&store).len();
    fake.push_envelope(900, durable(0x9f, 1, None));
    stream.pushed.notify_one();
    drive_until(&mut run, Duration::from_secs(2), "the ack", || {
        fake.acked().len() == 1
    })
    .await;
    drive_for(&mut run, Duration::from_millis(600)).await;
    let attempts = checkpoint_reports(&store).len() - before;
    assert!(
        (2..=10).contains(&attempts),
        "a 100 ms backoff over 600 ms allows a handful of attempts, not {attempts}"
    );
    assert_eq!(readiness.snapshot().reason, Some(REASON_STORE_UNAVAILABLE));

    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("receiver must finish promptly")
        .expect("shutdown succeeds");
}

/// Run a bootstrapped receiver until it is ready, optionally apply one
/// event, then shut it down gracefully. Returns the store calls made from
/// the shutdown signal on.
async fn run_then_shut_down(harness: &mut Harness, apply_one: bool) -> Vec<StoreCall> {
    harness.receiver.receiver.checkpoint_interval = Duration::from_secs(60);
    let readiness = harness.receiver.readiness();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let receiver = std::mem::replace(
        &mut harness.receiver,
        DurableReceiver::new(
            &config(),
            ReceiverRuntime {
                store: Arc::new(harness.store.clone()),
                stream: Arc::new(harness.stream.clone()),
                target: Arc::new(harness.target.clone()),
            },
        )
        .expect("the test config declares a required receiver"),
    );
    let run = receiver.run_with_shutdown(shutdown_rx);
    tokio::pin!(run);
    let stream = harness.stream.clone();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !readiness.is_ready() {
            tokio::select! {
                result = &mut run => panic!("receiver stopped before shutdown: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
        if apply_one {
            stream.push_envelope(900, durable(0x9f, 1, None));
            while stream.acked().is_empty() {
                tokio::select! {
                    result = &mut run => panic!("receiver stopped before application: {result:?}"),
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
        }
    })
    .await
    .expect("receiver must reach readiness");
    let before_shutdown = harness.store.calls().len();
    shutdown_tx.send(true).expect("receiver observes shutdown");
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("receiver must finish promptly")
        .expect("shutdown succeeds");
    harness.store.calls()[before_shutdown..].to_vec()
}

/// WP-115 row 68: the case the marker exists for. An idle receiver whose
/// frontier is already reported had nothing to send on shutdown, so its
/// generation stayed `ready` and looked exactly like a live one. The
/// graceful stop now sends the draining write anyway.
#[tokio::test]
async fn a_graceful_shutdown_marks_an_idle_caught_up_generation_draining() {
    let mut harness = harness(900);
    let calls = run_then_shut_down(&mut harness, false).await;
    let draining: Vec<&CheckpointReport> = calls
        .iter()
        .filter_map(|call| match call {
            StoreCall::DrainingCheckpoint(report) => Some(&**report),
            _ => None,
        })
        .collect();
    assert_eq!(
        draining.len(),
        1,
        "exactly one draining write on a graceful stop"
    );
    assert_eq!(draining[0].contiguous_frontier, 899);
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, StoreCall::Checkpoint(_))),
        "an accepted draining write needs no second, ordinary report"
    );
    assert_eq!(
        harness.store.member_state(IDENTITY, 1).as_deref(),
        Some("draining")
    );
}

/// A refused draining write (here, the store answers that the generation
/// is not drainable) still leaves the ordinary final checkpoint of any
/// unreported work. The generation is not marked, so an operator would
/// need the stop confirmation to retire it.
#[tokio::test]
async fn a_refused_draining_write_falls_back_to_the_ordinary_final_checkpoint() {
    let mut harness = harness(900);
    harness
        .store
        .next_draining_checkpoint(Ok(CheckpointOutcome::NotDrainable {
            state: "joining".to_string(),
        }));
    let calls = run_then_shut_down(&mut harness, true).await;
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, StoreCall::DrainingCheckpoint(_))),
        "the draining write is attempted first"
    );
    assert!(
        calls.iter().any(|call| matches!(
            call, StoreCall::Checkpoint(report) if report.contiguous_frontier == 900
        )),
        "the unreported frontier still reaches the projection"
    );
    assert_eq!(
        harness.store.member_state(IDENTITY, 1).as_deref(),
        Some("ready")
    );
}

/// A draining write that meets a concurrent join adopts the cell's version
/// and resends once, as the bootstrap's own checkpoint does.
#[tokio::test]
async fn a_draining_write_resends_once_after_a_membership_version_conflict() {
    let mut harness = harness(900);
    harness
        .store
        .next_draining_checkpoint(Ok(CheckpointOutcome::MembershipVersionConflict {
            current_membership_version: 2,
        }));
    let calls = run_then_shut_down(&mut harness, false).await;
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, StoreCall::DrainingCheckpoint(_)))
            .count(),
        2
    );
    assert_eq!(
        harness.store.member_state(IDENTITY, 1).as_deref(),
        Some("draining")
    );
}

/// A receiver restarting on the generation its graceful shutdown marked
/// `draining` resumes it rather than joining a new one: no join, no new
/// capture, the persisted frontier restored, and the generation back to
/// `ready`.
#[tokio::test]
async fn a_restart_resumes_a_draining_generation_to_ready() {
    let mut first = harness(900);
    let calls = run_then_shut_down(&mut first, true).await;
    assert!(
        calls
            .iter()
            .any(|call| matches!(call, StoreCall::DrainingCheckpoint(_)))
    );
    assert_eq!(
        first.store.member_state(IDENTITY, 1).as_deref(),
        Some("draining")
    );

    // A second process over the same durable store and stream.
    let restarted = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(first.store.clone()),
            stream: Arc::new(first.stream.clone()),
            target: Arc::new(first.target.clone()),
        },
    )
    .expect("the test config declares a required receiver");
    let before = first.store.calls().len();
    let session = restarted.bootstrap().await.expect("the restart resumes");
    assert!(session.ready);
    assert_eq!(session.membership_generation, 1, "no generation is spent");
    assert_eq!(session.contiguous_frontier(), 900);
    let restart_calls = &first.store.calls()[before..];
    assert!(
        !restart_calls
            .iter()
            .any(|call| matches!(call, StoreCall::Join { .. } | StoreCall::Capture { .. })),
        "a resume neither joins nor re-records the capture: {restart_calls:?}"
    );
    assert_eq!(
        first.store.member_state(IDENTITY, 1).as_deref(),
        Some("ready")
    );
    // The un-drain is the restart's first membership write, ahead of the
    // capture, so no delivery is consumed behind a `draining` row.
    let first_readiness = restart_calls
        .iter()
        .position(|call| matches!(call, StoreCall::Readiness { .. }))
        .expect("the resume moves the generation back to ready");
    let first_baseline = restart_calls
        .iter()
        .position(|call| matches!(call, StoreCall::Baseline { .. }))
        .expect("the resume records its baseline");
    assert!(
        first_readiness < first_baseline,
        "the draining generation must leave draining before it consumes: {restart_calls:?}"
    );
    assert_eq!(
        first.stream.captures().len(),
        2,
        "one capture per process, and the resume did not join or capture anew"
    );
}

/// A retirement that commits while the receiver is down wins. The
/// restart's un-drain is refused before it captures or consumes anything,
/// and the next bootstrap starts a new generation.
#[tokio::test]
async fn a_draining_generation_retired_before_the_restart_is_not_resumed() {
    let mut first = harness(900);
    run_then_shut_down(&mut first, false).await;
    assert_eq!(
        first.store.member_state(IDENTITY, 1).as_deref(),
        Some("draining")
    );
    first.store.next_readiness(Ok(MembershipCas::WrongState {
        state: "retired".to_string(),
    }));
    let captures_before = first.stream.captures().len();
    let restarted = DurableReceiver::new(
        &config(),
        ReceiverRuntime {
            store: Arc::new(first.store.clone()),
            stream: Arc::new(first.stream.clone()),
            target: Arc::new(first.target.clone()),
        },
    )
    .expect("the test config declares a required receiver");
    let failure = restarted
        .bootstrap()
        .await
        .expect_err("a retired generation is not resumed");
    assert_eq!(failure, BootstrapFailure::Retired(REASON_PLACEMENT_MOVED));
    assert_eq!(
        first.stream.captures().len(),
        captures_before,
        "the refusal lands before any capture"
    );
}

#[test]
fn a_fresh_readiness_handle_is_not_ready() {
    let readiness = ReceiverReadiness::new();
    let snapshot = readiness.snapshot();
    assert!(!snapshot.ready);
    assert_eq!(snapshot.reason, Some(REASON_NOT_STARTED));
    assert_eq!(snapshot.generation, None);
}

#[test]
fn only_the_four_disposed_outcomes_acknowledge() {
    assert!(StepOutcome::Applied.acknowledged());
    assert!(StepOutcome::Duplicate.acknowledged());
    assert!(StepOutcome::Stale.acknowledged());
    assert!(StepOutcome::Refetched.acknowledged());
    assert!(
        !StepOutcome::Parked("UNSUPPORTED_SCHEMA").acknowledged(),
        "a parked event must never be acknowledged; the unacknowledged sequence is what \
         stalls the frontier"
    );
    assert!(!StepOutcome::Transient(REASON_STREAM_UNAVAILABLE).acknowledged());
    assert!(!StepOutcome::Retired(REASON_PLACEMENT_MOVED).acknowledged());
    assert!(!StepOutcome::Idle.acknowledged());
}

#[test]
fn every_readiness_reason_is_a_closed_low_cardinality_label() {
    for reason in [
        REASON_NOT_STARTED,
        REASON_BOOTSTRAPPING,
        REASON_LAG_THRESHOLD,
        REASON_STREAM_UNAVAILABLE,
        REASON_STORE_UNAVAILABLE,
        REASON_POISON_PARKED,
        REASON_PLACEMENT_MOVED,
        REASON_CONFIGURATION_REJECTED,
        REASON_STOPPED,
    ] {
        assert!(!reason.is_empty());
        assert!(reason.is_ascii());
        assert!(!reason.contains(' '));
    }
}

/// A membership version conflict is retryable; a placement move is not.
/// Getting this backwards would either spin on a dead generation or throw
/// away a live one.
#[test]
fn membership_answers_split_into_retry_and_retire() {
    assert_eq!(
        retire_on(MembershipCas::VersionConflict {
            current_membership_version: 9,
        }),
        BootstrapFailure::Transient(REASON_BOOTSTRAPPING)
    );
    assert_eq!(
        retire_on(MembershipCas::PlacementMoved {
            current_stream_identity: Some("DURABLE-a-r2".to_string()),
            current_stream_epoch: Some(1),
        }),
        BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
    );
    assert_eq!(
        retire_on(MembershipCas::NoCheckpointAtCurrentPlacement),
        BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
    );
}

#[test]
fn a_transient_store_failure_retries_and_a_rejection_does_not() {
    assert_eq!(
        store_failure(
            lore_server::plugins::remote_notification::receiver_store::ReceiverStoreError::Unavailable(
                "pool exhausted".into()
            )
        ),
        BootstrapFailure::Transient(REASON_STORE_UNAVAILABLE)
    );
    assert!(matches!(
        store_failure(
            lore_server::plugins::remote_notification::receiver_store::ReceiverStoreError::Rejected(
                "stream_epoch must be >= 1".into()
            )
        ),
        BootstrapFailure::Rejected(_)
    ));
}

#[test]
fn a_moved_placement_retires_rather_than_backing_off() {
    assert_eq!(
        stream_failure(StreamError::PlacementMoved {
            current: lore_server::plugins::remote_notification::stream::StreamPlacement::new(
                "DURABLE-a-r2",
                1
            ),
        }),
        BootstrapFailure::Retired(REASON_PLACEMENT_MOVED)
    );
    assert_eq!(
        stream_failure(StreamError::Transient("broker down".into())),
        BootstrapFailure::Transient(REASON_STREAM_UNAVAILABLE)
    );
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Phase 10's gap/refetch row, closed: receiver-level proof of
//! receiver-side fault injection at the `DurableStreamSource` seam
//! (`lore-server/src/plugins/remote_notification/faults.rs`), driving a real
//! `DurableReceiver` over an in-process `FakeDurableStream`.
//!
//! The fault spec grammar and the decorator's own contract (`Anchor`,
//! `FaultConfig`, `Trigger`, `FaultyDurableStream`) are unit-tested
//! co-located in `faults.rs` itself now
//! (`#[cfg(all(test, feature = "failure_generator"))] mod tests`), because
//! `faults.rs` is where those types live and a co-located test can reach
//! private internals if it ever needs to. This file is the other half:
//! proving each fault drives the intended `StepOutcome` and `AckFrontier`
//! state through the ACTUAL receiver (`receiver.rs`, a sibling module), which
//! needs a real `InMemoryReceiverStore` and config parsing besides -- the
//! reason this proof cannot live inside `faults.rs` itself.
//!
//! # Tier limit
//!
//! **Everything in this file runs against the in-process fake stream, never
//! a live broker.** It proves the receiver's classification of each injected
//! fault (drop -> gap/refetch, duplicate, poison, transient read, transient
//! ack) end to end through `DurableReceiver::step` and `AckFrontier`. It does
//! NOT prove that a real JetStream/NATS broker redelivers an unacknowledged
//! message the way this file's tests simulate by re-pushing an envelope onto
//! the fake -- that half is the two-process live harness's job, and is what
//! this fault seam exists to make possible there. See `faults.rs`'s own
//! module documentation for why WP-119 Phase 10's gap/refetch row stayed open
//! without it.
//!
//! # Why (almost) everything here is feature-gated
//!
//! `FaultConfig`, `FaultyDurableStream`, and `Trigger` only exist in a build
//! carrying `--features failure_generator` -- `faults.rs`'s own module
//! documentation explains why that must be true even for `lore-server`'s
//! *own* test code, the same way it is for `lore-postgres`'s failpoints. The
//! one test outside `injected_fault_tests` below deliberately uses none of
//! them: it is the default-build guard that proves the always-available
//! façade (`faults::wrap_stream`, `faults::faults_compiled`) is inert when
//! the feature is off, which is the property the rest of this file's tier is
//! trusting.

use std::sync::Arc;

use lore_server::plugins::remote_notification::DurableStreamSource;
use lore_server::plugins::remote_notification::FakeDurableStream;
use lore_server::plugins::remote_notification::StreamPlacement;
use lore_server::plugins::remote_notification::faults;

/// Runs in every tier, including a default build with no `failure_generator`
/// feature at all.
///
/// A default build cannot even name `faults::Anchor` or
/// `faults::FaultyDurableStream` -- that is `faults.rs`'s own load-bearing
/// claim, verified by simply trying to build this file without the feature.
/// What a default build's own `#[test]`s *can* prove is the always-present
/// façade: `wrap_stream` must add nothing, not even a layer, and
/// `faults_compiled()` must say so. Asserting `Arc::ptr_eq` rather than mere
/// behavioural equivalence is the stronger claim -- it proves no
/// `Arc::new` indirection was introduced at all, which is what "the
/// decorator is not compiled in" has to mean operationally.
#[tokio::test]
async fn wrap_stream_adds_no_layer_when_nothing_is_armed() {
    let inner: Arc<dyn DurableStreamSource> = Arc::new(FakeDurableStream::at(
        StreamPlacement::new("DURABLE-a", 1),
        1,
    ));
    let wrapped = faults::wrap_stream(Arc::clone(&inner));
    assert!(
        Arc::ptr_eq(&inner, &wrapped),
        "with LORE_RECEIVER_FAULTS unset, wrap_stream must return the identical Arc: a default \
         build (where the decorator cannot even be named) and a failure_generator build with \
         nothing armed must be indistinguishable to a caller"
    );

    #[cfg(not(feature = "failure_generator"))]
    {
        assert!(
            !faults::faults_compiled(),
            "a default build must report that it cannot inject receiver faults, so a harness \
             that armed LORE_RECEIVER_FAULTS against this binary by mistake has something to \
             read rather than silent inaction"
        );
    }
    #[cfg(feature = "failure_generator")]
    {
        assert!(
            faults::faults_compiled(),
            "a failure_generator build must report that it CAN inject receiver faults"
        );
    }
}

#[cfg(feature = "failure_generator")]
mod injected_fault_tests {
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use bytes::Bytes;
    use lore_base::types::RepositoryId;
    use lore_postgres::domain::outbox::PoisonEntry;
    use lore_postgres::domain::outbox::SequenceGap;
    use lore_server::plugins::remote_notification::AggregateVersion;
    use lore_server::plugins::remote_notification::DurableEnvelopeV1;
    use lore_server::plugins::remote_notification::DurableInvalidationBody;
    use lore_server::plugins::remote_notification::DurableReceiver;
    use lore_server::plugins::remote_notification::DurableStreamSource;
    use lore_server::plugins::remote_notification::EnvelopeCommon;
    use lore_server::plugins::remote_notification::EventId;
    use lore_server::plugins::remote_notification::FakeDurableStream;
    use lore_server::plugins::remote_notification::InMemoryReceiverStore;
    use lore_server::plugins::remote_notification::ReceiverRuntime;
    use lore_server::plugins::remote_notification::RecordingInvalidationTarget;
    use lore_server::plugins::remote_notification::RemoteNotificationConfig;
    use lore_server::plugins::remote_notification::StepOutcome;
    use lore_server::plugins::remote_notification::StreamPlacement;
    use lore_server::plugins::remote_notification::apply::POISON_CLASS_UNSUPPORTED_SCHEMA;
    use lore_server::plugins::remote_notification::apply::TargetCall;
    use lore_server::plugins::remote_notification::faults::FaultConfig;
    use lore_server::plugins::remote_notification::faults::FaultyDurableStream;
    use lore_server::plugins::remote_notification::faults::Trigger;
    use lore_server::plugins::remote_notification::receiver::REASON_STREAM_UNAVAILABLE;
    use lore_server::plugins::remote_notification::wire;

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

    /// A durable envelope with an explicit `event_kind`/`aggregate_kind`/
    /// `aggregate_identity`, for tests that need more than one `AggregateKey`
    /// on the same repository. [`durable`] is the common case, built on this
    /// with a `branch.pushed`.
    fn durable_kind(
        repository_byte: u8,
        event_kind: &str,
        aggregate_kind: &str,
        aggregate_identity: &str,
        ordinal: u64,
    ) -> wire::PrivateEnvelopeV1 {
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
                event_kind: event_kind.to_string(),
                repository_generation: 1,
                aggregate_kind: aggregate_kind.to_string(),
                aggregate_identity: aggregate_identity.to_string(),
                aggregate_version: AggregateVersion {
                    ordinal,
                    identity: None,
                },
                payload: Bytes::new(),
                committed_at: UNIX_EPOCH,
                actor: None,
            },
        }
        .encode(1..=1)
        .expect("the test envelope is inside every contract bound")
    }

    /// One valid durable envelope for `repository_byte`, at `ordinal`. Every
    /// call shares the same event/aggregate identity, so a run of these is
    /// always one `AggregateKey`.
    fn durable(repository_byte: u8, ordinal: u64) -> wire::PrivateEnvelopeV1 {
        durable_kind(
            repository_byte,
            "branch.pushed",
            "branch",
            "0123456789abcdef",
            ordinal,
        )
    }

    /// A fresh, unscripted fake, captured at `start_sequence`.
    fn fake(start_sequence: i64) -> FakeDurableStream {
        FakeDurableStream::at(
            StreamPlacement::new("DURABLE-sfo3-cell-a", 8),
            start_sequence,
        )
    }

    /// A receiver over `stream`, with a fresh in-memory store and a recording
    /// target this test can inspect.
    fn build_receiver(
        stream: Arc<dyn DurableStreamSource>,
    ) -> (DurableReceiver, RecordingInvalidationTarget) {
        let target = RecordingInvalidationTarget::new();
        let receiver = DurableReceiver::new(
            &config(),
            ReceiverRuntime {
                store: Arc::new(InMemoryReceiverStore::new(CELL)),
                stream,
                target: Arc::new(target.clone()),
            },
        )
        .expect("the test config declares a required receiver");
        (receiver, target)
    }

    fn applied_count(target: &RecordingInvalidationTarget) -> usize {
        target
            .calls()
            .iter()
            .filter(|call| matches!(call, TargetCall::Apply { .. }))
            .count()
    }

    // -----------------------------------------------------------------
    // Receiver-level proof: a real DurableReceiver over the decorated (or,
    // for `stale`, the plain) fake stream.
    // -----------------------------------------------------------------
    //
    // Every case below bootstraps against an EMPTY queue first, so the
    // bootstrap's own internal drain consumes exactly one `next()` call
    // against CaughtUp before this file pushes anything. That is why a
    // `next`-call-counted fault (`stream_transient`) below is armed at
    // ordinal 2, not 1: ordinal 1 belongs to the bootstrap's own read.

    /// WP-119 Phase 10's gap/refetch row, end to end: one `AggregateKey`
    /// delivered at ordinals 1, 2, 3 on broker sequences s, s+1, s+2. The
    /// `drop` anchor swallows delivery 2 (broker sequence s+1). The
    /// resulting ordinal jump (1 -> 3) is a version gap, resolved by an
    /// authoritative refetch before the acknowledgement, while the broker
    /// sequence gap at s+1 independently blocks the frontier. Redelivering
    /// s+1 afterwards (the fake stream standing in for a broker's
    /// redelivery of an unacknowledged message) then closes it.
    #[tokio::test]
    async fn a_dropped_delivery_produces_a_gap_and_a_refetch_then_recovers_on_redelivery() {
        let inner = fake(900);
        let faulty: Arc<dyn DurableStreamSource> = Arc::new(FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            FaultConfig {
                stream_drop: Some(Trigger::Ordinal(2)),
                ..Default::default()
            },
            None,
        ));
        let (receiver, target) = build_receiver(faulty);
        let mut session = receiver
            .bootstrap()
            .await
            .expect("bootstraps against an empty queue");
        assert_eq!(session.contiguous_frontier(), 899);

        inner.push_envelope(900, durable(1, 1));
        inner.push_envelope(901, durable(1, 2)); // swallowed by the drop anchor
        inner.push_envelope(902, durable(1, 3));

        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Applied,
            "ordinal 1 at broker sequence 900 applies"
        );
        assert_eq!(session.contiguous_frontier(), 900);

        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Idle,
            "the drop swallows delivery 2 and reports CaughtUp, not an error"
        );
        assert_eq!(
            session.contiguous_frontier(),
            900,
            "an idle step never touches the frontier"
        );

        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Refetched,
            "ordinal 3 arriving after ordinal 1 is a version gap, resolved by refetch"
        );
        assert!(
            target
                .calls()
                .iter()
                .any(|call| matches!(call, TargetCall::Refetch(repo) if *repo == repository(1))),
            "the gap must be resolved by an authoritative refetch before the acknowledgement"
        );

        let report = session.checkpoint_report(IDENTITY);
        assert_eq!(
            report.contiguous_frontier, 900,
            "broker sequence 902 is acknowledged, but the hole at 901 blocks the frontier"
        );
        assert_eq!(report.gaps, vec![SequenceGap { from: 901, to: 901 }]);
        assert!(session.has_blockers());

        // Recovery: the broker redelivers the unacknowledged sequence 901.
        inner.push_envelope(901, durable(1, 2));
        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Applied,
            "the refetch forgot this repository's applied versions, so the redelivered ordinal \
             2 is the next one to apply, not a duplicate"
        );
        assert_eq!(
            session.contiguous_frontier(),
            902,
            "the frontier closes over the resolved hole, up to the already-acked 902"
        );
        assert!(!session.has_blockers());
    }

    /// WP-119 case O's own live bug, pinned: an exactly-once assertion must
    /// name the `AggregateKey` it counts -- (repository, event_kind,
    /// aggregate_kind, aggregate_identity) -- not just the repository. A
    /// governed repository create appends `repository.published` and
    /// `branch.created` before any push appends `branch.pushed`; the live
    /// case's own bug counted applies by repository alone and answered 3
    /// where the push was applied exactly once, because the two prerequisite
    /// events are distinct aggregates, not duplicates of it.
    #[tokio::test]
    async fn exactly_once_counting_must_be_scoped_by_aggregate_key_not_repository() {
        let inner = fake(900);
        let stream: Arc<dyn DurableStreamSource> = Arc::new(inner.clone());
        let (receiver, target) = build_receiver(stream);
        let mut session = receiver
            .bootstrap()
            .await
            .expect("bootstraps against an empty queue");

        // Three distinct aggregates on the SAME repository: a governed
        // create's two prerequisite events, then the push.
        inner.push_envelope(
            900,
            durable_kind(1, "repository.published", "repository", "repo", 1),
        );
        inner.push_envelope(901, durable_kind(1, "branch.created", "branch", "main", 1));
        inner.push_envelope(902, durable_kind(1, "branch.pushed", "branch", "main", 2));

        for _ in 0..3 {
            assert_eq!(receiver.step(&mut session).await, StepOutcome::Applied);
        }

        // Naively counting every apply on this repository answers 3 -- this
        // is NOT three duplicates, it is three distinct aggregates. This is
        // exactly the count case O's live assertion made, and exactly why 3
        // was the wrong number to treat as a failure.
        let all_applies_on_repository = target
            .calls()
            .iter()
            .filter(
                |call| matches!(call, TargetCall::Apply { repository: r, .. } if *r == repository(1)),
            )
            .count();
        assert_eq!(
            all_applies_on_repository, 3,
            "three distinct aggregates on one repository produce three applies, not a duplicate"
        );

        // The discriminating count case O's assertion should have made:
        // exactly one `branch.pushed` apply, scoped by its own AggregateKey.
        let push_applies = target
            .calls()
            .iter()
            .filter(
                |call| matches!(call, TargetCall::Apply { event_kind, .. } if event_kind == "branch.pushed"),
            )
            .count();
        assert_eq!(push_applies, 1);

        // A REAL duplicate: redelivering the push unchanged shares its
        // AggregateKey and version with the one already applied.
        inner.push_envelope(903, durable_kind(1, "branch.pushed", "branch", "main", 2));
        assert_eq!(receiver.step(&mut session).await, StepOutcome::Duplicate);
        let push_applies_after = target
            .calls()
            .iter()
            .filter(
                |call| matches!(call, TargetCall::Apply { event_kind, .. } if event_kind == "branch.pushed"),
            )
            .count();
        assert_eq!(
            push_applies_after, 1,
            "the redelivered push is a duplicate, not a fourth apply"
        );
    }

    /// The `duplicate` anchor: the target applies once, and the frontier
    /// advances once, even though the delivery was observed twice.
    #[tokio::test]
    async fn duplicate_applies_once_and_advances_the_frontier_once() {
        let inner = fake(900);
        let faulty: Arc<dyn DurableStreamSource> = Arc::new(FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            FaultConfig {
                stream_duplicate: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        ));
        let (receiver, target) = build_receiver(faulty);
        let mut session = receiver
            .bootstrap()
            .await
            .expect("bootstraps against an empty queue");

        inner.push_envelope(900, durable(1, 5));
        assert_eq!(receiver.step(&mut session).await, StepOutcome::Applied);
        assert_eq!(session.contiguous_frontier(), 900);

        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Duplicate,
            "the injected replay is read on the very next step"
        );
        assert_eq!(
            session.contiguous_frontier(),
            900,
            "the duplicate's own acknowledgement is a no-op at or below the frontier"
        );
        assert_eq!(applied_count(&target), 1, "exactly one apply, never twice");
        assert_eq!(
            inner.acked(),
            vec![900, 900],
            "both the original and the duplicate are acknowledged"
        );
    }

    /// No fault needed: a lower ordinal delivered after a higher one is
    /// classified `Stale` by the receiver's own version comparison. Included
    /// here so the fault suite is self-contained end to end.
    #[tokio::test]
    async fn stale_is_acked_with_no_second_apply() {
        let inner = fake(900);
        let stream: Arc<dyn DurableStreamSource> = Arc::new(inner.clone());
        let (receiver, target) = build_receiver(stream);
        let mut session = receiver
            .bootstrap()
            .await
            .expect("bootstraps against an empty queue");

        inner.push_envelope(900, durable(1, 2));
        assert_eq!(receiver.step(&mut session).await, StepOutcome::Applied);

        inner.push_envelope(901, durable(1, 1));
        assert_eq!(receiver.step(&mut session).await, StepOutcome::Stale);
        assert_eq!(inner.acked(), vec![900, 901]);
        assert_eq!(
            applied_count(&target),
            1,
            "a stale delivery must never apply"
        );
    }

    /// The `poison` anchor: the corrupted `payload_version` is caught by the
    /// receiver's own bound check and parks under the shared
    /// `POISON_CLASS_UNSUPPORTED_SCHEMA` constant, never a hardcoded literal.
    #[tokio::test]
    async fn poison_parks_and_never_acknowledges() {
        let inner = fake(900);
        let faulty: Arc<dyn DurableStreamSource> = Arc::new(FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            FaultConfig {
                stream_poison: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        ));
        let (receiver, _target) = build_receiver(faulty);
        let mut session = receiver
            .bootstrap()
            .await
            .expect("bootstraps against an empty queue");
        assert_eq!(session.contiguous_frontier(), 899);

        inner.push_envelope(900, durable(1, 5));
        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Parked(POISON_CLASS_UNSUPPORTED_SCHEMA)
        );
        assert!(
            inner.acked().is_empty(),
            "a parked event must never be acknowledged"
        );
        assert_eq!(
            session.contiguous_frontier(),
            899,
            "an unresolved park stalls the frontier"
        );
        assert!(session.has_blockers());

        let report = session.checkpoint_report(IDENTITY);
        assert_eq!(
            report.poison,
            vec![PoisonEntry {
                broker_sequence: 900,
                class: POISON_CLASS_UNSUPPORTED_SCHEMA.to_string(),
            }]
        );
    }

    /// The `stream.transient` anchor: the step fails without acknowledging,
    /// and the very next step proceeds normally once the fault is spent --
    /// against the SAME still-queued envelope, since the decorator never
    /// touches the inner source before deciding to fire.
    #[tokio::test]
    async fn stream_transient_blocks_one_step_then_the_next_step_proceeds_normally() {
        let inner = fake(900);
        let faulty: Arc<dyn DurableStreamSource> = Arc::new(FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            // Call #1 is the bootstrap's own empty-queue drain read; call #2
            // is this test's first explicit step.
            FaultConfig {
                stream_transient: Some(Trigger::Ordinal(2)),
                ..Default::default()
            },
            None,
        ));
        let (receiver, target) = build_receiver(faulty);
        let mut session = receiver
            .bootstrap()
            .await
            .expect("bootstraps against an empty queue");
        assert_eq!(session.contiguous_frontier(), 899);

        inner.push_envelope(900, durable(1, 5));
        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Transient(REASON_STREAM_UNAVAILABLE)
        );
        assert!(
            inner.acked().is_empty(),
            "a transient read must never acknowledge anything"
        );
        assert_eq!(session.contiguous_frontier(), 899);

        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Applied,
            "the fault is spent; the same delivery is read cleanly on the very next step"
        );
        assert_eq!(session.contiguous_frontier(), 900);
        assert_eq!(applied_count(&target), 1);
    }

    /// The `ack.transient` anchor: the apply already happened and is NOT
    /// undone by the ack failure; the step reports `Transient`; a
    /// redelivery of the same sequence is then a `Duplicate` with still
    /// exactly one apply recorded.
    #[tokio::test]
    async fn ack_transient_does_not_undo_the_apply_and_redelivery_is_a_duplicate() {
        let inner = fake(900);
        let faulty: Arc<dyn DurableStreamSource> = Arc::new(FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            FaultConfig {
                ack_transient: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        ));
        let (receiver, target) = build_receiver(faulty);
        let mut session = receiver
            .bootstrap()
            .await
            .expect("bootstraps against an empty queue");

        inner.push_envelope(900, durable(1, 7));
        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Transient(REASON_STREAM_UNAVAILABLE),
            "the apply happened, but the ack that would have confirmed it failed"
        );
        assert!(
            inner.acked().is_empty(),
            "the failed ack call must not be recorded as an ack"
        );
        assert_eq!(
            session.contiguous_frontier(),
            899,
            "an unacknowledged apply does not advance the frontier"
        );
        assert_eq!(
            applied_count(&target),
            1,
            "the apply is NOT undone by the ack failure"
        );

        // The broker never saw an ack, so it redelivers the same sequence.
        inner.push_envelope(900, durable(1, 7));
        assert_eq!(
            receiver.step(&mut session).await,
            StepOutcome::Duplicate,
            "the version was already applied; the redelivery is a no-op"
        );
        assert_eq!(session.contiguous_frontier(), 900);
        assert_eq!(applied_count(&target), 1, "still exactly one apply");
    }
}

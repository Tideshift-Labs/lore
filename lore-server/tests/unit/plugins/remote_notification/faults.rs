// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
#![cfg(feature = "failure_generator")]
// Unit tests: the spec grammar, and the decorator's own contract against
// `FakeDurableStream` directly. Receiver-level proof (a real `DurableReceiver`
// disposing each outcome class) lives in
// `lore-server/tests/remote_notification_receiver_faults.rs`.
//
// The whole file is gated on `failure_generator`: these tests name `Anchor`,
// `FaultConfig`, `FaultyDurableStream` and `Trigger`, which exist only in that
// build.

use std::sync::Arc;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use lore_base::types::RepositoryId;
use lore_server::plugins::remote_notification::envelope::AggregateVersion;
use lore_server::plugins::remote_notification::envelope::DurableEnvelopeV1;
use lore_server::plugins::remote_notification::envelope::DurableInvalidationBody;
use lore_server::plugins::remote_notification::envelope::EnvelopeCommon;
use lore_server::plugins::remote_notification::envelope::EventId;
use lore_server::plugins::remote_notification::faults::*;
use lore_server::plugins::remote_notification::stream::CaptureRequest;
use lore_server::plugins::remote_notification::stream::CapturedStreamPosition;
use lore_server::plugins::remote_notification::stream::DurableStreamSource;
use lore_server::plugins::remote_notification::stream::FakeDurableStream;
use lore_server::plugins::remote_notification::stream::StreamDelivery;
use lore_server::plugins::remote_notification::stream::StreamError;
use lore_server::plugins::remote_notification::stream::StreamPlacement;
use lore_server::plugins::remote_notification::wire;
const CELL: &str = "sfo3-cell-a";
const IDENTITY: &str = "loreserver-sfo3-cell-a-2";

fn repository(byte: u8) -> RepositoryId {
    let mut id = RepositoryId::default();
    *id.data_mut() = [byte; 16];
    id
}

/// One valid durable envelope for `repository_byte`, at `ordinal`. Every
/// call shares the same event/aggregate identity, so a run of these is
/// always one `AggregateKey`.
fn durable(repository_byte: u8, ordinal: u64) -> wire::PrivateEnvelopeV1 {
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

/// A minimal envelope with no body, for tests that only care which
/// delivery a fault landed on (by broker sequence), not its content --
/// mirrors `stream.rs`'s own `envelope()` test helper.
fn bare_envelope() -> wire::PrivateEnvelopeV1 {
    wire::PrivateEnvelopeV1 {
        transport_version: wire::TRANSPORT_VERSION,
        ..Default::default()
    }
}

/// A fresh, unscripted fake, captured at `start_sequence`.
fn fake(start_sequence: i64) -> FakeDurableStream {
    FakeDurableStream::at(
        StreamPlacement::new("DURABLE-sfo3-cell-a", 8),
        start_sequence,
    )
}

// -----------------------------------------------------------------
// Spec parsing (`FaultConfig::parse`, `Anchor::parse`)
// -----------------------------------------------------------------

#[test]
fn every_anchor_name_parses_to_its_own_variant() {
    for (name, anchor) in [
        ("receiver.stream.drop", Anchor::StreamDrop),
        ("receiver.stream.duplicate", Anchor::StreamDuplicate),
        ("receiver.stream.poison", Anchor::StreamPoison),
        ("receiver.stream.transient", Anchor::StreamTransient),
        ("receiver.ack.transient", Anchor::AckTransient),
    ] {
        assert_eq!(Anchor::parse(name), Some(anchor), "{name} must parse");
    }
    assert_eq!(Anchor::parse("receiver.stream.bogus"), None);
    assert_eq!(Anchor::parse(""), None);
}

#[test]
fn the_parser_accepts_every_anchor_armed_at_once() {
    let config = FaultConfig::parse(
        "receiver.stream.drop=1,receiver.stream.duplicate=2,receiver.stream.poison=3,\
         receiver.stream.transient=4,receiver.ack.transient=5",
    );
    assert_eq!(config.stream_drop, Some(Trigger::Ordinal(1)));
    assert_eq!(config.stream_duplicate, Some(Trigger::Ordinal(2)));
    assert_eq!(config.stream_poison, Some(Trigger::Ordinal(3)));
    assert_eq!(config.stream_transient, Some(Trigger::Ordinal(4)));
    assert_eq!(config.ack_transient, Some(Trigger::Ordinal(5)));
    assert!(!config.is_empty());
}

#[test]
fn an_unknown_anchor_is_dropped_and_the_rest_of_the_spec_still_applies() {
    let config = FaultConfig::parse("bogus.anchor=1,receiver.stream.drop=2");
    assert_eq!(config.stream_drop, Some(Trigger::Ordinal(2)));
    assert_eq!(config.stream_duplicate, None);
}

#[test]
fn a_zero_ordinal_is_dropped() {
    assert!(FaultConfig::parse("receiver.stream.drop=0").is_empty());
}

#[test]
fn a_non_numeric_ordinal_is_dropped() {
    assert!(FaultConfig::parse("receiver.stream.drop=x").is_empty());
}

#[test]
fn an_entry_with_no_equals_sign_is_dropped() {
    assert!(FaultConfig::parse("receiver.stream.drop").is_empty());
}

#[test]
fn empty_entries_and_stray_separators_are_skipped_not_fatal() {
    assert!(FaultConfig::parse("").is_empty());
    assert!(FaultConfig::parse(",, ,").is_empty());
    let config = FaultConfig::parse("  ,receiver.stream.drop=1,  ,");
    assert_eq!(config.stream_drop, Some(Trigger::Ordinal(1)));
}

#[test]
fn whitespace_around_names_and_ordinals_is_trimmed() {
    let config = FaultConfig::parse(" receiver.stream.drop = 3 , receiver.ack.transient = 7 ");
    assert_eq!(config.stream_drop, Some(Trigger::Ordinal(3)));
    assert_eq!(config.ack_transient, Some(Trigger::Ordinal(7)));
}

/// A second entry for an already-armed anchor is dropped, keeping the
/// first trigger.
#[test]
fn a_duplicated_anchor_keeps_the_first_trigger_and_warns() {
    let config = FaultConfig::parse("receiver.stream.drop=2,receiver.stream.drop=9");
    assert_eq!(config.stream_drop, Some(Trigger::Ordinal(2)));
}

#[test]
fn an_empty_or_absent_spec_wraps_nothing() {
    assert!(FaultConfig::parse("").is_empty());
    assert!(FaultConfig::default().is_empty());
}

// -----------------------------------------------------------------
// The `Trigger` grammar itself
// -----------------------------------------------------------------

#[test]
fn trigger_next_parses_case_insensitively_and_every_spelling_round_trips() {
    assert_eq!(Trigger::parse("next"), Some(Trigger::Armed));
    assert_eq!(Trigger::parse("NEXT"), Some(Trigger::Armed));
    assert_eq!(Trigger::parse("NeXt"), Some(Trigger::Armed));
    assert_eq!(Trigger::parse("3"), Some(Trigger::Ordinal(3)));
    assert_eq!(Trigger::parse("0"), None, "an ordinal must be positive");
    assert_eq!(Trigger::parse("x"), None);
    assert_eq!(Trigger::parse(""), None);
    assert_eq!(Trigger::Armed.spelling(), "next");
    assert_eq!(Trigger::Ordinal(7).spelling(), "7");
}

/// A `next` trigger with no configured rendezvous directory could never
/// fire, so the parser drops it at parse time rather than arming
/// something inert.
///
/// A reviewer flagged the previous version of this test: it read the REAL
/// process environment directly (`std::env::var_os(FAULT_DIR_ENV)`)
/// outside of any `temp_env` lock, while the sibling test below mutates
/// that same variable through `temp_env`. Under the default multi-thread
/// test harness those two race -- `testing.md` requires isolated tests,
/// and a `#[serial]` bandage would not fix the actual defect, which is
/// touching the real environment at all. `temp_env::with_var(..., None,
/// ...)` both guarantees the unset state for the duration of this
/// closure AND takes the same global lock `with_vars` does below, so the
/// two tests can never observe each other's mutation, needing no
/// `#[serial]`.
#[test]
fn a_next_trigger_is_dropped_when_the_fault_dir_env_is_unset() {
    temp_env::with_var(FAULT_DIR_ENV, None::<&str>, || {
        let config = FaultConfig::parse("receiver.stream.drop=next");
        assert!(
            config.is_empty(),
            "a `next` trigger with LORE_RECEIVER_FAULT_DIR unset can never fire and must be \
             dropped rather than armed"
        );
    });
}

/// The other side of the same rule, over a scoped `temp_env` mutation
/// (this crate's own established pattern, e.g. `telemetry::resource`'s
/// tests) rather than a raw `std::env::set_var`, so no state escapes.
#[test]
fn a_next_trigger_is_accepted_when_the_fault_dir_env_is_set() {
    temp_env::with_vars([(FAULT_DIR_ENV, Some("/some/rendezvous/dir"))], || {
        let config = FaultConfig::parse("receiver.stream.drop=next");
        assert_eq!(config.stream_drop, Some(Trigger::Armed));
    });
}

// -----------------------------------------------------------------
// Decorator behaviour against `FakeDurableStream` directly
// -----------------------------------------------------------------

#[tokio::test]
async fn with_nothing_armed_the_decorator_is_fully_transparent() {
    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    inner.push_error(StreamError::Transient("down".to_string()));
    inner.push_caught_up();
    let decorated =
        FaultyDurableStream::with_dir(Arc::new(inner.clone()), FaultConfig::default(), None);

    assert!(matches!(
        decorated.next().await,
        Ok(StreamDelivery::Message(_))
    ));
    assert_eq!(
        decorated.next().await,
        Err(StreamError::Transient("down".to_string()))
    );
    assert_eq!(decorated.next().await, Ok(StreamDelivery::CaughtUp));
    assert!(decorated.ack(1).await.is_ok());
    assert_eq!(inner.acked(), vec![1], "acks pass straight through");
}

#[tokio::test]
async fn capture_is_never_perturbed_by_any_armed_fault() {
    let inner = fake(900);
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner.clone()),
        FaultConfig {
            stream_drop: Some(Trigger::Ordinal(1)),
            stream_duplicate: Some(Trigger::Ordinal(1)),
            stream_poison: Some(Trigger::Ordinal(1)),
            stream_transient: Some(Trigger::Ordinal(1)),
            ack_transient: Some(Trigger::Ordinal(1)),
        },
        None,
    );
    let placement = StreamPlacement::new("DURABLE-sfo3-cell-a", 8);
    let request = CaptureRequest {
        receiver_identity: "r".to_string(),
        membership_generation: 1,
        placement: placement.clone(),
        placement_revision: 1,
        resume_from: None,
    };
    let captured = decorated
        .capture(&request)
        .await
        .expect("capture is never perturbed, even with every anchor armed at ordinal 1");
    assert_eq!(captured.start_sequence, 900);
    assert_eq!(inner.captures(), vec![("r".to_string(), 1)]);
}

#[tokio::test]
async fn stream_drop_swallows_exactly_the_nth_delivery_and_is_spent_after() {
    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    inner.push_envelope(2, durable(1, 11));
    inner.push_envelope(3, durable(1, 12));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner.clone()),
        FaultConfig {
            stream_drop: Some(Trigger::Ordinal(2)),
            ..Default::default()
        },
        None,
    );

    assert!(
        matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
        "the 1st delivery is untouched"
    );
    assert_eq!(
        decorated.next().await,
        Ok(StreamDelivery::CaughtUp),
        "the 2nd delivery is swallowed and reported as CaughtUp"
    );
    assert!(
        matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
        "the fault is one-shot; the 3rd delivery is untouched"
    );
    assert_eq!(decorated.deliveries_seen(), 3);
    assert!(
        inner.acked().is_empty(),
        "the decorator never acks on the caller's behalf"
    );
}

#[tokio::test]
async fn stream_duplicate_replays_the_nth_delivery_once_without_advancing_the_counter() {
    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    inner.push_envelope(2, durable(1, 11));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner.clone()),
        FaultConfig {
            stream_duplicate: Some(Trigger::Ordinal(1)),
            ..Default::default()
        },
        None,
    );

    let Ok(StreamDelivery::Message(first)) = decorated.next().await else {
        panic!("expected the 1st delivery");
    };
    let Ok(StreamDelivery::Message(replay)) = decorated.next().await else {
        panic!("expected the replay");
    };
    assert_eq!(
        first, replay,
        "the replay must be byte-identical to the original"
    );
    let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
        panic!("expected the real 2nd delivery");
    };
    assert_eq!(second.broker_sequence, 2);
    assert_eq!(
        decorated.deliveries_seen(),
        2,
        "the replay must not advance the delivery counter -- only 2 real deliveries occurred"
    );
}

#[tokio::test]
async fn stream_poison_corrupts_exactly_the_nth_delivery() {
    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_poison: Some(Trigger::Ordinal(1)),
            ..Default::default()
        },
        None,
    );

    let Ok(StreamDelivery::Message(delivered)) = decorated.next().await else {
        panic!("expected a message");
    };
    let Some(wire::private_envelope_v1::Body::DurableInvalidation(body)) =
        delivered.envelope.body.as_ref()
    else {
        panic!("expected a durable invalidation body");
    };
    assert_eq!(
        body.payload_version,
        u32::MAX,
        "the injected corruption pushes payload_version out of every cell's configured range"
    );
}

#[tokio::test]
async fn stream_transient_fails_exactly_the_nth_next_call_and_is_spent_after() {
    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    inner.push_envelope(2, durable(1, 11));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_transient: Some(Trigger::Ordinal(1)),
            ..Default::default()
        },
        None,
    );

    assert!(matches!(
        decorated.next().await,
        Err(StreamError::Transient(_))
    ));
    assert!(
        matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
        "the fault is spent; the next call reads cleanly"
    );
    assert!(matches!(
        decorated.next().await,
        Ok(StreamDelivery::Message(_))
    ));
}

/// An inner source that answers `CaughtUp` once per permit and blocks
/// otherwise, like an idle gateway stream.
#[derive(Debug)]
struct GatedStream {
    inner: FakeDurableStream,
    permits: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl DurableStreamSource for GatedStream {
    async fn capture(
        &self,
        request: &CaptureRequest,
    ) -> Result<CapturedStreamPosition, StreamError> {
        self.inner.capture(request).await
    }

    async fn next(&self) -> Result<StreamDelivery, StreamError> {
        self.permits
            .acquire()
            .await
            .expect("the test never closes the semaphore")
            .forget();
        Ok(StreamDelivery::CaughtUp)
    }

    async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError> {
        self.inner.ack(broker_sequence).await
    }
}

/// The receiver drops a read blocked on an idle stream when shutdown or a
/// checkpoint deadline wins. How often that happens depends on timing, so a
/// dropped read must not take a `receiver.stream.transient` ordinal.
#[tokio::test]
async fn stream_transient_does_not_count_a_dropped_next_call() {
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(GatedStream {
            inner: fake(1),
            permits: permits.clone(),
        }),
        FaultConfig {
            stream_transient: Some(Trigger::Ordinal(3)),
            ..Default::default()
        },
        None,
    );

    // Call 1 completes.
    assert!(matches!(
        decorated.next().await,
        Ok(StreamDelivery::CaughtUp)
    ));
    // A blocked read is dropped, as the receiver's select drops it.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), decorated.next())
            .await
            .is_err(),
        "with no permit the read blocks"
    );
    // Call 2 completes: the dropped read took no ordinal.
    permits.add_permits(1);
    assert!(
        matches!(decorated.next().await, Ok(StreamDelivery::CaughtUp)),
        "a dropped read must not move the transient anchor one call earlier"
    );
    // Call 3 is the armed one.
    assert!(matches!(
        decorated.next().await,
        Err(StreamError::Transient(_))
    ));
}

#[tokio::test]
async fn ack_transient_fails_exactly_the_nth_ack_call_and_is_spent_after() {
    let inner = fake(1);
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            ack_transient: Some(Trigger::Ordinal(1)),
            ..Default::default()
        },
        None,
    );

    assert!(matches!(
        decorated.ack(900).await,
        Err(StreamError::Transient(_))
    ));
    assert!(
        decorated.ack(901).await.is_ok(),
        "the fault is spent after its one call"
    );
}

/// One-shot is enforced centrally so that recreating the arm file after
/// a firing does not re-arm an already-spent anchor.
#[tokio::test]
async fn an_armed_trigger_fires_once_even_if_the_arm_file_is_recreated() {
    let dir = tempfile::tempdir().expect("a temp rendezvous directory");
    let arm = dir
        .path()
        .join(format!("{}{}", Anchor::StreamDrop.name(), ARM_SUFFIX));
    let fired = dir
        .path()
        .join(format!("{}{}", Anchor::StreamDrop.name(), FIRED_SUFFIX));

    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    inner.push_envelope(2, durable(1, 11));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_drop: Some(Trigger::Armed),
            ..Default::default()
        },
        Some(dir.path().to_path_buf()),
    );

    std::fs::write(&arm, b"arm").expect("arm the anchor");
    assert_eq!(
        decorated.next().await,
        Ok(StreamDelivery::CaughtUp),
        "the armed drop fires on the first delivery it sees"
    );
    assert!(
        fired.exists(),
        "a firing must leave the .fired marker a live case waits on"
    );
    assert!(!arm.exists(), "the arm file must be consumed on firing");

    // Recreate the arm file. The anchor is already spent and must not
    // fire a second time no matter how many times it is re-armed.
    std::fs::write(&arm, b"arm").expect("re-arm the anchor");
    assert!(
        matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
        "the anchor is spent; recreating the arm file must not fire it again"
    );
}

/// WP-119 case O's own live lesson, pinned: an armed trigger fires on
/// whatever delivery is next, not on some "intended" one a harness
/// assumed. Two deliveries are already queued -- both already "in
/// flight" -- before the anchor is armed, and the fault lands on the
/// first, never the second.
#[tokio::test]
async fn an_armed_trigger_fires_on_whatever_delivery_is_next_not_the_intended_one() {
    let dir = tempfile::tempdir().expect("a temp rendezvous directory");
    let inner = fake(900);
    inner.push_envelope(900, bare_envelope());
    inner.push_envelope(901, bare_envelope());
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_drop: Some(Trigger::Armed),
            ..Default::default()
        },
        Some(dir.path().to_path_buf()),
    );
    std::fs::write(
        dir.path()
            .join(format!("{}{}", Anchor::StreamDrop.name(), ARM_SUFFIX)),
        b"arm",
    )
    .expect("arm the anchor");

    assert_eq!(
        decorated.next().await,
        Ok(StreamDelivery::CaughtUp),
        "the armed drop fires on the FIRST delivery it sees, broker sequence 900 -- a \
         harness cannot assume it lands on some later, 'intended' delivery"
    );
    let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
        panic!("expected the second, untouched delivery");
    };
    assert_eq!(
        second.broker_sequence, 901,
        "the anchor is already spent; the second delivery proves the fault landed on the \
         first, not on this one"
    );
}

/// The module doc's own "An armed anchor fires on TRAFFIC, not on
/// wall-clock time" section, pinned: this decorator has no background
/// task and no timer, so `fires()` can only ever run synchronously
/// inside a `next()`/`ack()` call. Real time passing with nothing
/// calling either must leave the anchor unfired; only an actual call
/// fires it. A future change that added polling to "help" a live
/// harness would break the documented arm-then-produce-traffic contract,
/// and this is the test that would catch it.
#[tokio::test]
async fn an_armed_trigger_never_fires_on_wall_clock_time_only_on_a_next_or_ack_call() {
    let dir = tempfile::tempdir().expect("a temp rendezvous directory");
    let fired = dir.path().join(format!(
        "{}{}",
        Anchor::StreamTransient.name(),
        FIRED_SUFFIX
    ));
    let inner = fake(1);
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_transient: Some(Trigger::Armed),
            ..Default::default()
        },
        Some(dir.path().to_path_buf()),
    );
    std::fs::write(
        dir.path()
            .join(format!("{}{}", Anchor::StreamTransient.name(), ARM_SUFFIX)),
        b"arm",
    )
    .expect("arm the anchor");

    // Real time passes with nothing calling next() or ack().
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !fired.exists(),
        "an armed anchor must never fire on wall-clock time alone; nothing has called \
         next() or ack() yet, so fires() has never run"
    );

    // Traffic arrives: the anchor fires on THIS call, not before it.
    assert!(matches!(
        decorated.next().await,
        Err(StreamError::Transient(_))
    ));
    assert!(
        fired.exists(),
        "the anchor fires once traffic (an actual next() call) arrives"
    );
}

/// Reviewer defect 1, pinned: `poison` must not report a firing that
/// perturbed nothing. A non-`DurableInvalidation` delivery at the armed
/// ordinal must leave the envelope byte-identical, the anchor UNSPENT
/// (no `.fired`, arm file untouched), and the next ELIGIBLE delivery
/// must still be poisoned. `Trigger::Armed` is required here rather than
/// `Trigger::Ordinal`: an ordinal trigger only ever equals the delivery
/// counter once, so if it were declined on that one delivery it could
/// never become due again -- exactly the scenario `is_due`/`commit`'s
/// two-phase split exists to keep armed through.
#[tokio::test]
async fn poison_declines_a_non_durable_invalidation_delivery_and_stays_armed_for_the_next_one() {
    let dir = tempfile::tempdir().expect("a temp rendezvous directory");
    let arm = dir
        .path()
        .join(format!("{}{}", Anchor::StreamPoison.name(), ARM_SUFFIX));
    let fired = dir
        .path()
        .join(format!("{}{}", Anchor::StreamPoison.name(), FIRED_SUFFIX));

    let inner = fake(1);
    inner.push_envelope(1, bare_envelope()); // not a DurableInvalidation
    inner.push_envelope(2, durable(1, 10)); // a real one
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_poison: Some(Trigger::Armed),
            ..Default::default()
        },
        Some(dir.path().to_path_buf()),
    );
    std::fs::write(&arm, b"arm").expect("arm the anchor");

    let Ok(StreamDelivery::Message(first)) = decorated.next().await else {
        panic!("expected the 1st delivery");
    };
    assert!(
        first.envelope.body.is_none(),
        "a declined firing must leave a non-DurableInvalidation body unchanged"
    );
    assert!(
        !fired.exists(),
        "a declined firing must not write the .fired marker -- nothing was perturbed"
    );
    assert!(
        arm.exists(),
        "a declined firing must leave the anchor armed, not consume the arm file"
    );

    let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
        panic!("expected the 2nd delivery");
    };
    let Some(wire::private_envelope_v1::Body::DurableInvalidation(body)) =
        second.envelope.body.as_ref()
    else {
        panic!("expected a durable invalidation body");
    };
    assert_eq!(
        body.payload_version,
        u32::MAX,
        "the next ELIGIBLE delivery must still be poisoned; the anchor was never spent"
    );
    assert!(
        fired.exists(),
        "this firing DID perturb something and must write .fired"
    );
}

/// Reviewer defect 2, pinned: a stashed duplicate replay belongs to the
/// generation that saw it. `capture()` ends a generation, so it must
/// discard any pending replay rather than letting it leak into the next
/// generation's first delivery carrying a broker sequence the new
/// capture never covered -- a fault the real stream cannot produce.
#[tokio::test]
async fn capture_discards_a_pending_duplicate_so_it_never_leaks_into_the_next_generation() {
    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    inner.push_envelope(2, durable(1, 11));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_duplicate: Some(Trigger::Ordinal(1)),
            ..Default::default()
        },
        None,
    );

    // Delivery 1 fires the duplicate anchor and stashes a replay of
    // broker sequence 1.
    let Ok(StreamDelivery::Message(first)) = decorated.next().await else {
        panic!("expected the 1st delivery");
    };
    assert_eq!(first.broker_sequence, 1);

    // A recapture ends this generation. It must discard the stashed
    // replay rather than serving it to the next one.
    let request = CaptureRequest {
        receiver_identity: "r".to_string(),
        membership_generation: 2,
        placement: StreamPlacement::new("DURABLE-sfo3-cell-a", 8),
        placement_revision: 1,
        resume_from: None,
    };
    decorated
        .capture(&request)
        .await
        .expect("capture passes through");

    // The next delivery must be the inner source's own next one, never
    // the discarded replay of broker sequence 1 from the prior
    // generation.
    let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
        panic!("expected the inner source's real 2nd delivery");
    };
    assert_eq!(
        second.broker_sequence, 2,
        "the stashed replay must be discarded on capture, not served as this generation's \
         first delivery"
    );
}

/// Reviewer defect 4, pinned at the parser: `drop` and a message-counted
/// anchor armed at the SAME ordinal is a warning, not a refusal -- both
/// stay in the parsed config, because the two anchors are independently
/// useful at different ordinals and a `next` trigger has no ordinal to
/// compare in the first place.
#[test]
fn warn_about_shadowing_does_not_drop_either_anchor_from_the_config() {
    let config = FaultConfig::parse("receiver.stream.drop=3,receiver.stream.poison=3");
    assert_eq!(config.stream_drop, Some(Trigger::Ordinal(3)));
    assert_eq!(
        config.stream_poison,
        Some(Trigger::Ordinal(3)),
        "shadowing is a warning, not a refusal -- both anchors stay armed at their \
         configured ordinal even though poison can never reach delivery 3"
    );

    let config = FaultConfig::parse("receiver.stream.drop=5,receiver.stream.duplicate=5");
    assert_eq!(config.stream_drop, Some(Trigger::Ordinal(5)));
    assert_eq!(config.stream_duplicate, Some(Trigger::Ordinal(5)));
}

/// The other half of reviewer defect 4: `drop` actually does shadow
/// `poison` at the decorator, not just in the warning. `drop` returns
/// before `poison`'s `is_due` is ever consulted, so poison's `.fired`
/// marker must never appear.
#[tokio::test]
async fn drop_shadows_poison_at_the_same_ordinal_and_poison_never_fires() {
    let dir = tempfile::tempdir().expect("a temp rendezvous directory");
    let poison_fired = dir
        .path()
        .join(format!("{}{}", Anchor::StreamPoison.name(), FIRED_SUFFIX));

    let inner = fake(1);
    inner.push_envelope(1, durable(1, 10));
    let decorated = FaultyDurableStream::with_dir(
        Arc::new(inner),
        FaultConfig {
            stream_drop: Some(Trigger::Ordinal(1)),
            stream_poison: Some(Trigger::Ordinal(1)),
            ..Default::default()
        },
        Some(dir.path().to_path_buf()),
    );

    assert_eq!(
        decorated.next().await,
        Ok(StreamDelivery::CaughtUp),
        "drop fires first and swallows the delivery"
    );
    assert!(
        !poison_fired.exists(),
        "poison is shadowed at the same ordinal and must never reach its own firing decision"
    );
}

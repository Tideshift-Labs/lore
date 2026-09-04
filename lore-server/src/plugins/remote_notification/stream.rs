// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The durable stream seam the receiver consumes, and its in-process fake.
//!
//! # BLOCKED(WP-111): the receiver-side gateway RPC is not pinned
//!
//! ```text
//! // BLOCKED(WP-111): /lorehub.notification.internal.v1.PrivateNotificationService
//! //                  has exactly one pinned method, `Publish`. No receiver-side
//! //                  subscribe/consume/acknowledge RPC exists in the frozen
//! //                  schema artifact
//! //                  (lorehub/apps/notification-gateway/proto/lorehub_notification_internal_v1.proto),
//! //                  and the notification-plane contract does not name one:
//! //                  WP-110 Phases 6-8 own "public `Subscribe`, bounded replay,
//! //                  durable receiver" and have not landed.
//! ```
//!
//! So the durable receiver is written against [`DurableStreamSource`] rather
//! than against a generated client. That is not a stub: the trait carries the
//! exact three operations the contract's receiver lifecycle needs — capture a
//! position, deliver in sequence order, acknowledge one sequence — so the
//! lifecycle, the frontier algebra, the checkpoint cadence, and every outcome
//! class are real and executable today. When WP-110 pins the RPC, one more
//! implementation of this trait lands beside [`FakeDurableStream`] and nothing
//! in [`super::receiver`] changes.
//!
//! # Why `capture` is a separate operation from `next`
//!
//! The contract's bootstrap is ordered: a receiver captures its durable
//! consumer at ONE stream identity, epoch, and start position **before** it
//! reads its authoritative baseline, and drains from that captured position
//! afterwards. A source that only exposed "give me the next message" could not
//! express that ordering — the position would be whatever the broker happened
//! to be at when the first read arrived, which is exactly the "newly sampled
//! live edge" the contract forbids as a readiness proof.
//!
//! # Why `CaughtUp` is a delivery rather than an error
//!
//! The same call drives two phases. During the bootstrap drain, `CaughtUp` is
//! the terminating condition: every event from the captured position has been
//! seen, so the frontier is now reportable. In steady state it means "nothing
//! pending", and the receiver idles for a bounded interval. Making it a
//! variant rather than an `Option` keeps the two readings in one closed match
//! at the call site.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use super::wire;

/// One stream's authoritative identity, as the contract keys it.
///
/// Identity and epoch travel together everywhere: a frontier from a prior
/// epoch says nothing about the current one, so no API here accepts one
/// without the other.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StreamPlacement {
    /// The broker's stream identity, e.g. `DURABLE-sfo3-cell-a`.
    pub stream_identity: String,
    /// The stream epoch. Always `>= 1`; zero is the absent value.
    pub stream_epoch: i64,
}

impl StreamPlacement {
    /// Convenience constructor for a placement with a borrowed identity.
    pub fn new(stream_identity: impl Into<String>, stream_epoch: i64) -> Self {
        Self {
            stream_identity: stream_identity.into(),
            stream_epoch,
        }
    }
}

/// The position one receiver generation captured, before its baseline.
///
/// This is the value the readiness compare-and-set is checked against. It is
/// captured once per generation and never resampled: a generation that finds
/// the authoritative placement has moved is retired, not re-pointed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedStreamPosition {
    /// The identity and epoch this generation is bound to.
    pub placement: StreamPlacement,
    /// The first broker sequence this generation is responsible for.
    pub start_sequence: i64,
}

/// One envelope delivered from the durable stream.
#[derive(Clone, Debug, PartialEq)]
pub struct DeliveredEnvelope {
    /// The sequence assigned within `(stream_identity, stream_epoch)`.
    pub broker_sequence: i64,
    /// The placement the broker served this message from. Compared against the
    /// captured placement on every message, so a silent epoch change cannot be
    /// applied as if it were ordinary traffic.
    pub placement: StreamPlacement,
    /// The raw wire envelope. Validated by the receiver, never by the source:
    /// a source that pre-validated would hide the poison path this component
    /// has to implement.
    pub envelope: wire::PrivateEnvelopeV1,
}

/// The result of one read from the durable stream.
#[derive(Clone, Debug, PartialEq)]
pub enum StreamDelivery {
    /// One message, in sequence order.
    Message(Box<DeliveredEnvelope>),
    /// Nothing pending at or before the current edge.
    CaughtUp,
}

/// Why a durable-stream operation did not produce a delivery.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum StreamError {
    /// The broker or the gateway is temporarily unreachable. The receiver
    /// backs off, leaves everything unacknowledged, and fails its lag
    /// readiness facet. It never acknowledges to clear a transient failure.
    #[error("durable stream is temporarily unavailable: {0}")]
    Transient(String),

    /// The authoritative placement is no longer the captured one. The
    /// generation is retired and a new one bootstraps from a fresh capture.
    /// It never resumes an impossible old epoch.
    #[error(
        "durable stream placement moved to {}@{}",
        current.stream_identity,
        current.stream_epoch
    )]
    PlacementMoved {
        /// The placement the broker reports as current.
        current: StreamPlacement,
    },

    /// The stream refused this receiver outright — an unknown consumer, a
    /// revoked credential, or a rejected capture. Not retried inside one
    /// bootstrap attempt; the generation is retired and re-created.
    #[error("durable stream refused this receiver: {0}")]
    Refused(String),
}

/// The durable `DURABLE_INVALIDATION` stream, as this component consumes it.
///
/// Three operations, matching the contract's three receiver responsibilities.
/// Deliberately not `Clone`: the receiver holds one `Arc<dyn>` for the life of
/// the process and every generation shares it, because the consumer's
/// *position* is generation state and lives in [`CapturedStreamPosition`], not
/// in the source.
#[async_trait]
pub trait DurableStreamSource: Send + Sync + std::fmt::Debug {
    /// Create or attach this receiver generation's durable consumer, and
    /// return the identity, epoch, and start position it is pinned to.
    ///
    /// # The precondition every implementation owes
    ///
    /// `start_sequence` must be the durable consumer's **first unacknowledged**
    /// sequence, not the stream's live tail. The receiver's whole frontier
    /// guarantee rests on it: it starts its frontier at `start_sequence - 1`
    /// and reports that as proved, so a capture that returned the live edge
    /// would have this receiver claim every sequence below the edge as
    /// consumed, and WP-119's reaper would delete rows nobody read. It is also
    /// the contract's own rule — a newly sampled live edge can never mark a
    /// receiver caught up.
    ///
    /// A capture is taken **once** per generation. An implementation must not
    /// move the position afterwards: the recorded capture is what the
    /// readiness compare-and-set is checked against.
    ///
    /// # Errors
    /// [`StreamError`] on an unreachable broker or a refused capture.
    async fn capture(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<CapturedStreamPosition, StreamError>;

    /// Read the next message at or after the captured position.
    ///
    /// # Errors
    /// [`StreamError`] on an unreachable broker or a moved placement.
    async fn next(&self) -> Result<StreamDelivery, StreamError>;

    /// Acknowledge one broker sequence.
    ///
    /// # Errors
    /// [`StreamError`] on an unreachable broker or a moved placement.
    async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError>;
}

// ---------------------------------------------------------------------------
// The in-process fake
// ---------------------------------------------------------------------------

/// One scripted step of a [`FakeDurableStream`].
#[derive(Clone, Debug)]
enum Step {
    Deliver(Box<DeliveredEnvelope>),
    Fail(StreamError),
    CaughtUp,
}

#[derive(Debug, Default)]
struct FakeState {
    steps: VecDeque<Step>,
    acked: Vec<i64>,
    captures: Vec<(String, i64)>,
    capture_error: Option<StreamError>,
    ack_error: Option<StreamError>,
}

/// A deterministic, in-process durable stream.
///
/// It is public rather than `#[cfg(test)]` for the reason
/// [`super::fake_gateway::FakeGateway`] is: the integration suites under
/// `lore-server/tests/` are a separate crate and cannot see a test-only type.
///
/// Every read pops one scripted step; an exhausted script reports
/// [`StreamDelivery::CaughtUp`] forever, which is what a real idle stream
/// does.
#[derive(Clone, Debug)]
pub struct FakeDurableStream {
    placement: Arc<Mutex<StreamPlacement>>,
    start_sequence: i64,
    state: Arc<Mutex<FakeState>>,
}

impl FakeDurableStream {
    /// A stream that captures at `placement` and `start_sequence`, with an
    /// empty script.
    pub fn at(placement: StreamPlacement, start_sequence: i64) -> Self {
        Self {
            placement: Arc::new(Mutex::new(placement)),
            start_sequence,
            state: Arc::new(Mutex::new(FakeState::default())),
        }
    }

    /// Queue one envelope at `broker_sequence`, at the stream's current
    /// placement.
    pub fn push_envelope(&self, broker_sequence: i64, envelope: wire::PrivateEnvelopeV1) -> &Self {
        let placement = self.placement();
        self.push_step(Step::Deliver(Box::new(DeliveredEnvelope {
            broker_sequence,
            placement,
            envelope,
        })));
        self
    }

    /// Queue one envelope at an explicit placement, so a test can deliver a
    /// message from an epoch the receiver did not capture.
    pub fn push_envelope_at(
        &self,
        broker_sequence: i64,
        placement: StreamPlacement,
        envelope: wire::PrivateEnvelopeV1,
    ) -> &Self {
        self.push_step(Step::Deliver(Box::new(DeliveredEnvelope {
            broker_sequence,
            placement,
            envelope,
        })));
        self
    }

    /// Queue one failed read.
    pub fn push_error(&self, error: StreamError) -> &Self {
        self.push_step(Step::Fail(error));
        self
    }

    /// Queue one explicit caught-up answer, so a test can end a drain in the
    /// middle of a longer script.
    pub fn push_caught_up(&self) -> &Self {
        self.push_step(Step::CaughtUp);
        self
    }

    /// Make the next [`DurableStreamSource::capture`] fail.
    pub fn fail_next_capture_with(&self, error: StreamError) -> &Self {
        self.lock().capture_error = Some(error);
        self
    }

    /// Make every [`DurableStreamSource::ack`] fail until cleared.
    pub fn fail_acks_with(&self, error: Option<StreamError>) -> &Self {
        self.lock().ack_error = error;
        self
    }

    /// Move the authoritative placement, as a broker reset would.
    pub fn set_placement(&self, placement: StreamPlacement) -> &Self {
        match self.placement.lock() {
            Ok(mut guard) => *guard = placement,
            Err(poisoned) => *poisoned.into_inner() = placement,
        }
        self
    }

    /// The placement this stream currently serves.
    pub fn placement(&self) -> StreamPlacement {
        match self.placement.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Every sequence acknowledged so far, in call order.
    pub fn acked(&self) -> Vec<i64> {
        self.lock().acked.clone()
    }

    /// Every `(receiver_identity, membership_generation)` capture, in order.
    pub fn captures(&self) -> Vec<(String, i64)> {
        self.lock().captures.clone()
    }

    /// Scripted steps not yet consumed.
    pub fn pending_steps(&self) -> usize {
        self.lock().steps.len()
    }

    fn push_step(&self, step: Step) {
        self.lock().steps.push_back(step);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[async_trait]
impl DurableStreamSource for FakeDurableStream {
    async fn capture(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<CapturedStreamPosition, StreamError> {
        let placement = self.placement();
        let mut state = self.lock();
        state
            .captures
            .push((receiver_identity.to_string(), membership_generation));
        if let Some(error) = state.capture_error.take() {
            return Err(error);
        }
        Ok(CapturedStreamPosition {
            placement,
            start_sequence: self.start_sequence,
        })
    }

    async fn next(&self) -> Result<StreamDelivery, StreamError> {
        let step = self.lock().steps.pop_front();
        match step {
            Some(Step::Deliver(envelope)) => Ok(StreamDelivery::Message(envelope)),
            Some(Step::Fail(error)) => Err(error),
            Some(Step::CaughtUp) | None => Ok(StreamDelivery::CaughtUp),
        }
    }

    async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError> {
        let mut state = self.lock();
        if let Some(error) = state.ack_error.clone() {
            return Err(error);
        }
        state.acked.push(broker_sequence);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> wire::PrivateEnvelopeV1 {
        wire::PrivateEnvelopeV1 {
            transport_version: wire::TRANSPORT_VERSION,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn an_exhausted_script_reports_caught_up_rather_than_failing() {
        let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
        assert_eq!(
            stream.next().await.expect("read succeeds"),
            StreamDelivery::CaughtUp
        );
    }

    #[tokio::test]
    async fn capture_records_the_generation_it_was_taken_for() {
        let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
        let captured = stream.capture("receiver-1", 4).await.expect("captures");
        assert_eq!(captured.start_sequence, 900);
        assert_eq!(captured.placement.stream_epoch, 8);
        assert_eq!(stream.captures(), vec![("receiver-1".to_string(), 4)]);
    }

    /// The script is a queue, so a delivery followed by a failure arrives in
    /// that order. Tests depend on this to place a fault at an exact boundary.
    #[tokio::test]
    async fn scripted_steps_are_served_in_order() {
        let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
        stream.push_envelope(900, envelope());
        stream.push_error(StreamError::Transient("broker down".into()));
        assert!(matches!(
            stream.next().await,
            Ok(StreamDelivery::Message(_))
        ));
        assert!(matches!(
            stream.next().await,
            Err(StreamError::Transient(_))
        ));
        assert_eq!(stream.pending_steps(), 0);
    }

    #[tokio::test]
    async fn a_moved_placement_is_visible_to_the_next_capture() {
        let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
        stream.set_placement(StreamPlacement::new("DURABLE-a-r2", 1));
        let captured = stream.capture("receiver-1", 5).await.expect("captures");
        assert_eq!(captured.placement.stream_identity, "DURABLE-a-r2");
        assert_eq!(captured.placement.stream_epoch, 1);
    }

    #[tokio::test]
    async fn a_failing_ack_records_nothing() {
        let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
        stream.fail_acks_with(Some(StreamError::Transient("ack lost".into())));
        assert!(stream.ack(901).await.is_err());
        assert!(stream.acked().is_empty());
    }
}

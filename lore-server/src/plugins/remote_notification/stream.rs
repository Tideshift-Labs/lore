// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The durable stream seam the receiver consumes, and its in-process fake.
//!
//! Two implementations: [`GrpcDurableStream`], which speaks the `Consume` and
//! `Ack` methods contract amendment A-24 pinned, and [`FakeDurableStream`],
//! which scripts the same three operations in process. The trait exists
//! because the receiver's hard cases are lifecycle races, and a race is one
//! line to script and a live broker to provoke.
//!
//! # The status mapping here is NOT the publisher's
//!
//! [`super::client::classify_status`] treats `PERMISSION_DENIED` and
//! `UNAUTHENTICATED` as transient, because credential rotation is an explicit
//! step of the contract's reassignment procedure and a publisher that gave up
//! on a rotating credential would drop hints it could have delivered.
//!
//! A receiver must not inherit that. For a receiver those two mean this
//! process is not the `receiver` role for this cell, and retrying cannot make
//! it so. Worse, `FAILED_PRECONDITION` — the epoch mismatch, the stale
//! generation, the unknown consumer — reads as "wait and try again" to a
//! publisher's classifier and means "your generation is dead, retire it" here.
//! Reusing the publish classifier would spin a retired generation against a
//! placement that moved. Amendment A-26 records why the asymmetry does not
//! generalise; [`status_to_stream_error`] is where it lives.
//!
//! # Why `capture` carries the placement the receiver believes
//!
//! `ConsumeRequestV1` sends the stream identity, epoch, and placement revision
//! the receiver read from its membership state, in **both** start modes. That
//! turns a disagreement into `RECEIVER_EPOCH_MISMATCH_V1` at the capture,
//! rather than a silent capture at an epoch the readiness compare-and-set
//! would then fail against several steps later. It is the difference between
//! learning the placement moved before the baseline and learning it after the
//! drain.
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
    /// The placement revision the gateway validated the request against.
    ///
    /// Diagnostic on this side: Step C's `readiness_cas` fences on identity and
    /// epoch, not on this. It is carried so a mismatch between what the
    /// receiver read and what the gateway validated is visible in a log rather
    /// than silent.
    pub placement_revision: i64,
}

/// What a receiver asks for when it opens its durable consumer.
///
/// One struct rather than five arguments because `ConsumeRequestV1` is one
/// message and the fields are only meaningful together: the placement is what
/// the start mode is interpreted against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureRequest {
    /// The configured receiver identity.
    pub receiver_identity: String,
    /// The generation Step C allocated.
    pub membership_generation: i64,
    /// The placement this receiver read as authoritative from its membership
    /// state. A gateway that disagrees refuses the capture.
    pub placement: StreamPlacement,
    /// The placement record version the receiver read.
    pub placement_revision: i64,
    /// `None` captures a new durable consumer at the placement's current edge.
    /// `Some(sequence)` resumes a position a previous attempt already pinned,
    /// and the gateway echoes the triple verbatim or fails the stream.
    pub resume_from: Option<i64>,
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
    /// [`StreamError`] on an unreachable broker or a refused capture. A
    /// placement the gateway does not agree with is
    /// [`StreamError::PlacementMoved`], not a transient failure.
    async fn capture(
        &self,
        request: &CaptureRequest,
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
// The gRPC implementation (contract amendment A-24)
// ---------------------------------------------------------------------------

/// Map one gRPC status onto this seam's three classes.
///
/// **Not** [`super::client::classify_status`]. That one is the publisher's,
/// and it treats a refused credential as transient because credential rotation
/// is a step of the reassignment procedure. Here the same status means this
/// process is not the `receiver` role for this cell, which no retry fixes, and
/// `FAILED_PRECONDITION` means the generation is dead rather than that the
/// gateway is busy. Amendment A-26 records why the asymmetry does not
/// generalise.
pub fn status_to_stream_error(status: &tonic::Status, current: &StreamPlacement) -> StreamError {
    use tonic::Code;
    match status.code() {
        // The gateway or the broker is down, or the stream ended mid-flight.
        Code::Unavailable | Code::DeadlineExceeded | Code::ResourceExhausted | Code::Aborted => {
            StreamError::Transient(status.code().to_string())
        }
        // Every ReceiverErrorV1 that maps to FAILED_PRECONDITION is a dead
        // generation: a placement mismatch, an epoch mismatch, a stale
        // generation, or an unknown durable consumer. All four are resolved by
        // retiring and bootstrapping a new generation, never by waiting.
        Code::FailedPrecondition => StreamError::PlacementMoved {
            current: current.clone(),
        },
        // Not this receiver, or not a request this contract version accepts.
        _ => StreamError::Refused(status.code().to_string()),
    }
}

/// A `uint64` from the wire, narrowed to the `i64` every consumer stores it in.
///
/// A value above `i64::MAX` is a malformed message rather than a number to
/// wrap, because the whole receiver-side model — Step C's columns, the
/// frontier, the projection — is `i64`. Silently wrapping would turn an
/// enormous sequence into a small one and let a frontier appear to advance.
fn narrow(value: u64, field: &'static str) -> Result<i64, StreamError> {
    i64::try_from(value)
        .map_err(|_| StreamError::Refused(format!("{field} exceeds i64::MAX and is malformed")))
}

/// The durable stream over the gateway's pinned `Consume` and `Ack` methods.
///
/// One open `Consume` stream per generation, held across calls to
/// [`DurableStreamSource::next`], plus a unary `Ack` per acknowledgement. The
/// stream handle lives behind a mutex rather than in the receiver's session
/// because the trait takes `&self` throughout: the receiver owns the
/// generation's *position*, and this owns the transport carrying it.
#[derive(Debug)]
pub struct GrpcDurableStream {
    channel: tonic::transport::Channel,
    cell_id: String,
    /// The open stream, and the request identity it was opened with. Replaced
    /// by each `capture`, so a retired generation's stream cannot serve a
    /// successor.
    session: tokio::sync::Mutex<Option<ConsumeSession>>,
}

#[derive(Debug)]
struct ConsumeSession {
    streaming: tonic::codec::Streaming<wire::ConsumeEventV1>,
    receiver_identity: String,
    membership_generation: i64,
    placement: StreamPlacement,
}

impl GrpcDurableStream {
    /// Build a stream source over an existing lazy channel.
    ///
    /// Takes the channel rather than the configuration so it shares the one
    /// `PublishTransport` already built: the receiver and the publisher speak
    /// to the same gateway over the same mTLS identity, and two channels would
    /// mean two connection pools for one cell.
    pub fn new(channel: tonic::transport::Channel, cell_id: impl Into<String>) -> Self {
        Self {
            channel,
            cell_id: cell_id.into(),
            session: tokio::sync::Mutex::new(None),
        }
    }

    fn client(&self) -> wire::PrivateNotificationServiceClient<tonic::transport::Channel> {
        wire::PrivateNotificationServiceClient::new(self.channel.clone())
    }
}

#[async_trait]
impl DurableStreamSource for GrpcDurableStream {
    async fn capture(
        &self,
        request: &CaptureRequest,
    ) -> Result<CapturedStreamPosition, StreamError> {
        let start = match request.resume_from {
            Some(sequence) => {
                wire::consume_request_v1::Start::CapturedPosition(wire::CapturedPositionV1 {
                    start_sequence: u64::try_from(sequence).map_err(|_| {
                        StreamError::Refused("resume position is negative".to_string())
                    })?,
                })
            }
            None => wire::consume_request_v1::Start::CaptureNew(wire::CaptureNewV1 {}),
        };
        let wire_request = wire::ConsumeRequestV1 {
            transport_version: wire::TRANSPORT_VERSION,
            cell_id: self.cell_id.clone(),
            receiver_identity: request.receiver_identity.clone(),
            membership_generation: u64::try_from(request.membership_generation).map_err(|_| {
                StreamError::Refused("membership generation is negative".to_string())
            })?,
            stream_identity: request.placement.stream_identity.clone(),
            stream_epoch: u64::try_from(request.placement.stream_epoch)
                .map_err(|_| StreamError::Refused("stream epoch is negative".to_string()))?,
            placement_revision: u64::try_from(request.placement_revision)
                .map_err(|_| StreamError::Refused("placement revision is negative".to_string()))?,
            start: Some(start),
        };

        let mut streaming = self
            .client()
            .consume(tonic::Request::new(wire_request))
            .await
            .map_err(|status| status_to_stream_error(&status, &request.placement))?
            .into_inner();

        // The contract makes the FIRST message a capture, in both start modes.
        // Anything else means the gateway is not speaking this contract
        // version, and consuming it as a delivery would apply an event against
        // a position nothing pinned.
        let first = streaming
            .message()
            .await
            .map_err(|status| status_to_stream_error(&status, &request.placement))?
            .ok_or_else(|| {
                StreamError::Transient("the consume stream ended before its capture".to_string())
            })?;
        if first.transport_version != wire::TRANSPORT_VERSION {
            return Err(StreamError::Refused(format!(
                "gateway served transport version {}, not {}",
                first.transport_version,
                wire::TRANSPORT_VERSION
            )));
        }
        let Some(wire::consume_event_v1::Event::Capture(capture)) = first.event else {
            return Err(StreamError::Refused(
                "the first consume message was not a capture".to_string(),
            ));
        };

        let placement = StreamPlacement {
            stream_identity: capture.stream_identity.clone(),
            stream_epoch: narrow(capture.stream_epoch, "stream_epoch")?,
        };
        // The gateway echoes the requested triple or fails the stream, so a
        // disagreement here is a contract violation rather than a moved
        // placement. It is still resolved by retiring: a generation bound to a
        // placement its gateway does not serve can never pass its readiness
        // compare-and-set.
        if placement != request.placement {
            return Err(StreamError::PlacementMoved { current: placement });
        }
        if capture.durable_consumer_name.len() != wire::DURABLE_CONSUMER_NAME_LEN {
            return Err(StreamError::Refused(format!(
                "durable consumer name is {} characters, not {}",
                capture.durable_consumer_name.len(),
                wire::DURABLE_CONSUMER_NAME_LEN
            )));
        }
        let start_sequence = narrow(capture.start_sequence, "start_sequence")?;
        if let Some(requested) = request.resume_from
            && start_sequence != requested
        {
            return Err(StreamError::Refused(format!(
                "gateway echoed start sequence {start_sequence}, not the requested {requested}"
            )));
        }

        let captured = CapturedStreamPosition {
            placement: placement.clone(),
            start_sequence,
            placement_revision: narrow(capture.placement_revision, "placement_revision")?,
        };
        *self.session.lock().await = Some(ConsumeSession {
            streaming,
            receiver_identity: request.receiver_identity.clone(),
            membership_generation: request.membership_generation,
            placement,
        });
        Ok(captured)
    }

    async fn next(&self) -> Result<StreamDelivery, StreamError> {
        let mut guard = self.session.lock().await;
        let Some(session) = guard.as_mut() else {
            return Err(StreamError::Refused(
                "no consume stream is open; capture first".to_string(),
            ));
        };
        let placement = session.placement.clone();
        let message = session
            .streaming
            .message()
            .await
            .map_err(|status| status_to_stream_error(&status, &placement))?;
        let Some(event) = message else {
            // A clean end-of-stream is the gateway closing the consumer. The
            // generation is not necessarily dead, so this is transient and the
            // next bootstrap decides.
            *guard = None;
            return Err(StreamError::Transient(
                "the consume stream ended".to_string(),
            ));
        };
        if event.transport_version != wire::TRANSPORT_VERSION {
            return Err(StreamError::Refused(format!(
                "gateway served transport version {}, not {}",
                event.transport_version,
                wire::TRANSPORT_VERSION
            )));
        }
        match event.event {
            Some(wire::consume_event_v1::Event::Delivery(delivery)) => {
                let Some(envelope) = delivery.envelope else {
                    return Err(StreamError::Refused(
                        "a delivery carried no envelope".to_string(),
                    ));
                };
                Ok(StreamDelivery::Message(Box::new(DeliveredEnvelope {
                    broker_sequence: narrow(delivery.broker_sequence, "broker_sequence")?,
                    placement: StreamPlacement {
                        stream_identity: delivery.stream_identity,
                        stream_epoch: narrow(delivery.stream_epoch, "stream_epoch")?,
                    },
                    envelope,
                })))
            }
            Some(wire::consume_event_v1::Event::CaughtUp(_)) => Ok(StreamDelivery::CaughtUp),
            // A second capture mid-stream, or an unset oneof. Neither is
            // applicable and neither is a delivery to acknowledge.
            Some(wire::consume_event_v1::Event::Capture(_)) | None => Err(StreamError::Refused(
                "the consume stream sent a second capture or an empty event".to_string(),
            )),
        }
    }

    async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError> {
        let (receiver_identity, membership_generation, placement) = {
            let guard = self.session.lock().await;
            let Some(session) = guard.as_ref() else {
                return Err(StreamError::Refused(
                    "no consume stream is open; capture first".to_string(),
                ));
            };
            (
                session.receiver_identity.clone(),
                session.membership_generation,
                session.placement.clone(),
            )
        };

        let request = wire::AckV1 {
            transport_version: wire::TRANSPORT_VERSION,
            cell_id: self.cell_id.clone(),
            receiver_identity,
            membership_generation: u64::try_from(membership_generation).unwrap_or(0),
            stream_identity: placement.stream_identity.clone(),
            stream_epoch: u64::try_from(placement.stream_epoch).unwrap_or(0),
            // One sequence per call. A-24 allows up to
            // `wire::MAX_ACKED_SEQUENCES` per message, which would cut the
            // round trips on a catch-up drain considerably.
            //
            // TODO(WP-111): batch acknowledgements. It needs an `ack_batch` on
            // this trait and a matching change in the receiver's disposal loop,
            // which currently acknowledges inside the same step that applies —
            // and that ordering is what makes each outcome class provable, so
            // batching is a deliberate second pass rather than a tweak.
            acked_sequences: vec![u64::try_from(broker_sequence).map_err(|_| {
                StreamError::Refused("acknowledged sequence is negative".to_string())
            })?],
            // The frontier, gaps, and poison on this message are the gateway's
            // lag signal only. The authoritative checkpoint vector is the
            // Postgres projection the receiver writes itself, which is why this
            // message carries no membership version to compare-and-set against
            // and why reporting zero here cannot understate anything.
            contiguous_frontier: 0,
            gaps: Vec::new(),
            poison: Vec::new(),
        };

        let result = self
            .client()
            .ack(tonic::Request::new(request))
            .await
            .map_err(|status| status_to_stream_error(&status, &placement))?
            .into_inner();

        if result.transport_version != wire::TRANSPORT_VERSION {
            return Err(StreamError::Refused(format!(
                "gateway answered Ack at transport version {}, not {}",
                result.transport_version,
                wire::TRANSPORT_VERSION
            )));
        }
        match wire::AckOutcomeV1::try_from(result.outcome) {
            Ok(wire::AckOutcomeV1::AllAccepted) => Ok(()),
            // One sequence went out, so a partial result that did not accept it
            // is a rejection. Treating it as success would advance a frontier
            // over an unacknowledged sequence.
            Ok(wire::AckOutcomeV1::PartiallyAccepted) => {
                if result
                    .accepted_sequences
                    .contains(&u64::try_from(broker_sequence).unwrap_or(u64::MAX))
                {
                    Ok(())
                } else {
                    Err(StreamError::Transient(
                        "the acknowledgement was not accepted".to_string(),
                    ))
                }
            }
            Ok(wire::AckOutcomeV1::Retryable) => Err(StreamError::Transient(
                "the gateway asked for the acknowledgement to be retried".to_string(),
            )),
            Ok(wire::AckOutcomeV1::Terminal) => Err(StreamError::Refused(
                "the gateway refused the acknowledgement terminally".to_string(),
            )),
            // The zero value is never returned; its presence is itself a
            // malformed response, and a malformed response never proves an
            // acknowledgement.
            Ok(wire::AckOutcomeV1::Unspecified) | Err(_) => Err(StreamError::Refused(
                "the gateway answered Ack with no outcome".to_string(),
            )),
        }
    }
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
    /// Answer every capture with this position, whatever was asked for.
    forced_capture_start: Option<i64>,
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

    /// Answer every capture with `start_sequence`, ignoring what was asked
    /// for.
    ///
    /// Models a gateway that does NOT echo a requested resume position
    /// byte-exactly, which the contract forbids and
    /// [`GrpcDurableStream::capture`] refuses. The receiver checks the echo
    /// itself as well, because it is the component whose frontier a wrong
    /// answer would overstate, and that check needs a source that can give a
    /// wrong answer.
    pub fn force_capture_start(&self, start_sequence: i64) -> &Self {
        self.lock().forced_capture_start = Some(start_sequence);
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
        request: &CaptureRequest,
    ) -> Result<CapturedStreamPosition, StreamError> {
        let placement = self.placement();
        let mut state = self.lock();
        state.captures.push((
            request.receiver_identity.clone(),
            request.membership_generation,
        ));
        if let Some(error) = state.capture_error.take() {
            return Err(error);
        }
        // The real gateway refuses a capture whose placement disagrees with the
        // one it holds, so the fake does too. A fake that accepted any
        // placement would let the receiver's own epoch check go untested.
        if request.placement != placement {
            return Err(StreamError::PlacementMoved { current: placement });
        }
        let start_sequence = state
            .forced_capture_start
            .unwrap_or_else(|| request.resume_from.unwrap_or(self.start_sequence));
        Ok(CapturedStreamPosition {
            placement,
            placement_revision: request.placement_revision,
            start_sequence,
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

    fn capture_request(generation: i64, placement: StreamPlacement) -> CaptureRequest {
        CaptureRequest {
            receiver_identity: "receiver-1".to_string(),
            membership_generation: generation,
            placement,
            placement_revision: 1,
            resume_from: None,
        }
    }

    #[tokio::test]
    async fn capture_records_the_generation_it_was_taken_for() {
        let placement = StreamPlacement::new("DURABLE-a", 8);
        let stream = FakeDurableStream::at(placement.clone(), 900);
        let captured = stream
            .capture(&capture_request(4, placement))
            .await
            .expect("captures");
        assert_eq!(captured.start_sequence, 900);
        assert_eq!(captured.placement.stream_epoch, 8);
        assert_eq!(stream.captures(), vec![("receiver-1".to_string(), 4)]);
    }

    /// The request asserts the placement the receiver believes authoritative,
    /// so a gateway serving a different one refuses at the capture instead of
    /// pinning a position the readiness compare-and-set would reject later.
    #[tokio::test]
    async fn a_capture_asserting_the_wrong_placement_is_refused() {
        let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
        let outcome = stream
            .capture(&capture_request(4, StreamPlacement::new("DURABLE-a", 7)))
            .await;
        assert!(matches!(outcome, Err(StreamError::PlacementMoved { .. })));
    }

    #[tokio::test]
    async fn a_resume_position_overrides_the_streams_default_start() {
        let placement = StreamPlacement::new("DURABLE-a", 8);
        let stream = FakeDurableStream::at(placement.clone(), 900);
        let mut request = capture_request(4, placement);
        request.resume_from = Some(950);
        let captured = stream.capture(&request).await.expect("captures");
        assert_eq!(captured.start_sequence, 950);
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
        let moved = StreamPlacement::new("DURABLE-a-r2", 1);
        stream.set_placement(moved.clone());
        let captured = stream
            .capture(&capture_request(5, moved))
            .await
            .expect("captures");
        assert_eq!(captured.placement.stream_identity, "DURABLE-a-r2");
        assert_eq!(captured.placement.stream_epoch, 1);
    }

    /// The receiver-side status mapping is not the publisher's. Getting these
    /// backwards either spins a retired generation or throws away a live one.
    #[test]
    fn the_receiver_status_mapping_differs_from_the_publishers() {
        let current = StreamPlacement::new("DURABLE-a", 8);
        assert!(matches!(
            status_to_stream_error(&tonic::Status::unavailable("down"), &current),
            StreamError::Transient(_)
        ));
        assert!(matches!(
            status_to_stream_error(&tonic::Status::failed_precondition("epoch"), &current),
            StreamError::PlacementMoved { .. }
        ));
        // The publisher retries both of these; a receiver must not.
        assert!(matches!(
            status_to_stream_error(&tonic::Status::permission_denied("role"), &current),
            StreamError::Refused(_)
        ));
        assert!(matches!(
            status_to_stream_error(&tonic::Status::unauthenticated("mtls"), &current),
            StreamError::Refused(_)
        ));
        assert!(matches!(
            status_to_stream_error(&tonic::Status::invalid_argument("malformed"), &current),
            StreamError::Refused(_)
        ));
    }

    /// Every `uint64` on this surface is stored in an `i64`, so a value above
    /// `i64::MAX` is malformed rather than a number to wrap. Wrapping would
    /// turn an enormous sequence into a small one and let a frontier appear to
    /// advance.
    #[test]
    fn a_sequence_above_i64_max_is_malformed_rather_than_wrapped() {
        assert_eq!(narrow(900, "broker_sequence"), Ok(900));
        assert_eq!(narrow(i64::MAX as u64, "broker_sequence"), Ok(i64::MAX));
        assert!(matches!(
            narrow(u64::MAX, "broker_sequence"),
            Err(StreamError::Refused(_))
        ));
    }

    #[tokio::test]
    async fn a_failing_ack_records_nothing() {
        let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
        stream.fail_acks_with(Some(StreamError::Transient("ack lost".into())));
        assert!(stream.ack(901).await.is_err());
        assert!(stream.acked().is_empty());
    }
}

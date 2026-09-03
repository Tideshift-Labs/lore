// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! A request-counting, scriptable, in-process fake private gateway.
//!
//! It implements [`PublishTransport`], so a test drives the **real**
//! [`super::client::PrivateGatewayClient`] classification, the real bounded
//! sender, and the real envelope encoding. Only the socket is missing.
//!
//! What it can script, matching the answers the contract's `publish-result`
//! fixtures name:
//!
//! | Script | Models |
//! | --- | --- |
//! | [`ScriptedResponse::Accept`] | a versioned acceptance with stream identity, epoch, and sequence |
//! | [`ScriptedResponse::Result`] | any raw result, including an unversioned or incomplete ack |
//! | [`ScriptedResponse::Status`] | 429 (`RESOURCE_EXHAUSTED`), the 5xx equivalent (`UNAVAILABLE`), terminal `INVALID_ARGUMENT` / `PERMISSION_DENIED`, and `DEADLINE_EXCEEDED` |
//! | [`ScriptedResponse::Hang`] | a gateway that never answers, so the client's own deadline fires |
//!
//! This is compiled unconditionally rather than behind `#[cfg(test)]`, because
//! `lore-server` has no test-support feature and an integration test under
//! `tests/` cannot see a `#[cfg(test)]` item. It is small, server-only, and
//! reachable from no production path: nothing outside a test constructs one.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;

use super::client::PublishTransport;
use super::wire;

/// One scripted answer.
#[derive(Clone, Debug)]
pub enum ScriptedResponse {
    /// A complete, versioned acceptance. The broker sequence is assigned
    /// monotonically per gateway instance, starting at 1.
    Accept {
        stream_identity: String,
        stream_epoch: u64,
    },
    /// A raw result, so a test can send an unversioned ack
    /// (`transport_version = 0`), an `ACCEPTED` missing its evidence, a
    /// mismatched `event_id`, or an unknown outcome value.
    Result(Box<wire::PublishResultV1>),
    /// A gRPC status.
    Status(tonic::Code, String),
    /// Sleeps for the given duration and then accepts. Longer than the client's
    /// deadline, this models a gateway that never answers in time.
    Hang(Duration),
}

impl ScriptedResponse {
    /// The default acceptance: `DURABLE-fake`, epoch 1.
    pub fn accept() -> Self {
        Self::Accept {
            stream_identity: "DURABLE-fake".to_string(),
            stream_epoch: 1,
        }
    }

    /// gRPC `RESOURCE_EXHAUSTED`, the 429 equivalent.
    pub fn rate_limited() -> Self {
        Self::Status(tonic::Code::ResourceExhausted, "429".to_string())
    }

    /// gRPC `UNAVAILABLE`, the 5xx equivalent.
    pub fn unavailable() -> Self {
        Self::Status(tonic::Code::Unavailable, "broker unavailable".to_string())
    }

    /// gRPC `DEADLINE_EXCEEDED` reported by the gateway itself.
    pub fn deadline_exceeded() -> Self {
        Self::Status(tonic::Code::DeadlineExceeded, "deadline".to_string())
    }

    /// A terminal `INVALID_ARGUMENT`.
    pub fn invalid_argument() -> Self {
        Self::Status(tonic::Code::InvalidArgument, "invalid scope".to_string())
    }

    /// A terminal `PERMISSION_DENIED`.
    pub fn permission_denied() -> Self {
        Self::Status(
            tonic::Code::PermissionDenied,
            "identity not authorized for this cell".to_string(),
        )
    }

    /// An `ACCEPTED` result carrying no transport version, so nothing in it
    /// proves acceptance under the pinned contract.
    pub fn unversioned_ack() -> Self {
        Self::Result(Box::new(wire::PublishResultV1 {
            transport_version: 0,
            outcome: wire::PublishOutcomeV1::Accepted as i32,
            stream_identity: "DURABLE-fake".to_string(),
            stream_epoch: 1,
            broker_sequence: 1,
            publisher_contract_version: 1,
            ..Default::default()
        }))
    }

    /// An `ACCEPTED` result missing its acceptance evidence.
    pub fn incomplete_ack() -> Self {
        Self::Result(Box::new(wire::PublishResultV1 {
            transport_version: wire::TRANSPORT_VERSION,
            outcome: wire::PublishOutcomeV1::Accepted as i32,
            publisher_contract_version: 1,
            ..Default::default()
        }))
    }
}

#[derive(Debug, Default)]
struct GatewayState {
    /// Every envelope this gateway was asked to publish, in order.
    requests: Vec<wire::PrivateEnvelopeV1>,
    /// Remaining scripted answers, consumed front to back.
    script: std::collections::VecDeque<ScriptedResponse>,
    /// Used once the script is exhausted.
    fallback: Option<ScriptedResponse>,
}

/// The in-process fake gateway.
///
/// Cheap to clone: every clone observes the same request log and consumes the
/// same script.
#[derive(Clone, Debug, Default)]
pub struct FakeGateway {
    state: Arc<Mutex<GatewayState>>,
    next_sequence: Arc<AtomicU64>,
}

impl FakeGateway {
    /// A gateway that accepts everything, with a monotonic broker sequence.
    pub fn accepting() -> Self {
        let gateway = Self::default();
        gateway.state.lock().fallback = Some(ScriptedResponse::accept());
        gateway
    }

    /// A gateway that answers from `script` in order, then falls back to
    /// accepting.
    pub fn scripted(script: impl IntoIterator<Item = ScriptedResponse>) -> Self {
        let gateway = Self::accepting();
        gateway.state.lock().script.extend(script);
        gateway
    }

    /// A gateway that answers from `script` in order and then repeats
    /// `fallback` forever. Use this for "always fails" cases, where the client's
    /// bounded retry budget is what must end the publication.
    pub fn scripted_with_fallback(
        script: impl IntoIterator<Item = ScriptedResponse>,
        fallback: ScriptedResponse,
    ) -> Self {
        let gateway = Self::default();
        {
            let mut state = gateway.state.lock();
            state.script.extend(script);
            state.fallback = Some(fallback);
        }
        gateway
    }

    /// A gateway that always answers the same way.
    pub fn always(response: ScriptedResponse) -> Self {
        Self::scripted_with_fallback(std::iter::empty(), response)
    }

    /// How many Publish calls this gateway has received.
    pub fn request_count(&self) -> usize {
        self.state.lock().requests.len()
    }

    /// Every envelope received, in order.
    pub fn requests(&self) -> Vec<wire::PrivateEnvelopeV1> {
        self.state.lock().requests.clone()
    }

    /// The envelope received at `index`, if there is one.
    pub fn request(&self, index: usize) -> Option<wire::PrivateEnvelopeV1> {
        self.state.lock().requests.get(index).cloned()
    }

    /// The distinct `event_id` values this gateway saw, in first-seen order.
    ///
    /// The point of the helper: a bounded retry of one logical publication must
    /// produce several requests carrying **one** event id.
    pub fn distinct_event_ids(&self) -> Vec<Bytes> {
        let mut seen: Vec<Bytes> = Vec::new();
        for request in self.state.lock().requests.iter() {
            if !seen.contains(&request.event_id) {
                seen.push(request.event_id.clone());
            }
        }
        seen
    }

    /// Adds more scripted answers to the back of the queue.
    pub fn push_script(&self, script: impl IntoIterator<Item = ScriptedResponse>) {
        self.state.lock().script.extend(script);
    }

    /// Forgets the request log, keeping the script.
    pub fn reset_requests(&self) {
        self.state.lock().requests.clear();
    }

    fn take_response(&self, envelope: wire::PrivateEnvelopeV1) -> ScriptedResponse {
        let mut state = self.state.lock();
        state.requests.push(envelope);
        state
            .script
            .pop_front()
            .or_else(|| state.fallback.clone())
            .unwrap_or_else(ScriptedResponse::accept)
    }

    fn accepted(
        &self,
        event_id: Bytes,
        stream_identity: String,
        stream_epoch: u64,
    ) -> wire::PublishResultV1 {
        wire::PublishResultV1 {
            transport_version: wire::TRANSPORT_VERSION,
            outcome: wire::PublishOutcomeV1::Accepted as i32,
            event_id,
            stream_identity,
            stream_epoch,
            broker_sequence: self.next_sequence.fetch_add(1, Ordering::SeqCst) + 1,
            publisher_contract_version: wire::TRANSPORT_VERSION,
            broker_accepted_at: None,
            failure_class: 0,
        }
    }
}

#[async_trait]
impl PublishTransport for FakeGateway {
    async fn publish(
        &self,
        envelope: wire::PrivateEnvelopeV1,
    ) -> Result<wire::PublishResultV1, tonic::Status> {
        let event_id = envelope.event_id.clone();
        match self.take_response(envelope) {
            ScriptedResponse::Accept {
                stream_identity,
                stream_epoch,
            } => Ok(self.accepted(event_id, stream_identity, stream_epoch)),
            ScriptedResponse::Result(result) => {
                // A raw scripted result keeps whatever event_id it was given, so
                // a test can deliberately script a mismatch. An unset one is
                // filled with the request's, which is the realistic case.
                let mut result = *result;
                if result.event_id.is_empty() {
                    result.event_id = event_id;
                }
                Ok(result)
            }
            ScriptedResponse::Status(code, message) => Err(tonic::Status::new(code, message)),
            ScriptedResponse::Hang(duration) => {
                tokio::time::sleep(duration).await;
                Ok(self.accepted(event_id, "DURABLE-fake".to_string(), 1))
            }
        }
    }
}

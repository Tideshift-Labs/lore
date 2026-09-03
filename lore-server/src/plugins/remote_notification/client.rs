// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The private gateway client: one Publish attempt, and the classification of
//! what came back.
//!
//! This client **never retries**. A single call is one attempt with one
//! deadline, and the answer is classified into either a
//! [`BrokerAcceptance`] or a closed [`PublishFailure`]. Retry policy belongs to
//! the caller, and the two callers have different policies:
//!
//! - [`super::sender`] runs a bounded jittered retry budget for best-effort
//!   `LIVE_HINT`s and drops the hint when the budget is spent;
//! - CR-032's relay (WP-119) owns durable retry, because a durable intent is a
//!   committed Postgres row with a claim generation and a lease, and only the
//!   relay can decide whether this worker still owns it.
//!
//! ## The classification is the contract, not gRPC folklore
//!
//! Every `tonic::Code` is matched explicitly, with no wildcard arm, so a status
//! this contract has no rule for is a visible decision rather than a default. The
//! mapping follows the notification-plane contract and CR-032's disposition
//! table, not the usual "5xx means retry" reflex:
//!
//! - a stale placement epoch is a **retryable** `FAILED_PRECONDITION`, because
//!   the cell is mid-reassignment and CR-032 retains durable work through the
//!   cutover;
//! - an answer that does not *prove* broker acceptance is `NotAccepted`, which
//!   is neither retried here nor dead-lettered: the intent stays pending with
//!   its original stable keys, because the publish may still have landed.

use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use async_trait::async_trait;
use tonic::Code;

use super::config::MtlsConfig;
use super::config::RemoteNotificationConfig;
use super::envelope::DurableEnvelopeV1;
use super::envelope::EventId;
use super::envelope::HintEnvelopeV1;
use super::error::NotAcceptedReason;
use super::error::PublishFailure;
use super::error::RemoteNotificationError;
use super::error::TerminalClass;
use super::error::TransientClass;
use super::metrics;
use super::wire;

/// CR-032 caps a relay's publish deadline at 10 seconds. The client enforces it
/// rather than trusting a caller's argument, so a mis-set relay setting cannot
/// hold a claim lease open past its 30-second window.
pub const MAX_DURABLE_PUBLISH_DEADLINE: Duration = Duration::from_secs(10);

/// The versioned proof a successful Publish carries.
///
/// Every field here is required by the contract's `acceptance_evidence_fields`.
/// A response missing any of them is `NotAccepted`, never a partial acceptance:
/// CR-032 records `broker_accepted` **plus** stream identity, epoch, and
/// sequence as one unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerAcceptance {
    /// Echoed from the envelope, and checked equal to it before acceptance.
    pub event_id: EventId,
    /// The stream the message landed in.
    pub stream_identity: String,
    /// The stream epoch that identity was serving.
    pub stream_epoch: u64,
    /// The JetStream sequence assigned within `(stream_identity, stream_epoch)`.
    pub broker_sequence: u64,
    /// The pinned private contract version the gateway served.
    pub publisher_contract_version: u32,
    /// Diagnostic only. Never ordering authority.
    pub broker_accepted_at: Option<SystemTime>,
}

/// One Publish attempt over some transport.
///
/// The trait exists so the classification above can be driven by an in-process
/// [`super::fake_gateway::FakeGateway`] without a socket. The real
/// implementation is [`GrpcPublishTransport`]; nothing but the transport itself
/// differs between them, so a component test exercises the same classification
/// a production cell runs.
#[async_trait]
pub trait PublishTransport: Send + Sync + std::fmt::Debug {
    /// Sends one envelope and returns the gateway's answer verbatim.
    ///
    /// Implementations do not interpret, retry, or time out; the client owns
    /// all three.
    async fn publish(
        &self,
        envelope: wire::PrivateEnvelopeV1,
    ) -> Result<wire::PublishResultV1, tonic::Status>;
}

/// The production transport: a tonic client over an mTLS-authenticated channel.
#[derive(Debug, Clone)]
pub struct GrpcPublishTransport {
    channel: tonic::transport::Channel,
}

impl GrpcPublishTransport {
    /// Builds the channel from validated configuration.
    ///
    /// The channel is **lazy**: a gateway that is down at boot must not stop a
    /// cell from starting and serving storage, and the notification plane's own
    /// readiness is a separate facet. The first publish then fails as
    /// `UNAVAILABLE`, which classifies transient.
    ///
    /// # Errors
    /// Returns [`RemoteNotificationError::MtlsMaterialUnreadable`] naming the
    /// field whose file could not be read, or
    /// [`RemoteNotificationError::GatewayChannel`] when the endpoint or TLS
    /// configuration is rejected. Neither message carries key material.
    pub fn connect_lazy(
        config: &RemoteNotificationConfig,
    ) -> Result<Self, RemoteNotificationError> {
        let mut endpoint = tonic::transport::Endpoint::from_shared(config.gateway_uri.clone())
            .map_err(|e| RemoteNotificationError::GatewayChannel(e.to_string()))?;

        if let Some(mtls) = config.mtls.as_ref() {
            endpoint = endpoint
                .tls_config(Self::tls_config(mtls)?)
                .map_err(|e| RemoteNotificationError::GatewayChannel(e.to_string()))?;
        }

        Ok(Self {
            channel: endpoint.connect_lazy(),
        })
    }

    fn tls_config(
        mtls: &MtlsConfig,
    ) -> Result<tonic::transport::ClientTlsConfig, RemoteNotificationError> {
        let client_cert = std::fs::read(&mtls.client_cert_path).map_err(|_| {
            RemoteNotificationError::MtlsMaterialUnreadable {
                field: "client_cert_path",
            }
        })?;
        let client_key = std::fs::read(&mtls.client_key_path).map_err(|_| {
            RemoteNotificationError::MtlsMaterialUnreadable {
                field: "client_key_path",
            }
        })?;
        let trust_roots = std::fs::read(&mtls.trust_roots_path).map_err(|_| {
            RemoteNotificationError::MtlsMaterialUnreadable {
                field: "trust_roots_path",
            }
        })?;

        Ok(tonic::transport::ClientTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(
                client_cert,
                client_key,
            ))
            .ca_certificate(tonic::transport::Certificate::from_pem(trust_roots))
            .assume_http2(true))
    }
}

#[async_trait]
impl PublishTransport for GrpcPublishTransport {
    async fn publish(
        &self,
        envelope: wire::PrivateEnvelopeV1,
    ) -> Result<wire::PublishResultV1, tonic::Status> {
        let mut client = wire::PrivateNotificationServiceClient::new(self.channel.clone());
        client
            .publish(tonic::Request::new(envelope))
            .await
            .map(tonic::Response::into_inner)
    }
}

/// The private gateway client.
#[derive(Clone, Debug)]
pub struct PrivateGatewayClient {
    transport: Arc<dyn PublishTransport>,
    supported_payload_versions: std::ops::RangeInclusive<u32>,
    request_timeout: Duration,
}

impl PrivateGatewayClient {
    /// Builds the production client from validated configuration.
    ///
    /// # Errors
    /// Propagates channel or mTLS-material faults from
    /// [`GrpcPublishTransport::connect_lazy`].
    pub fn connect(config: &RemoteNotificationConfig) -> Result<Self, RemoteNotificationError> {
        let transport = GrpcPublishTransport::connect_lazy(config)?;
        Ok(Self::with_transport(config, Arc::new(transport)))
    }

    /// Builds a client over a supplied transport. This is how a component test
    /// drives the real classification against
    /// [`super::fake_gateway::FakeGateway`].
    pub fn with_transport(
        config: &RemoteNotificationConfig,
        transport: Arc<dyn PublishTransport>,
    ) -> Self {
        Self {
            transport,
            supported_payload_versions: config.contract.durable_payload_version_min
                ..=config.contract.durable_payload_version_max,
            request_timeout: config.request_timeout,
        }
    }

    /// Publishes one best-effort hint. **One attempt.** The caller owns retry.
    ///
    /// # Errors
    /// Returns the classified [`PublishFailure`]. A hint that violates a
    /// contract bound never leaves this process and returns
    /// [`TerminalClass::LocallyRejected`].
    pub async fn publish_hint(
        &self,
        hint: &HintEnvelopeV1,
    ) -> Result<BrokerAcceptance, PublishFailure> {
        let delivery_class = if hint.shadow {
            metrics::CLASS_SHADOW
        } else {
            metrics::CLASS_LIVE_HINT
        };
        let envelope = match hint.encode() {
            Ok(envelope) => envelope,
            Err(violation) => {
                tracing::warn!(
                    violation = violation.as_metric_label(),
                    repository = %hex::encode(hint.common.repository.data()),
                    event_id = %hint.common.event_id.to_hyphenated(),
                    "remote notification hint rejected by its own bounds check; not published"
                );
                let failure = PublishFailure::Terminal(TerminalClass::LocallyRejected);
                metrics::record_publish_result(
                    delivery_class,
                    failure.family_label(),
                    failure.class_label(),
                );
                return Err(failure);
            }
        };
        self.attempt(
            delivery_class,
            hint.common.event_id,
            envelope,
            self.request_timeout,
        )
        .await
    }

    /// Publishes one `DURABLE_INVALIDATION` from a committed CR-032 outbox row.
    ///
    /// **One attempt, and no retry ever happens here.** The relay owns retry
    /// because only the relay knows whether its claim generation still matches.
    /// `deadline` is capped at [`MAX_DURABLE_PUBLISH_DEADLINE`]; a larger value
    /// is silently reduced rather than honoured, so a mis-set relay setting
    /// cannot outlive its claim lease.
    ///
    /// # Errors
    /// Returns the closed [`PublishFailure`] classification CR-032's
    /// disposition table consumes:
    ///
    /// - [`PublishFailure::NotAccepted`] — retain the row pending with its
    ///   original stable keys;
    /// - [`PublishFailure::Transient`] — back off and republish with the same
    ///   keys;
    /// - [`PublishFailure::Terminal`] — dead-letter without blocking later
    ///   rows, and fail the affected event-readiness facet.
    pub async fn publish_durable_invalidation(
        &self,
        envelope: &DurableEnvelopeV1,
        deadline: Duration,
    ) -> Result<BrokerAcceptance, PublishFailure> {
        let deadline = deadline.min(MAX_DURABLE_PUBLISH_DEADLINE);
        let encoded = match envelope.encode(self.supported_payload_versions.clone()) {
            Ok(encoded) => encoded,
            Err(violation) => {
                tracing::error!(
                    violation = violation.as_metric_label(),
                    repository = %hex::encode(envelope.common.repository.data()),
                    event_id = %envelope.common.event_id.to_hyphenated(),
                    event_kind = %envelope.body.event_kind,
                    "durable invalidation rejected by its own bounds check; not published"
                );
                let failure = PublishFailure::Terminal(TerminalClass::LocallyRejected);
                metrics::record_publish_result(
                    metrics::CLASS_DURABLE,
                    failure.family_label(),
                    failure.class_label(),
                );
                return Err(failure);
            }
        };
        self.attempt(
            metrics::CLASS_DURABLE,
            envelope.common.event_id,
            encoded,
            deadline,
        )
        .await
    }

    async fn attempt(
        &self,
        delivery_class: &'static str,
        event_id: EventId,
        envelope: wire::PrivateEnvelopeV1,
        deadline: Duration,
    ) -> Result<BrokerAcceptance, PublishFailure> {
        let started = std::time::Instant::now();
        let answer = tokio::time::timeout(deadline, self.transport.publish(envelope)).await;

        let outcome = match answer {
            // The local deadline elapsed. The broker may or may not have
            // accepted; never fabricate acceptance from this.
            Err(_elapsed) => Err(PublishFailure::Transient(TransientClass::Timeout)),
            Ok(Err(status)) => Err(classify_status(&status)),
            Ok(Ok(result)) => classify_result(event_id, &result),
        };

        match &outcome {
            Ok(_) => {
                metrics::record_publish_result(delivery_class, "accepted", "accepted");
                metrics::record_ack_latency_ms(
                    delivery_class,
                    started.elapsed().as_secs_f64() * 1_000.0,
                );
            }
            Err(failure) => metrics::record_publish_result(
                delivery_class,
                failure.family_label(),
                failure.class_label(),
            ),
        }
        outcome
    }
}

/// Classifies a gRPC status into the closed failure set.
///
/// Every `tonic::Code` is named. There is no wildcard arm, so a code this
/// contract has no rule for cannot silently inherit a neighbour's disposition.
pub fn classify_status(status: &tonic::Status) -> PublishFailure {
    match status.code() {
        // Cannot appear on an `Err`, but the match must be total.
        Code::Ok => PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus),

        // Transient: the same envelope with the same stable keys may succeed.
        Code::Cancelled => PublishFailure::Transient(TransientClass::Transport),
        Code::DeadlineExceeded => PublishFailure::Transient(TransientClass::Timeout),
        Code::ResourceExhausted => PublishFailure::Transient(TransientClass::RateLimited),
        Code::Unknown | Code::Aborted | Code::Internal | Code::Unavailable => {
            PublishFailure::Transient(TransientClass::BrokerUnavailable)
        }
        // The cell is quiescing or its placement epoch moved. The contract
        // requires a RETRYABLE placement result, and CR-032 retains durable
        // work in the outbox through the cutover.
        Code::FailedPrecondition => PublishFailure::Transient(TransientClass::PlacementQuiescing),

        // A refused credential is transient, NOT terminal. Credential rotation
        // is an explicit step of the contract's reassignment procedure, so a
        // rotation lag or a gateway restarting with a cold trust store would
        // otherwise dead-letter every committed durable row in flight. A
        // genuine scope or identity mismatch arrives as a `TERMINAL` result
        // with `SCOPE_MISMATCH`, which `classify_result` handles. A permanently
        // wrong credential surfaces as relay backlog and durable-event
        // readiness failure rather than as data loss; see
        // `TransientClass::IdentityRejected` for why CR-032's event-specific
        // quarantine rule cannot cover this case.
        Code::PermissionDenied | Code::Unauthenticated => {
            PublishFailure::Transient(TransientClass::IdentityRejected)
        }

        // Terminal: this exact event cannot succeed under this contract version.
        Code::InvalidArgument | Code::OutOfRange => {
            PublishFailure::Terminal(TerminalClass::InvalidRequest)
        }
        Code::Unimplemented => PublishFailure::Terminal(TerminalClass::UnsupportedSchema),

        // Off-contract for Publish, so the intent is retained rather than
        // guessed at in either direction. A duplicate under the same stable keys
        // is an ACCEPTED result by contract, not ALREADY_EXISTS. DATA_LOSS says
        // nothing about whether the message landed. NOT_FOUND is not a defined
        // Publish answer either: an unknown cell or an unresolvable placement
        // fails closed by contract, which is not the same as poison.
        Code::AlreadyExists | Code::DataLoss | Code::NotFound => {
            PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus)
        }
    }
}

/// Classifies an OK response body.
///
/// The acceptance path is deliberately strict: acceptance evidence is all-or-
/// nothing, so a partially-filled `ACCEPTED` is `NotAccepted` rather than a
/// half-recorded row.
pub fn classify_result(
    expected_event_id: EventId,
    result: &wire::PublishResultV1,
) -> Result<BrokerAcceptance, PublishFailure> {
    if result.transport_version != wire::TRANSPORT_VERSION {
        return Err(PublishFailure::NotAccepted(
            NotAcceptedReason::UnversionedResponse,
        ));
    }

    let outcome = wire::PublishOutcomeV1::try_from(result.outcome)
        .map_err(|_| PublishFailure::NotAccepted(NotAcceptedReason::UnrecognizedOutcome))?;

    match outcome {
        wire::PublishOutcomeV1::Unspecified => Err(PublishFailure::NotAccepted(
            NotAcceptedReason::UnrecognizedOutcome,
        )),
        wire::PublishOutcomeV1::Accepted => accept(expected_event_id, result),
        wire::PublishOutcomeV1::Timeout => Err(PublishFailure::Transient(TransientClass::Timeout)),
        wire::PublishOutcomeV1::Retryable => Err(PublishFailure::Transient(
            match wire::PublishFailureClassV1::try_from(result.failure_class) {
                Ok(wire::PublishFailureClassV1::PlacementQuiescing) => {
                    TransientClass::PlacementQuiescing
                }
                Ok(wire::PublishFailureClassV1::StreamFull) => TransientClass::StreamFull,
                // BROKER_UNAVAILABLE, an unset class, or a class this build does
                // not know: the outcome already said retryable, so the class only
                // refines the label.
                _ => TransientClass::BrokerUnavailable,
            },
        )),
        wire::PublishOutcomeV1::Terminal => Err(PublishFailure::Terminal(
            match wire::PublishFailureClassV1::try_from(result.failure_class) {
                Ok(wire::PublishFailureClassV1::ScopeMismatch) => TerminalClass::ScopeMismatch,
                Ok(wire::PublishFailureClassV1::UnsupportedSchema) => {
                    TerminalClass::UnsupportedSchema
                }
                _ => TerminalClass::InvalidRequest,
            },
        )),
    }
}

fn accept(
    expected_event_id: EventId,
    result: &wire::PublishResultV1,
) -> Result<BrokerAcceptance, PublishFailure> {
    if result.event_id.as_ref() != expected_event_id.as_bytes().as_slice() {
        return Err(PublishFailure::NotAccepted(
            NotAcceptedReason::EventIdMismatch,
        ));
    }
    // PIN(WP-111): the contract lists stream_identity, stream_epoch,
    // broker_sequence and publisher_contract_version as "required" acceptance
    // evidence but does not say which values are impossible. A stream epoch is
    // observed starting at 1 (a reset yields "epoch 1"), and a JetStream
    // sequence starts at 1, so a protobuf default of 0 in any of these means
    // "absent", not "zero". Treating an absent field as present would let an
    // unversioned gateway advance an outbox row.
    if result.stream_identity.is_empty()
        || result.stream_epoch == 0
        || result.broker_sequence == 0
        || result.publisher_contract_version == 0
    {
        return Err(PublishFailure::NotAccepted(
            NotAcceptedReason::IncompleteAcceptanceEvidence,
        ));
    }
    if result.publisher_contract_version != wire::TRANSPORT_VERSION {
        return Err(PublishFailure::NotAccepted(
            NotAcceptedReason::UnrecognizedPublisherContract,
        ));
    }
    Ok(BrokerAcceptance {
        event_id: expected_event_id,
        stream_identity: result.stream_identity.clone(),
        stream_epoch: result.stream_epoch,
        broker_sequence: result.broker_sequence,
        publisher_contract_version: result.publisher_contract_version,
        broker_accepted_at: result
            .broker_accepted_at
            .as_ref()
            .and_then(|t| SystemTime::try_from(*t).ok()),
    })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn event_id() -> EventId {
        EventId::from_bytes([7; 16])
    }

    fn accepted() -> wire::PublishResultV1 {
        wire::PublishResultV1 {
            transport_version: wire::TRANSPORT_VERSION,
            outcome: wire::PublishOutcomeV1::Accepted as i32,
            event_id: Bytes::copy_from_slice(event_id().as_bytes()),
            stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            stream_epoch: 8,
            broker_sequence: 918,
            publisher_contract_version: 1,
            broker_accepted_at: None,
            failure_class: 0,
        }
    }

    #[test]
    fn a_complete_versioned_acceptance_is_the_only_result_that_proves_acceptance() {
        let acceptance = classify_result(event_id(), &accepted()).expect("accepted");
        assert_eq!(acceptance.stream_identity, "DURABLE-sfo3-cell-a");
        assert_eq!(acceptance.stream_epoch, 8);
        assert_eq!(acceptance.broker_sequence, 918);
        assert_eq!(acceptance.publisher_contract_version, 1);
    }

    #[test]
    fn an_unversioned_response_is_not_accepted() {
        let mut result = accepted();
        result.transport_version = 0;
        assert_eq!(
            classify_result(event_id(), &result).expect_err("unversioned"),
            PublishFailure::NotAccepted(NotAcceptedReason::UnversionedResponse)
        );
    }

    #[test]
    fn every_missing_acceptance_evidence_field_makes_the_response_not_accepted() {
        for mutate in [
            (|r: &mut wire::PublishResultV1| r.stream_identity.clear()) as fn(&mut _),
            |r: &mut wire::PublishResultV1| r.stream_epoch = 0,
            |r: &mut wire::PublishResultV1| r.broker_sequence = 0,
            |r: &mut wire::PublishResultV1| r.publisher_contract_version = 0,
        ] {
            let mut result = accepted();
            mutate(&mut result);
            assert_eq!(
                classify_result(event_id(), &result).expect_err("incomplete evidence"),
                PublishFailure::NotAccepted(NotAcceptedReason::IncompleteAcceptanceEvidence)
            );
        }
    }

    #[test]
    fn an_echoed_event_id_that_does_not_match_the_claim_is_not_accepted() {
        let mut result = accepted();
        result.event_id = Bytes::from_static(&[9; 16]);
        assert_eq!(
            classify_result(event_id(), &result).expect_err("event id mismatch"),
            PublishFailure::NotAccepted(NotAcceptedReason::EventIdMismatch)
        );
    }

    #[test]
    fn an_unrecognized_publisher_contract_is_not_accepted() {
        let mut result = accepted();
        result.publisher_contract_version = 2;
        assert_eq!(
            classify_result(event_id(), &result).expect_err("publisher contract"),
            PublishFailure::NotAccepted(NotAcceptedReason::UnrecognizedPublisherContract)
        );
    }

    #[test]
    fn retryable_and_terminal_result_classes_map_to_the_cr_032_dispositions() {
        let cases = [
            (
                wire::PublishOutcomeV1::Retryable,
                wire::PublishFailureClassV1::BrokerUnavailable,
                PublishFailure::Transient(TransientClass::BrokerUnavailable),
            ),
            (
                wire::PublishOutcomeV1::Retryable,
                wire::PublishFailureClassV1::PlacementQuiescing,
                PublishFailure::Transient(TransientClass::PlacementQuiescing),
            ),
            (
                wire::PublishOutcomeV1::Retryable,
                wire::PublishFailureClassV1::StreamFull,
                PublishFailure::Transient(TransientClass::StreamFull),
            ),
            (
                wire::PublishOutcomeV1::Terminal,
                wire::PublishFailureClassV1::ScopeMismatch,
                PublishFailure::Terminal(TerminalClass::ScopeMismatch),
            ),
            (
                wire::PublishOutcomeV1::Terminal,
                wire::PublishFailureClassV1::UnsupportedSchema,
                PublishFailure::Terminal(TerminalClass::UnsupportedSchema),
            ),
        ];
        for (outcome, class, expected) in cases {
            let mut result = accepted();
            result.outcome = outcome as i32;
            result.failure_class = class as i32;
            assert_eq!(
                classify_result(event_id(), &result).expect_err("failure"),
                expected
            );
        }
    }

    #[test]
    fn a_timeout_outcome_never_fabricates_acceptance() {
        let mut result = accepted();
        result.outcome = wire::PublishOutcomeV1::Timeout as i32;
        assert_eq!(
            classify_result(event_id(), &result).expect_err("timeout"),
            PublishFailure::Transient(TransientClass::Timeout)
        );
    }

    #[test]
    fn an_unspecified_or_unknown_outcome_is_not_accepted() {
        let mut result = accepted();
        result.outcome = wire::PublishOutcomeV1::Unspecified as i32;
        assert_eq!(
            classify_result(event_id(), &result).expect_err("unspecified"),
            PublishFailure::NotAccepted(NotAcceptedReason::UnrecognizedOutcome)
        );

        let mut result = accepted();
        result.outcome = 99;
        assert_eq!(
            classify_result(event_id(), &result).expect_err("unknown outcome"),
            PublishFailure::NotAccepted(NotAcceptedReason::UnrecognizedOutcome)
        );
    }

    #[test]
    fn every_grpc_code_has_an_explicit_disposition() {
        let cases = [
            (
                Code::Cancelled,
                PublishFailure::Transient(TransientClass::Transport),
            ),
            (
                Code::Unknown,
                PublishFailure::Transient(TransientClass::BrokerUnavailable),
            ),
            (
                Code::InvalidArgument,
                PublishFailure::Terminal(TerminalClass::InvalidRequest),
            ),
            (
                Code::DeadlineExceeded,
                PublishFailure::Transient(TransientClass::Timeout),
            ),
            (
                Code::NotFound,
                PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus),
            ),
            (
                Code::AlreadyExists,
                PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus),
            ),
            (
                Code::PermissionDenied,
                PublishFailure::Transient(TransientClass::IdentityRejected),
            ),
            (
                Code::ResourceExhausted,
                PublishFailure::Transient(TransientClass::RateLimited),
            ),
            (
                Code::FailedPrecondition,
                PublishFailure::Transient(TransientClass::PlacementQuiescing),
            ),
            (
                Code::Aborted,
                PublishFailure::Transient(TransientClass::BrokerUnavailable),
            ),
            (
                Code::OutOfRange,
                PublishFailure::Terminal(TerminalClass::InvalidRequest),
            ),
            (
                Code::Unimplemented,
                PublishFailure::Terminal(TerminalClass::UnsupportedSchema),
            ),
            (
                Code::Internal,
                PublishFailure::Transient(TransientClass::BrokerUnavailable),
            ),
            (
                Code::Unavailable,
                PublishFailure::Transient(TransientClass::BrokerUnavailable),
            ),
            (
                Code::DataLoss,
                PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus),
            ),
            (
                Code::Unauthenticated,
                PublishFailure::Transient(TransientClass::IdentityRejected),
            ),
        ];
        for (code, expected) in cases {
            assert_eq!(
                classify_status(&tonic::Status::new(code, "test")),
                expected,
                "unexpected disposition for {code:?}"
            );
        }
    }

    #[test]
    fn transport_faults_retry_and_event_specific_rejections_do_not() {
        assert!(classify_status(&tonic::Status::resource_exhausted("429")).is_retryable());
        assert!(classify_status(&tonic::Status::unavailable("5xx")).is_retryable());
        // A refused credential retries: credential rotation is a contract step,
        // and dead-lettering a committed durable row over a rotation lag would
        // lose the mutation event.
        assert!(classify_status(&tonic::Status::permission_denied("no")).is_retryable());
        assert!(classify_status(&tonic::Status::unauthenticated("no")).is_retryable());
        // An event-specific rejection does not.
        assert!(!classify_status(&tonic::Status::invalid_argument("bad")).is_retryable());
        assert!(!classify_status(&tonic::Status::unimplemented("v2 only")).is_retryable());
        // An off-contract answer is neither retried here nor dead-lettered: the
        // caller retains the intent with its original stable keys.
        assert!(!classify_status(&tonic::Status::not_found("no cell")).is_retryable());
    }
}

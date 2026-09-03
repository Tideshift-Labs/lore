// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Layered error types for the remote notification component.
//!
//! Per Lore's error standard each module carries its own `thiserror` enum and
//! translates outward at the boundary. Here the boundary is the plugin
//! registry, so [`RemoteNotificationError`] converts into
//! [`crate::plugins::PluginError`] and nothing below it ever constructs a
//! `PluginError` directly.
//!
//! None of these messages may carry certificate material, private keys, or
//! bearer credentials. Configuration errors name a *field*, never its value,
//! for every field that can hold a secret or a path to one.

use thiserror::Error;

use crate::plugins::PluginError;

/// Errors raised while validating or constructing the remote plugin.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RemoteNotificationError {
    /// The plugin's TOML section did not parse into the typed config.
    #[error("remote notification configuration is malformed: {0}")]
    ConfigParse(String),

    /// A field parsed but violates a contract bound or a safety rule.
    #[error("remote notification configuration field `{field}` is invalid: {reason}")]
    ConfigField {
        /// The offending field's name. Never its value.
        field: &'static str,
        /// Why it was rejected. Never contains secret material.
        reason: String,
    },

    /// The configured private transport version is not one this build speaks.
    #[error(
        "remote notification private transport version {configured} is incompatible; this build speaks exactly {supported}"
    )]
    IncompatibleTransportVersion { configured: u32, supported: u32 },

    /// The configured durable payload-version range excludes what this build
    /// can decode.
    #[error(
        "remote notification durable payload version range {min}..={max} does not cover version {supported}, which this build requires"
    )]
    IncompatibleDurablePayloadVersion { min: u32, max: u32, supported: u32 },

    /// mTLS material could not be read. The message names the field, never the
    /// path contents.
    #[error("remote notification mTLS material for `{field}` could not be read")]
    MtlsMaterialUnreadable { field: &'static str },

    /// The gateway channel could not be constructed or connected.
    #[error("remote notification gateway channel could not be established: {0}")]
    GatewayChannel(String),
}

impl RemoteNotificationError {
    /// The field-scoped constructor, so a call site cannot accidentally
    /// interpolate a secret value into `field`.
    pub fn field(field: &'static str, reason: impl Into<String>) -> Self {
        Self::ConfigField {
            field,
            reason: reason.into(),
        }
    }

    /// True when this is a configuration fault rather than an initialization
    /// fault. Drives the `PluginError` variant chosen at the boundary.
    fn is_config_fault(&self) -> bool {
        matches!(
            self,
            Self::ConfigParse(_)
                | Self::ConfigField { .. }
                | Self::IncompatibleTransportVersion { .. }
                | Self::IncompatibleDurablePayloadVersion { .. }
        )
    }

    /// Translates outward to the plugin registry's error type.
    pub fn into_plugin_error(self, plugin_name: &str) -> PluginError {
        let message = self.to_string();
        if self.is_config_fault() {
            PluginError::from(lore_base::error::PluginConfigError {
                plugin_name: plugin_name.to_string(),
                message,
            })
        } else {
            PluginError::from(lore_base::error::PluginInitError {
                plugin_name: plugin_name.to_string(),
                message,
            })
        }
    }
}

/// Why a well-formed gateway response still failed to prove broker acceptance.
///
/// Kept separate from [`RemoteNotificationError`] because this is not a fault of
/// this process: it is a classification of what the gateway said. CR-032's relay
/// turns each of these into "retain the row with its original stable keys".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotAcceptedReason {
    /// `transport_version` was absent or not the pinned version, so the
    /// response is unversioned under this contract.
    UnversionedResponse,
    /// The outcome said `ACCEPTED` but a required acceptance-evidence field was
    /// missing or left at its protobuf default.
    IncompleteAcceptanceEvidence,
    /// The echoed `event_id` did not match the envelope's, so this response
    /// cannot be matched to the caller's claim.
    EventIdMismatch,
    /// `publisher_contract_version` names a contract this build does not speak.
    UnrecognizedPublisherContract,
    /// The outcome enum itself was unspecified or an unknown value.
    UnrecognizedOutcome,
    /// The gateway answered with a gRPC status this contract does not define
    /// for Publish. The intent is retained with its original stable keys rather
    /// than guessed at in either direction.
    OffContractStatus,
}

impl NotAcceptedReason {
    /// A stable, low-cardinality label for metrics.
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::UnversionedResponse => "unversioned_response",
            Self::IncompleteAcceptanceEvidence => "incomplete_evidence",
            Self::EventIdMismatch => "event_id_mismatch",
            Self::UnrecognizedPublisherContract => "unrecognized_publisher_contract",
            Self::UnrecognizedOutcome => "unrecognized_outcome",
            Self::OffContractStatus => "off_contract_status",
        }
    }
}

/// Transient failure classes: the publication may still succeed later with the
/// same stable keys, so the caller backs off rather than dead-lettering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransientClass {
    /// A transport-level fault: connection refused, reset, TLS handshake, h2.
    Transport,
    /// The deadline elapsed with no answer. The broker may or may not have
    /// accepted; never fabricate acceptance from this.
    Timeout,
    /// gRPC `RESOURCE_EXHAUSTED`, the HTTP 429 equivalent.
    RateLimited,
    /// gRPC `UNAVAILABLE` / `INTERNAL` / `UNKNOWN` / `ABORTED` / `CANCELLED`,
    /// the 5xx equivalents, or a gateway result of `RETRYABLE` with
    /// `BROKER_UNAVAILABLE`.
    BrokerUnavailable,
    /// The cell is mid-reassignment and the gateway rejects new publishes with
    /// a retryable placement result.
    PlacementQuiescing,
    /// The `DURABLE` stream is at its finite bound and `DiscardNew` rejected
    /// rather than evicting unacknowledged correctness work.
    StreamFull,
    /// Transport-level authentication or authorization was refused
    /// (`UNAUTHENTICATED` / `PERMISSION_DENIED`).
    ///
    /// This is deliberately transient, not terminal. Credential rotation is an
    /// explicit step of the contract's reassignment procedure, and a rotation
    /// lag or a gateway restarting with a cold trust store would otherwise
    /// dead-letter every durable row in flight. A genuine scope or identity
    /// mismatch is signalled as a `TERMINAL` result with `SCOPE_MISMATCH`, not
    /// as a transport status.
    ///
    /// A producer whose credential is permanently wrong therefore retains its
    /// rows rather than losing them, and is caught by the plane's own health
    /// signal instead: this class is a refusal of the *producer*, not of one
    /// event, so every publish fails, the relay backlog grows, and durable-event
    /// readiness fails. CR-032's twenty-identical-rejections quarantine
    /// deliberately does NOT apply here; it is scoped to an event-specific 4xx
    /// and requires that other events of the same version still publish, which
    /// by construction they cannot.
    IdentityRejected,
}

impl TransientClass {
    /// A stable, low-cardinality label for metrics.
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::BrokerUnavailable => "broker_unavailable",
            Self::PlacementQuiescing => "placement_quiescing",
            Self::StreamFull => "stream_full",
            Self::IdentityRejected => "identity_rejected",
        }
    }
}

/// Terminal failure classes: retrying this exact event under this contract
/// version cannot succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalClass {
    /// Invalid scope, or an identity mismatch among mTLS cell, placement cell,
    /// subject, envelope, and embedded event.
    ScopeMismatch,
    /// The gateway does not speak this producer's schema or payload version.
    UnsupportedSchema,
    /// The gateway rejected this specific event with a 4xx-equivalent status
    /// (`INVALID_ARGUMENT`, `OUT_OF_RANGE`).
    ///
    /// Transport-level authentication failures are deliberately NOT here: see
    /// [`TransientClass::IdentityRejected`] for why a refused credential is
    /// retried rather than dead-lettered.
    InvalidRequest,
    /// The envelope failed this component's own pre-publication bounds check,
    /// so it was never sent.
    LocallyRejected,
}

impl TerminalClass {
    /// A stable, low-cardinality label for metrics.
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::ScopeMismatch => "scope_mismatch",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InvalidRequest => "invalid_request",
            Self::LocallyRejected => "locally_rejected",
        }
    }
}

/// The closed classification of a failed Publish, as CR-032's relay consumes it.
///
/// This is deliberately closed: the relay's disposition table maps every
/// variant, so adding a class is a compile error at every match site rather
/// than a silently-defaulted row state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishFailure {
    /// The call returned, but nothing in the answer proves broker acceptance.
    /// Retain the row pending with its original stable keys.
    NotAccepted(NotAcceptedReason),
    /// Back off and republish with the same stable keys.
    Transient(TransientClass),
    /// Dead-letter without blocking later rows, and fail the affected
    /// event-readiness facet.
    Terminal(TerminalClass),
}

impl PublishFailure {
    /// A stable, low-cardinality outcome label for metrics: the family only.
    /// The class goes in a second bounded label so the pair stays small.
    pub const fn family_label(self) -> &'static str {
        match self {
            Self::NotAccepted(_) => "not_accepted",
            Self::Transient(_) => "transient",
            Self::Terminal(_) => "terminal",
        }
    }

    /// The class label within the family.
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NotAccepted(reason) => reason.as_metric_label(),
            Self::Transient(class) => class.as_metric_label(),
            Self::Terminal(class) => class.as_metric_label(),
        }
    }

    /// Whether a bounded retry loop should try this publication again.
    ///
    /// `NotAccepted` is deliberately **not** retried by this client. CR-032
    /// requires the relay to retain the intent and republish under its own
    /// claim, because a response that does not prove acceptance may still have
    /// landed at the broker.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

impl std::fmt::Display for PublishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.family_label(), self.class_label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_faults_translate_to_plugin_config_error() {
        let err = RemoteNotificationError::field("gateway_uri", "must use https");
        let plugin_error = err.into_plugin_error("remote");
        assert!(plugin_error.is_plugin_config_error());
    }

    #[test]
    fn init_faults_translate_to_plugin_init_error() {
        let err = RemoteNotificationError::MtlsMaterialUnreadable {
            field: "client_key_path",
        };
        let plugin_error = err.into_plugin_error("remote");
        assert!(plugin_error.is_plugin_init_error());
    }

    #[test]
    fn only_transient_failures_are_retried_by_this_client() {
        assert!(PublishFailure::Transient(TransientClass::Timeout).is_retryable());
        assert!(
            !PublishFailure::NotAccepted(NotAcceptedReason::UnversionedResponse).is_retryable()
        );
        assert!(!PublishFailure::Terminal(TerminalClass::ScopeMismatch).is_retryable());
    }

    #[test]
    fn every_failure_label_pair_is_low_cardinality_and_stable() {
        // A label built from a formatted value rather than a fixed string would
        // let a repository or event id reach a metric dimension. Both halves are
        // `&'static str` by construction; this pins that they stay non-empty and
        // free of interpolation markers.
        for failure in [
            PublishFailure::NotAccepted(NotAcceptedReason::IncompleteAcceptanceEvidence),
            PublishFailure::Transient(TransientClass::StreamFull),
            PublishFailure::Transient(TransientClass::IdentityRejected),
            PublishFailure::Terminal(TerminalClass::ScopeMismatch),
        ] {
            assert!(!failure.family_label().is_empty());
            assert!(!failure.class_label().is_empty());
            assert!(!failure.class_label().contains('{'));
        }
    }
}

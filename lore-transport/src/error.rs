// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use lore_base::error::*;
use lore_error_set::prelude::*;
use thiserror::Error;

/// Typed proof that a session-bearing command was refused before dispatch.
///
/// This stays inside `ProtocolError::Internal`. Making it an error-set variant would widen every
/// strict-forward target in the client API even though only the session layer may act on it.
#[derive(Debug, Clone, Error)]
#[error("Connection replaced; session must be rebound before this command is sent again")]
pub(crate) struct SessionRebindRequired;

#[error_set(clone)]
pub enum ProtocolError {
    Disconnected,
    SlowDown,
    NotAuthorized,
    NotAuthenticated,
    Maintenance,
    NotFound,
    NoRemote,
    NotSupported,
    Oversized,
    /// A dispatched mutable request whose outcome is not known (WP-120).
    ///
    /// Deliberately a peer of `Disconnected` rather than a shade of it. Every reconnect and
    /// reissue path in this crate branches on `Disconnected`, so an unknown outcome that
    /// answered to that predicate would be replayed by all of them — which is the one thing
    /// it must never be. It is built in exactly one place,
    /// [`crate::outcome::resolve`].
    OutcomeUnknown,
}

pub(crate) fn is_session_rebind_required(error: &ProtocolError) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(source) = current {
        if source.downcast_ref::<SessionRebindRequired>().is_some() {
            return true;
        }
        current = source.source();
    }
    false
}

impl From<tonic::Status> for ProtocolError {
    fn from(value: tonic::Status) -> Self {
        // Checked once, before any branch on the code, for the reason the QUIC classifier
        // checks its own orthogonal property once: a per-arm check is a promise every future
        // arm has to remember to repeat, and arms do not.
        //
        // The marker is what a server sets when *it* knows its result was indeterminate. It is
        // not inferred from `Code::Unknown`, which only means the server did not classify the
        // failure — an unmarked status stays the ordinary protocol error it always was, and a
        // lost *mutable* response is upgraded independently by the caller's own dispatch
        // classification in `crate::outcome`.
        if let Some(unknown) = outcome_unknown_marker(&value) {
            return ProtocolError::from(unknown);
        }
        match value.code() {
            tonic::Code::Unavailable | tonic::Code::Unknown => ProtocolError::from(Disconnected),
            tonic::Code::Unauthenticated => ProtocolError::from(NotAuthenticated),
            tonic::Code::PermissionDenied => ProtocolError::from(NotAuthorized),
            tonic::Code::NotFound => ProtocolError::from(NotFound),
            tonic::Code::ResourceExhausted => ProtocolError::from(SlowDown),
            tonic::Code::OutOfRange => ProtocolError::from(Oversized {
                context: value.message().to_string(),
            }),
            tonic::Code::Unimplemented => ProtocolError::from(NotSupported {
                operation: value.message().to_string(),
            }),
            _ => ProtocolError::internal(value.to_string()),
        }
    }
}

/// What an attempt id reads as when the server marked an outcome unknown without naming one.
///
/// Deliberately not an empty string: it reaches a human in an error message and a caller's
/// journal, and "no id was supplied" is a different fact from "the id is blank".
pub(crate) const UNNAMED_ATTEMPT: &str = "unnamed";

/// Read a server's semantic unknown-outcome marker off a status, if it set one.
///
/// Returns the discrete error already populated with the operation and attempt the server
/// named, falling back to the status's own text when it named neither — an unknown outcome
/// with a weak identity is still an unknown outcome, and dropping it because the identity is
/// thin would turn it back into the retryable error the whole contract exists to avoid.
fn outcome_unknown_marker(status: &tonic::Status) -> Option<OutcomeUnknown> {
    let metadata = status.metadata();
    let text = |key: &str| {
        metadata
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };

    if text(crate::outcome::OUTCOME_UNKNOWN_METADATA_KEY).as_deref()
        != Some(crate::outcome::OUTCOME_UNKNOWN_METADATA_VALUE)
    {
        return None;
    }

    Some(OutcomeUnknown {
        operation: text(crate::outcome::OUTCOME_UNKNOWN_OPERATION_KEY)
            .unwrap_or_else(|| status.message().to_string()),
        // Named rather than left empty. A server that marked the outcome unknown without
        // naming an attempt has told the caller something real, and rendering the gap as
        // `(attempt )` reads as a bug in this client rather than as a thin marker.
        attempt_id: text(crate::outcome::OUTCOME_UNKNOWN_ATTEMPT_KEY)
            .unwrap_or_else(|| UNNAMED_ATTEMPT.to_string()),
    })
}

impl From<ProtocolError> for tonic::Status {
    fn from(value: ProtocolError) -> Self {
        let msg = value.to_string();
        if let ProtocolError::OutcomeUnknown(unknown) = &value {
            let mut status = tonic::Status::new(tonic::Code::Unknown, msg);
            let metadata = status.metadata_mut();
            insert_marker(
                metadata,
                crate::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
                crate::outcome::OUTCOME_UNKNOWN_METADATA_VALUE,
            );
            insert_marker(
                metadata,
                crate::outcome::OUTCOME_UNKNOWN_OPERATION_KEY,
                &unknown.operation,
            );
            insert_marker(
                metadata,
                crate::outcome::OUTCOME_UNKNOWN_ATTEMPT_KEY,
                &unknown.attempt_id,
            );
            return status;
        }
        match value {
            ProtocolError::NotAuthenticated(_) => {
                tonic::Status::new(tonic::Code::Unauthenticated, msg)
            }
            ProtocolError::NotAuthorized(_) => {
                tonic::Status::new(tonic::Code::PermissionDenied, msg)
            }
            ProtocolError::SlowDown(_) => tonic::Status::new(tonic::Code::ResourceExhausted, msg),
            ProtocolError::NotFound(_) => tonic::Status::new(tonic::Code::NotFound, msg),
            ProtocolError::Oversized(_) => tonic::Status::new(tonic::Code::OutOfRange, msg),
            ProtocolError::Disconnected(_) | ProtocolError::Maintenance(_) => {
                tonic::Status::new(tonic::Code::Unavailable, msg)
            }
            ProtocolError::NotSupported(_) => tonic::Status::new(tonic::Code::Unimplemented, msg),
            ProtocolError::NoRemote(_) | ProtocolError::Internal(_) => {
                tonic::Status::new(tonic::Code::Internal, msg)
            }
            // Handled above, where the marker metadata is attached.
            ProtocolError::OutcomeUnknown(_) => tonic::Status::new(tonic::Code::Unknown, msg),
        }
    }
}

/// Attach one marker header, skipping a value gRPC metadata cannot carry.
///
/// A header that will not encode is dropped rather than failing the conversion: losing the
/// operation name degrades the detail, while failing the conversion would lose the unknown
/// outcome itself.
fn insert_marker(metadata: &mut tonic::metadata::MetadataMap, key: &'static str, value: &str) {
    if let Ok(value) = value.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()
        && let Ok(key) = key.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>()
    {
        metadata.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-017(c): a server-side auth rejection must classify as `NotAuthenticated`
    // (FFI 16), not collapse into the catch-all `Internal` (FFI -1) — a client
    // needs to distinguish "not authenticated" from an opaque internal error to
    // drive recovery (WP-074 Phase 1).
    #[test]
    fn unauthenticated_status_maps_to_not_authenticated() {
        let status = tonic::Status::unauthenticated("authorization header required");
        let err = ProtocolError::from(status);
        assert!(matches!(err, ProtocolError::NotAuthenticated(_)));
        // Codes are `#[ffi_code(..)]` in `lore-base/src/error.rs`; upstream
        // b98b4d6 regrouped them into blocks, which is what a mismatch means.
        assert_eq!(err.ffi_code(), 16);
    }

    // Regression pin: a neighboring arm untouched by CR-017(c) still classifies
    // correctly.
    #[test]
    fn unavailable_status_maps_to_disconnected() {
        let status = tonic::Status::unavailable("server unreachable");
        let err = ProtocolError::from(status);
        assert!(matches!(err, ProtocolError::Disconnected(_)));
        assert_eq!(err.ffi_code(), 28);
    }

    // An unmapped tonic code still falls through to `Internal`, not
    // `NotAuthenticated` or any other handleable variant.
    #[test]
    fn unmapped_status_falls_back_to_internal() {
        let status = tonic::Status::internal("something went wrong");
        let err = ProtocolError::from(status);
        assert!(matches!(err, ProtocolError::Internal(_)));
        assert_eq!(err.ffi_code(), -1);
    }
}

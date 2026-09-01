// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
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

impl From<ProtocolError> for tonic::Status {
    fn from(value: ProtocolError) -> Self {
        let msg = value.to_string();
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
        }
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

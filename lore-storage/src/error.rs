// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_error_set::prelude::*;
use lore_transport::ProtocolError;

use crate::errors::*;

#[error_set(clone)]
pub enum StorageError {
    AddressNotFound,
    PayloadNotFound,
    NotConnected,
    Disconnected,
    SlowDown,
    Oversized,
    InvalidArguments,
    Maintenance,
    NoRemote,
    NotAuthenticated,
    NotAuthorized,
    NotFound,
    NotSupported,
    /// A dispatched mutable storage request whose outcome is not known (WP-120).
    ///
    /// Declared here rather than folded into `NotConnected` because the two say opposite
    /// things to a caller: one means the write did not happen, the other means nobody knows.
    OutcomeUnknown,
}

/// Map a `ProtocolError` to a `StorageError`: a miss to `AddressNotFound` at `address`, a refusal
/// to itself with its trace, which carries the remote's reason where the transport gives one,
/// `Disconnected` and `SlowDown` to themselves, and anything else to `NotConnected`.
pub fn protocol_error_to_storage(
    err: ProtocolError,
    address: lore_base::types::Address,
) -> StorageError {
    match err {
        // Kept apart from the connectivity family: an unknown outcome that fell through to
        // `NotConnected` would tell the caller the write did not happen, which is the one thing
        // this transport does not know.
        ProtocolError::OutcomeUnknown(unknown) => StorageError::OutcomeUnknown(unknown),
        ProtocolError::NotAuthenticated(refusal) => StorageError::NotAuthenticated(refusal),
        ProtocolError::NotAuthorized(refusal) => StorageError::NotAuthorized(refusal),
        ProtocolError::NotFound(_) | ProtocolError::NoRemote(_) => {
            StorageError::from(AddressNotFound::from(address))
        }
        ProtocolError::Disconnected(_) => StorageError::from(Disconnected),
        ProtocolError::SlowDown(_) => StorageError::from(SlowDown),
        err => StorageError::from(NotConnected {
            reason: format!("{err}"),
        }),
    }
}

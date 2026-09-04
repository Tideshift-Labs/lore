// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_error_set::prelude::*;

use crate::errors::*;

#[error_set]
pub enum StorageError {
    AddressNotFound,
    PayloadNotFound,
    NotConnected,
    Disconnected,
    SlowDown,
    Oversized,
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

/// Map a `ProtocolError` to a `StorageError`, preserving the address when available.
pub fn protocol_error_to_storage(
    err: lore_transport::ProtocolError,
    address: lore_base::types::Address,
) -> StorageError {
    // Checked first, before the connectivity family: an unknown outcome that fell through to
    // `NotConnected` would tell the caller the write did not happen, which is the one thing
    // this transport does not know.
    if let lore_transport::ProtocolError::OutcomeUnknown(unknown) = &err {
        return StorageError::from(OutcomeUnknown::clone(unknown));
    }
    if err.is_not_found() || err.is_no_remote() {
        StorageError::from(AddressNotFound::from(address))
    } else if err.is_disconnected() {
        StorageError::from(Disconnected)
    } else if err.is_slow_down() {
        StorageError::from(SlowDown)
    } else {
        StorageError::from(NotConnected {
            reason: format!("{err}"),
        })
    }
}

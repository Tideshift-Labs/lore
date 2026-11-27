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
        // FORK-LOCAL (Tideshift): kept with its trace, which names where the transport failed to
        // connect (the QUIC storage handshake's host and UDP port).
        ProtocolError::Disconnected(disconnected) => StorageError::Disconnected(disconnected),
        ProtocolError::SlowDown(_) => StorageError::from(SlowDown),
        err => StorageError::from(NotConnected {
            reason: format!("{err}"),
        }),
    }
}

/// FORK-LOCAL (Tideshift, silence bound): [`protocol_error_to_storage`] for a remote READ, with one
/// difference: a read the transport's bound ended (the server took it and sent no byte for one
/// bound, or the path could not be replaced within it; see
/// `lore_transport::quic::client::bound_unmanaged_silence`) is `Disconnected` (ffi 28), not
/// `NotConnected`.
///
/// `NotConnected` reads as a stale session, which a remote read retries on a fresh session up to
/// five times, each retry waiting a whole bound again: a sync took six bounds to fail. The bound
/// already decided, as an exhausted reconnect does, and `Disconnected` is the error a read does
/// not retry. A write keeps [`protocol_error_to_storage`]; its callers read the transport error
/// itself (`note_unmanaged_refusal`).
pub fn read_error_to_storage(
    err: ProtocolError,
    address: lore_base::types::Address,
) -> StorageError {
    if lore_transport::is_managed_reconnect_expired(&err) {
        lore_base::lore_warn!("remote read ended by the transport's bound: {err}");
        return StorageError::from(crate::errors::Disconnected);
    }
    protocol_error_to_storage(err, address)
}

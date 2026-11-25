// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `protocol_error_to_storage` keeps what a transport said about a failed connect.
use lore_base::error::Disconnected;
use lore_base::types::Address;
use lore_error_set::prelude::*;
use lore_storage::error::StorageError;
use lore_storage::error::protocol_error_to_storage;
use lore_transport::ProtocolError;

fn address() -> Address {
    Address::default()
}

fn has_context(error: &StorageError, needle: &str) -> bool {
    error.trace().locations().iter().any(|location| {
        location
            .context()
            .is_some_and(|context| context.contains(needle))
    })
}

/// The QUIC handshake's reason (host, UDP port) rides the trace of its `Disconnected`; mapping it
/// to a storage error used to rebuild it bare and drop the reason.
#[test]
fn a_disconnected_keeps_its_trace_context_through_the_storage_mapping() {
    let unreachable = Err::<(), _>(ProtocolError::from(Disconnected))
        .forward_with::<ProtocolError, _>(|| {
            "Could not reach 127.0.0.1 on UDP port 41337".to_string()
        })
        .expect_err("an error");

    let mapped = protocol_error_to_storage(unreachable, address());

    assert!(
        matches!(mapped, StorageError::Disconnected(_)),
        "{mapped:?}"
    );
    assert!(
        has_context(&mapped, "UDP port 41337"),
        "the context was dropped: {mapped:?}"
    );
}

/// A bare `Disconnected` still maps to the `Disconnected` variant, with nothing to keep.
#[test]
fn a_bare_disconnected_is_still_disconnected() {
    let mapped = protocol_error_to_storage(ProtocolError::from(Disconnected), address());

    assert!(
        matches!(mapped, StorageError::Disconnected(_)),
        "{mapped:?}"
    );
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `protocol_error_to_storage` keeps what a transport said about a failed connect.
use lore_base::error::Disconnected;
use lore_base::error::QuicUnreachable;
use lore_base::types::Address;
use lore_error_set::prelude::*;
use lore_storage::error::StorageError;
use lore_storage::error::protocol_error_to_storage;
use lore_storage::error::read_error_to_storage;
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

/// The typed unreachable detail (host, UDP port, TCP URL) travels with the mapped error, so a
/// caller above storage can publish it without parsing the message.
#[test]
fn a_disconnected_with_the_unreachable_detail_keeps_it_through_the_storage_mapping() {
    let unreachable = ProtocolError::from(Disconnected::unreachable(QuicUnreachable {
        host: "127.0.0.1".to_string(),
        port: 41337,
        tcp_url: "grpcs://127.0.0.1:41337".to_string(),
    }));
    assert!(unreachable.quic_unreachable().is_some(), "precondition");

    let mapped = protocol_error_to_storage(unreachable, address());

    assert!(
        matches!(mapped, StorageError::Disconnected(_)),
        "{mapped:?}"
    );
    assert_eq!(
        mapped.unreachable_endpoint(),
        Some(("127.0.0.1", 41337, "grpcs://127.0.0.1:41337"))
    );
    assert!(
        mapped.to_string().contains("UDP port 41337"),
        "the mapped message names the port: {mapped}"
    );
}

/// A bare `Disconnected` maps with no endpoint.
#[test]
fn a_bare_disconnected_maps_with_no_unreachable_endpoint() {
    let mapped = protocol_error_to_storage(ProtocolError::from(Disconnected), address());

    assert_eq!(mapped.unreachable_endpoint(), None);
}

/// A read the transport's bound ended (here the not-sent marker, the one the transport exposes to
/// other crates) is `Disconnected`, which a remote read never retries, not `NotConnected`, which it
/// retries on a fresh session with a whole new bound each time.
///
/// The other marker (a dispatched read whose answer was lost) has a crate-private type in
/// `lore-transport` and no test constructor, so it cannot be built from here. The same
/// `is_managed_reconnect_expired` test accepts both; the dispatched one is covered end to end by
/// `quic_unmanaged_silence_sync_test.rs` (a real sync ends with code 28 after one Get).
#[test]
fn a_read_the_transport_bound_ended_maps_to_disconnected() {
    let expired = lore_transport::error::managed_reconnect_expired_for_test("get");
    assert!(lore_transport::is_managed_reconnect_expired(&expired));

    let mapped = read_error_to_storage(expired, address());

    assert!(
        matches!(mapped, StorageError::Disconnected(_)),
        "{mapped:?}"
    );
}

/// Control: a plain internal protocol error is still `NotConnected` on the read mapping.
#[test]
fn a_plain_internal_error_on_the_read_mapping_is_still_not_connected() {
    let plain = ProtocolError::internal("get: Invalid server response");
    assert!(!lore_transport::is_managed_reconnect_expired(&plain));

    let mapped = read_error_to_storage(plain, address());

    assert!(
        matches!(mapped, StorageError::NotConnected(_)),
        "{mapped:?}"
    );
}

/// The write mapping is unchanged: the same marker is `NotConnected` there, because a write's
/// caller reads the transport error itself.
#[test]
fn the_write_mapping_still_maps_the_bound_marker_to_not_connected() {
    let expired = lore_transport::error::managed_reconnect_expired_for_test("put");

    let mapped = protocol_error_to_storage(expired, address());

    assert!(
        matches!(mapped, StorageError::NotConnected(_)),
        "{mapped:?}"
    );
}

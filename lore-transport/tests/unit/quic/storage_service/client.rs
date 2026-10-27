// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! WP-124 slice 2a: the `AuthorizeStart` payload builder.
//!
//! The server parses these bytes (`lore-server`'s `protocol/storage/authorize.rs`), so the layout
//! is pinned here as literal offsets, not through the builder under test.
use lore_base::types::Partition;
use lore_transport::quic::storage_service::client::authorize_start_payload;
use zerocopy::IntoBytes;

const CAPS: &str = "outcome_unknown_v1";

fn partition() -> Partition {
    rand::random::<Partition>()
}

/// The layout action 0 has always had, built by hand: `action | partition(16) | corr_len(1) |
/// corr | token_len(2, LE) | token`.
fn legacy_layout(partition: Partition, correlation_id: &str, token: &str) -> Vec<u8> {
    let mut bytes = vec![0u8];
    bytes.extend_from_slice(partition.as_bytes());
    bytes.push(correlation_id.len() as u8);
    bytes.extend_from_slice(correlation_id.as_bytes());
    bytes.extend_from_slice(&(token.len() as u16).to_le_bytes());
    bytes.extend_from_slice(token.as_bytes());
    bytes
}

#[test]
fn action_zero_is_byte_identical_to_the_pre_declaration_layout() {
    let partition = partition();
    for (correlation, token) in [
        ("", ""),
        ("corr", ""),
        ("corr-id-1", "a.jwt.token"),
        ("c", "t".repeat(300).leak() as &str),
    ] {
        let payload = authorize_start_payload(partition, correlation, token, None)
            .expect("an undeclared payload always builds");
        assert_eq!(
            payload.as_ref(),
            legacy_layout(partition, correlation, token).as_slice(),
            "correlation {correlation:?} token length {}",
            token.len()
        );
        assert_eq!(payload[0], 0, "no capabilities means action 0");
    }
}

#[test]
fn action_two_is_the_action_zero_payload_with_caps_appended() {
    let partition = partition();
    let token = "a.jwt.token";
    let payload = authorize_start_payload(partition, "corr-id-1", token, Some(CAPS))
        .expect("a declared payload builds");

    let mut expected = legacy_layout(partition, "corr-id-1", token);
    expected[0] = 2;
    expected.extend_from_slice(&(CAPS.len() as u16).to_le_bytes());
    expected.extend_from_slice(CAPS.as_bytes());
    assert_eq!(payload.as_ref(), expected.as_slice());

    // The tail, read the way the server reads it: little-endian length, then ASCII.
    let tail = &payload[payload.len() - (2 + CAPS.len())..];
    assert_eq!(u16::from_le_bytes([tail[0], tail[1]]) as usize, CAPS.len());
    assert_eq!(&tail[2..], CAPS.as_bytes());
}

#[test]
fn the_declared_and_undeclared_payloads_differ_only_in_action_and_tail() {
    let partition = partition();
    let plain = authorize_start_payload(partition, "corr", "tok", None).expect("builds");
    let declared = authorize_start_payload(partition, "corr", "tok", Some(CAPS)).expect("builds");

    assert_eq!(declared[1..plain.len()], plain[1..]);
    assert_eq!((plain[0], declared[0]), (0, 2));
    assert_eq!(declared.len(), plain.len() + 2 + CAPS.len());
}

#[test]
fn a_capability_list_longer_than_a_u16_is_refused_rather_than_truncated() {
    let too_long = "a".repeat(usize::from(u16::MAX) + 1);
    let error = authorize_start_payload(partition(), "corr", "tok", Some(&too_long))
        .expect_err("a list that does not fit its length field must not be framed");
    assert!(error.to_string().contains("too long"), "{error}");
}

#[test]
fn an_empty_capability_list_still_declares_action_two() {
    let payload = authorize_start_payload(partition(), "corr", "tok", Some(""))
        .expect("an empty list frames");
    assert_eq!(payload[0], 2);
    assert_eq!(&payload[payload.len() - 2..], &[0, 0]);
}

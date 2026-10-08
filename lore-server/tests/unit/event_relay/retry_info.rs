// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;

use lore_server::event_relay::retry_info::*;
use prost::Message;

#[test]
fn a_delay_round_trips_through_the_trailer_encoding() {
    for delay in [
        Duration::from_secs(1),
        Duration::from_millis(2_500),
        Duration::from_secs(300),
    ] {
        let encoded = retry_info_details(delay, "backlog");
        assert_eq!(decode_retry_delay(&encoded), Some(delay), "delay {delay:?}");
    }
}

/// The trailer must be a `google.rpc.Status`, not a bare `RetryInfo`, or a
/// standard client will not find the detail at all.
#[test]
fn the_trailer_is_a_status_carrying_the_detail_under_its_canonical_url() {
    let encoded = retry_info_details(Duration::from_secs(5), "the backlog is too old");
    let status = RpcStatus::decode(encoded.as_ref()).expect("decodes as google.rpc.Status");
    assert_eq!(status.code, tonic::Code::ResourceExhausted as i32);
    assert_eq!(status.message, "the backlog is too old");
    assert_eq!(status.details.len(), 1);
    assert_eq!(status.details[0].type_url, RETRY_INFO_TYPE_URL);
}

/// A client that reads the trailer's message rather than the status line
/// must not see an empty explanation.
#[test]
fn the_trailer_message_is_never_empty_when_one_was_supplied() {
    let encoded = retry_info_details(Duration::from_secs(5), "a reason");
    let status = RpcStatus::decode(encoded.as_ref()).expect("decodes");
    assert!(!status.message.is_empty());
}

#[test]
fn garbage_decodes_to_no_delay_rather_than_panicking() {
    assert_eq!(decode_retry_delay(&[0xFF, 0xFF, 0xFF]), None);
    assert_eq!(decode_retry_delay(&[]), None);
}

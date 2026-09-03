// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `google.rpc.RetryInfo` for the required-event admission gate.
//!
//! CR-032 requires an admission rejection to be `RESOURCE_EXHAUSTED` **with
//! bounded `RetryInfo`**, so the delay has to be machine-readable rather than a
//! sentence in the status message.
//!
//! # Why the messages are hand-transcribed
//!
//! Two reasons, the same ones WP-111 gives for hand-transcribing the private
//! notification protobuf. `protoc` is optional in this workspace, and the
//! generated-code path is common wiring; and the whole of what is needed here
//! is two messages of three fields, both frozen for over a decade in
//! `google/rpc/status.proto` and `google/rpc/error_details.proto`. Pulling a
//! code-generation dependency for that costs more than it removes.
//!
//! # PIN(WP-119): this fork's `details` field carries raw bytes elsewhere
//!
//! `tonic::Status::with_details` writes the `grpc-status-details-bin` trailer,
//! which the gRPC specification defines as a serialized `google.rpc.Status`.
//! Several existing handlers in this crate put their own opaque bytes there
//! instead (see `grpc::mod`'s `MessageHandleError` mapping), so a client of
//! this server cannot already assume the standard shape. This gate uses the
//! standard shape, because CR-032 names `RetryInfo` specifically and a bespoke
//! encoding of it would be a second private contract for no gain. Raise it with
//! the CR owner if the two conventions on one trailer become a problem.

use std::time::Duration;

use bytes::Bytes;
use prost::Message;

/// `google.rpc.Status`, the payload of the `grpc-status-details-bin` trailer.
///
/// The code and message duplicate what the gRPC status itself carries, and they
/// are populated anyway: several standard clients surface the trailer's copy
/// rather than the status line, and a reader that finds an empty message there
/// reports a `RESOURCE_EXHAUSTED` with no explanation at all. The two copies
/// are written from the same values at one call site, so they cannot disagree.
#[derive(Clone, PartialEq, Message)]
pub struct RpcStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(message, repeated, tag = "3")]
    pub details: Vec<prost_types::Any>,
}

/// `google.rpc.RetryInfo`.
#[derive(Clone, PartialEq, Message)]
pub struct RetryInfo {
    #[prost(message, optional, tag = "1")]
    pub retry_delay: Option<prost_types::Duration>,
}

/// The canonical type URL a `RetryInfo` is packed under.
pub const RETRY_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.RetryInfo";

/// Encode a bounded retry delay as trailer bytes, alongside the same message
/// the gRPC status line carries.
pub fn retry_info_details(delay: Duration, message: &str) -> Bytes {
    let retry_info = RetryInfo {
        retry_delay: Some(prost_types::Duration {
            seconds: i64::try_from(delay.as_secs()).unwrap_or(i64::MAX),
            nanos: delay.subsec_nanos() as i32,
        }),
    };
    let status = RpcStatus {
        code: tonic::Code::ResourceExhausted as i32,
        message: message.to_string(),
        details: vec![prost_types::Any {
            type_url: RETRY_INFO_TYPE_URL.to_string(),
            value: retry_info.encode_to_vec(),
        }],
    };
    Bytes::from(status.encode_to_vec())
}

/// Read a retry delay back out of trailer bytes.
///
/// Exists so the encoding is provable rather than asserted: a round-trip test
/// is the only way to know the bytes a client will parse are the bytes this
/// gate meant to send.
pub fn decode_retry_delay(details: &[u8]) -> Option<Duration> {
    let status = RpcStatus::decode(details).ok()?;
    let any = status
        .details
        .iter()
        .find(|any| any.type_url == RETRY_INFO_TYPE_URL)?;
    let retry_info = RetryInfo::decode(&any.value[..]).ok()?;
    let delay = retry_info.retry_delay?;
    let seconds = u64::try_from(delay.seconds).ok()?;
    let nanos = u32::try_from(delay.nanos).ok()?;
    Some(Duration::new(seconds, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

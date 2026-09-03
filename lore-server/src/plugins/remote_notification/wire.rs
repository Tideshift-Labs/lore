// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Hand-maintained prost/tonic transcription of the vendored private
//! notification contract.
//!
//! The schema of record is
//! [`proto/lorehub_notification_internal_v1.proto`](./proto/lorehub_notification_internal_v1.proto),
//! sitting beside this file. That `.proto` is **not** compiled by `build.rs`:
//! `protoc` is optional in this workspace (`lore-proto` and `lore-server` both
//! fall back to pregenerated sources when it is absent), and `lore-server`'s
//! build script is common wiring that WP-119 owns during `SCHEMA-119`. So the
//! Rust here is written by hand in exactly the shape `tonic-prost-build` would
//! emit, and [`tests`] pins every field number, tag, and enum value against the
//! `.proto` text so the two cannot drift apart silently.
//!
//! Nothing in this module validates. Decoding a `PrivateEnvelopeV1` proves only
//! that the bytes were well-formed protobuf; every bound the contract states
//! lives in [`super::envelope`].

use prost::Message;
use tonic::codegen::Body;
use tonic::codegen::StdError;
use tonic::codegen::http;

/// The pinned private transport version. The contract's `transport_version` is
/// "required integer, exactly 1".
pub const TRANSPORT_VERSION: u32 = 1;

/// The pinned durable payload version this component supports today. CR-032's
/// "payload schema version" row field under its wire name.
pub const DURABLE_PAYLOAD_VERSION: u32 = 1;

/// Fully-qualified name of the private publication service.
pub const PRIVATE_NOTIFICATION_SERVICE: &str =
    "lorehub.notification.internal.v1.PrivateNotificationService";

/// The one pinned method path this component calls.
pub const PUBLISH_METHOD_PATH: &str =
    "/lorehub.notification.internal.v1.PrivateNotificationService/Publish";

/// Delivery class of one private envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DeliveryClassV1 {
    Unspecified = 0,
    LiveHint = 1,
    DurableInvalidation = 2,
    ShadowObservation = 3,
}

/// Outcome class of one Publish attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PublishOutcomeV1 {
    Unspecified = 0,
    Accepted = 1,
    Retryable = 2,
    Timeout = 3,
    Terminal = 4,
}

/// Failure class, set only when the outcome is `Retryable` or `Terminal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PublishFailureClassV1 {
    Unspecified = 0,
    BrokerUnavailable = 1,
    PlacementQuiescing = 2,
    StreamFull = 3,
    ScopeMismatch = 4,
    UnsupportedSchema = 5,
}

/// Monotonic ordinal plus an optional opaque identity component.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregateVersionV1 {
    #[prost(uint64, tag = "1")]
    pub ordinal: u64,
    #[prost(string, tag = "2")]
    pub identity: ::prost::alloc::string::String,
}

/// The `DURABLE_INVALIDATION` body.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DurableInvalidationBodyV1 {
    #[prost(uint32, tag = "1")]
    pub payload_version: u32,
    #[prost(bytes = "bytes", tag = "2")]
    pub idempotency_key: ::bytes::Bytes,
    #[prost(string, tag = "3")]
    pub event_kind: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub repository_generation: u64,
    #[prost(string, tag = "5")]
    pub aggregate_kind: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub aggregate_identity: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "7")]
    pub aggregate_version: ::core::option::Option<AggregateVersionV1>,
    #[prost(bytes = "bytes", tag = "8")]
    pub payload: ::bytes::Bytes,
    #[prost(message, optional, tag = "9")]
    pub committed_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(string, tag = "10")]
    pub actor: ::prost::alloc::string::String,
}

/// The private envelope, transport version 1.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrivateEnvelopeV1 {
    #[prost(uint32, tag = "1")]
    pub transport_version: u32,
    #[prost(string, tag = "2")]
    pub cell_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub placement_epoch: u64,
    #[prost(bytes = "bytes", tag = "4")]
    pub event_id: ::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "5")]
    pub repository: ::bytes::Bytes,
    #[prost(enumeration = "DeliveryClassV1", tag = "6")]
    pub delivery_class: i32,
    #[prost(string, tag = "7")]
    pub producer_instance_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "8")]
    pub produced_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(oneof = "private_envelope_v1::Body", tags = "9, 10")]
    pub body: ::core::option::Option<private_envelope_v1::Body>,
}

/// Nested items of [`PrivateEnvelopeV1`], laid out the way prost generates them.
pub mod private_envelope_v1 {
    /// The class-specific body. Exactly one, and it must agree with
    /// `delivery_class`.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        /// The serialized public `lore.notification.Event`.
        #[prost(bytes, tag = "9")]
        LoreEvent(::bytes::Bytes),
        #[prost(message, tag = "10")]
        DurableInvalidation(super::DurableInvalidationBodyV1),
    }
}

/// Result of one Publish attempt.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublishResultV1 {
    #[prost(uint32, tag = "1")]
    pub transport_version: u32,
    #[prost(enumeration = "PublishOutcomeV1", tag = "2")]
    pub outcome: i32,
    #[prost(bytes = "bytes", tag = "3")]
    pub event_id: ::bytes::Bytes,
    #[prost(string, tag = "4")]
    pub stream_identity: ::prost::alloc::string::String,
    #[prost(uint64, tag = "5")]
    pub stream_epoch: u64,
    #[prost(uint64, tag = "6")]
    pub broker_sequence: u64,
    #[prost(uint32, tag = "7")]
    pub publisher_contract_version: u32,
    #[prost(message, optional, tag = "8")]
    pub broker_accepted_at: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(enumeration = "PublishFailureClassV1", tag = "9")]
    pub failure_class: i32,
}

/// Client for the private publication service, in the shape
/// `tonic-prost-build` generates for a single unary method.
#[derive(Debug, Clone)]
pub struct PrivateNotificationServiceClient<T> {
    inner: tonic::client::Grpc<T>,
}

impl<T> PrivateNotificationServiceClient<T>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = ::bytes::Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner: tonic::client::Grpc::new(inner),
        }
    }

    /// Publishes one private envelope.
    ///
    /// # Errors
    /// Returns the transport or application [`tonic::Status`] verbatim. Callers
    /// classify it; this method never retries and never interprets.
    pub async fn publish(
        &mut self,
        request: tonic::Request<PrivateEnvelopeV1>,
    ) -> Result<tonic::Response<PublishResultV1>, tonic::Status> {
        self.inner.ready().await.map_err(|e| {
            tonic::Status::unavailable(format!(
                "private notification gateway not ready: {}",
                e.into()
            ))
        })?;
        let codec = tonic_prost::ProstCodec::default();
        let path = http::uri::PathAndQuery::from_static(PUBLISH_METHOD_PATH);
        let mut request = request;
        request
            .extensions_mut()
            .insert(tonic::codegen::GrpcMethod::new(
                PRIVATE_NOTIFICATION_SERVICE,
                "Publish",
            ));
        self.inner.unary(request, path, codec).await
    }
}

/// Encodes a message to its protobuf bytes.
pub fn encode<M: Message>(message: &M) -> ::bytes::Bytes {
    let mut buf = ::bytes::BytesMut::with_capacity(message.encoded_len());
    // `encode` only fails when the buffer lacks capacity, and `BytesMut` grows.
    let _ = message.encode(&mut buf);
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `.proto` beside this module, read at test time.
    ///
    /// The schema is maintained by hand in two artifacts, so the tests below
    /// pin **both sides independently**: the encoded tag bytes prove what
    /// `wire.rs` actually puts on the wire, and the `.proto` text proves the
    /// vendored schema of record declares the same thing. A change to either
    /// artifact alone fails here.
    const VENDORED_PROTO: &str = include_str!("proto/lorehub_notification_internal_v1.proto");

    /// Protobuf wire types this schema uses.
    const VARINT: u32 = 0;
    const LENGTH_DELIMITED: u32 = 2;

    /// The single tag byte protobuf emits for a field number below 16.
    ///
    /// Every field in this schema is 1..=10, so one byte is always enough. A
    /// field of 16 or more would need a two-byte varint and this helper would
    /// silently truncate, so it asserts rather than lie.
    fn tag_byte(field: u32, wire_type: u32) -> u8 {
        assert!(
            (1..16).contains(&field),
            "field {field} needs a multi-byte tag; this helper only covers 1..15"
        );
        assert!(
            wire_type < 8,
            "wire type {wire_type} is not a protobuf wire type"
        );
        ((field << 3) | wire_type) as u8
    }

    /// Asserts that `message`, which must have exactly one non-default field
    /// set, encodes that field under `field`/`wire_type`.
    ///
    /// This reads the bytes `wire.rs` really produces, so renumbering a
    /// `#[prost(tag = ...)]` attribute fails here even if the `.proto` is left
    /// untouched.
    fn assert_encodes_tag<M: Message>(message: &M, field: u32, wire_type: u32, what: &str) {
        let bytes = encode(message);
        assert_eq!(
            bytes.first().copied(),
            Some(tag_byte(field, wire_type)),
            "{what} did not encode as field {field} wire type {wire_type}; got bytes {bytes:?}"
        );
    }

    /// One field-number case: the `.proto` declaration, the field number, the
    /// wire type, and a setter that leaves only that field non-default.
    type FieldCase<M> = (&'static str, u32, u32, fn(&mut M));

    /// Returns the body of `message <name> {` / `enum <name> {` from the
    /// vendored `.proto`, so a field-number assertion is scoped to its own
    /// message rather than matched anywhere in the file.
    fn declaration_block<'a>(proto: &'a str, kind: &str, name: &str) -> &'a str {
        let header = format!("{kind} {name} {{");
        let start = proto
            .find(&header)
            .unwrap_or_else(|| panic!("vendored proto declares no `{header}`"))
            + header.len();
        let rest = &proto[start..];
        let mut depth = 1usize;
        for (offset, byte) in rest.bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &rest[..offset];
                    }
                }
                _ => {}
            }
        }
        panic!("`{kind} {name}` is not closed in the vendored proto")
    }

    /// Asserts the named message's own block declares `declaration`.
    fn assert_declares(kind: &str, name: &str, declaration: &str) {
        let block = declaration_block(VENDORED_PROTO, kind, name);
        assert!(
            block.contains(declaration),
            "`{kind} {name}` no longer declares `{declaration}`; wire.rs and the .proto have drifted"
        );
    }

    fn empty_envelope() -> PrivateEnvelopeV1 {
        PrivateEnvelopeV1 {
            transport_version: 0,
            cell_id: String::new(),
            placement_epoch: 0,
            event_id: ::bytes::Bytes::new(),
            repository: ::bytes::Bytes::new(),
            delivery_class: 0,
            producer_instance_id: String::new(),
            produced_at: None,
            body: None,
        }
    }

    #[test]
    fn the_vendored_proto_pins_the_method_path_this_client_calls() {
        assert!(VENDORED_PROTO.contains("package lorehub.notification.internal.v1;"));
        assert!(VENDORED_PROTO.contains("service PrivateNotificationService {"));
        assert!(
            VENDORED_PROTO.contains("rpc Publish (PrivateEnvelopeV1) returns (PublishResultV1);")
        );
        assert_eq!(
            PUBLISH_METHOD_PATH,
            "/lorehub.notification.internal.v1.PrivateNotificationService/Publish"
        );
        assert!(VENDORED_PROTO.contains(PUBLISH_METHOD_PATH));
        assert_eq!(
            PRIVATE_NOTIFICATION_SERVICE,
            "lorehub.notification.internal.v1.PrivateNotificationService"
        );
    }

    #[test]
    fn every_envelope_field_encodes_under_the_number_the_proto_declares() {
        let cases: [FieldCase<PrivateEnvelopeV1>; 10] = [
            ("uint32 transport_version = 1;", 1, VARINT, |e| {
                e.transport_version = 1;
            }),
            ("string cell_id = 2;", 2, LENGTH_DELIMITED, |e| {
                e.cell_id = "a".to_string();
            }),
            ("uint64 placement_epoch = 3;", 3, VARINT, |e| {
                e.placement_epoch = 1;
            }),
            ("bytes event_id = 4;", 4, LENGTH_DELIMITED, |e| {
                e.event_id = ::bytes::Bytes::from_static(&[1]);
            }),
            ("bytes repository = 5;", 5, LENGTH_DELIMITED, |e| {
                e.repository = ::bytes::Bytes::from_static(&[1]);
            }),
            ("DeliveryClassV1 delivery_class = 6;", 6, VARINT, |e| {
                e.delivery_class = DeliveryClassV1::LiveHint as i32;
            }),
            (
                "string producer_instance_id = 7;",
                7,
                LENGTH_DELIMITED,
                |e| e.producer_instance_id = "a".to_string(),
            ),
            (
                "google.protobuf.Timestamp produced_at = 8;",
                8,
                LENGTH_DELIMITED,
                |e| e.produced_at = Some(::prost_types::Timestamp::default()),
            ),
            ("bytes lore_event = 9;", 9, LENGTH_DELIMITED, |e| {
                e.body = Some(private_envelope_v1::Body::LoreEvent(
                    ::bytes::Bytes::from_static(&[1]),
                ));
            }),
            (
                "DurableInvalidationBodyV1 durable_invalidation = 10;",
                10,
                LENGTH_DELIMITED,
                |e| {
                    e.body = Some(private_envelope_v1::Body::DurableInvalidation(
                        DurableInvalidationBodyV1::default(),
                    ));
                },
            ),
        ];
        for (declaration, field, wire_type, set) in cases {
            assert_declares("message", "PrivateEnvelopeV1", declaration);
            let mut envelope = empty_envelope();
            set(&mut envelope);
            assert_encodes_tag(&envelope, field, wire_type, declaration);
        }
    }

    #[test]
    fn every_durable_body_field_encodes_under_the_number_the_proto_declares() {
        let cases: [FieldCase<DurableInvalidationBodyV1>; 10] = [
            ("uint32 payload_version = 1;", 1, VARINT, |b| {
                b.payload_version = 1;
            }),
            ("bytes idempotency_key = 2;", 2, LENGTH_DELIMITED, |b| {
                b.idempotency_key = ::bytes::Bytes::from_static(&[1]);
            }),
            ("string event_kind = 3;", 3, LENGTH_DELIMITED, |b| {
                b.event_kind = "a".to_string();
            }),
            ("uint64 repository_generation = 4;", 4, VARINT, |b| {
                b.repository_generation = 1;
            }),
            ("string aggregate_kind = 5;", 5, LENGTH_DELIMITED, |b| {
                b.aggregate_kind = "a".to_string();
            }),
            ("string aggregate_identity = 6;", 6, LENGTH_DELIMITED, |b| {
                b.aggregate_identity = "a".to_string();
            }),
            (
                "AggregateVersionV1 aggregate_version = 7;",
                7,
                LENGTH_DELIMITED,
                |b| b.aggregate_version = Some(AggregateVersionV1::default()),
            ),
            ("bytes payload = 8;", 8, LENGTH_DELIMITED, |b| {
                b.payload = ::bytes::Bytes::from_static(&[1]);
            }),
            (
                "google.protobuf.Timestamp committed_at = 9;",
                9,
                LENGTH_DELIMITED,
                |b| b.committed_at = Some(::prost_types::Timestamp::default()),
            ),
            ("string actor = 10;", 10, LENGTH_DELIMITED, |b| {
                b.actor = "a".to_string();
            }),
        ];
        for (declaration, field, wire_type, set) in cases {
            assert_declares("message", "DurableInvalidationBodyV1", declaration);
            let mut body = DurableInvalidationBodyV1::default();
            set(&mut body);
            assert_encodes_tag(&body, field, wire_type, declaration);
        }
    }

    #[test]
    fn every_aggregate_version_field_encodes_under_the_number_the_proto_declares() {
        let cases: [FieldCase<AggregateVersionV1>; 2] = [
            ("uint64 ordinal = 1;", 1, VARINT, |v| v.ordinal = 1),
            ("string identity = 2;", 2, LENGTH_DELIMITED, |v| {
                v.identity = "a".to_string();
            }),
        ];
        for (declaration, field, wire_type, set) in cases {
            assert_declares("message", "AggregateVersionV1", declaration);
            let mut version = AggregateVersionV1::default();
            set(&mut version);
            assert_encodes_tag(&version, field, wire_type, declaration);
        }
    }

    #[test]
    fn every_publish_result_field_encodes_under_the_number_the_proto_declares() {
        let cases: [FieldCase<PublishResultV1>; 9] = [
            ("uint32 transport_version = 1;", 1, VARINT, |r| {
                r.transport_version = 1;
            }),
            ("PublishOutcomeV1 outcome = 2;", 2, VARINT, |r| {
                r.outcome = PublishOutcomeV1::Accepted as i32;
            }),
            ("bytes event_id = 3;", 3, LENGTH_DELIMITED, |r| {
                r.event_id = ::bytes::Bytes::from_static(&[1]);
            }),
            ("string stream_identity = 4;", 4, LENGTH_DELIMITED, |r| {
                r.stream_identity = "a".to_string();
            }),
            ("uint64 stream_epoch = 5;", 5, VARINT, |r| {
                r.stream_epoch = 1
            }),
            ("uint64 broker_sequence = 6;", 6, VARINT, |r| {
                r.broker_sequence = 1;
            }),
            ("uint32 publisher_contract_version = 7;", 7, VARINT, |r| {
                r.publisher_contract_version = 1;
            }),
            (
                "google.protobuf.Timestamp broker_accepted_at = 8;",
                8,
                LENGTH_DELIMITED,
                |r| r.broker_accepted_at = Some(::prost_types::Timestamp::default()),
            ),
            ("PublishFailureClassV1 failure_class = 9;", 9, VARINT, |r| {
                r.failure_class = PublishFailureClassV1::StreamFull as i32;
            }),
        ];
        for (declaration, field, wire_type, set) in cases {
            assert_declares("message", "PublishResultV1", declaration);
            let mut result = PublishResultV1::default();
            set(&mut result);
            assert_encodes_tag(&result, field, wire_type, declaration);
        }
    }

    #[test]
    fn every_enum_value_matches_the_vendored_proto() {
        let delivery: [(&str, DeliveryClassV1); 4] = [
            (
                "DELIVERY_CLASS_V1_UNSPECIFIED = 0;",
                DeliveryClassV1::Unspecified,
            ),
            ("LIVE_HINT = 1;", DeliveryClassV1::LiveHint),
            (
                "DURABLE_INVALIDATION = 2;",
                DeliveryClassV1::DurableInvalidation,
            ),
            (
                "SHADOW_OBSERVATION = 3;",
                DeliveryClassV1::ShadowObservation,
            ),
        ];
        for (declaration, value) in delivery {
            assert_declares("enum", "DeliveryClassV1", declaration);
            assert_eq!(declared_value(declaration), value as i32, "{declaration}");
            assert_eq!(DeliveryClassV1::try_from(value as i32), Ok(value));
        }

        let outcome: [(&str, PublishOutcomeV1); 5] = [
            (
                "PUBLISH_OUTCOME_V1_UNSPECIFIED = 0;",
                PublishOutcomeV1::Unspecified,
            ),
            ("ACCEPTED = 1;", PublishOutcomeV1::Accepted),
            ("RETRYABLE = 2;", PublishOutcomeV1::Retryable),
            ("TIMEOUT = 3;", PublishOutcomeV1::Timeout),
            ("TERMINAL = 4;", PublishOutcomeV1::Terminal),
        ];
        for (declaration, value) in outcome {
            assert_declares("enum", "PublishOutcomeV1", declaration);
            assert_eq!(declared_value(declaration), value as i32, "{declaration}");
            assert_eq!(PublishOutcomeV1::try_from(value as i32), Ok(value));
        }

        let failure: [(&str, PublishFailureClassV1); 6] = [
            (
                "PUBLISH_FAILURE_CLASS_V1_UNSPECIFIED = 0;",
                PublishFailureClassV1::Unspecified,
            ),
            (
                "BROKER_UNAVAILABLE = 1;",
                PublishFailureClassV1::BrokerUnavailable,
            ),
            (
                "PLACEMENT_QUIESCING = 2;",
                PublishFailureClassV1::PlacementQuiescing,
            ),
            ("STREAM_FULL = 3;", PublishFailureClassV1::StreamFull),
            ("SCOPE_MISMATCH = 4;", PublishFailureClassV1::ScopeMismatch),
            (
                "UNSUPPORTED_SCHEMA = 5;",
                PublishFailureClassV1::UnsupportedSchema,
            ),
        ];
        for (declaration, value) in failure {
            assert_declares("enum", "PublishFailureClassV1", declaration);
            assert_eq!(declared_value(declaration), value as i32, "{declaration}");
            assert_eq!(PublishFailureClassV1::try_from(value as i32), Ok(value));
        }
    }

    /// Parses the numeric value out of a `NAME = N;` proto enum declaration.
    fn declared_value(declaration: &str) -> i32 {
        declaration
            .rsplit_once("= ")
            .and_then(|(_, tail)| tail.trim_end_matches(';').parse().ok())
            .unwrap_or_else(|| panic!("`{declaration}` is not a `NAME = N;` declaration"))
    }

    /// A guard for the guards: the block extractor must actually scope, or
    /// every assertion above degrades to a whole-file substring search.
    #[test]
    fn the_declaration_block_extractor_really_scopes() {
        let envelope = declaration_block(VENDORED_PROTO, "message", "PrivateEnvelopeV1");
        assert!(envelope.contains("uint64 placement_epoch = 3;"));
        // `payload_version = 1` belongs to the durable body, not the envelope.
        assert!(!envelope.contains("uint32 payload_version = 1;"));
        let body = declaration_block(VENDORED_PROTO, "message", "DurableInvalidationBodyV1");
        assert!(body.contains("uint32 payload_version = 1;"));
        assert!(!body.contains("uint64 placement_epoch = 3;"));
    }

    #[test]
    fn a_renumbered_field_would_be_caught_by_the_tag_assertion() {
        // Proves `assert_encodes_tag` discriminates rather than always passing:
        // `cell_id` is field 2, so asserting field 3 must fail.
        let mut envelope = empty_envelope();
        envelope.cell_id = "a".to_string();
        let bytes = encode(&envelope);
        assert_eq!(bytes.first().copied(), Some(tag_byte(2, LENGTH_DELIMITED)));
        assert_ne!(bytes.first().copied(), Some(tag_byte(3, LENGTH_DELIMITED)));
    }

    #[test]
    fn an_envelope_round_trips_through_protobuf() {
        let envelope = PrivateEnvelopeV1 {
            transport_version: TRANSPORT_VERSION,
            cell_id: "sfo3-cell-a".to_string(),
            placement_epoch: 12,
            event_id: ::bytes::Bytes::from_static(&[7u8; 16]),
            repository: ::bytes::Bytes::from_static(&[3u8; 16]),
            delivery_class: DeliveryClassV1::LiveHint as i32,
            producer_instance_id: "loreserver-sfo3-cell-a-2".to_string(),
            produced_at: None,
            body: Some(private_envelope_v1::Body::LoreEvent(
                ::bytes::Bytes::from_static(b"opaque"),
            )),
        };
        let bytes = encode(&envelope);
        let decoded = PrivateEnvelopeV1::decode(bytes).expect("round trip");
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn a_durable_body_round_trips_through_protobuf() {
        let envelope = PrivateEnvelopeV1 {
            transport_version: TRANSPORT_VERSION,
            cell_id: "sfo3-cell-a".to_string(),
            placement_epoch: 12,
            event_id: ::bytes::Bytes::from_static(&[9u8; 16]),
            repository: ::bytes::Bytes::from_static(&[4u8; 16]),
            delivery_class: DeliveryClassV1::DurableInvalidation as i32,
            producer_instance_id: "loreserver-sfo3-cell-a-2".to_string(),
            produced_at: None,
            body: Some(private_envelope_v1::Body::DurableInvalidation(
                DurableInvalidationBodyV1 {
                    payload_version: DURABLE_PAYLOAD_VERSION,
                    idempotency_key: ::bytes::Bytes::from_static(&[1u8; 32]),
                    event_kind: "branch.tip_advanced".to_string(),
                    repository_generation: 8814,
                    aggregate_kind: "branch".to_string(),
                    aggregate_identity: "b1c2d3e4f5061728".to_string(),
                    aggregate_version: Some(AggregateVersionV1 {
                        ordinal: 417,
                        identity: "revision:2c9f0a7b4d1e6358a0b1c2d3e4f50617".to_string(),
                    }),
                    payload: ::bytes::Bytes::from_static(b"{}"),
                    committed_at: None,
                    actor: String::new(),
                },
            )),
        };
        let decoded = PrivateEnvelopeV1::decode(encode(&envelope)).expect("round trip");
        assert_eq!(envelope, decoded);
    }
}

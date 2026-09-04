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

/// The pinned publication method path.
pub const PUBLISH_METHOD_PATH: &str =
    "/lorehub.notification.internal.v1.PrivateNotificationService/Publish";

/// The pinned durable receiver stream, frozen by contract amendment A-24.
pub const CONSUME_METHOD_PATH: &str =
    "/lorehub.notification.internal.v1.PrivateNotificationService/Consume";

/// The pinned durable acknowledgement path, frozen by contract amendment A-24.
pub const ACK_METHOD_PATH: &str =
    "/lorehub.notification.internal.v1.PrivateNotificationService/Ack";

/// Most sequences one [`AckV1`] may carry, from A-24.
pub const MAX_ACKED_SEQUENCES: usize = 1024;

/// Longest `durable_consumer_name` the gateway derives. Exactly 44 ASCII
/// characters by A-24's byte-exact derivation, so this is an equality, not a
/// ceiling.
pub const DURABLE_CONSUMER_NAME_LEN: usize = 44;

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

// ---------------------------------------------------------------------------
// The private receiver stream (contract amendment A-24)
// ---------------------------------------------------------------------------

/// Resume from a position a previous generation already captured.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CapturedPositionV1 {
    #[prost(uint64, tag = "1")]
    pub start_sequence: u64,
}

/// Capture a new durable consumer at the current edge of the request's
/// placement. Empty by construction.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CaptureNewV1 {}

/// Open one durable receiver stream.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumeRequestV1 {
    #[prost(uint32, tag = "1")]
    pub transport_version: u32,
    #[prost(string, tag = "2")]
    pub cell_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub receiver_identity: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub membership_generation: u64,
    #[prost(string, tag = "5")]
    pub stream_identity: ::prost::alloc::string::String,
    #[prost(uint64, tag = "6")]
    pub stream_epoch: u64,
    #[prost(uint64, tag = "7")]
    pub placement_revision: u64,
    #[prost(oneof = "consume_request_v1::Start", tags = "8, 9")]
    pub start: ::core::option::Option<consume_request_v1::Start>,
}

/// Nested items of [`ConsumeRequestV1`].
pub mod consume_request_v1 {
    /// Exactly one start mode. An unset oneof is a malformed request.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Start {
        #[prost(message, tag = "8")]
        CapturedPosition(super::CapturedPositionV1),
        #[prost(message, tag = "9")]
        CaptureNew(super::CaptureNewV1),
    }
}

/// The first message on every Consume stream, in both start modes.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumeCaptureV1 {
    #[prost(string, tag = "1")]
    pub stream_identity: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub stream_epoch: u64,
    #[prost(uint64, tag = "3")]
    pub start_sequence: u64,
    #[prost(string, tag = "4")]
    pub durable_consumer_name: ::prost::alloc::string::String,
    #[prost(uint64, tag = "5")]
    pub placement_revision: u64,
}

/// One durable event delivered in broker order.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumeDeliveryV1 {
    #[prost(message, optional, tag = "1")]
    pub envelope: ::core::option::Option<PrivateEnvelopeV1>,
    #[prost(uint64, tag = "2")]
    pub broker_sequence: u64,
    #[prost(string, tag = "3")]
    pub stream_identity: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub stream_epoch: u64,
    #[prost(uint32, tag = "5")]
    pub redelivery_count: u32,
}

/// Nothing pending at or before the current edge.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumeCaughtUpV1 {
    #[prost(uint64, tag = "1")]
    pub edge_sequence: u64,
}

/// One message on the Consume stream.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumeEventV1 {
    #[prost(uint32, tag = "1")]
    pub transport_version: u32,
    #[prost(oneof = "consume_event_v1::Event", tags = "2, 3, 4")]
    pub event: ::core::option::Option<consume_event_v1::Event>,
}

/// Nested items of [`ConsumeEventV1`].
pub mod consume_event_v1 {
    /// Exactly one arm. An unset oneof is a malformed server response.
    ///
    /// The `Delivery` arm carries a whole `PrivateEnvelopeV1` and the other two
    /// are a handful of scalars, so clippy reads the size difference as a
    /// mistake. Boxing it would fix the lint and break the file's purpose: this
    /// module is a verbatim transcription of what `tonic-prost-build` emits for
    /// the schema of record, and a boxed variant is not that shape. The
    /// receiver already boxes the value it keeps, in
    /// [`super::super::stream::StreamDelivery`], which is where the size
    /// actually matters.
    #[allow(
        clippy::large_enum_variant,
        reason = "a hand transcription of generated prost output; boxing would diverge from the \
                  vendored schema this module exists to mirror"
    )]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Event {
        #[prost(message, tag = "2")]
        Capture(super::ConsumeCaptureV1),
        #[prost(message, tag = "3")]
        Delivery(super::ConsumeDeliveryV1),
        #[prost(message, tag = "4")]
        CaughtUp(super::ConsumeCaughtUpV1),
    }
}

/// One unresolved sequence range, inclusive at both ends.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SequenceGapV1 {
    #[prost(uint64, tag = "1")]
    pub from: u64,
    #[prost(uint64, tag = "2")]
    pub to: u64,
}

/// One parked poison disposition.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoisonEntryV1 {
    #[prost(uint64, tag = "1")]
    pub broker_sequence: u64,
    #[prost(string, tag = "2")]
    pub poison_class: ::prost::alloc::string::String,
}

/// Acknowledge applied sequences and report this generation's frontier.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AckV1 {
    #[prost(uint32, tag = "1")]
    pub transport_version: u32,
    #[prost(string, tag = "2")]
    pub cell_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub receiver_identity: ::prost::alloc::string::String,
    #[prost(uint64, tag = "4")]
    pub membership_generation: u64,
    #[prost(string, tag = "5")]
    pub stream_identity: ::prost::alloc::string::String,
    #[prost(uint64, tag = "6")]
    pub stream_epoch: u64,
    #[prost(uint64, repeated, tag = "7")]
    pub acked_sequences: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, tag = "8")]
    pub contiguous_frontier: u64,
    #[prost(message, repeated, tag = "9")]
    pub gaps: ::prost::alloc::vec::Vec<SequenceGapV1>,
    #[prost(message, repeated, tag = "10")]
    pub poison: ::prost::alloc::vec::Vec<PoisonEntryV1>,
}

/// Outcome class of one Ack call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AckOutcomeV1 {
    Unspecified = 0,
    AllAccepted = 1,
    PartiallyAccepted = 2,
    Retryable = 3,
    Terminal = 4,
}

/// Why a receiver request was refused. Shared by Consume and Ack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ReceiverErrorV1 {
    Unspecified = 0,
    MalformedReceiverRequest = 1,
    UnsupportedReceiverSchema = 2,
    UnauthenticatedReceiver = 3,
    UnauthorizedReceiverRole = 4,
    CrossCellReceiver = 5,
    ReceiverScopeMismatch = 6,
    ReceiverPlacementMismatch = 7,
    ReceiverEpochMismatch = 8,
    StaleMembershipGeneration = 9,
    UnknownDurableConsumer = 10,
    ReceiverBrokerUnavailable = 11,
}

/// Result of one Ack call.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AckResultV1 {
    #[prost(uint32, tag = "1")]
    pub transport_version: u32,
    #[prost(enumeration = "AckOutcomeV1", tag = "2")]
    pub outcome: i32,
    #[prost(uint64, repeated, tag = "3")]
    pub accepted_sequences: ::prost::alloc::vec::Vec<u64>,
    #[prost(uint64, repeated, tag = "4")]
    pub rejected_sequences: ::prost::alloc::vec::Vec<u64>,
    #[prost(enumeration = "ReceiverErrorV1", tag = "5")]
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

    /// Opens one durable receiver stream.
    ///
    /// The first message is always a `ConsumeCaptureV1`; deliveries and
    /// caught-up answers follow. Caller role is `receiver`.
    ///
    /// # Errors
    /// Returns the transport or application [`tonic::Status`] verbatim. A
    /// receiver classifies it differently from a publisher, so this method
    /// never interprets it — see `super::stream`'s status mapping.
    pub async fn consume(
        &mut self,
        request: tonic::Request<ConsumeRequestV1>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<ConsumeEventV1>>, tonic::Status> {
        self.inner.ready().await.map_err(|e| {
            tonic::Status::unavailable(format!(
                "private notification gateway not ready: {}",
                e.into()
            ))
        })?;
        let codec = tonic_prost::ProstCodec::default();
        let path = http::uri::PathAndQuery::from_static(CONSUME_METHOD_PATH);
        let mut request = request;
        request
            .extensions_mut()
            .insert(tonic::codegen::GrpcMethod::new(
                PRIVATE_NOTIFICATION_SERVICE,
                "Consume",
            ));
        self.inner.server_streaming(request, path, codec).await
    }

    /// Acknowledges applied sequences and reports the generation's frontier.
    ///
    /// # Errors
    /// Returns the transport or application [`tonic::Status`] verbatim.
    pub async fn ack(
        &mut self,
        request: tonic::Request<AckV1>,
    ) -> Result<tonic::Response<AckResultV1>, tonic::Status> {
        self.inner.ready().await.map_err(|e| {
            tonic::Status::unavailable(format!(
                "private notification gateway not ready: {}",
                e.into()
            ))
        })?;
        let codec = tonic_prost::ProstCodec::default();
        let path = http::uri::PathAndQuery::from_static(ACK_METHOD_PATH);
        let mut request = request;
        request
            .extensions_mut()
            .insert(tonic::codegen::GrpcMethod::new(
                PRIVATE_NOTIFICATION_SERVICE,
                "Ack",
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

    /// Every receiver-stream field, pinned against the vendored `.proto`.
    ///
    /// A-24 numbers each of these explicitly, and the two copies of the schema
    /// are byte-identical below their headers by contract. So a renumbering
    /// that compiles here has to fail somewhere, and this is that somewhere.
    #[test]
    fn every_receiver_field_matches_the_vendored_proto() {
        let fields: [(&str, &str, &str); 34] = [
            ("CapturedPositionV1", "uint64 start_sequence = 1;", "1"),
            ("ConsumeRequestV1", "uint32 transport_version = 1;", "1"),
            ("ConsumeRequestV1", "string cell_id = 2;", "2"),
            ("ConsumeRequestV1", "string receiver_identity = 3;", "3"),
            ("ConsumeRequestV1", "uint64 membership_generation = 4;", "4"),
            ("ConsumeRequestV1", "string stream_identity = 5;", "5"),
            ("ConsumeRequestV1", "uint64 stream_epoch = 6;", "6"),
            ("ConsumeRequestV1", "uint64 placement_revision = 7;", "7"),
            (
                "ConsumeRequestV1",
                "CapturedPositionV1 captured_position = 8;",
                "8",
            ),
            ("ConsumeRequestV1", "CaptureNewV1 capture_new = 9;", "9"),
            ("ConsumeCaptureV1", "string stream_identity = 1;", "1"),
            ("ConsumeCaptureV1", "uint64 stream_epoch = 2;", "2"),
            ("ConsumeCaptureV1", "uint64 start_sequence = 3;", "3"),
            ("ConsumeCaptureV1", "string durable_consumer_name = 4;", "4"),
            ("ConsumeCaptureV1", "uint64 placement_revision = 5;", "5"),
            ("ConsumeDeliveryV1", "PrivateEnvelopeV1 envelope = 1;", "1"),
            ("ConsumeDeliveryV1", "uint64 broker_sequence = 2;", "2"),
            ("ConsumeDeliveryV1", "string stream_identity = 3;", "3"),
            ("ConsumeDeliveryV1", "uint64 stream_epoch = 4;", "4"),
            ("ConsumeDeliveryV1", "uint32 redelivery_count = 5;", "5"),
            ("ConsumeCaughtUpV1", "uint64 edge_sequence = 1;", "1"),
            ("ConsumeEventV1", "uint32 transport_version = 1;", "1"),
            ("ConsumeEventV1", "ConsumeCaptureV1 capture = 2;", "2"),
            ("ConsumeEventV1", "ConsumeDeliveryV1 delivery = 3;", "3"),
            ("ConsumeEventV1", "ConsumeCaughtUpV1 caught_up = 4;", "4"),
            ("SequenceGapV1", "uint64 from = 1;", "1"),
            ("SequenceGapV1", "uint64 to = 2;", "2"),
            ("PoisonEntryV1", "uint64 broker_sequence = 1;", "1"),
            ("PoisonEntryV1", "string poison_class = 2;", "2"),
            ("AckV1", "repeated uint64 acked_sequences = 7;", "7"),
            ("AckV1", "uint64 contiguous_frontier = 8;", "8"),
            ("AckResultV1", "AckOutcomeV1 outcome = 2;", "2"),
            (
                "AckResultV1",
                "repeated uint64 accepted_sequences = 3;",
                "3",
            ),
            ("AckResultV1", "ReceiverErrorV1 failure_class = 5;", "5"),
        ];
        for (message, declaration, number) in fields {
            assert_declares("message", message, declaration);
            assert!(
                declaration.ends_with(&format!("= {number};")),
                "{declaration} does not carry field number {number}"
            );
        }
    }

    /// The two new enums, value by value. `ReceiverErrorV1` in particular is
    /// what the gateway's status mapping is derived from, so an off-by-one
    /// here would silently reclassify a refusal as a retry.
    #[test]
    fn every_receiver_enum_value_matches_the_vendored_proto() {
        let outcomes: [(&str, AckOutcomeV1); 5] = [
            ("ACK_OUTCOME_V1_UNSPECIFIED = 0;", AckOutcomeV1::Unspecified),
            ("ACK_ALL_ACCEPTED = 1;", AckOutcomeV1::AllAccepted),
            (
                "ACK_PARTIALLY_ACCEPTED = 2;",
                AckOutcomeV1::PartiallyAccepted,
            ),
            ("ACK_RETRYABLE = 3;", AckOutcomeV1::Retryable),
            ("ACK_TERMINAL = 4;", AckOutcomeV1::Terminal),
        ];
        for (declaration, value) in outcomes {
            assert_declares("enum", "AckOutcomeV1", declaration);
            assert_eq!(declared_value(declaration), value as i32, "{declaration}");
            assert_eq!(AckOutcomeV1::try_from(value as i32), Ok(value));
        }

        let errors: [(&str, ReceiverErrorV1); 12] = [
            (
                "RECEIVER_ERROR_V1_UNSPECIFIED = 0;",
                ReceiverErrorV1::Unspecified,
            ),
            (
                "MALFORMED_RECEIVER_REQUEST_V1 = 1;",
                ReceiverErrorV1::MalformedReceiverRequest,
            ),
            (
                "UNSUPPORTED_RECEIVER_SCHEMA_V1 = 2;",
                ReceiverErrorV1::UnsupportedReceiverSchema,
            ),
            (
                "UNAUTHENTICATED_RECEIVER_V1 = 3;",
                ReceiverErrorV1::UnauthenticatedReceiver,
            ),
            (
                "UNAUTHORIZED_RECEIVER_ROLE_V1 = 4;",
                ReceiverErrorV1::UnauthorizedReceiverRole,
            ),
            (
                "CROSS_CELL_RECEIVER_V1 = 5;",
                ReceiverErrorV1::CrossCellReceiver,
            ),
            (
                "RECEIVER_SCOPE_MISMATCH_V1 = 6;",
                ReceiverErrorV1::ReceiverScopeMismatch,
            ),
            (
                "RECEIVER_PLACEMENT_MISMATCH_V1 = 7;",
                ReceiverErrorV1::ReceiverPlacementMismatch,
            ),
            (
                "RECEIVER_EPOCH_MISMATCH_V1 = 8;",
                ReceiverErrorV1::ReceiverEpochMismatch,
            ),
            (
                "STALE_MEMBERSHIP_GENERATION_V1 = 9;",
                ReceiverErrorV1::StaleMembershipGeneration,
            ),
            (
                "UNKNOWN_DURABLE_CONSUMER_V1 = 10;",
                ReceiverErrorV1::UnknownDurableConsumer,
            ),
            (
                "RECEIVER_BROKER_UNAVAILABLE_V1 = 11;",
                ReceiverErrorV1::ReceiverBrokerUnavailable,
            ),
        ];
        for (declaration, value) in errors {
            assert_declares("enum", "ReceiverErrorV1", declaration);
            assert_eq!(declared_value(declaration), value as i32, "{declaration}");
            assert_eq!(ReceiverErrorV1::try_from(value as i32), Ok(value));
        }
    }

    #[test]
    fn the_vendored_proto_pins_both_receiver_method_paths() {
        assert!(
            VENDORED_PROTO
                .contains("rpc Consume (ConsumeRequestV1) returns (stream ConsumeEventV1);")
        );
        assert!(VENDORED_PROTO.contains("rpc Ack (AckV1) returns (AckResultV1);"));
        assert_eq!(
            CONSUME_METHOD_PATH,
            "/lorehub.notification.internal.v1.PrivateNotificationService/Consume"
        );
        assert_eq!(
            ACK_METHOD_PATH,
            "/lorehub.notification.internal.v1.PrivateNotificationService/Ack"
        );
        assert!(VENDORED_PROTO.contains(CONSUME_METHOD_PATH));
        assert!(VENDORED_PROTO.contains(ACK_METHOD_PATH));

        // The two bounds this module names as constants, against the schema's
        // own prose. Neither is a field number, so nothing else would catch a
        // change to them.
        assert_eq!(MAX_ACKED_SEQUENCES, 1024);
        assert!(
            declaration_block(VENDORED_PROTO, "message", "AckV1").contains("1 to 1024 entries"),
            "the acknowledgement batch bound moved; MAX_ACKED_SEQUENCES is stale"
        );
        assert_eq!(DURABLE_CONSUMER_NAME_LEN, 44);
        assert!(
            declaration_block(VENDORED_PROTO, "message", "ConsumeCaptureV1")
                .contains("Exactly 44 ASCII"),
            "the durable consumer name width moved; DURABLE_CONSUMER_NAME_LEN is stale"
        );
    }

    /// A `ConsumeEventV1` round trips, including the oneof arm that carries a
    /// whole envelope. This is the message the receiver decodes on every
    /// delivery, so a tag error here is a decode failure in production.
    #[test]
    fn a_consume_delivery_round_trips_through_protobuf() {
        let event = ConsumeEventV1 {
            transport_version: TRANSPORT_VERSION,
            event: Some(consume_event_v1::Event::Delivery(ConsumeDeliveryV1 {
                envelope: Some(PrivateEnvelopeV1 {
                    transport_version: TRANSPORT_VERSION,
                    cell_id: "sfo3-cell-a".to_string(),
                    ..Default::default()
                }),
                broker_sequence: 918,
                stream_identity: "DURABLE-sfo3-cell-a".to_string(),
                stream_epoch: 8,
                redelivery_count: 1,
            })),
        };
        let decoded = ConsumeEventV1::decode(encode(&event)).expect("a consume event round trips");
        assert_eq!(decoded, event);
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

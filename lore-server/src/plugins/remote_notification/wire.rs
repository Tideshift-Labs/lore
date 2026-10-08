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

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Hand-maintained transcription of the frozen `StreamResetService` contract,
//! plus its canonical derivation (WP-119 Step C).
//!
//! FORK-LOCAL (Tideshift, CR-032 / WP-119). Pinned method path:
//!   `/lorehub.notification.internal.v1.StreamResetService/ReportStreamReset`
//!
//! WP-111 vendored the private notification `.proto` under
//! `plugins/remote_notification/proto/`, and its closing comment says the
//! `StreamResetService` is WP-119's and "not vendored this round". This module
//! is WP-119's own transcription of it. It deliberately does **not** edit
//! WP-111's `.proto` or `wire.rs`: those are that component's source of record,
//! and the two lanes share a contract rather than a file.
//!
//! Unlike WP-111's envelope, nothing here is a conservative reading. The
//! notification-plane contract's Phase 0 freeze gives every field number, every
//! enum value, the exact digest preimage, and the UUID namespace, so the
//! transcription below is transcription rather than design. Field numbers are
//! part of the freeze: a message described only by field names is not
//! freezable, and the unit tests (`tests/unit/event_relay/reset_wire.rs`) pin the
//! numbers this module actually puts on the wire against that text.
//!
//! # `protoc` is not involved
//!
//! `protoc` is optional in this workspace and `lore-server`'s `build.rs` is
//! shared wiring, so this is written by hand in the shape `tonic-prost-build`
//! emits for one unary method — the same choice, for the same reasons, that
//! WP-111 made one step earlier.
//!
//! # The derivation is here, not in `lore-postgres`
//!
//! `reset_fingerprint` and `detection_id` are wire facts: they are computed from
//! the request's own fields and validated **once**, before any durable lookup.
//! A fingerprint that does not recompute, a detection ID that is not the `UUIDv5`
//! of it, or a fingerprint that is not 32 bytes is `MALFORMED_REPORT_V1` — not a
//! successor failure and not a stored-record mismatch. Putting the derivation
//! next to the storage would have invited the opposite order.

use bytes::BufMut;
use prost::Message;
use ring::digest;
use tonic::codegen::Body;
use tonic::codegen::StdError;
use tonic::codegen::*;
use uuid::Uuid;

/// Fully-qualified name of the frozen internal service.
pub const STREAM_RESET_SERVICE: &str = "lorehub.notification.internal.v1.StreamResetService";

/// The one pinned method path this service serves.
pub const REPORT_STREAM_RESET_METHOD_PATH: &str =
    "/lorehub.notification.internal.v1.StreamResetService/ReportStreamReset";

/// `schema_version`, fixed to 1 on both the request and the acknowledgement.
pub const RESET_SCHEMA_VERSION: u32 = 1;

/// Domain prefix of the fingerprint preimage: ASCII `reset-fingerprint-v1`
/// followed by one `0x00` byte, contributing 21 bytes and **not** itself
/// length-prefixed.
pub const FINGERPRINT_DOMAIN: &[u8] = b"reset-fingerprint-v1\0";

/// `UUIDv5` namespace for `detection_id`.
pub const DETECTION_ID_NAMESPACE: Uuid = Uuid::from_u128(0xc6a4_2b98_2d15_5e0f_8a77_7a63_04c9_b4dd);

/// `evidence_id`, at most 64 characters.
pub const MAX_EVIDENCE_ID_CHARS: usize = 64;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Why the broker reset. The zero value exists because proto3 requires one and
/// never appears in a valid report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ResetReasonV1 {
    /// Never valid on the wire; a report carrying it is `MALFORMED_REPORT_V1`.
    Unspecified = 0,
    /// The stream identity changed.
    StreamIdentityChanged = 1,
    /// The identity is unchanged and the epoch advanced.
    StreamEpochAdvanced = 2,
    /// A sequence rollback. A restored stream may keep its identity.
    SequenceRollback = 3,
    /// The broker was restored from a backup.
    BrokerRestore = 4,
    /// An operator moved the stream deliberately.
    OperatorReset = 5,
}

/// The protected error detail enum. Every value maps to exactly one gRPC code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ResetReportErrorV1 {
    /// Never returned.
    Unspecified = 0,
    /// Derivation failed, a field is out of bounds, or the reason is
    /// unspecified. `INVALID_ARGUMENT`.
    MalformedReport = 1,
    /// No valid internal-service mTLS identity. `UNAUTHENTICATED`.
    UnauthenticatedReport = 2,
    /// Authenticated but not an authorized emitter. `PERMISSION_DENIED`.
    UnauthorizedReport = 3,
    /// The principal maps to another cell. `PERMISSION_DENIED`.
    CrossCellReport = 4,
    /// A previously unseen report whose placement revision is stale.
    /// `FAILED_PRECONDITION`.
    PlacementMismatch = 5,
    /// A previously unseen report whose old identity/epoch is no longer
    /// current. `FAILED_PRECONDITION`.
    StaleOldStream = 6,
    /// The successor transition is not valid. `FAILED_PRECONDITION`.
    InvalidSuccessorStream = 7,
    /// A detection key resolved to a record with a different payload, emitter,
    /// or cell. `ALREADY_EXISTS`. **Never** a derivation failure.
    ResetDetectionMismatch = 8,
}

impl ResetReportErrorV1 {
    /// The gRPC code this detail maps to, frozen by the contract.
    pub fn code(self) -> tonic::Code {
        match self {
            // Never returned, but a code is still required rather than a panic:
            // an internal caller that reaches it has a bug, and `Internal` is
            // the honest report of that.
            Self::Unspecified => tonic::Code::Internal,
            Self::MalformedReport => tonic::Code::InvalidArgument,
            Self::UnauthenticatedReport => tonic::Code::Unauthenticated,
            Self::UnauthorizedReport | Self::CrossCellReport => tonic::Code::PermissionDenied,
            Self::PlacementMismatch | Self::StaleOldStream | Self::InvalidSuccessorStream => {
                tonic::Code::FailedPrecondition
            }
            Self::ResetDetectionMismatch => tonic::Code::AlreadyExists,
        }
    }

    /// The detail's own name, carried as the status message so a caller can
    /// classify without parsing prose. Fixed and low-cardinality.
    pub fn detail(self) -> &'static str {
        match self {
            Self::Unspecified => "RESET_REPORT_ERROR_V1_UNSPECIFIED",
            Self::MalformedReport => "MALFORMED_REPORT_V1",
            Self::UnauthenticatedReport => "UNAUTHENTICATED_REPORT_V1",
            Self::UnauthorizedReport => "UNAUTHORIZED_REPORT_V1",
            Self::CrossCellReport => "CROSS_CELL_REPORT_V1",
            Self::PlacementMismatch => "PLACEMENT_MISMATCH_V1",
            Self::StaleOldStream => "STALE_OLD_STREAM_V1",
            Self::InvalidSuccessorStream => "INVALID_SUCCESSOR_STREAM_V1",
            Self::ResetDetectionMismatch => "RESET_DETECTION_MISMATCH_V1",
        }
    }

    /// This detail as a `tonic::Status`.
    pub fn status(self) -> tonic::Status {
        tonic::Status::new(self.code(), self.detail())
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// The frozen request. Field numbers are part of `OUTBOX-CONTRACT-FROZEN`.
///
/// It carries **no** `reset_generation`: WP-119 assigns that, and a
/// caller-supplied one would let a detector choose which fence it installs.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamResetReportV1 {
    /// Exactly 1.
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    /// `UUIDv5` of the lowercase hexadecimal fingerprint.
    #[prost(string, tag = "2")]
    pub detection_id: ::prost::alloc::string::String,
    /// Exactly 32 bytes.
    #[prost(bytes = "bytes", tag = "3")]
    pub reset_fingerprint: ::bytes::Bytes,
    /// Authoritative broker reset identity.
    #[prost(string, tag = "4")]
    pub broker_reset_identity: ::prost::alloc::string::String,
    /// The reporting cell.
    #[prost(string, tag = "5")]
    pub cell_id: ::prost::alloc::string::String,
    /// Placement revision the emitter believed was current.
    #[prost(uint64, tag = "6")]
    pub placement_revision: u64,
    /// Stream identity before the reset.
    #[prost(string, tag = "7")]
    pub old_stream_identity: ::prost::alloc::string::String,
    /// Stream epoch before the reset.
    #[prost(uint64, tag = "8")]
    pub old_stream_epoch: u64,
    /// Stream identity after the reset.
    #[prost(string, tag = "9")]
    pub new_stream_identity: ::prost::alloc::string::String,
    /// Stream epoch after the reset.
    #[prost(uint64, tag = "10")]
    pub new_stream_epoch: u64,
    /// `ResetReasonV1`.
    #[prost(enumeration = "ResetReasonV1", tag = "11")]
    pub reason_code: i32,
    /// Detection timestamp. Excluded from the fingerprint and from duplicate
    /// equality.
    #[prost(int64, tag = "12")]
    pub detected_at_unix_ms: i64,
}

/// The frozen acknowledgement. There is no duplicate-result enum: an equivalent
/// retry receives the identical stored ack bytes, which is what makes a
/// duplicate indistinguishable from the original by design.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamResetAckV1 {
    /// Exactly 1.
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    /// Echoed cell.
    #[prost(string, tag = "2")]
    pub cell_id: ::prost::alloc::string::String,
    /// Echoed detection identity.
    #[prost(string, tag = "3")]
    pub detection_id: ::prost::alloc::string::String,
    /// Echoed fingerprint.
    #[prost(bytes = "bytes", tag = "4")]
    pub reset_fingerprint: ::bytes::Bytes,
    /// Assigned by WP-119, never by the caller.
    #[prost(uint64, tag = "5")]
    pub reset_generation: u64,
    /// At most 64 characters.
    #[prost(string, tag = "6")]
    pub evidence_id: ::prost::alloc::string::String,
    /// When the receipt transaction persisted the evidence.
    #[prost(int64, tag = "7")]
    pub persisted_at_unix_ms: i64,
}

/// Encode a message to its protobuf bytes.
///
/// Used once per accepted reset, to produce the bytes that are then **stored**
/// and replayed verbatim. Protobuf serialization is not canonical, so the bytes
/// this produces are the record; re-encoding the same fields later is not
/// guaranteed to reproduce them.
pub fn encode<M: Message>(message: &M) -> Vec<u8> {
    let mut buf = Vec::with_capacity(message.encoded_len());
    // `encode` only fails when the buffer lacks capacity, and `Vec` grows.
    let _ = message.encode(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Canonical derivation
// ---------------------------------------------------------------------------

/// Compute the contract's canonical fingerprint preimage.
///
/// ASCII `reset-fingerprint-v1` plus one `0x00`, then, in this order:
/// length-prefixed `broker_reset_identity`, `cell_id`, `old_stream_identity`;
/// big-endian `old_stream_epoch`; length-prefixed `new_stream_identity`;
/// big-endian `new_stream_epoch`.
///
/// Every string length is its **UTF-8 byte** length as a four-byte unsigned
/// big-endian integer, never a character count. The contract's
/// `multibyte-broker-identity` vector exists precisely to catch the character
/// count: a 20-character identity that is 21 bytes produces a different digest
/// under the wrong reading, and the vector's pinned digest is the one that only
/// the byte length reproduces.
///
/// `detected_at_unix_ms`, `placement_revision`, and `reason_code` are excluded.
pub fn fingerprint_preimage(
    broker_reset_identity: &str,
    cell_id: &str,
    old_stream_identity: &str,
    old_stream_epoch: u64,
    new_stream_identity: &str,
    new_stream_epoch: u64,
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        FINGERPRINT_DOMAIN.len()
            + 4 * 4
            + broker_reset_identity.len()
            + cell_id.len()
            + old_stream_identity.len()
            + new_stream_identity.len()
            + 16,
    );
    preimage.extend_from_slice(FINGERPRINT_DOMAIN);
    push_length_prefixed(&mut preimage, broker_reset_identity);
    push_length_prefixed(&mut preimage, cell_id);
    push_length_prefixed(&mut preimage, old_stream_identity);
    preimage.extend_from_slice(&old_stream_epoch.to_be_bytes());
    push_length_prefixed(&mut preimage, new_stream_identity);
    preimage.extend_from_slice(&new_stream_epoch.to_be_bytes());
    preimage
}

/// Append one string as a four-byte unsigned big-endian **UTF-8 byte** length
/// followed by its bytes.
///
/// The byte length, never the character count. That distinction is the whole
/// point of the contract's `multibyte-broker-identity` vector, and it is why
/// this is a named function rather than an inline `extend_from_slice` pair at
/// four call sites where one of them could quietly drift to `chars().count()`.
fn push_length_prefixed(preimage: &mut Vec<u8>, value: &str) {
    // `as u32` is safe by construction: every field carrying a length here is
    // bounded well under 4 GiB by the contract, and a request reaching this
    // function has already passed its width checks.
    preimage.extend_from_slice(&(value.len() as u32).to_be_bytes());
    preimage.extend_from_slice(value.as_bytes());
}

/// SHA-256 of [`fingerprint_preimage`].
pub fn reset_fingerprint(
    broker_reset_identity: &str,
    cell_id: &str,
    old_stream_identity: &str,
    old_stream_epoch: u64,
    new_stream_identity: &str,
    new_stream_epoch: u64,
) -> [u8; 32] {
    let preimage = fingerprint_preimage(
        broker_reset_identity,
        cell_id,
        old_stream_identity,
        old_stream_epoch,
        new_stream_identity,
        new_stream_epoch,
    );
    let digest = digest::digest(&digest::SHA256, &preimage);
    let mut out = [0_u8; 32];
    // SHA-256 is 32 bytes by definition, so the slice lengths match.
    out.copy_from_slice(digest.as_ref());
    out
}

/// The `UUIDv5` `detection_id` of a fingerprint.
///
/// The name is the **64-character lowercase hexadecimal** rendering of the
/// digest, not its raw bytes. Hashing the raw bytes produces a different, wrong
/// UUID that no fixture would match.
///
/// `UUIDv5` is SHA-1 over the namespace bytes followed by the name, with the
/// version and variant bits overwritten. The `uuid` crate is built in this
/// workspace without its `v5` feature, so the construction is explicit here;
/// `ring`'s SHA-1 is named `SHA1_FOR_LEGACY_USE_ONLY` because SHA-1 is broken
/// for signatures, and this is exactly the legacy use that name refers to — the
/// digest is a name-to-identifier mapping fixed by RFC 4122, not a security
/// property.
pub fn detection_id(reset_fingerprint: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut name = String::with_capacity(64);
    for byte in reset_fingerprint {
        // `write!` into a `String` cannot fail for any reason this code can
        // act on, so the result is discarded rather than propagated.
        let _ = write!(name, "{byte:02x}");
    }
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(DETECTION_ID_NAMESPACE.as_bytes());
    context.update(name.as_bytes());
    let hashed = context.finish();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hashed.as_ref()[..16]);
    // Version 5 in the high nibble of byte 6, RFC 4122 variant in the top two
    // bits of byte 8.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).hyphenated().to_string()
}

// ---------------------------------------------------------------------------
// A codec that puts the STORED ack bytes on the wire
// ---------------------------------------------------------------------------

/// One acknowledgement, as the exact bytes persisted in the receipt
/// transaction.
///
/// The response type is bytes rather than [`StreamResetAckV1`] on purpose. The
/// contract requires an equivalent retry to receive the **identical stored ack
/// bytes**, and calls that a storage rule precisely because protobuf
/// serialization is not canonical: re-encoding the same fields across library
/// versions can differ. Decoding the stored record and letting the ordinary
/// prost codec re-encode it would therefore satisfy the rule only by
/// coincidence of both ends running the same prost build. Carrying the bytes
/// through makes it true by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAck(pub Vec<u8>);

/// Encodes a [`StoredAck`] by writing its bytes verbatim.
#[derive(Debug, Default, Clone, Copy)]
pub struct StoredAckEncoder;

impl tonic::codec::Encoder for StoredAckEncoder {
    type Item = StoredAck;
    type Error = tonic::Status;

    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        dst.put_slice(&item.0);
        Ok(())
    }
}

/// Decodes a [`StreamResetReportV1`] with prost.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReportDecoder;

impl tonic::codec::Decoder for ReportDecoder {
    type Item = StreamResetReportV1;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        // A body that is not well-formed protobuf never reaches the service, so
        // it is classified here rather than there. It is malformed input, which
        // is `INVALID_ARGUMENT` -- the same code the contract's
        // `MALFORMED_REPORT_V1` maps to.
        let message = StreamResetReportV1::decode(src).map_err(|error| {
            tonic::Status::invalid_argument(format!(
                "{}: the request body is not a well-formed StreamResetReportV1: {error}",
                ResetReportErrorV1::MalformedReport.detail()
            ))
        })?;
        Ok(Some(message))
    }
}

/// The codec this service is served with.
#[derive(Debug, Default, Clone, Copy)]
pub struct StreamResetCodec;

impl tonic::codec::Codec for StreamResetCodec {
    type Encode = StoredAck;
    type Decode = StreamResetReportV1;
    type Encoder = StoredAckEncoder;
    type Decoder = ReportDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        StoredAckEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        ReportDecoder
    }
}

// ---------------------------------------------------------------------------
// Server, in the shape `tonic-prost-build` emits for one unary method
// ---------------------------------------------------------------------------

/// The service trait one implementor satisfies.
#[async_trait]
pub trait StreamResetService: std::marker::Send + std::marker::Sync + 'static {
    /// Accept, replay, or reject one authenticated reset report.
    ///
    /// Returns the **stored** acknowledgement bytes, never a freshly encoded
    /// message. See [`StoredAck`].
    async fn report_stream_reset(
        &self,
        request: tonic::Request<StreamResetReportV1>,
    ) -> std::result::Result<tonic::Response<StoredAck>, tonic::Status>;
}

/// The tonic service wrapper.
#[derive(Debug)]
pub struct StreamResetServiceServer<T> {
    inner: Arc<T>,
}

impl<T> StreamResetServiceServer<T> {
    /// Wrap one implementor.
    pub fn new(inner: T) -> Self {
        Self::from_arc(Arc::new(inner))
    }

    /// Wrap one already-shared implementor.
    pub fn from_arc(inner: Arc<T>) -> Self {
        Self { inner }
    }
}

impl<T> Clone for StreamResetServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, B> tonic::codegen::Service<http::Request<B>> for StreamResetServiceServer<T>
where
    T: StreamResetService,
    B: Body + std::marker::Send + 'static,
    B::Error: Into<StdError> + std::marker::Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        if req.uri().path() != REPORT_STREAM_RESET_METHOD_PATH {
            return Box::pin(async move {
                let mut response = http::Response::new(tonic::body::Body::default());
                let headers = response.headers_mut();
                headers.insert(
                    tonic::Status::GRPC_STATUS,
                    (tonic::Code::Unimplemented as i32).into(),
                );
                headers.insert(
                    http::header::CONTENT_TYPE,
                    tonic::metadata::GRPC_CONTENT_TYPE,
                );
                Ok(response)
            });
        }

        #[allow(non_camel_case_types)]
        struct ReportStreamResetSvc<T: StreamResetService>(pub Arc<T>);
        impl<T: StreamResetService> tonic::server::UnaryService<StreamResetReportV1>
            for ReportStreamResetSvc<T>
        {
            type Response = StoredAck;
            type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
            fn call(&mut self, request: tonic::Request<StreamResetReportV1>) -> Self::Future {
                let inner = Arc::clone(&self.0);
                Box::pin(async move {
                    <T as StreamResetService>::report_stream_reset(&inner, request).await
                })
            }
        }

        let inner = self.inner.clone();
        Box::pin(async move {
            let method = ReportStreamResetSvc(inner);
            let mut grpc = tonic::server::Grpc::new(StreamResetCodec);
            Ok(grpc.unary(method, req).await)
        })
    }
}

impl<T> tonic::server::NamedService for StreamResetServiceServer<T> {
    const NAME: &'static str = STREAM_RESET_SERVICE;
}

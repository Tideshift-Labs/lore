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
//! freezable, and [`tests`] pins the numbers this module actually puts on the
//! wire against that text.
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
//! A fingerprint that does not recompute, a detection ID that is not the UUIDv5
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

/// UUIDv5 namespace for `detection_id`.
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
    /// UUIDv5 of the lowercase hexadecimal fingerprint.
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

/// The UUIDv5 `detection_id` of a fingerprint.
///
/// The name is the **64-character lowercase hexadecimal** rendering of the
/// digest, not its raw bytes. Hashing the raw bytes produces a different, wrong
/// UUID that no fixture would match.
///
/// UUIDv5 is SHA-1 over the namespace bytes followed by the name, with the
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

#[cfg(test)]
mod tests {
    use lore_postgres::domain::outbox::reset;

    use super::*;

    /// Protobuf wire types this schema uses.
    const VARINT: u32 = 0;
    const LENGTH_DELIMITED: u32 = 2;

    /// The single tag byte protobuf emits for a field number below 16. Every
    /// field here is 1..=12, so one byte is always enough; a larger field would
    /// need a two-byte varint, so this asserts rather than truncating silently.
    fn tag_byte(field: u32, wire_type: u32) -> u8 {
        assert!(
            (1..16).contains(&field),
            "field {field} needs a multi-byte tag; this helper only covers 1..15"
        );
        ((field << 3) | wire_type) as u8
    }

    /// One field-number case: the field number, its wire type, and a setter that
    /// leaves only that field non-default.
    type FieldCase<M> = (u32, u32, fn(&mut M));

    /// Asserts that `message`, which must have exactly one non-default field
    /// set, encodes that field under `field`/`wire_type`.
    ///
    /// This reads the bytes this module really produces, so renumbering a
    /// `#[prost(tag = ...)]` fails here.
    fn assert_encodes_tag<M: Message>(message: &M, field: u32, wire_type: u32, what: &str) {
        let bytes = encode(message);
        assert_eq!(
            bytes.first().copied(),
            Some(tag_byte(field, wire_type)),
            "{what} did not encode as field {field} wire type {wire_type}; got {bytes:?}"
        );
    }

    fn empty_report() -> StreamResetReportV1 {
        StreamResetReportV1 {
            schema_version: 0,
            detection_id: String::new(),
            reset_fingerprint: ::bytes::Bytes::new(),
            broker_reset_identity: String::new(),
            cell_id: String::new(),
            placement_revision: 0,
            old_stream_identity: String::new(),
            old_stream_epoch: 0,
            new_stream_identity: String::new(),
            new_stream_epoch: 0,
            reason_code: 0,
            detected_at_unix_ms: 0,
        }
    }

    fn empty_ack() -> StreamResetAckV1 {
        StreamResetAckV1 {
            schema_version: 0,
            cell_id: String::new(),
            detection_id: String::new(),
            reset_fingerprint: ::bytes::Bytes::new(),
            reset_generation: 0,
            evidence_id: String::new(),
            persisted_at_unix_ms: 0,
        }
    }

    #[test]
    fn the_request_field_numbers_are_the_frozen_ones() {
        let cases: Vec<FieldCase<StreamResetReportV1>> = vec![
            (1, VARINT, |m| m.schema_version = 1),
            (2, LENGTH_DELIMITED, |m| m.detection_id = "d".into()),
            (3, LENGTH_DELIMITED, |m| {
                m.reset_fingerprint = ::bytes::Bytes::from_static(&[1])
            }),
            (4, LENGTH_DELIMITED, |m| {
                m.broker_reset_identity = "b".into()
            }),
            (5, LENGTH_DELIMITED, |m| m.cell_id = "c".into()),
            (6, VARINT, |m| m.placement_revision = 1),
            (7, LENGTH_DELIMITED, |m| m.old_stream_identity = "o".into()),
            (8, VARINT, |m| m.old_stream_epoch = 1),
            (9, LENGTH_DELIMITED, |m| m.new_stream_identity = "n".into()),
            (10, VARINT, |m| m.new_stream_epoch = 1),
            (11, VARINT, |m| {
                m.reason_code = ResetReasonV1::StreamEpochAdvanced as i32
            }),
            (12, VARINT, |m| m.detected_at_unix_ms = 1),
        ];
        for (field, wire_type, set) in cases {
            let mut message = empty_report();
            set(&mut message);
            assert_encodes_tag(
                &message,
                field,
                wire_type,
                &format!("StreamResetReportV1 field {field}"),
            );
        }
    }

    #[test]
    fn the_ack_field_numbers_are_the_frozen_ones() {
        let cases: Vec<FieldCase<StreamResetAckV1>> = vec![
            (1, VARINT, |m| m.schema_version = 1),
            (2, LENGTH_DELIMITED, |m| m.cell_id = "c".into()),
            (3, LENGTH_DELIMITED, |m| m.detection_id = "d".into()),
            (4, LENGTH_DELIMITED, |m| {
                m.reset_fingerprint = ::bytes::Bytes::from_static(&[1])
            }),
            (5, VARINT, |m| m.reset_generation = 1),
            (6, LENGTH_DELIMITED, |m| m.evidence_id = "e".into()),
            (7, VARINT, |m| m.persisted_at_unix_ms = 1),
        ];
        for (field, wire_type, set) in cases {
            let mut message = empty_ack();
            set(&mut message);
            assert_encodes_tag(
                &message,
                field,
                wire_type,
                &format!("StreamResetAckV1 field {field}"),
            );
        }
    }

    #[test]
    fn the_ack_has_no_duplicate_result_field() {
        // Seven fields, 1..=7, and nothing at 8. A duplicate-result enum added
        // later would land there and this catches it.
        let mut ack = empty_ack();
        ack.schema_version = 1;
        ack.cell_id = "sfo3-cell-a".into();
        ack.detection_id = "efaa31a7-a8db-5666-a6fe-3eb00881fd27".into();
        ack.reset_fingerprint = ::bytes::Bytes::from(vec![0x11; 32]);
        ack.reset_generation = 3;
        ack.evidence_id = "rst-3-1111111111111111".into();
        ack.persisted_at_unix_ms = 1_787_000_000_000;
        let tags = encode(&ack);
        assert!(
            !tags.contains(&tag_byte(8, VARINT)) && !tags.contains(&tag_byte(8, LENGTH_DELIMITED)),
            "the frozen ack has exactly seven fields and no duplicate-result enum"
        );
    }

    #[test]
    fn the_reason_values_are_the_frozen_ones() {
        assert_eq!(ResetReasonV1::Unspecified as i32, 0);
        assert_eq!(ResetReasonV1::StreamIdentityChanged as i32, 1);
        assert_eq!(ResetReasonV1::StreamEpochAdvanced as i32, 2);
        assert_eq!(ResetReasonV1::SequenceRollback as i32, 3);
        assert_eq!(ResetReasonV1::BrokerRestore as i32, 4);
        assert_eq!(ResetReasonV1::OperatorReset as i32, 5);
    }

    /// The storage side persists and validates these numbers without depending
    /// on this crate, so the two declarations are pinned against each other
    /// here. A renumbering on either side fails rather than silently storing a
    /// reason under another name.
    #[test]
    fn the_wire_reasons_agree_with_the_storage_reasons() {
        assert_eq!(
            ResetReasonV1::StreamIdentityChanged as i32,
            reset::RESET_REASON_STREAM_IDENTITY_CHANGED
        );
        assert_eq!(
            ResetReasonV1::StreamEpochAdvanced as i32,
            reset::RESET_REASON_STREAM_EPOCH_ADVANCED
        );
        assert_eq!(
            ResetReasonV1::SequenceRollback as i32,
            reset::RESET_REASON_SEQUENCE_ROLLBACK
        );
        assert_eq!(
            ResetReasonV1::BrokerRestore as i32,
            reset::RESET_REASON_BROKER_RESTORE
        );
        assert_eq!(
            ResetReasonV1::OperatorReset as i32,
            reset::RESET_REASON_OPERATOR_RESET
        );
        assert!(
            !reset::RESET_REASONS.contains(&(ResetReasonV1::Unspecified as i32)),
            "the proto3 zero value must never be a storable reason"
        );
    }

    #[test]
    fn the_error_values_and_codes_are_the_frozen_ones() {
        let cases = [
            (
                ResetReportErrorV1::MalformedReport,
                1,
                tonic::Code::InvalidArgument,
            ),
            (
                ResetReportErrorV1::UnauthenticatedReport,
                2,
                tonic::Code::Unauthenticated,
            ),
            (
                ResetReportErrorV1::UnauthorizedReport,
                3,
                tonic::Code::PermissionDenied,
            ),
            (
                ResetReportErrorV1::CrossCellReport,
                4,
                tonic::Code::PermissionDenied,
            ),
            (
                ResetReportErrorV1::PlacementMismatch,
                5,
                tonic::Code::FailedPrecondition,
            ),
            (
                ResetReportErrorV1::StaleOldStream,
                6,
                tonic::Code::FailedPrecondition,
            ),
            (
                ResetReportErrorV1::InvalidSuccessorStream,
                7,
                tonic::Code::FailedPrecondition,
            ),
            (
                ResetReportErrorV1::ResetDetectionMismatch,
                8,
                tonic::Code::AlreadyExists,
            ),
        ];
        for (error, value, code) in cases {
            assert_eq!(error as i32, value, "{} renumbered", error.detail());
            assert_eq!(error.code(), code, "{} remapped", error.detail());
        }
        assert_eq!(ResetReportErrorV1::Unspecified as i32, 0);
    }

    /// The method path is the freeze. A rename here silently stops serving the
    /// contract while still compiling.
    #[test]
    fn the_method_path_is_the_frozen_one() {
        assert_eq!(
            REPORT_STREAM_RESET_METHOD_PATH,
            "/lorehub.notification.internal.v1.StreamResetService/ReportStreamReset"
        );
        assert_eq!(
            STREAM_RESET_SERVICE,
            "lorehub.notification.internal.v1.StreamResetService"
        );
        assert!(REPORT_STREAM_RESET_METHOD_PATH.ends_with("/ReportStreamReset"));
        assert!(REPORT_STREAM_RESET_METHOD_PATH.starts_with(&format!("/{STREAM_RESET_SERVICE}")));
    }

    // -----------------------------------------------------------------------
    // Derivation vectors, from
    // lorehub/docs/contracts/fixtures/lore-notification-plane/
    // stream-reset-derivation.json (fixture_set_version 3).
    //
    // Inline here so this module proves its own algorithm without a path out of
    // the repo; the conformance suite loads the fixture itself and would catch
    // a drift between the two.
    // -----------------------------------------------------------------------

    struct Vector {
        id: &'static str,
        broker_reset_identity: &'static str,
        cell_id: &'static str,
        old_stream_identity: &'static str,
        old_stream_epoch: u64,
        new_stream_identity: &'static str,
        new_stream_epoch: u64,
        preimage_hex: &'static str,
        preimage_byte_length: usize,
        reset_fingerprint_hex: &'static str,
        detection_id: &'static str,
    }

    const VECTORS: [Vector; 4] = [
        Vector {
            id: "epoch-advanced",
            broker_reset_identity: "sfo3-01:JS-9Q2F7K3M1X",
            cell_id: "sfo3-cell-a",
            old_stream_identity: "DURABLE-sfo3-cell-a",
            old_stream_epoch: 7,
            new_stream_identity: "DURABLE-sfo3-cell-a",
            new_stream_epoch: 8,
            preimage_hex: "72657365742d66696e6765727072696e742d7631000000001573666f332d30313a4a532d39513246374b334d31580000000b73666f332d63656c6c2d610000001344555241424c452d73666f332d63656c6c2d6100000000000000070000001344555241424c452d73666f332d63656c6c2d610000000000000008",
            preimage_byte_length: 123,
            reset_fingerprint_hex: "f76037e9acfa1793a8346331db69084fec229da20c6387206ec71bceb7233c66",
            detection_id: "efaa31a7-a8db-5666-a6fe-3eb00881fd27",
        },
        Vector {
            id: "broker-restore-identity-changed",
            broker_reset_identity: "sfo3-01:JS-9Q2F7K3M1X",
            cell_id: "sfo3-cell-a",
            old_stream_identity: "DURABLE-sfo3-cell-a",
            old_stream_epoch: 8,
            new_stream_identity: "DURABLE-sfo3-cell-a-r2",
            new_stream_epoch: 1,
            preimage_hex: "72657365742d66696e6765727072696e742d7631000000001573666f332d30313a4a532d39513246374b334d31580000000b73666f332d63656c6c2d610000001344555241424c452d73666f332d63656c6c2d6100000000000000080000001644555241424c452d73666f332d63656c6c2d612d72320000000000000001",
            preimage_byte_length: 126,
            reset_fingerprint_hex: "e33cee69097dcaa8d796ef220475a8819d6aa09f2790d02cfb4c51eeb576a01d",
            detection_id: "eaa112c1-f05a-5cb4-a77e-2ac01e01a7c0",
        },
        Vector {
            id: "multibyte-broker-identity",
            broker_reset_identity: "sfo3-01:JS-café-7K3M",
            cell_id: "sfo3-cell-b",
            old_stream_identity: "DURABLE-sfo3-cell-b",
            old_stream_epoch: 1,
            new_stream_identity: "DURABLE-sfo3-cell-b-r2",
            new_stream_epoch: 1,
            preimage_hex: "72657365742d66696e6765727072696e742d7631000000001573666f332d30313a4a532d636166c3a92d374b334d0000000b73666f332d63656c6c2d620000001344555241424c452d73666f332d63656c6c2d6200000000000000010000001644555241424c452d73666f332d63656c6c2d622d72320000000000000001",
            preimage_byte_length: 126,
            reset_fingerprint_hex: "447cafe4639fb23163c79305fca67b6e724ee9ce5447e749c1b417b4643b72d2",
            detection_id: "4e29a481-a6a7-527c-94de-852751b5cefc",
        },
        Vector {
            id: "max-epoch-boundary",
            broker_reset_identity: "sfo3-02:JS-0000000000",
            cell_id: "sfo3-cell-c",
            old_stream_identity: "DURABLE-sfo3-cell-c",
            old_stream_epoch: 18_446_744_073_709_551_614,
            new_stream_identity: "DURABLE-sfo3-cell-c",
            new_stream_epoch: 18_446_744_073_709_551_615,
            preimage_hex: "72657365742d66696e6765727072696e742d7631000000001573666f332d30323a4a532d303030303030303030300000000b73666f332d63656c6c2d630000001344555241424c452d73666f332d63656c6c2d63fffffffffffffffe0000001344555241424c452d73666f332d63656c6c2d63ffffffffffffffff",
            preimage_byte_length: 123,
            reset_fingerprint_hex: "8e8096fa38ae0b47dcbe23a70ba0284a354a38f89d5a8d611cb70a20d0537cbf",
            detection_id: "740c68c6-67f0-5c7d-8a49-ed6eead61019",
        },
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn preimage_of(vector: &Vector) -> Vec<u8> {
        fingerprint_preimage(
            vector.broker_reset_identity,
            vector.cell_id,
            vector.old_stream_identity,
            vector.old_stream_epoch,
            vector.new_stream_identity,
            vector.new_stream_epoch,
        )
    }

    fn fingerprint_of(vector: &Vector) -> [u8; 32] {
        reset_fingerprint(
            vector.broker_reset_identity,
            vector.cell_id,
            vector.old_stream_identity,
            vector.old_stream_epoch,
            vector.new_stream_identity,
            vector.new_stream_epoch,
        )
    }

    #[test]
    fn every_derivation_vector_reproduces() {
        for vector in &VECTORS {
            let preimage = preimage_of(vector);
            assert_eq!(
                preimage.len(),
                vector.preimage_byte_length,
                "{}: preimage length",
                vector.id
            );
            assert_eq!(
                hex(&preimage),
                vector.preimage_hex,
                "{}: preimage",
                vector.id
            );
            let fingerprint = fingerprint_of(vector);
            assert_eq!(
                hex(&fingerprint),
                vector.reset_fingerprint_hex,
                "{}: fingerprint",
                vector.id
            );
            assert_eq!(
                detection_id(&fingerprint),
                vector.detection_id,
                "{}: detection id",
                vector.id
            );
        }
    }

    /// The multibyte vector's discriminating negative: prefixing character
    /// counts instead of UTF-8 byte counts must not reproduce the pinned digest.
    /// Without this the vector proves nothing, because recomputing from the same
    /// declared inputs can only ever match.
    #[test]
    fn a_character_length_prefix_does_not_reproduce_the_digest() {
        let vector = &VECTORS[2];
        assert_ne!(
            vector.broker_reset_identity.chars().count(),
            vector.broker_reset_identity.len(),
            "the discriminating vector must actually be multibyte"
        );
        fn push_chars(preimage: &mut Vec<u8>, value: &str) {
            preimage.extend_from_slice(&(value.chars().count() as u32).to_be_bytes());
            preimage.extend_from_slice(value.as_bytes());
        }
        let mut preimage = Vec::new();
        preimage.extend_from_slice(FINGERPRINT_DOMAIN);
        push_chars(&mut preimage, vector.broker_reset_identity);
        push_chars(&mut preimage, vector.cell_id);
        push_chars(&mut preimage, vector.old_stream_identity);
        preimage.extend_from_slice(&vector.old_stream_epoch.to_be_bytes());
        push_chars(&mut preimage, vector.new_stream_identity);
        preimage.extend_from_slice(&vector.new_stream_epoch.to_be_bytes());
        assert_ne!(
            hex(digest::digest(&digest::SHA256, &preimage).as_ref()),
            vector.reset_fingerprint_hex
        );
    }

    /// Proves the pinned digests were computed WITHOUT `detected_at_unix_ms`: a
    /// build that DOES include the excluded field must differ.
    #[test]
    fn appending_the_detection_timestamp_changes_the_digest() {
        let vector = &VECTORS[0];
        let mut preimage = preimage_of(vector);
        preimage.extend_from_slice(&1_787_000_000_000_u64.to_be_bytes());
        assert_ne!(
            hex(digest::digest(&digest::SHA256, &preimage).as_ref()),
            vector.reset_fingerprint_hex
        );
    }

    /// Same discrimination for `reason_code`, the other field excluded from the
    /// fingerprint but retained in duplicate equality.
    #[test]
    fn appending_the_reason_changes_the_digest() {
        let vector = &VECTORS[0];
        let mut preimage = preimage_of(vector);
        let reason = "STREAM_EPOCH_ADVANCED";
        preimage.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        preimage.extend_from_slice(reason.as_bytes());
        assert_ne!(
            hex(digest::digest(&digest::SHA256, &preimage).as_ref()),
            vector.reset_fingerprint_hex
        );
    }

    /// The exclusion is load-bearing rather than vacuous: two reports differing
    /// only in the detection timestamp are one detection, and would not be if
    /// the field were an input.
    #[test]
    fn two_detection_timestamps_do_not_change_the_identity() {
        let vector = &VECTORS[0];
        let fingerprint = fingerprint_of(vector);
        assert_eq!(fingerprint, fingerprint_of(vector));
        assert_eq!(detection_id(&fingerprint), vector.detection_id);

        let mut a = preimage_of(vector);
        let mut b = a.clone();
        a.extend_from_slice(&1_787_000_000_000_u64.to_be_bytes());
        b.extend_from_slice(&1_787_000_450_000_u64.to_be_bytes());
        assert_ne!(
            hex(digest::digest(&digest::SHA256, &a).as_ref()),
            hex(digest::digest(&digest::SHA256, &b).as_ref()),
            "if the timestamp were an input, these two would differ; excluding it is what makes \
             them one detection"
        );
    }

    /// The name is the lowercase hexadecimal rendering, not the raw digest
    /// bytes. Hashing the bytes yields a different, wrong UUID.
    #[test]
    fn the_detection_id_name_is_the_hex_rendering_not_the_raw_bytes() {
        let fingerprint = fingerprint_of(&VECTORS[0]);
        let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        context.update(DETECTION_ID_NAMESPACE.as_bytes());
        context.update(&fingerprint);
        let hashed = context.finish();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hashed.as_ref()[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        assert_ne!(
            Uuid::from_bytes(bytes).hyphenated().to_string(),
            VECTORS[0].detection_id
        );
    }

    #[test]
    fn the_detection_id_namespace_is_the_frozen_one() {
        assert_eq!(
            DETECTION_ID_NAMESPACE.hyphenated().to_string(),
            "c6a42b98-2d15-5e0f-8a77-7a6304c9b4dd"
        );
    }

    #[test]
    fn every_detection_id_is_a_v5_uuid() {
        for vector in &VECTORS {
            let id = detection_id(&fingerprint_of(vector));
            let parsed = Uuid::parse_str(&id).expect("a hyphenated UUID");
            assert_eq!(parsed.get_version_num(), 5, "{}", vector.id);
            assert_eq!(
                parsed.get_variant(),
                uuid::Variant::RFC4122,
                "{}",
                vector.id
            );
        }
    }

    #[test]
    fn the_domain_prefix_is_twenty_one_bytes_and_not_length_prefixed() {
        assert_eq!(FINGERPRINT_DOMAIN.len(), 21);
        assert_eq!(FINGERPRINT_DOMAIN[20], 0x00);
        assert_eq!(&FINGERPRINT_DOMAIN[..20], b"reset-fingerprint-v1");
        // Not length-prefixed: the preimage starts with the ASCII bytes
        // themselves, never with a four-byte length.
        let preimage = preimage_of(&VECTORS[0]);
        assert_eq!(&preimage[..21], FINGERPRINT_DOMAIN);
    }
}

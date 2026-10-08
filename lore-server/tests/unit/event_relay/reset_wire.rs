// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_postgres::domain::outbox::reset;
use lore_server::event_relay::reset_wire::*;
use prost::Message;
use ring::digest;
use uuid::Uuid;

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
            m.reset_fingerprint = ::bytes::Bytes::from_static(&[1]);
        }),
        (4, LENGTH_DELIMITED, |m| {
            m.broker_reset_identity = "b".into();
        }),
        (5, LENGTH_DELIMITED, |m| m.cell_id = "c".into()),
        (6, VARINT, |m| m.placement_revision = 1),
        (7, LENGTH_DELIMITED, |m| m.old_stream_identity = "o".into()),
        (8, VARINT, |m| m.old_stream_epoch = 1),
        (9, LENGTH_DELIMITED, |m| m.new_stream_identity = "n".into()),
        (10, VARINT, |m| m.new_stream_epoch = 1),
        (11, VARINT, |m| {
            m.reason_code = ResetReasonV1::StreamEpochAdvanced as i32;
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
            m.reset_fingerprint = ::bytes::Bytes::from_static(&[1]);
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

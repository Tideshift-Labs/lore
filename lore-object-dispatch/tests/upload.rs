// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::CanonicalPutUploadStreamRejected;
use lore_object_dispatch::CanonicalUploadPutStreamIdentity;
use lore_object_dispatch::PutUploadStreamRejectReason;
use lore_object_dispatch::UploadContractError;
use lore_object_dispatch::UploadPutStreamIdentity;
use lore_object_dispatch::build_empty_stream_upload_rejection;
use lore_object_dispatch::build_identity_mismatch_upload_rejection;
use lore_object_dispatch::build_upload_put_stream_identity;
use lore_object_dispatch::empty_upload_put_stream_identity_blake3;
use lore_object_dispatch::lowest_upload_put_stream_identity_mismatch_field;
use lore_object_dispatch::validate_upload_stream_rejection;

const IDENTITY_DIGEST: [u8; 32] = [
    0xe3, 0x15, 0x75, 0xea, 0xc6, 0x0e, 0x15, 0x5a, 0x50, 0x3a, 0xea, 0x7d, 0xa7, 0xa6, 0x8a, 0x05,
    0x39, 0xd4, 0xd4, 0x3a, 0x46, 0x86, 0x88, 0x60, 0x69, 0x1e, 0x23, 0x20, 0xdd, 0x9c, 0x9d, 0xf3,
];
const EMPTY_IDENTITY_DIGEST: [u8; 32] = [
    0xf3, 0x33, 0xbc, 0x17, 0x0a, 0x84, 0x8c, 0x10, 0x9e, 0x91, 0xde, 0x3b, 0x43, 0xeb, 0x2b, 0x92,
    0xd7, 0x7c, 0x60, 0x59, 0xea, 0xaf, 0xdc, 0x59, 0x54, 0x47, 0x43, 0x53, 0x60, 0x0b, 0xf2, 0x17,
];
const MISMATCH_DETAIL_DIGEST: [u8; 32] = [
    0x93, 0x72, 0x9f, 0xff, 0xe2, 0xd2, 0x92, 0x34, 0xae, 0xd8, 0x7f, 0xd7, 0xac, 0x2f, 0xd5, 0xe6,
    0xa0, 0xfb, 0xaa, 0x9f, 0xd4, 0xc1, 0x48, 0x2f, 0xd2, 0xd0, 0x2b, 0x76, 0xd6, 0xbd, 0x3f, 0x70,
];
const EMPTY_DETAIL_DIGEST: [u8; 32] = [
    0xa7, 0x23, 0x1e, 0x5f, 0x5c, 0x48, 0x97, 0xf6, 0x51, 0x3a, 0xef, 0x37, 0x0f, 0xb3, 0x06, 0x1d,
    0xf1, 0x67, 0x75, 0x30, 0xc9, 0x71, 0x50, 0x2c, 0x13, 0x7f, 0x4a, 0xd8, 0x7e, 0x60, 0xf0, 0xae,
];

fn identity() -> UploadPutStreamIdentity {
    UploadPutStreamIdentity {
        protocol_revision: "protocol-1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
        attempt_id: "018f3e12-a457-7abc-8def-0123456789ab".to_string(),
        upload_id: "upload-1".to_string(),
        upload_fence: 7,
    }
}

fn independent_text(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("literal text length must fit u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

fn independent_identity_preimage() -> Vec<u8> {
    let value = identity();
    let mut output = b"object-store-upload-stream-identity-v1\0".to_vec();
    for field in [
        value.protocol_revision,
        value.provider_boundary_id,
        value.authenticated_cell_id,
        value.authenticated_tenant_id,
        value.logical_request_id,
        value.attempt_id,
        value.upload_id,
    ] {
        independent_text(&mut output, &field);
    }
    output.extend_from_slice(&value.upload_fence.to_be_bytes());
    output
}

fn canonical_identity() -> CanonicalUploadPutStreamIdentity {
    build_upload_put_stream_identity(identity(), 64).expect("canonical identity must validate")
}

fn mismatched_identity_candidates() -> Vec<UploadPutStreamIdentity> {
    let frozen = identity();
    let mut mutations = Vec::new();
    let mut value = frozen.clone();
    value.protocol_revision = "other".to_string();
    mutations.push(value);
    let mut value = frozen.clone();
    value.provider_boundary_id = "other".to_string();
    mutations.push(value);
    let mut value = frozen.clone();
    value.authenticated_cell_id = "other".to_string();
    mutations.push(value);
    let mut value = frozen.clone();
    value.authenticated_tenant_id = "other".to_string();
    mutations.push(value);
    let mut value = frozen.clone();
    value.logical_request_id = "018f3e12-a458-7abc-8def-0123456789ab".to_string();
    mutations.push(value);
    let mut value = frozen.clone();
    value.attempt_id = "018f3e12-a458-7abc-8def-0123456789ab".to_string();
    mutations.push(value);
    let mut value = frozen.clone();
    value.upload_id = "other".to_string();
    mutations.push(value);
    let mut value = frozen;
    value.upload_fence = 8;
    mutations.push(value);
    mutations
}

fn independent_rejection_preimage(
    protocol_revision: &str,
    reason: u32,
    stream_identity_blake3: &[u8; 32],
    rejected_chunk_index: u64,
    rejected_field_number: u32,
) -> Vec<u8> {
    let mut output = b"object-store-upload-stream-rejected-v1\0".to_vec();
    independent_text(&mut output, protocol_revision);
    output.extend_from_slice(&reason.to_be_bytes());
    output.extend_from_slice(&32_u32.to_be_bytes());
    output.extend_from_slice(stream_identity_blake3);
    output.extend_from_slice(&rejected_chunk_index.to_be_bytes());
    output.extend_from_slice(&rejected_field_number.to_be_bytes());
    output
}

fn mismatch_rejection() -> CanonicalPutUploadStreamRejected {
    let mut candidate = identity();
    candidate.authenticated_cell_id = "other".to_string();
    build_identity_mismatch_upload_rejection(&canonical_identity(), &candidate, 9, 64)
        .expect("canonical mismatch rejection must validate")
}

#[test]
fn upload_identity_pins_independent_189_byte_preimage_and_digest() {
    let expected = independent_identity_preimage();
    let actual = canonical_identity();

    assert_eq!(expected.len(), 189);
    assert_eq!(actual.canonical_preimage(), expected);
    assert_eq!(blake3::hash(&expected).as_bytes(), &IDENTITY_DIGEST);
    assert_eq!(actual.stream_identity_blake3(), &IDENTITY_DIGEST);
}

#[test]
fn upload_identity_reports_zero_for_equal_and_lowest_field_for_all_mismatches() {
    let frozen = identity();
    assert_eq!(
        lowest_upload_put_stream_identity_mismatch_field(&frozen, &frozen.clone()),
        0
    );

    for (index, mutation) in mismatched_identity_candidates().iter().enumerate() {
        assert_eq!(
            lowest_upload_put_stream_identity_mismatch_field(&frozen, mutation),
            index as u32 + 1
        );
    }
    let mut multiple = frozen.clone();
    multiple.authenticated_cell_id = "other".to_string();
    multiple.upload_fence = 8;
    assert_eq!(
        lowest_upload_put_stream_identity_mismatch_field(&frozen, &multiple),
        3
    );
}

#[test]
fn upload_identity_enforces_canonical_bounded_text_uuid_and_positive_fence() {
    let mut u64_max = identity();
    u64_max.upload_fence = u64::MAX;
    assert!(build_upload_put_stream_identity(u64_max, 64).is_ok());

    let mut invalid = Vec::new();
    let mut value = identity();
    value.protocol_revision.clear();
    invalid.push(value);
    let mut value = identity();
    value.provider_boundary_id = "e\u{301}".to_string();
    invalid.push(value);
    let mut value = identity();
    value.authenticated_cell_id = "x".repeat(65);
    invalid.push(value);
    let mut value = identity();
    value.authenticated_tenant_id.push('\0');
    invalid.push(value);
    let mut value = identity();
    value.logical_request_id.make_ascii_uppercase();
    invalid.push(value);
    let mut value = identity();
    value.attempt_id = "not-a-uuid".to_string();
    invalid.push(value);
    let mut value = identity();
    value.logical_request_id = value.logical_request_id.replace("-7abc-", "-6abc-");
    invalid.push(value);
    let mut value = identity();
    value.attempt_id = value.attempt_id.replace("-8def-", "-cdef-");
    invalid.push(value);
    let mut value = identity();
    value.upload_id.clear();
    invalid.push(value);
    let mut value = identity();
    value.upload_fence = 0;
    invalid.push(value);

    for value in invalid {
        assert!(build_upload_put_stream_identity(value, 64).is_err());
    }
    assert_eq!(
        build_upload_put_stream_identity(identity(), 0),
        Err(UploadContractError::InvalidTextMaximum)
    );
}

#[test]
fn upload_rejections_pin_independent_mismatch_empty_preimages_and_digests() {
    let mismatch = mismatch_rejection();
    let expected_mismatch = independent_rejection_preimage("protocol-1", 1, &IDENTITY_DIGEST, 9, 3);
    assert_eq!(expected_mismatch.len(), 105);
    assert_eq!(mismatch.canonical_preimage(), expected_mismatch);
    assert_eq!(mismatch.detail().detail_blake3, MISMATCH_DETAIL_DIGEST);

    assert_eq!(
        empty_upload_put_stream_identity_blake3(),
        EMPTY_IDENTITY_DIGEST
    );
    assert_eq!(b"object-store-upload-stream-identity-v1\0".len(), 39);
    let empty = build_empty_stream_upload_rejection("protocol-1".to_string(), 64)
        .expect("canonical empty-stream rejection must validate");
    let expected_empty =
        independent_rejection_preimage("protocol-1", 2, &EMPTY_IDENTITY_DIGEST, 0, 0);
    assert_eq!(expected_empty.len(), 105);
    assert_eq!(empty.canonical_preimage(), expected_empty);
    assert_eq!(empty.detail().detail_blake3, EMPTY_DETAIL_DIGEST);
}

#[test]
fn identity_mismatch_rejection_derives_exact_fields_one_through_eight() {
    let frozen = canonical_identity();
    for (index, candidate) in mismatched_identity_candidates().iter().enumerate() {
        let rejection = build_identity_mismatch_upload_rejection(&frozen, candidate, u64::MAX, 64)
            .expect("each mismatch must build a rejection");
        assert_eq!(rejection.detail().rejected_field_number, index as u32 + 1);
        assert_eq!(rejection.detail().rejected_chunk_index, u64::MAX);
    }

    let mut multiple = identity();
    multiple.authenticated_cell_id = "other".to_string();
    multiple.upload_id = "also-other".to_string();
    assert_eq!(
        build_identity_mismatch_upload_rejection(&frozen, &multiple, 9, 64)
            .expect("multiple mismatches must bind the lowest field")
            .detail()
            .rejected_field_number,
        3
    );
}

#[test]
fn identity_mismatch_rejection_rejects_equal_frozen_and_candidate_identities() {
    let frozen = canonical_identity();

    assert_eq!(
        build_identity_mismatch_upload_rejection(&frozen, frozen.identity(), 0, 64),
        Err(UploadContractError::IdentitiesMatch)
    );
}

#[test]
fn empty_stream_rejection_has_exact_closed_reason_shape() {
    let empty = build_empty_stream_upload_rejection("protocol-1".to_string(), 64)
        .expect("canonical empty-stream rejection must validate");
    assert_eq!(
        empty.detail().reason,
        PutUploadStreamRejectReason::EmptyStream
    );
    assert_eq!(empty.detail().stream_identity_blake3, EMPTY_IDENTITY_DIGEST);
    assert_eq!(empty.detail().rejected_chunk_index, 0);
    assert_eq!(empty.detail().rejected_field_number, 0);

    let mut wrong_digest = empty.detail().clone();
    wrong_digest.stream_identity_blake3 = [0; 32];
    let mut wrong_chunk = empty.detail().clone();
    wrong_chunk.rejected_chunk_index = 1;
    let mut wrong_field = empty.detail().clone();
    wrong_field.rejected_field_number = 1;
    for malformed in [wrong_digest, wrong_chunk, wrong_field] {
        assert_eq!(
            validate_upload_stream_rejection(&malformed, 64),
            Err(UploadContractError::InvalidEmptyStreamShape)
        );
    }
}

#[test]
fn upload_rejection_validation_rejects_every_stale_field_or_digest_mutation() {
    let mismatch = mismatch_rejection();
    let detail = mismatch.detail();
    let mut mutations = Vec::new();
    let mut value = detail.clone();
    value.protocol_revision = "protocol-2".to_string();
    mutations.push(value);
    let mut value = detail.clone();
    value.reason = PutUploadStreamRejectReason::EmptyStream;
    mutations.push(value);
    let mut value = detail.clone();
    value.stream_identity_blake3[0] ^= 0xff;
    mutations.push(value);
    let mut value = detail.clone();
    value.rejected_chunk_index += 1;
    mutations.push(value);
    let mut value = detail.clone();
    value.rejected_field_number += 1;
    mutations.push(value);
    let mut value = detail.clone();
    value.detail_blake3[0] ^= 0xff;
    mutations.push(value);

    for mutation in mutations {
        assert!(validate_upload_stream_rejection(&mutation, 64).is_err());
    }
    assert_eq!(
        validate_upload_stream_rejection(detail, 0),
        Err(UploadContractError::InvalidTextMaximum)
    );
}

#[test]
fn upload_diagnostics_redact_identity_preimage_and_both_digests() {
    let identity = canonical_identity();
    let rejection = mismatch_rejection();
    let diagnostic = format!("{identity:?} {rejection:?}");

    for secret in [
        "boundary-1",
        "cell-1",
        "tenant-1",
        "018f3e12-a456-7abc-8def-0123456789ab",
        "018f3e12-a457-7abc-8def-0123456789ab",
        "upload-1",
        "object-store-upload-stream-identity-v1",
    ] {
        assert!(!diagnostic.contains(secret), "diagnostic leaked {secret}");
    }
    assert!(!diagnostic.contains("227, 21, 117, 234"));
    assert!(!diagnostic.contains("147, 114, 159, 255"));
    assert!(diagnostic.contains("[REDACTED]"));
}

#[test]
fn upload_contract_remains_effect_free_and_unwired() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // CR-033 D1/D6/P2 removed the separate-process service shell entirely; assert that
    // structurally instead of grepping a deleted `src/service.rs` for the wiring it never had.
    for removed in ["src/service.rs", "src/server.rs", "src/main.rs"] {
        assert!(
            !manifest.join(removed).exists(),
            "process-composition surface must stay removed: {removed}"
        );
    }
    let source = std::fs::read_to_string(manifest.join("src/upload.rs"))
        .expect("upload contract source must be readable");

    for forbidden in [
        "tokio_postgres",
        "std::fs",
        "aws_sdk",
        "lore_aws",
        "lore_postgres",
    ] {
        assert!(
            !source.contains(forbidden),
            "pure upload contract must not depend on effect surface {forbidden}"
        );
    }
}

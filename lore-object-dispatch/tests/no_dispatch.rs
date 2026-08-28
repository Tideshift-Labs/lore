// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::CanonicalNoDispatchProof;
use lore_object_dispatch::NoDispatchProofError;
use lore_object_dispatch::NoDispatchProofFields;
use lore_object_dispatch::NoDispatchReason;
use lore_object_dispatch::build_no_dispatch_proof;
use lore_object_dispatch::validate_no_dispatch_proof;

const COMMITTED_AT: i64 = 0x018f_3e12_a456;
const GOLDEN_DIGEST: [u8; 32] = [
    0xa9, 0x0a, 0x54, 0x47, 0x76, 0x41, 0x6d, 0x8e, 0x40, 0xc6, 0xdc, 0xdf, 0x43, 0x0c, 0xc0, 0xb2,
    0x14, 0x50, 0x35, 0xd3, 0xab, 0xbb, 0xc2, 0x7b, 0x73, 0xa1, 0x4c, 0xf2, 0x0a, 0xfd, 0x5a, 0x01,
];

fn uuid_v7(timestamp_unix_ms: u64, tail: &str) -> String {
    let timestamp = format!("{timestamp_unix_ms:012x}");
    format!("{}-{}-7abc-8def-{tail}", &timestamp[..8], &timestamp[8..])
}

fn fields() -> NoDispatchProofFields {
    NoDispatchProofFields {
        reason: NoDispatchReason::PreparedTtlExpired,
        proof_id: uuid_v7(COMMITTED_AT as u64, "0123456789ab"),
        proof_fence: 5,
        committed_at_unix_ms: COMMITTED_AT,
        authority_epoch: 6,
    }
}

fn independent_preimage() -> Vec<u8> {
    let proof_id = uuid_v7(COMMITTED_AT as u64, "0123456789ab");
    let mut output = b"object-store-no-dispatch-proof-v1\0".to_vec();
    output.extend_from_slice(&4_u32.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(proof_id.len())
            .expect("literal proof ID length must fit u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(proof_id.as_bytes());
    output.extend_from_slice(&5_u64.to_be_bytes());
    output.extend_from_slice(&(COMMITTED_AT as u64).to_be_bytes());
    output.extend_from_slice(&6_u64.to_be_bytes());
    output
}

fn built() -> CanonicalNoDispatchProof {
    build_no_dispatch_proof(fields(), 1024).expect("canonical proof must build")
}

#[test]
fn no_dispatch_proof_pins_independent_102_byte_preimage_and_digest() {
    let expected = independent_preimage();
    let actual = built();

    assert_eq!(expected.len(), 102);
    assert_eq!(actual.canonical_preimage(), expected);
    assert_eq!(blake3::hash(&expected).as_bytes(), &GOLDEN_DIGEST);
    assert_eq!(actual.proof().proof_blake3, GOLDEN_DIGEST);
}

#[test]
fn no_dispatch_reason_accepts_exact_closed_codes_one_through_eight() {
    let reasons = [
        NoDispatchReason::CellAdmissionRejected,
        NoDispatchReason::AuthorityCancelledBeforeSend,
        NoDispatchReason::DispatcherProvedNotSent,
        NoDispatchReason::PreparedTtlExpired,
        NoDispatchReason::SdkConstructionFailed,
        NoDispatchReason::LocalValidationFailed,
        NoDispatchReason::RequestDeadlineExpired,
        NoDispatchReason::AuthorityLostBeforeDispatch,
    ];

    for (index, expected) in reasons.into_iter().enumerate() {
        assert_eq!(NoDispatchReason::try_from(index as u32 + 1), Ok(expected));
    }
    assert_eq!(
        NoDispatchReason::try_from(0),
        Err(NoDispatchProofError::InvalidReason)
    );
    assert_eq!(
        NoDispatchReason::try_from(9),
        Err(NoDispatchProofError::InvalidReason)
    );
}

#[test]
fn no_dispatch_proof_requires_canonical_uuid_timestamp_equal_to_database_commit() {
    let mut uppercase = fields();
    uppercase.proof_id.make_ascii_uppercase();
    let mut mismatched = fields();
    mismatched.proof_id = uuid_v7(COMMITTED_AT as u64 + 1, "0123456789ab");
    let mut negative = fields();
    negative.committed_at_unix_ms = -1;

    assert_eq!(
        build_no_dispatch_proof(uppercase, 1024),
        Err(NoDispatchProofError::InvalidProofId)
    );
    assert_eq!(
        build_no_dispatch_proof(mismatched, 1024),
        Err(NoDispatchProofError::ProofTimestampMismatch)
    );
    assert_eq!(
        build_no_dispatch_proof(negative, 1024),
        Err(NoDispatchProofError::InvalidCommitTime)
    );
}

#[test]
fn no_dispatch_proof_accepts_inclusive_numeric_and_preimage_boundaries() {
    let mut maximum = fields();
    maximum.proof_fence = u64::MAX;
    maximum.authority_epoch = u64::MAX;
    let canonical = build_no_dispatch_proof(maximum, 1024).expect("u64 maxima must be valid");
    let exact_size = canonical.canonical_preimage().len() as u32;

    assert!(build_no_dispatch_proof(fields(), exact_size).is_ok());
    assert_eq!(
        build_no_dispatch_proof(fields(), exact_size - 1),
        Err(NoDispatchProofError::PreimageTooLarge)
    );

    for timestamp in [0, (1_i64 << 48) - 1] {
        let mut boundary = fields();
        boundary.proof_id = uuid_v7(timestamp as u64, "0123456789ab");
        boundary.committed_at_unix_ms = timestamp;
        assert!(build_no_dispatch_proof(boundary, 1024).is_ok());
    }
}

#[test]
fn no_dispatch_proof_rejects_zero_fence_epoch_and_maximum() {
    let mut zero_fence = fields();
    zero_fence.proof_fence = 0;
    let mut zero_epoch = fields();
    zero_epoch.authority_epoch = 0;

    assert_eq!(
        build_no_dispatch_proof(zero_fence, 1024),
        Err(NoDispatchProofError::InvalidProofFence)
    );
    assert_eq!(
        build_no_dispatch_proof(zero_epoch, 1024),
        Err(NoDispatchProofError::InvalidAuthorityEpoch)
    );
    assert_eq!(
        build_no_dispatch_proof(fields(), 0),
        Err(NoDispatchProofError::InvalidMaximum)
    );
}

#[test]
fn no_dispatch_validation_rejects_every_stale_field_or_digest_mutation() {
    let canonical = built();
    let proof = canonical.proof();
    let mut mutations = Vec::new();
    let mut reason = proof.clone();
    reason.fields.reason = NoDispatchReason::SdkConstructionFailed;
    mutations.push(reason);
    let mut proof_id = proof.clone();
    proof_id.fields.proof_id = uuid_v7(COMMITTED_AT as u64, "1123456789ab");
    mutations.push(proof_id);
    let mut fence = proof.clone();
    fence.fields.proof_fence += 1;
    mutations.push(fence);
    let mut time = proof.clone();
    time.fields.committed_at_unix_ms += 1;
    mutations.push(time);
    let mut epoch = proof.clone();
    epoch.fields.authority_epoch += 1;
    mutations.push(epoch);
    let mut digest = proof.clone();
    digest.proof_blake3[0] ^= 0xff;
    mutations.push(digest);

    for mutation in mutations {
        assert!(validate_no_dispatch_proof(&mutation, 1024).is_err());
    }
}

#[test]
fn no_dispatch_diagnostics_redact_proof_identity_digest_and_preimage() {
    let canonical = built();
    let diagnostic = format!("{canonical:?}");

    assert!(!diagnostic.contains(&canonical.proof().fields.proof_id));
    assert!(!diagnostic.contains("169, 10, 84, 71"));
    assert!(!diagnostic.contains("object-store-no-dispatch-proof-v1"));
    assert!(diagnostic.contains("[REDACTED]"));
}

#[test]
fn no_dispatch_contract_remains_effect_free_and_unwired() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // CR-033 D1/D6/P2 removed the separate-process service shell entirely; assert that
    // structurally instead of grepping a deleted `src/service.rs` for the wiring it never had.
    for removed in ["src/service.rs", "src/server.rs", "src/main.rs"] {
        assert!(
            !manifest.join(removed).exists(),
            "process-composition surface must stay removed: {removed}"
        );
    }
    let source = std::fs::read_to_string(manifest.join("src/no_dispatch.rs"))
        .expect("no-dispatch source must be readable");

    for forbidden in [
        "tokio_postgres",
        "std::fs",
        "aws_sdk",
        "lore_aws",
        "lore_postgres",
    ] {
        assert!(
            !source.contains(forbidden),
            "pure proof contract must not depend on effect surface {forbidden}"
        );
    }
}

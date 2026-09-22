// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::CanonicalNoDispatchProof;
use lore_object_dispatch::NoDispatchProofError;
use lore_object_dispatch::NoDispatchProofFields;
use lore_object_dispatch::NoDispatchReason;
use lore_object_dispatch::build_no_dispatch_proof;
use lore_object_dispatch::validate_no_dispatch_proof;

const COMMITTED_AT: i64 = 0x018f_3e12_a456;
// Deliberately NOT derived from COMMITTED_AT: WP-114 CD-6 requires `logical_request_id` to be
// canonical UUIDv7, but explicitly does not constrain its embedded timestamp against
// `committed_at_unix_ms` the way `proof_id` is constrained. Using a different embedded timestamp
// here is itself part of the proof that no such ordering is enforced.
const LOGICAL_REQUEST_ID: &str = "00000000-0000-7abc-8def-1111111111aa";
const OTHER_LOGICAL_REQUEST_ID: &str = "00000000-0000-7abc-8def-2222222222bb";
// Recomputed for the WP-114 CD-6 field addition: independently derived (Python + the `blake3`
// package) from `independent_preimage()` below, not copied from any Rust run.
//
// CROSS-LANGUAGE: this exact vector and digest are also pinned by the TypeScript twin, at
// `lorehub/packages/control-plane/test/capacity/object-store-no-dispatch-proof.test.ts`
// ("agrees byte-for-byte with the Rust twin on one shared cross-language vector"). Both
// implementations encode `object-store-no-dispatch-proof-v1`; before CD-6 they pinned DIFFERENT
// inputs and stayed green while disagreeing byte for byte. Move this vector and you must move
// that one in the same commit.
const GOLDEN_DIGEST: [u8; 32] = [
    0xe0, 0x67, 0xc2, 0x6c, 0x7e, 0x42, 0x2e, 0x2e, 0x5b, 0xb3, 0xe1, 0xd0, 0xe7, 0x43, 0xdd, 0x42,
    0xa5, 0x78, 0x55, 0x10, 0x10, 0xf3, 0x5e, 0x4f, 0xd0, 0x3c, 0xb5, 0x42, 0xeb, 0x5e, 0x79, 0xfe,
];

fn uuid_v7(timestamp_unix_ms: u64, tail: &str) -> String {
    let timestamp = format!("{timestamp_unix_ms:012x}");
    format!("{}-{}-7abc-8def-{tail}", &timestamp[..8], &timestamp[8..])
}

fn fields() -> NoDispatchProofFields {
    NoDispatchProofFields {
        reason: NoDispatchReason::PreparedTtlExpired,
        logical_request_id: LOGICAL_REQUEST_ID.to_string(),
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
        &u32::try_from(LOGICAL_REQUEST_ID.len())
            .expect("literal logical request ID length must fit u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(LOGICAL_REQUEST_ID.as_bytes());
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
fn no_dispatch_proof_pins_independent_142_byte_preimage_and_digest() {
    let expected = independent_preimage();
    let actual = built();

    assert_eq!(expected.len(), 142);
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

/// WP-114 CD-6: `logical_request_id` is checked for canonicality only. Unlike `proof_id`, its
/// embedded UUIDv7 timestamp is never compared against `committed_at_unix_ms` -- `fields()` above
/// already uses a deliberately different embedded timestamp, and every other passing test in this
/// file relies on that not being rejected. This test pins it explicitly so a future change adding
/// a timestamp-ordering constraint here is caught.
#[test]
fn no_dispatch_proof_logical_request_id_has_no_timestamp_ordering_constraint() {
    let mut far_future = fields();
    far_future.logical_request_id = uuid_v7((1_u64 << 48) - 1, "1111111111aa");
    assert!(build_no_dispatch_proof(far_future, 1024).is_ok());

    let mut zero_timestamp = fields();
    zero_timestamp.logical_request_id = uuid_v7(0, "1111111111aa");
    assert!(build_no_dispatch_proof(zero_timestamp, 1024).is_ok());
}

/// `logical_request_id` must still be a canonical UUIDv7: empty, non-UUID-shaped, and
/// non-canonical (wrong case, wrong version/variant nibble) values are all rejected the same way
/// as an invalid `proof_id` is, just against the new field's own error variant.
#[test]
fn no_dispatch_proof_rejects_every_non_canonical_logical_request_id_shape() {
    let cases: [(&str, &str); 5] = [
        ("", "empty"),
        ("not-a-uuid", "not UUID-shaped"),
        ("00000000-0000-7abc-8def-1111111111ag", "non-hex tail"),
        (
            "00000000-0000-4abc-8def-1111111111aa",
            "version nibble is 4, not 7",
        ),
        (
            "00000000-0000-7abc-1def-1111111111aa",
            "variant nibble is 1, not 8/9/a/b",
        ),
    ];

    for (candidate, label) in cases {
        let mut broken = fields();
        broken.logical_request_id = candidate.to_string();
        assert_eq!(
            build_no_dispatch_proof(broken, 1024),
            Err(NoDispatchProofError::InvalidLogicalRequestId),
            "case: {label}"
        );
    }

    let mut uppercase = fields();
    uppercase.logical_request_id.make_ascii_uppercase();
    assert_eq!(
        build_no_dispatch_proof(uppercase, 1024),
        Err(NoDispatchProofError::InvalidLogicalRequestId),
        "case: uppercase is not canonical lowercase hex"
    );
}

/// Two proofs differing ONLY in `logical_request_id` must diverge in `proof_blake3`, so a proof
/// minted for request A can never be replayed as if it were minted for request B: mint proof
/// bytes for one, mutate the field, and prove neither the preimage nor the digest can still match.
#[test]
fn no_dispatch_proofs_for_different_logical_requests_have_different_digests() {
    let for_a = build_no_dispatch_proof(fields(), 1024).expect("proof for request A must build");
    let mut fields_b = fields();
    fields_b.logical_request_id = OTHER_LOGICAL_REQUEST_ID.to_string();
    let for_b = build_no_dispatch_proof(fields_b, 1024).expect("proof for request B must build");

    assert_ne!(for_a.canonical_preimage(), for_b.canonical_preimage());
    assert_ne!(for_a.proof().proof_blake3, for_b.proof().proof_blake3);

    // A's digest, replayed against B's fields (the exact substitution attack CD-6 closes), must
    // fail validation rather than silently pass.
    let mut swapped = for_b.proof().clone();
    swapped.proof_blake3 = for_a.proof().proof_blake3;
    assert_eq!(
        validate_no_dispatch_proof(&swapped, 1024),
        Err(NoDispatchProofError::DigestMismatch)
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
    let mut logical_request_id = proof.clone();
    logical_request_id.fields.logical_request_id = OTHER_LOGICAL_REQUEST_ID.to_string();
    mutations.push(logical_request_id);
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
    assert!(!diagnostic.contains(&canonical.proof().fields.logical_request_id));
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

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Drift guard for the fork-local `lore.object_dispatch.v1` private wire.

use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;

const PROTO: &str = include_str!("../proto/lore/object_dispatch/v1/object_dispatch.proto");
const GENERATED: &str = include_str!("../src/grpc/lore.object_dispatch.v1.rs");

// These independent values fingerprint the exact declaration token stream of the canonical record
// schema. Comments and formatting are deliberately excluded, while every package, type, field name,
// field number, reserved field number, optional/repeated qualifier, oneof branch, enum name, and
// enum number remains covered. Re-freeze all three together, in the same commit as the proto edit.
const CONTRACT_TOKEN_BYTES: usize = 20_612;
const CONTRACT_FNV1A64: u64 = 0x4d34_14d5_b5a6_438d;
const CONTRACT_DJB2_XOR64: u64 = 0xb3d4_8c7d_3014_e8bb;

fn without_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

fn contract_tokens(source: &str) -> Vec<u8> {
    without_line_comments(source)
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn djb2_xor64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(5381_u64, |hash, byte| {
        hash.wrapping_mul(33) ^ u64::from(*byte)
    })
}

#[test]
fn object_dispatch_v1_contract_matches_wp_121() {
    let tokens = contract_tokens(PROTO);

    assert_eq!(
        tokens.len(),
        CONTRACT_TOKEN_BYTES,
        "proto token length drifted"
    );
    assert_eq!(fnv1a64(&tokens), CONTRACT_FNV1A64, "proto contract drifted");
    assert_eq!(
        djb2_xor64(&tokens),
        CONTRACT_DJB2_XOR64,
        "proto contract drifted"
    );
}

#[test]
fn object_dispatch_v1_has_no_service_or_streaming_surface() {
    let source = without_line_comments(PROTO);
    let declarations: [&str; 0] = [];

    assert!(source.contains("package lore.object_dispatch.v1;"));
    assert_eq!(
        source.matches("service ObjectStoreDispatchService").count(),
        0,
        "the seven-RPC service block must not be present (CR-033 D1/D6)"
    );
    assert_eq!(source.matches("rpc ").count(), declarations.len());
    for declaration in declarations {
        assert!(
            source.contains(declaration),
            "missing exact RPC declaration: {declaration}"
        );
    }
}

#[test]
fn object_dispatch_v1_is_marked_as_fork_local_cr_033() {
    assert!(PROTO.contains("FORK-LOCAL (Tideshift, CR-033)"));
    assert!(PROTO.contains("package lore.object_dispatch.v1;"));
    assert!(PROTO.contains("upstream"));
    assert!(PROTO.contains("collision"));
}

#[test]
fn removed_continuity_arm_field_numbers_stay_reserved() {
    let source = without_line_comments(PROTO);

    assert_eq!(
        source.matches("reserved 4, 5;").count(),
        1,
        "the receipt envelope must reserve the removed continuity arms 4 and 5 (CR-033 D2)"
    );
    assert_eq!(
        source.matches("reserved 2, 4;").count(),
        1,
        "the outcome envelope must reserve the removed continuity arms 2 and 4 (CR-033 D2)"
    );
}

#[test]
fn checked_in_bindings_and_public_exports_are_available() {
    let _ = ObjectStoreRequestV1::default();
    assert!(!GENERATED.contains("pub mod object_store_dispatch_service_client"));
    assert!(!GENERATED.contains("pub mod object_store_dispatch_service_server"));
    let generated_tokens =
        String::from_utf8(contract_tokens(GENERATED)).expect("generated Rust is UTF-8");
    let boxed_outcome_types = ["::prost::alloc::boxed::Box<super::ObjectStoreRequestStateV1>"];
    for outcome_type in boxed_outcome_types {
        assert_eq!(
            generated_tokens.matches(outcome_type).count(),
            2,
            "outcome type must remain boxed in both generated oneofs: {outcome_type}"
        );
    }
    // Compare against code only. Both files carry tombstone comments that name the removed
    // types on purpose, so a raw containment check would trip on the documentation.
    let proto_code = without_line_comments(PROTO);
    let generated_code = without_line_comments(GENERATED);
    for removed_message in [
        "ObjectStoreContinuityQuarantinedV1",
        "ObjectStoreContinuityAdjudicatedV1",
        "ObjectStoreContinuityIntentKindV1",
        "ObjectStoreContinuityQuarantineReasonV1",
        "ObjectStoreContinuityQuotaOwnershipV1",
        "ObjectStoreContinuityAdjudicationKindV1",
        "ObjectStoreContinuityAdjudicationProofV1",
        "ObjectStoreContinuityQuotaReleaseReceiptV1",
        // The superseded global dispatch authority record and its per-dimension child
        // (CR-033 D6). Nothing was ever typed with either, so they encoded nothing.
        "ObjectStoreDispatchAuthorityV1",
        "ProviderDimensionAuthorityV1",
    ] {
        assert!(
            !generated_code.contains(removed_message),
            "removed type must not reappear in generated bindings: {removed_message}"
        );
        assert!(
            !proto_code.contains(removed_message),
            "removed type must not be re-declared in the proto: {removed_message}"
        );
    }
}

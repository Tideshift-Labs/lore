// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Drift guard for the fork-local `lore.object_dispatch.v1` private wire.

use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;
use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_client::ObjectStoreDispatchServiceClient;
use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_server::ObjectStoreDispatchService;

const PROTO: &str = include_str!("../proto/lore/object_dispatch/v1/object_dispatch.proto");
const GENERATED: &str = include_str!("../src/grpc/lore.object_dispatch.v1.rs");

// These independent values fingerprint the exact declaration token stream frozen by the five
// proto blocks in WP-121. Comments and formatting are deliberately excluded, while every package,
// service, RPC streaming marker, type, field name, field number, optional/repeated qualifier,
// oneof branch, enum name, and enum number remains covered.
const CONTRACT_TOKEN_BYTES: usize = 25_211;
const CONTRACT_FNV1A64: u64 = 0xf9f3_bc6a_e59c_092b;
const CONTRACT_DJB2_XOR64: u64 = 0x6a28_3221_de00_e751;

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
fn object_dispatch_v1_has_exact_service_and_streaming_shape() {
    let source = without_line_comments(PROTO);
    let declarations = [
        "rpc ReservePut(ReservePutRequestV1) returns (ReservePutAckV1);",
        "rpc UploadPut(stream UploadPutChunkV1) returns (PutSpoolReadyV1);",
        "rpc Submit(ObjectStoreRequestV1) returns (ObjectStoreRequestReceiptV1);",
        "rpc GetRequest(ObjectStoreRequestQueryV1) returns (ObjectStoreRequestOutcomeV1);",
        "rpc FetchResult(ObjectStoreResultFetchV1) returns (stream ObjectStoreResultChunkV1);",
        "rpc AcknowledgeResult(ObjectStoreResultAckV1) returns (ObjectStoreResultAckReceiptV1);",
        "rpc DiscardResult(ObjectStoreResultDiscardV1) returns (ObjectStoreResultDiscardReceiptV1);",
    ];

    assert!(source.contains("package lore.object_dispatch.v1;"));
    assert_eq!(
        source.matches("service ObjectStoreDispatchService").count(),
        1
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
    assert!(PROTO.contains("lore.object_dispatch.v1.ObjectStoreDispatchService"));
    assert!(PROTO.contains("upstream"));
    assert!(PROTO.contains("collision"));
}

#[test]
fn checked_in_bindings_and_public_exports_are_available() {
    fn client_export<T>() -> std::marker::PhantomData<ObjectStoreDispatchServiceClient<T>> {
        std::marker::PhantomData
    }
    fn _server_export<T: ObjectStoreDispatchService>() {}

    let _ = ObjectStoreRequestV1::default();
    let _ = client_export::<()>();
    assert!(GENERATED.contains("pub mod object_store_dispatch_service_client"));
    assert!(GENERATED.contains("pub mod object_store_dispatch_service_server"));
    let generated_tokens =
        String::from_utf8(contract_tokens(GENERATED)).expect("generated Rust is UTF-8");
    let boxed_outcome_types = [
        "::prost::alloc::boxed::Box<super::ObjectStoreRequestStateV1>",
        "::prost::alloc::boxed::Box<super::ObjectStoreContinuityQuarantinedV1>",
        "::prost::alloc::boxed::Box<super::ObjectStoreContinuityAdjudicatedV1>",
    ];
    for outcome_type in boxed_outcome_types {
        assert_eq!(
            generated_tokens.matches(outcome_type).count(),
            2,
            "outcome type must remain boxed in both generated oneofs: {outcome_type}"
        );
    }
}

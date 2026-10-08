// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::interface::LoreBinary;
use lore_revision::interface::LoreMetadata;
use lore_revision::interface::LoreString;

/// The JSON shape is a published wire format that existing clients read, and
/// the serializer producing it is hand-written rather than derived, so the
/// exact bytes are the contract — not just that a round trip works. Every
/// kind is pinned, because each reaches JSON by its own route: a bool for a
/// byte, hex text for the identifiers, and base64 for a block of raw bytes.
#[test]
fn json_keeps_the_adjacently_tagged_shape() {
    let hash = lore_base::types::Hash::from([0xabu8; 32]);
    let context = lore_base::types::Context::from([0xcdu8; 16]);
    let cases = [
        (
            LoreMetadata::String(LoreString::from_str("hi")),
            r#"{"tagName":"string","data":"hi"}"#.to_string(),
        ),
        (
            LoreMetadata::Numeric(4207),
            r#"{"tagName":"numeric","data":4207}"#.to_string(),
        ),
        (
            LoreMetadata::Boolean(1),
            r#"{"tagName":"boolean","data":true}"#.to_string(),
        ),
        (
            LoreMetadata::Boolean(0),
            r#"{"tagName":"boolean","data":false}"#.to_string(),
        ),
        (
            LoreMetadata::Binary(LoreBinary::from_bytes(&[0x00, 0xff, 0x01])),
            r#"{"tagName":"binary","data":"AP8B"}"#.to_string(),
        ),
        (
            LoreMetadata::Hash(hash),
            format!(r#"{{"tagName":"hash","data":"{}"}}"#, "ab".repeat(32)),
        ),
        (
            LoreMetadata::Context(context),
            format!(r#"{{"tagName":"context","data":"{}"}}"#, "cd".repeat(16)),
        ),
        (
            LoreMetadata::Address(lore_base::types::Address { hash, context }),
            format!(
                r#"{{"tagName":"address","data":"{}-{}"}}"#,
                "ab".repeat(32),
                "cd".repeat(16)
            ),
        ),
    ];

    for (value, want) in cases {
        let json = serde_json::to_string(&value).expect("serialize");
        assert_eq!(json, want, "the published shape must not drift");
        let back: LoreMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, value);
    }
}

/// A boolean is a JSON bool but a byte in the C union, and the two must not
/// disagree: any non-zero byte is true, and true reads back as exactly 1.
#[test]
fn a_non_zero_boolean_byte_normalizes_through_json() {
    let json = serde_json::to_string(&LoreMetadata::Boolean(37)).expect("serialize");
    assert_eq!(json, r#"{"tagName":"boolean","data":true}"#);
    let back: LoreMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, LoreMetadata::Boolean(1));
}

/// Every variant has to survive the format used between a client and the
/// service, which cannot read the tagged shape at all.
#[test]
fn every_variant_survives_the_compact_format() {
    let values = [
        LoreMetadata::Address(lore_base::types::Address::default()),
        LoreMetadata::Boolean(1),
        LoreMetadata::Binary(LoreBinary::from_bytes(&[0x00, 0xff])),
        LoreMetadata::Context(lore_base::types::Context::default()),
        LoreMetadata::Hash(lore_base::types::Hash::default()),
        LoreMetadata::Numeric(u64::MAX),
        LoreMetadata::String(LoreString::from_str("hi")),
    ];

    for value in values {
        let encoded = bitcode::serialize(&value).expect("serialize");
        let decoded: LoreMetadata = bitcode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded, value, "{value:?} must survive the compact format");
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::interface::LoreBinary;

/// `LoreBinary` owns its payload, so a clone survives the original being
/// dropped. Before it owned anything, the clone was a copy of a pointer and
/// this read freed memory.
#[test]
fn a_clone_outlives_the_value_it_came_from() {
    let clone = {
        let original = LoreBinary::from_bytes(&[0xde, 0xad, 0xbe, 0xef]);
        original.clone()
    };
    assert_eq!(clone.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn an_empty_block_is_a_null_pointer_of_zero_length() {
    let empty = LoreBinary::from_bytes(&[]);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(empty.payload.is_null());
    assert_eq!(empty.as_bytes(), &[] as &[u8]);
    assert_eq!(empty, LoreBinary::default());
}

/// An event carrying a binary metadata value reaches an out-of-process
/// caller as a serialized value, so it has to deserialize. It used to panic
/// outright: the impl was `unimplemented!()`, which is why the revision-tree
/// read verb refused binary values rather than delivering one.
///
/// Both a self-describing format and a non-self-describing one are covered,
/// because the two take different paths through the impl.
#[test]
fn a_binary_value_survives_serialization() {
    let block = LoreBinary::from_bytes(b"raw\x00bytes");

    let json = serde_json::to_vec(&block).expect("json serialize");
    let from_json: LoreBinary = serde_json::from_slice(&json).expect("json deserialize");
    assert_eq!(from_json, block, "json must round-trip a binary block");

    let encoded = bitcode::serialize(&block).expect("bitcode serialize");
    let from_bitcode: LoreBinary = bitcode::deserialize(&encoded).expect("bitcode deserialize");
    assert_eq!(
        from_bitcode, block,
        "bitcode must round-trip a binary block"
    );
}

/// Equality is by content, not by length or by pointer identity: two blocks
/// of the same size holding different bytes are different values.
#[test]
fn blocks_of_equal_length_compare_by_content() {
    let block = LoreBinary::from_bytes(&[1, 2, 3, 4]);
    assert_eq!(block, LoreBinary::from_bytes(&[1, 2, 3, 4]));
    assert_ne!(block, LoreBinary::from_bytes(&[1, 2, 3, 5]));
    assert_ne!(block, LoreBinary::from_bytes(&[1, 2, 3]));
}

/// An empty block still has to survive a round trip: the deserializer has to
/// produce the null-pointer form rather than a dangling allocation. Both
/// formats are covered, since an empty block is the one input where the
/// text encoding carries no characters at all.
#[test]
fn an_empty_block_survives_serialization() {
    let empty = LoreBinary::from_bytes(&[]);

    let json = serde_json::to_string(&empty).expect("json serialize");
    assert_eq!(json, r#""""#);
    let from_json: LoreBinary = serde_json::from_str(&json).expect("json deserialize");
    assert_eq!(from_json, empty);
    assert!(from_json.payload.is_null());

    let encoded = bitcode::serialize(&empty).expect("bitcode serialize");
    let decoded: LoreBinary = bitcode::deserialize(&encoded).expect("bitcode deserialize");
    assert_eq!(decoded, empty);
    assert!(decoded.payload.is_null());
}

/// Text that is not base64 is a malformed payload, not an empty block: a
/// reader that quietly produced one would hand a caller a value the sender
/// never wrote.
#[test]
fn json_text_that_is_not_base64_fails_to_read() {
    let result: Result<LoreBinary, _> = serde_json::from_str(r#""not base64!""#);
    assert!(result.is_err());
}

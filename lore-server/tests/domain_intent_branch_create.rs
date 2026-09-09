// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_server::domain_intent::CanonicalIntent;
use lore_server::domain_intent::canonical_intent_digest;
use lore_server::domain_intent::canonical_intent_preimage;

const REPOSITORY: [u8; 16] = [0x11; 16];
const BRANCH: [u8; 16] = [0x22; 16];
const PARENT: [u8; 16] = [0x33; 16];
const REVISION: [u8; 32] = [0x44; 32];

fn intent<'a>(creator: Option<&'a str>, stack: &'a [(&'a [u8], &'a [u8])]) -> CanonicalIntent<'a> {
    CanonicalIntent::BranchCreate {
        repository_id: &REPOSITORY,
        branch_id: &BRANCH,
        name: "N",
        category: "C",
        creator,
        stack,
    }
}

#[test]
fn absent_creator_matches_literal_framing_vector() {
    let expected = hex::decode(concat!(
        "6c6f72652d6272616e63682d6372656174652d696e74656e742d763100",
        "0000001011111111111111111111111111111111",
        "0000001022222222222222222222222222222222",
        "000000014e0000000143",
        "0000000000",
        "00000000"
    ))
    .unwrap();
    assert_eq!(
        canonical_intent_preimage(&intent(None, &[])).unwrap(),
        expected
    );
    assert_eq!(
        canonical_intent_digest(&intent(None, &[])).unwrap(),
        blake3::hash(&expected).as_bytes()
    );
}

#[test]
fn explicit_empty_creator_has_a_distinct_literal_mode_byte() {
    let expected = hex::decode(concat!(
        "6c6f72652d6272616e63682d6372656174652d696e74656e742d763100",
        "0000001011111111111111111111111111111111",
        "0000001022222222222222222222222222222222",
        "000000014e0000000143",
        "0100000000",
        "00000000"
    ))
    .unwrap();
    assert_eq!(
        canonical_intent_preimage(&intent(Some(""), &[])).unwrap(),
        expected
    );
    assert_ne!(
        canonical_intent_digest(&intent(None, &[])).unwrap(),
        canonical_intent_digest(&intent(Some(""), &[])).unwrap()
    );
}

#[test]
fn ordered_parent_revision_pairs_match_literal_vector() {
    let second_parent = [0x55; 16];
    let second_revision = [0x66; 32];
    let stack: &[(&[u8], &[u8])] = &[(&PARENT, &REVISION), (&second_parent, &second_revision)];
    let expected = hex::decode(concat!(
        "6c6f72652d6272616e63682d6372656174652d696e74656e742d763100",
        "0000001011111111111111111111111111111111",
        "0000001022222222222222222222222222222222",
        "000000014e0000000143",
        "010000000161",
        "00000002",
        "0000001033333333333333333333333333333333",
        "000000204444444444444444444444444444444444444444444444444444444444444444",
        "0000001055555555555555555555555555555555",
        "000000206666666666666666666666666666666666666666666666666666666666666666"
    ))
    .unwrap();
    assert_eq!(
        canonical_intent_preimage(&intent(Some("a"), stack)).unwrap(),
        expected
    );
    let reverse = [stack[1], stack[0]];
    assert_ne!(
        canonical_intent_digest(&intent(Some("a"), stack)).unwrap(),
        canonical_intent_digest(&intent(Some("a"), &reverse)).unwrap()
    );
}

#[test]
fn each_caller_known_field_changes_the_digest() {
    let stack: &[(&[u8], &[u8])] = &[(&PARENT, &REVISION)];
    let original = intent(Some("a"), stack);
    let digest = canonical_intent_digest(&original).unwrap();
    for field in 0..7 {
        let mut changed = original.clone();
        let changed_parent = [0x77; 16];
        let changed_revision = [0x88; 32];
        let alternate_stack: &[(&[u8], &[u8])] = if field == 5 {
            &[(&changed_parent, &REVISION)]
        } else {
            &[(&PARENT, &changed_revision)]
        };
        let CanonicalIntent::BranchCreate {
            repository_id,
            branch_id,
            name,
            category,
            creator,
            stack,
        } = &mut changed
        else {
            unreachable!()
        };
        match field {
            0 => *repository_id = &PARENT,
            1 => *branch_id = &PARENT,
            2 => *name = "different",
            3 => *category = "different",
            4 => *creator = Some("b"),
            _ => *stack = alternate_stack,
        }
        assert_ne!(
            canonical_intent_digest(&changed).unwrap(),
            digest,
            "field {field}"
        );
    }
}

#[test]
fn stack_accepts_1024_entries_and_rejects_1025() {
    let mut stack: Vec<(&[u8], &[u8])> = vec![(&PARENT, &REVISION); 1024];
    let empty_len = canonical_intent_preimage(&intent(None, &[])).unwrap().len();
    let accepted = canonical_intent_preimage(&intent(None, &stack)).unwrap();
    assert_eq!(accepted.len(), empty_len + 1024 * (4 + 16 + 4 + 32));
    assert_eq!(&accepted[empty_len - 4..empty_len], &[0, 0, 4, 0]);
    stack.push((&PARENT, &REVISION));
    assert!(canonical_intent_preimage(&intent(None, &stack)).is_err());
}

#[test]
fn every_fixed_identity_width_is_checked() {
    for field in 0..4 {
        let expected = if field == 3 { 32 } else { 16 };
        for length in [expected - 1, expected + 1] {
            let bad = vec![0x99; length];
            let stack: &[(&[u8], &[u8])] = match field {
                2 => &[(&bad, &REVISION)],
                3 => &[(&PARENT, &bad)],
                _ => &[(&PARENT, &REVISION)],
            };
            let test = CanonicalIntent::BranchCreate {
                repository_id: if field == 0 { &bad } else { &REPOSITORY },
                branch_id: if field == 1 { &bad } else { &BRANCH },
                name: "N",
                category: "C",
                creator: None,
                stack,
            };
            assert!(
                canonical_intent_preimage(&test).is_err(),
                "field {field}, length {length}"
            );
        }
    }
}

#[test]
fn text_limits_count_utf8_bytes_and_preserve_empty_optional_values() {
    let boundary = "é".repeat(500);
    let oversized = format!("{boundary}x");
    for field in 0..3 {
        for (text, valid) in [(&boundary, true), (&oversized, false)] {
            let test = CanonicalIntent::BranchCreate {
                repository_id: &REPOSITORY,
                branch_id: &BRANCH,
                name: if field == 0 { text } else { "N" },
                category: if field == 1 { text } else { "" },
                creator: Some(if field == 2 { text } else { "" }),
                stack: &[],
            };
            assert_eq!(
                canonical_intent_preimage(&test).is_ok(),
                valid,
                "field {field}"
            );
        }
    }
}

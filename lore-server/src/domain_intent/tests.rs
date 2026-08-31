// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use super::*;

const REPOSITORY_ID: [u8; 16] = [
    0x01, 0x91, 0x23, 0x45, 0x67, 0x89, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];
const BRANCH_ID: [u8; 16] = [
    0x01, 0x91, 0x23, 0x45, 0x67, 0x89, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac,
];
const EXPECTED_HASH: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const NEW_HASH: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const REQUESTED_REVISION: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
const ADDRESS_HASH: [u8; 32] = [
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];
const ADDRESS_CONTEXT: [u8; 16] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
];

fn decode_hex(literal: &str) -> Vec<u8> {
    hex::decode(literal).expect("frozen hexadecimal literal must decode")
}

fn assert_vector(intent: CanonicalIntent<'_>, preimage: &str, digest: &str) {
    assert_eq!(
        canonical_intent_preimage(&intent).expect("frozen intent must encode"),
        decode_hex(preimage)
    );
    assert_eq!(
        canonical_intent_digest(&intent).expect("frozen intent must hash"),
        decode_hex(digest)
    );
}

#[test]
fn repository_create_matches_the_independent_literal_vector() {
    assert_vector(
        CanonicalIntent::RepositoryCreate {
            repository_id: &REPOSITORY_ID,
            name: "game",
            description: "binary-first",
            default_branch_id: &BRANCH_ID,
            default_branch_name: "main",
            creator: Some("alice"),
            caller_created: None,
        },
        "6c6f72652d7265706f7369746f72792d6372656174652d696e74656e742d763100000000100191234567897abc8def0123456789ab0000000467616d650000000c62696e6172792d6669727374000000100191234567897abc8def0123456789ac000000046d61696e0100000005616c696365000000000000000000",
        "521449645b4e48359996366eaea364171892017242ce4bfd47de61bb6ad355c9",
    );
}

#[test]
fn repository_delete_matches_the_independent_literal_vector() {
    assert_vector(
        CanonicalIntent::RepositoryDelete {
            repository_id: &REPOSITORY_ID,
        },
        "6c6f72652d7265706f7369746f72792d64656c6574652d696e74656e742d763100000000100191234567897abc8def0123456789ab",
        "a55b416b0f8562cea9e245f94c702537f59ab59cd37131b84b1541be77019e4e",
    );
}

#[test]
fn repository_metadata_cas_matches_the_independent_literal_vector() {
    assert_vector(
        CanonicalIntent::RepositoryMetadataCas {
            repository_id: &REPOSITORY_ID,
            expected_hash: &EXPECTED_HASH,
            new_hash: &NEW_HASH,
        },
        "6c6f72652d7265706f7369746f72792d6d657461646174612d6361732d696e74656e742d763100000000100191234567897abc8def0123456789ab00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "d8acfc2f105acb7e9fca557950b56a225ea3a8fb3d8d9aed7a552977efa3598d",
    );
}

#[test]
fn branch_metadata_cas_matches_the_independent_literal_vector() {
    assert_vector(
        CanonicalIntent::BranchMetadataCas {
            repository_id: &REPOSITORY_ID,
            branch_id: &BRANCH_ID,
            expected_hash: &EXPECTED_HASH,
            new_hash: &NEW_HASH,
        },
        "6c6f72652d6272616e63682d6d657461646174612d6361732d696e74656e742d763100000000100191234567897abc8def0123456789ab000000100191234567897abc8def0123456789ac00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "fe0d26dc83286fc00b9fb53c965edef52153eb437d6b9d52934d23c157311f83",
    );
}

#[test]
fn branch_push_matches_the_independent_literal_vector() {
    assert_vector(
        CanonicalIntent::BranchPush {
            repository_id: &REPOSITORY_ID,
            branch_id: &BRANCH_ID,
            requested_revision: &REQUESTED_REVISION,
            force: true,
            fast_forward_merge: false,
        },
        "6c6f72652d6272616e63682d707573682d696e74656e742d763100000000100191234567897abc8def0123456789ab000000100191234567897abc8def0123456789ac00000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0100",
        "34cc7b2ce86fd743046d9db6fca30bf25754fc9669a2937a8fc98c0226c83581",
    );
}

#[test]
fn obliterate_matches_the_independent_literal_vector() {
    assert_vector(
        CanonicalIntent::Obliterate {
            repository_id: &REPOSITORY_ID,
            address_hash: &ADDRESS_HASH,
            address_context: &ADDRESS_CONTEXT,
        },
        "6c6f72652d6f626c697465726174652d696e74656e742d763100000000100191234567897abc8def0123456789ab00000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f00000010808182838485868788898a8b8c8d8e8f",
        "cb3bee99b06034efb6a73b6d1d317a78988e9c4aa6ec4b30b131828b45b44573",
    );
}

#[test]
fn every_byte_flip_changes_each_frozen_family_digest() {
    let vectors = [
        (
            "repository create",
            "6c6f72652d7265706f7369746f72792d6372656174652d696e74656e742d763100000000100191234567897abc8def0123456789ab0000000467616d650000000c62696e6172792d6669727374000000100191234567897abc8def0123456789ac000000046d61696e0100000005616c696365000000000000000000",
        ),
        (
            "repository delete",
            "6c6f72652d7265706f7369746f72792d64656c6574652d696e74656e742d763100000000100191234567897abc8def0123456789ab",
        ),
        (
            "repository metadata CAS",
            "6c6f72652d7265706f7369746f72792d6d657461646174612d6361732d696e74656e742d763100000000100191234567897abc8def0123456789ab00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        ),
        (
            "branch metadata CAS",
            "6c6f72652d6272616e63682d6d657461646174612d6361732d696e74656e742d763100000000100191234567897abc8def0123456789ab000000100191234567897abc8def0123456789ac00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        ),
        (
            "branch push",
            "6c6f72652d6272616e63682d707573682d696e74656e742d763100000000100191234567897abc8def0123456789ab000000100191234567897abc8def0123456789ac00000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0100",
        ),
        (
            "obliterate",
            "6c6f72652d6f626c697465726174652d696e74656e742d763100000000100191234567897abc8def0123456789ab00000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f00000010808182838485868788898a8b8c8d8e8f",
        ),
    ];

    for (family, literal) in vectors {
        let original = decode_hex(literal);
        let original_digest = blake3::hash(&original);
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 0x01;
            assert_ne!(
                blake3::hash(&changed),
                original_digest,
                "{family} byte {index} was not digest-sensitive"
            );
        }
    }
}

fn create_digest(
    repository_id: &[u8],
    name: &str,
    description: &str,
    default_branch_id: &[u8],
    default_branch_name: &str,
    creator: Option<&str>,
    caller_created: Option<u64>,
) -> Result<Vec<u8>, CanonicalIntentError> {
    canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
        repository_id,
        name,
        description,
        default_branch_id,
        default_branch_name,
        creator,
        caller_created,
    })
}

#[test]
fn every_semantic_create_field_changes_the_digest() {
    let base = create_digest(
        &REPOSITORY_ID,
        "game",
        "binary-first",
        &BRANCH_ID,
        "main",
        None,
        None,
    )
    .expect("base create must hash");
    let other_repository = [0x11; 16];
    let other_branch = [0x12; 16];
    let mutations = [
        create_digest(
            &other_repository,
            "game",
            "binary-first",
            &BRANCH_ID,
            "main",
            None,
            None,
        ),
        create_digest(
            &REPOSITORY_ID,
            "games",
            "binary-first",
            &BRANCH_ID,
            "main",
            None,
            None,
        ),
        create_digest(
            &REPOSITORY_ID,
            "game",
            "binary first",
            &BRANCH_ID,
            "main",
            None,
            None,
        ),
        create_digest(
            &REPOSITORY_ID,
            "game",
            "binary-first",
            &other_branch,
            "main",
            None,
            None,
        ),
        create_digest(
            &REPOSITORY_ID,
            "game",
            "binary-first",
            &BRANCH_ID,
            "trunk",
            None,
            None,
        ),
        create_digest(
            &REPOSITORY_ID,
            "game",
            "binary-first",
            &BRANCH_ID,
            "main",
            Some("alice"),
            None,
        ),
        create_digest(
            &REPOSITORY_ID,
            "game",
            "binary-first",
            &BRANCH_ID,
            "main",
            Some("bob"),
            None,
        ),
        create_digest(
            &REPOSITORY_ID,
            "game",
            "binary-first",
            &BRANCH_ID,
            "main",
            None,
            Some(1),
        ),
        create_digest(
            &REPOSITORY_ID,
            "game",
            "binary-first",
            &BRANCH_ID,
            "main",
            None,
            Some(2),
        ),
    ];
    for mutation in mutations {
        assert_ne!(mutation.expect("semantic mutation must remain valid"), base);
    }
}

#[test]
fn every_semantic_fixed_width_field_changes_the_digest() {
    let changed16 = [0x31; 16];
    let changed32 = [0x32; 32];
    let cases = [
        (
            canonical_intent_digest(&CanonicalIntent::RepositoryDelete {
                repository_id: &REPOSITORY_ID,
            }),
            canonical_intent_digest(&CanonicalIntent::RepositoryDelete {
                repository_id: &changed16,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: &REPOSITORY_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
            canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: &changed16,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: &REPOSITORY_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
            canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: &REPOSITORY_ID,
                expected_hash: &changed32,
                new_hash: &NEW_HASH,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: &REPOSITORY_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
            canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: &REPOSITORY_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &changed32,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: &changed16,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &changed16,
                branch_id: &BRANCH_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                expected_hash: &changed32,
                new_hash: &NEW_HASH,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                expected_hash: &EXPECTED_HASH,
                new_hash: &changed32,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: false,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &changed32,
                force: true,
                fast_forward_merge: false,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: false,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &changed16,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: false,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: false,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &changed16,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: false,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: false,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: false,
                fast_forward_merge: false,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: false,
            }),
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: &REQUESTED_REVISION,
                force: true,
                fast_forward_merge: true,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &REPOSITORY_ID,
                address_hash: &ADDRESS_HASH,
                address_context: &ADDRESS_CONTEXT,
            }),
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &REPOSITORY_ID,
                address_hash: &changed32,
                address_context: &ADDRESS_CONTEXT,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &REPOSITORY_ID,
                address_hash: &ADDRESS_HASH,
                address_context: &ADDRESS_CONTEXT,
            }),
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &changed16,
                address_hash: &ADDRESS_HASH,
                address_context: &ADDRESS_CONTEXT,
            }),
        ),
        (
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &REPOSITORY_ID,
                address_hash: &ADDRESS_HASH,
                address_context: &ADDRESS_CONTEXT,
            }),
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &REPOSITORY_ID,
                address_hash: &ADDRESS_HASH,
                address_context: &changed16,
            }),
        ),
    ];
    for (base, changed) in cases {
        assert_ne!(
            base.expect("base must hash"),
            changed.expect("mutation must hash")
        );
    }
}

#[test]
fn all_fixed_width_fields_reject_one_byte_short_and_long() {
    for wrong in [&[0u8; 15][..], &[0u8; 17][..]] {
        assert!(
            canonical_intent_digest(&CanonicalIntent::RepositoryDelete {
                repository_id: wrong
            })
            .is_err()
        );
        assert!(
            canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
                repository_id: &REPOSITORY_ID,
                branch_id: wrong,
                expected_hash: &EXPECTED_HASH,
                new_hash: &NEW_HASH
            })
            .is_err()
        );
        assert!(
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &REPOSITORY_ID,
                address_hash: &ADDRESS_HASH,
                address_context: wrong
            })
            .is_err()
        );
    }
    for wrong in [&[0u8; 31][..], &[0u8; 33][..]] {
        assert!(
            canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: &REPOSITORY_ID,
                expected_hash: wrong,
                new_hash: &NEW_HASH
            })
            .is_err()
        );
        assert!(
            canonical_intent_digest(&CanonicalIntent::BranchPush {
                repository_id: &REPOSITORY_ID,
                branch_id: &BRANCH_ID,
                requested_revision: wrong,
                force: false,
                fast_forward_merge: false
            })
            .is_err()
        );
        assert!(
            canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: &REPOSITORY_ID,
                address_hash: wrong,
                address_context: &ADDRESS_CONTEXT
            })
            .is_err()
        );
    }
}

#[test]
fn create_text_boundaries_and_empty_rules_are_exact() {
    let name_max = "n".repeat(1_000);
    let description_max = "d".repeat(65_536);
    let branch_max = "b".repeat(1_000);
    let creator_max = "c".repeat(1_000);
    assert!(
        create_digest(
            &REPOSITORY_ID,
            &name_max,
            &description_max,
            &BRANCH_ID,
            &branch_max,
            Some(&creator_max),
            Some(u64::MAX)
        )
        .is_ok()
    );
    assert!(create_digest(&REPOSITORY_ID, "n", "", &BRANCH_ID, "b", None, None).is_ok());

    assert!(create_digest(&REPOSITORY_ID, "", "", &BRANCH_ID, "b", None, None).is_err());
    assert!(create_digest(&REPOSITORY_ID, "n", "", &BRANCH_ID, "", None, None).is_err());
    assert!(create_digest(&REPOSITORY_ID, "n", "", &BRANCH_ID, "b", Some(""), None).is_err());
    assert!(
        create_digest(
            &REPOSITORY_ID,
            &"n".repeat(1_001),
            "",
            &BRANCH_ID,
            "b",
            None,
            None
        )
        .is_err()
    );
    assert!(
        create_digest(
            &REPOSITORY_ID,
            "n",
            &"d".repeat(65_537),
            &BRANCH_ID,
            "b",
            None,
            None
        )
        .is_err()
    );
    assert!(
        create_digest(
            &REPOSITORY_ID,
            "n",
            "",
            &BRANCH_ID,
            &"b".repeat(1_001),
            None,
            None
        )
        .is_err()
    );
    assert!(
        create_digest(
            &REPOSITORY_ID,
            "n",
            "",
            &BRANCH_ID,
            "b",
            Some(&"c".repeat(1_001)),
            None
        )
        .is_err()
    );
}

#[test]
fn create_text_limits_count_utf8_bytes_and_preserve_normalization() {
    let composed_at_limit = "é".repeat(500);
    let composed_over_limit = "é".repeat(501);
    assert_eq!(composed_at_limit.len(), 1_000);
    assert!(
        create_digest(
            &REPOSITORY_ID,
            &composed_at_limit,
            "",
            &BRANCH_ID,
            "main",
            None,
            None,
        )
        .is_ok()
    );
    assert!(
        create_digest(
            &REPOSITORY_ID,
            &composed_over_limit,
            "",
            &BRANCH_ID,
            "main",
            None,
            None,
        )
        .is_err()
    );

    let composed = create_digest(&REPOSITORY_ID, "é", "", &BRANCH_ID, "main", None, None)
        .expect("composed UTF-8 must hash");
    let decomposed = create_digest(
        &REPOSITORY_ID,
        "e\u{301}",
        "",
        &BRANCH_ID,
        "main",
        None,
        None,
    )
    .expect("decomposed UTF-8 must hash");
    assert_ne!(composed, decomposed, "intent text must not be normalized");
}

#[test]
fn maximum_create_preimage_is_exactly_68635_bytes_and_over_limit_refuses() {
    let name = "n".repeat(1_000);
    let description = "d".repeat(65_536);
    let branch = "b".repeat(1_000);
    let creator = "c".repeat(1_000);
    let maximum = CanonicalIntent::RepositoryCreate {
        repository_id: &REPOSITORY_ID,
        name: &name,
        description: &description,
        default_branch_id: &BRANCH_ID,
        default_branch_name: &branch,
        creator: Some(&creator),
        caller_created: Some(u64::MAX),
    };
    assert_eq!(
        canonical_intent_preimage(&maximum)
            .expect("inclusive maximum must encode")
            .len(),
        68_635
    );

    let oversized_description = format!("{description}x");
    assert!(
        create_digest(
            &REPOSITORY_ID,
            &name,
            &oversized_description,
            &BRANCH_ID,
            &branch,
            Some(&creator),
            Some(u64::MAX)
        )
        .is_err()
    );
}

#[test]
fn intent_surface_excludes_authority_and_server_derived_seams() {
    fn exhaustively_destructure(intent: CanonicalIntent<'_>) {
        match intent {
            CanonicalIntent::RepositoryCreate {
                repository_id: _,
                name: _,
                description: _,
                default_branch_id: _,
                default_branch_name: _,
                creator: _,
                caller_created: _,
            } => {}
            CanonicalIntent::RepositoryDelete { repository_id: _ } => {}
            CanonicalIntent::RepositoryMetadataCas {
                repository_id: _,
                expected_hash: _,
                new_hash: _,
            } => {}
            CanonicalIntent::BranchMetadataCas {
                repository_id: _,
                branch_id: _,
                expected_hash: _,
                new_hash: _,
            } => {}
            CanonicalIntent::BranchPush {
                repository_id: _,
                branch_id: _,
                requested_revision: _,
                force: _,
                fast_forward_merge: _,
            } => {}
            CanonicalIntent::Obliterate {
                repository_id: _,
                address_hash: _,
                address_context: _,
            } => {}
        }
    }
    exhaustively_destructure(CanonicalIntent::RepositoryDelete {
        repository_id: &REPOSITORY_ID,
    });
}

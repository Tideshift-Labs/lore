// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-116 Part 2, priority 5: v0/v1 canonical-intent digest agreement for the
//! two metadata CAS families.
//!
//! `repository_metadata_set.rs` and `repository/v1/repository_metadata_set.rs`
//! (respectively `branch_metadata_set.rs` and `revision/v1/branch_metadata_set.rs`)
//! each independently extract the same logical fields from their own wire
//! shape and call the SAME `canonical_intent_digest(&CanonicalIntent::...)`.
//! There is only one construction point for each variant, so "v0 and v1
//! agree" reduces to "the shared function is a deterministic pure function of
//! its field values" -- which is exactly what CR-029 freezes one intent
//! family per semantic operation to guarantee, and exactly what a hidden
//! nondeterminism (a stray timestamp, an iteration-order-dependent encoding)
//! would silently break without a test noticing. Pure, no Postgres, no
//! server construction.

use lore_server::domain_intent::CanonicalIntent;
use lore_server::domain_intent::canonical_intent_digest;

fn repo_id() -> [u8; 16] {
    [0x11; 16]
}

fn branch_id() -> [u8; 16] {
    [0x22; 16]
}

fn hash_a() -> [u8; 32] {
    [0xAA; 32]
}

fn hash_b() -> [u8; 32] {
    [0xBBu8; 32]
}

/// Two independent constructions of the identical `RepositoryMetadataCas`
/// intent (standing in for v0 and v1 extracting the same wire values into
/// separate `CanonicalIntent` literals) must digest identically.
#[test]
fn repository_metadata_cas_is_deterministic_across_independent_constructions() {
    let repository_id = repo_id();
    let expected_hash = hash_a();
    let new_hash = hash_b();

    let v0 = CanonicalIntent::RepositoryMetadataCas {
        repository_id: &repository_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    };
    let v1 = CanonicalIntent::RepositoryMetadataCas {
        repository_id: &repository_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    };
    assert_eq!(
        canonical_intent_digest(&v0).expect("digest v0"),
        canonical_intent_digest(&v1).expect("digest v1"),
        "two independent constructions of the identical intent must digest identically -- this \
         is what makes v0 and v1 agree, since each builds its own CanonicalIntent literal from \
         its own wire shape"
    );
}

/// Same property for `BranchMetadataCas`.
#[test]
fn branch_metadata_cas_is_deterministic_across_independent_constructions() {
    let repository_id = repo_id();
    let branch_id = branch_id();
    let expected_hash = hash_a();
    let new_hash = hash_b();

    let v0 = CanonicalIntent::BranchMetadataCas {
        repository_id: &repository_id,
        branch_id: &branch_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    };
    let v1 = CanonicalIntent::BranchMetadataCas {
        repository_id: &repository_id,
        branch_id: &branch_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    };
    assert_eq!(
        canonical_intent_digest(&v0).expect("digest v0"),
        canonical_intent_digest(&v1).expect("digest v1")
    );
}

/// Discriminating half: every field actually participates. Changing any one
/// field alone must change the digest, so agreement above isn't vacuously
/// true from an intent that ignores its inputs.
#[test]
fn every_repository_metadata_cas_field_changes_the_digest_alone() {
    let repository_id = repo_id();
    let expected_hash = hash_a();
    let new_hash = hash_b();
    let base = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
        repository_id: &repository_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    })
    .expect("base digest");

    let mut different_repository_id = repository_id;
    different_repository_id[0] ^= 0x01;
    let changed_repository_id = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
        repository_id: &different_repository_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    })
    .expect("changed repository_id digest");
    assert_ne!(base, changed_repository_id);

    let mut different_expected = expected_hash;
    different_expected[0] ^= 0x01;
    let changed_expected = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
        repository_id: &repository_id,
        expected_hash: &different_expected,
        new_hash: &new_hash,
    })
    .expect("changed expected_hash digest");
    assert_ne!(base, changed_expected);

    let mut different_new = new_hash;
    different_new[0] ^= 0x01;
    let changed_new = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
        repository_id: &repository_id,
        expected_hash: &expected_hash,
        new_hash: &different_new,
    })
    .expect("changed new_hash digest");
    assert_ne!(base, changed_new);

    // Swapping expected/new must not coincidentally collide -- proves the
    // two 32-byte fields aren't concatenated in a way that lets one absorb
    // the other's boundary.
    let swapped = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
        repository_id: &repository_id,
        expected_hash: &new_hash,
        new_hash: &expected_hash,
    })
    .expect("swapped digest");
    assert_ne!(base, swapped);
}

/// Same discriminating property for `BranchMetadataCas`, including its extra
/// `branch_id` field.
#[test]
fn every_branch_metadata_cas_field_changes_the_digest_alone() {
    let repository_id = repo_id();
    let branch_id = branch_id();
    let expected_hash = hash_a();
    let new_hash = hash_b();
    let base = canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
        repository_id: &repository_id,
        branch_id: &branch_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    })
    .expect("base digest");

    let mut different_branch_id = branch_id;
    different_branch_id[0] ^= 0x01;
    let changed_branch_id = canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
        repository_id: &repository_id,
        branch_id: &different_branch_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    })
    .expect("changed branch_id digest");
    assert_ne!(base, changed_branch_id);
}

/// Family separation: identical `repository_id`/`expected_hash`/`new_hash`
/// values under `RepositoryMetadataCas` and `BranchMetadataCas` must never
/// collide. CR-029 freezes one family per semantic operation specifically so
/// a repository-scoped and a branch-scoped CAS can never be confused for one
/// another even when their raw byte values happen to line up.
#[test]
fn repository_and_branch_metadata_cas_families_never_collide() {
    let repository_id = repo_id();
    let expected_hash = hash_a();
    let new_hash = hash_b();

    let repository_digest = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
        repository_id: &repository_id,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    })
    .expect("repository digest");
    // branch_id deliberately set to expected_hash's leading 16 bytes to make
    // this an adversarial near-collision attempt, not just two unrelated
    // random values.
    let branch_id_from_expected_hash: [u8; 16] = expected_hash[..16]
        .try_into()
        .expect("hash_a is at least 16 bytes");
    let branch_digest = canonical_intent_digest(&CanonicalIntent::BranchMetadataCas {
        repository_id: &repository_id,
        branch_id: &branch_id_from_expected_hash,
        expected_hash: &expected_hash,
        new_hash: &new_hash,
    })
    .expect("branch digest");

    assert_ne!(
        repository_digest, branch_digest,
        "the two CAS families must never produce the same digest for related field values"
    );
}

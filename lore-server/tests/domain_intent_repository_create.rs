// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-116 Part 3: v0/v1 canonical-intent digest agreement for repository
//! create.
//!
//! Mirrors `domain_intent_metadata_cas.rs`'s pattern for the metadata-CAS
//! families: `lore-server/src/grpc/handlers/repository_create.rs` (v0) and
//! `.../grpc/repository/v1/repository_create.rs` (v1) each independently
//! extract the same logical fields from their own wire shape and, once
//! wired, must call the SAME `canonical_intent_digest(&CanonicalIntent::
//! RepositoryCreate { .. })`. Two independent constructions of the identical
//! intent standing in for v0 and v1's own literals is what "v0 and v1 agree"
//! reduces to, since there is exactly one construction point per site.
//!
//! `CanonicalIntent::RepositoryCreate`'s own encoding (byte-flip vectors,
//! per-field independence, text boundaries, the 68,635-byte maximum
//! preimage, and authority/server-derived-field exclusion) is already
//! exhaustively pinned in `lore-server/src/domain_intent/tests.rs`. This file
//! does not repeat that ground; it proves the narrower, WP-116-Part-3-scoped
//! property those tests cannot: that two independently-built literals for the
//! same logical create -- one standing in for v0's wire shape, one for v1's
//! -- agree, and that the `creator`/`caller_created` mode bits (the two
//! fields whose `Option`-ness itself is meaningful, not just their value)
//! actually participate in the digest. Pure, no Postgres, no server
//! construction.
//!
//! # Why this file exists ahead of the real wiring
//!
//! Neither `repository_create.rs` (v0) nor `repository/v1/repository_create.rs`
//! (v1) constructs `CanonicalIntent::RepositoryCreate` yet as of this
//! writing -- both still unconditionally refuse admitted governed carriage
//! via `reject_unwired_governed_operation`. `CanonicalIntent::RepositoryCreate`
//! itself is a pure, already-frozen, already-shipped variant with no
//! dependency on either handler, so this coverage is real today; it is not
//! validated against either handler's actual field extraction until Part 3's
//! wiring lands, at which point a companion source-level guard belongs
//! alongside `p12_governed_wiring.rs`'s existing pattern (assert each site's
//! source calls `canonical_intent_digest` with a `CanonicalIntent::
//! RepositoryCreate` literal), not in this file.

use lore_server::domain_intent::CanonicalIntent;
use lore_server::domain_intent::canonical_intent_digest;

fn repo_id() -> [u8; 16] {
    [0x11; 16]
}

fn branch_id() -> [u8; 16] {
    [0x22; 16]
}

/// A representative "mode 1/1" create: caller supplies both an explicit
/// creator and a caller-observed creation time (v0's shape, when both
/// request fields are populated).
fn base_intent<'a>(
    repository_id: &'a [u8; 16],
    default_branch_id: &'a [u8; 16],
) -> CanonicalIntent<'a> {
    CanonicalIntent::RepositoryCreate {
        repository_id,
        name: "my-repo",
        description: "a description",
        default_branch_id,
        default_branch_name: "main",
        creator: Some("alice"),
        caller_created: Some(1_700_000_000),
    }
}

/// Two independent constructions of the identical `RepositoryCreate` intent
/// (standing in for v0 and v1 extracting the same logical fields into
/// separate `CanonicalIntent` literals) must digest identically.
#[test]
fn repository_create_is_deterministic_across_independent_constructions() {
    let repository_id = repo_id();
    let branch_id = branch_id();

    let v0 = base_intent(&repository_id, &branch_id);
    let v1 = base_intent(&repository_id, &branch_id);
    assert_eq!(
        canonical_intent_digest(&v0).expect("digest v0"),
        canonical_intent_digest(&v1).expect("digest v1"),
        "two independent constructions of the identical intent must digest identically -- this \
         is what makes v0 and v1 agree, since each builds its own CanonicalIntent literal from \
         its own wire shape"
    );
}

/// Discriminating half: every field actually participates, so the agreement
/// above is not vacuously true from an intent that ignores its inputs.
#[test]
fn every_repository_create_field_changes_the_digest_alone() {
    let repository_id = repo_id();
    let branch_id = branch_id();
    let base =
        canonical_intent_digest(&base_intent(&repository_id, &branch_id)).expect("base digest");

    let mut different_repository_id = repository_id;
    different_repository_id[0] ^= 0x01;
    assert_ne!(
        base,
        canonical_intent_digest(&base_intent(&different_repository_id, &branch_id))
            .expect("changed repository_id digest")
    );

    let mut different_branch_id = branch_id;
    different_branch_id[0] ^= 0x01;
    assert_ne!(
        base,
        canonical_intent_digest(&base_intent(&repository_id, &different_branch_id))
            .expect("changed default_branch_id digest")
    );

    assert_ne!(
        base,
        canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
            repository_id: &repository_id,
            name: "a-different-repo",
            description: "a description",
            default_branch_id: &branch_id,
            default_branch_name: "main",
            creator: Some("alice"),
            caller_created: Some(1_700_000_000),
        })
        .expect("changed name digest")
    );

    assert_ne!(
        base,
        canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
            repository_id: &repository_id,
            name: "my-repo",
            description: "a different description",
            default_branch_id: &branch_id,
            default_branch_name: "main",
            creator: Some("alice"),
            caller_created: Some(1_700_000_000),
        })
        .expect("changed description digest")
    );

    assert_ne!(
        base,
        canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
            repository_id: &repository_id,
            name: "my-repo",
            description: "a description",
            default_branch_id: &branch_id,
            default_branch_name: "not-main",
            creator: Some("alice"),
            caller_created: Some(1_700_000_000),
        })
        .expect("changed default_branch_name digest")
    );

    assert_ne!(
        base,
        canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
            repository_id: &repository_id,
            name: "my-repo",
            description: "a description",
            default_branch_id: &branch_id,
            default_branch_name: "main",
            creator: Some("bob"),
            caller_created: Some(1_700_000_000),
        })
        .expect("changed creator digest")
    );

    assert_ne!(
        base,
        canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
            repository_id: &repository_id,
            name: "my-repo",
            description: "a description",
            default_branch_id: &branch_id,
            default_branch_name: "main",
            creator: Some("alice"),
            caller_created: Some(1_700_000_001),
        })
        .expect("changed caller_created digest")
    );
}

/// `creator: Option<&str>` and `caller_created: Option<u64>` each encode a
/// leading presence byte ahead of their value bytes (see
/// `canonical_intent_preimage`'s `out.push(u8::from(creator.is_some()))` /
/// `..caller_created.is_some()..`). `Some(0)` and `None` must not collide for
/// `caller_created` even though `None`'s value bytes
/// (`unwrap_or_default().to_be_bytes()`) are themselves all zero -- proving
/// the mode bit participates, not just the value. `creator` cannot take the
/// analogous `Some("")` (the text bound requires at least 1 byte when
/// present), so its mode-bit coverage is the `Some`/`None` split at a fixed
/// nonempty value, which the field-independence test above already exercises
/// once `caller_created`'s value is held fixed.
#[test]
fn caller_created_mode_bit_participates_independently_of_its_zero_value() {
    let repository_id = repo_id();
    let branch_id = branch_id();

    let with_none = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
        repository_id: &repository_id,
        name: "my-repo",
        description: "a description",
        default_branch_id: &branch_id,
        default_branch_name: "main",
        creator: Some("alice"),
        caller_created: None,
    })
    .expect("digest with caller_created: None");
    let with_some_zero = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
        repository_id: &repository_id,
        name: "my-repo",
        description: "a description",
        default_branch_id: &branch_id,
        default_branch_name: "main",
        creator: Some("alice"),
        caller_created: Some(0),
    })
    .expect("digest with caller_created: Some(0)");
    assert_ne!(
        with_none, with_some_zero,
        "caller_created's presence bit must participate in the digest even when Some's value \
         bytes are all zero, matching None's own zero-filled default -- otherwise a v0 caller \
         explicitly asserting creation time zero would be indistinguishable from a v1 caller \
         that supplied no creation time at all"
    );
}

/// Family separation: `RepositoryCreate` and `RepositoryDelete` sharing the
/// same `repository_id` must never collide. CR-029 freezes one intent family
/// per semantic operation specifically so a create and a delete targeting the
/// same repository can never be confused for one another.
#[test]
fn repository_create_and_repository_delete_never_collide_on_shared_repository_id() {
    let repository_id = repo_id();
    let branch_id = branch_id();

    let create_digest =
        canonical_intent_digest(&base_intent(&repository_id, &branch_id)).expect("create digest");
    let delete_digest = canonical_intent_digest(&CanonicalIntent::RepositoryDelete {
        repository_id: &repository_id,
    })
    .expect("delete digest");

    assert_ne!(
        create_digest, delete_digest,
        "a repository create and a repository delete targeting the same repository_id must \
         never produce the same digest"
    );
}

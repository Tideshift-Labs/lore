// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-level completeness guard for CR029-CARRIAGE-INTENT-V1.
//!
//! Runtime mutation behavior belongs to the real-Postgres component tier. This
//! file pins the closed list of authenticated handler entry sites so a new
//! family-local digest or a leftover guarded site cannot be missed by a green
//! canonicalizer suite.

struct Site {
    label: &'static str,
    source: &'static str,
    family: &'static str,
}

/// The sites that still refuse governed carriage, after WP-116 Part 3 wired the
/// two authenticated repository-create sites. Three, not five.
///
/// Each is guarded for a different reason and they must not be collapsed into
/// one "not done yet" bucket: forwarded v1 create is fenced by CR-029's
/// CARRIAGE-02-LORE until a frozen authenticated forwarding contract exists and
/// has no verified principal to admit against at all, while both deletes are
/// blocked on an unfrozen `delete_proof` derivation. Every one carries its
/// reason at the call site.
const GUARDED_SITES: [&str; 3] = [
    include_str!("../src/grpc/forwarded_repository/v1/repository_create.rs"),
    include_str!("../src/grpc/handlers/repository_delete.rs"),
    include_str!("../src/grpc/repository/v1/repository_delete.rs"),
];

/// The shared governed seam both create sites commit through.
const GOVERNED_SEAM: &str = include_str!("../src/domain.rs");

const WIRED_SITES: [Site; 8] = [
    Site {
        label: "v0/v1 shared branch push",
        source: include_str!("../src/grpc/handlers/branch_push.rs"),
        family: "CanonicalIntent::BranchPush",
    },
    Site {
        label: "v0 obliterate",
        source: include_str!("../src/grpc/handlers/obliterate.rs"),
        family: "CanonicalIntent::Obliterate",
    },
    Site {
        label: "v0 repository metadata CAS",
        source: include_str!("../src/grpc/handlers/repository_metadata_set.rs"),
        family: "CanonicalIntent::RepositoryMetadataCas",
    },
    Site {
        label: "v1 repository metadata CAS",
        source: include_str!("../src/grpc/repository/v1/repository_metadata_set.rs"),
        family: "CanonicalIntent::RepositoryMetadataCas",
    },
    Site {
        label: "v0 branch metadata CAS",
        source: include_str!("../src/grpc/handlers/branch_metadata_set.rs"),
        family: "CanonicalIntent::BranchMetadataCas",
    },
    Site {
        label: "v1 branch metadata CAS",
        source: include_str!("../src/grpc/revision/v1/branch_metadata_set.rs"),
        family: "CanonicalIntent::BranchMetadataCas",
    },
    Site {
        label: "v0 repository create",
        source: include_str!("../src/grpc/handlers/repository_create.rs"),
        family: "CanonicalIntent::RepositoryCreate",
    },
    Site {
        label: "v1 repository create",
        source: include_str!("../src/grpc/repository/v1/repository_create.rs"),
        family: "CanonicalIntent::RepositoryCreate",
    },
];

#[test]
fn every_authenticated_site_uses_the_one_canonical_intent_definition() {
    for site in WIRED_SITES {
        assert!(
            site.source.contains(site.family),
            "{} must construct {}",
            site.label,
            site.family
        );
        assert!(
            site.source.contains("canonical_intent_digest("),
            "{} must derive its binding through the shared digest function",
            site.label
        );
    }
    assert!(
        WIRED_SITES[0]
            .source
            .contains(".branch_push_commit(&self.operation")
    );
    // WP-116 Part 1: the push must hand its classified event to the
    // coordinator.
    //
    // Scoped to the `BranchPushCommitInput` literal, not to the whole file.
    // `include_str!` pulls in `#[cfg(test)] mod tests` too, so a file-wide
    // `contains`/`!contains` pair is both unsound (a test fixture writing
    // `event: None` fails it spuriously) and too weak (a regression to
    // `let event = None;` above the literal satisfies it). The literal is the
    // one place where feeding versus not feeding the coordinator is decided.
    let literal = {
        let start = WIRED_SITES[0]
            .source
            .find("let input = BranchPushCommitInput {")
            .expect("branch push must build its coordinator input as a struct literal");
        let rest = &WIRED_SITES[0].source[start..];
        let end = rest
            .find("\n        };")
            .expect("the BranchPushCommitInput literal must terminate");
        &rest[..end]
    };
    // No trailing newline in the needle: `event,` is the literal's last field,
    // so the slice ends immediately after it.
    assert!(
        literal.contains("\n            event,"),
        "branch push must pass its built event to the coordinator; a literal \
         that sets `event: None`, or omits the field, has regressed to the \
         pre-WP-116 unfed outbox"
    );
    assert!(
        !literal.contains("event: None"),
        "branch push must not regress to an unfed outbox event"
    );
    // The event has to come from the shared pinned builder rather than a
    // second, file-local definition of the same classification. This is the
    // same rule `the_removed_inline_branch_push_definition_cannot_return`
    // enforces for the canonical intent digest.
    assert_eq!(
        WIRED_SITES[0]
            .source
            .matches("outbox_builders::branch_pushed(")
            .count(),
        1,
        "branch push must build its event through exactly one call to the \
         shared pinned builder"
    );

    // WP-116 Part 2: every metadata-CAS site goes through the one shared
    // governed seam and the one shared coordinator method. Four near-identical
    // handlers is how two of them come to mean different things, which is the
    // divergence CR-029 exists to end, so the pin is on the seam rather than on
    // each handler's own text.
    // Selected by family rather than by index into `WIRED_SITES`: hard-coded
    // positions silently stop selecting the right rows the moment a site is
    // added or reordered, and this loop's assertions would then pass by
    // checking nothing.
    let mut checked = 0usize;
    for site in WIRED_SITES
        .iter()
        .filter(|site| site.family.ends_with("MetadataCas"))
    {
        checked += 1;
        assert!(
            site.source.contains("GovernedMetadataCas::prepare("),
            "{} must admit through the shared governed metadata-CAS seam",
            site.label
        );
        assert!(
            site.source.contains("MetadataCasOutcome::Lost(observed)"),
            "{} must preserve CR-029 Phase 5's in-band pointer on CAS loss, \
             not map the loss to an error",
            site.label
        );
        assert!(
            !site.source.contains("reject_unwired_governed_operation("),
            "{} is wired and must not still refuse governed carriage",
            site.label
        );
    }
    assert_eq!(
        checked, 4,
        "all four metadata-CAS sites must be selected; a filter matching none          would let this loop pass by checking nothing"
    );
}

/// WP-116 Part 3: both authenticated repository-create sites commit through the
/// one shared governed seam, and that seam emits the pair CR-032 classifies.
#[test]
fn both_repository_create_sites_publish_through_the_shared_governed_seam() {
    let mut checked = 0usize;
    for site in WIRED_SITES
        .iter()
        .filter(|site| site.family.ends_with("RepositoryCreate"))
    {
        checked += 1;
        assert!(
            site.source.contains("GovernedRepositoryCreate::prepare("),
            "{} must admit through the shared governed create seam",
            site.label
        );
        assert!(
            site.source.contains("governed_repository_create("),
            "{} must publish through the one shared governed create body, not \
             a second copy of it",
            site.label
        );
    }
    assert_eq!(
        checked, 2,
        "both create sites must be selected; a filter matching none would let \
         this loop pass by checking nothing"
    );

    // The v0 site is wired outright. The v1 site keeps exactly one refusal, for
    // its forwarding branch: a cell that forwards has no local coordinator call
    // site, and CARRIAGE-02-LORE fences the forwarded entry point. More than
    // one occurrence means the direct path has regressed to refusing too.
    //
    // Selected by label rather than by index into `WIRED_SITES`: a site added
    // or reordered above these two would silently retarget both assertions at
    // the wrong file and leave the test passing.
    let site = |label: &str| {
        WIRED_SITES
            .iter()
            .find(|site| site.label == label)
            .unwrap_or_else(|| panic!("{label} must be a wired site"))
            .source
    };
    let v0 = site("v0 repository create");
    let v1 = site("v1 repository create");
    assert!(
        !v0.contains("reject_unwired_governed_operation("),
        "v0 repository create is wired and must not still refuse governed carriage"
    );
    assert_eq!(
        v1.matches("reject_unwired_governed_operation(").count(),
        1,
        "v1 repository create must refuse governed carriage only on its \
         forwarding branch"
    );

    // CR-032 classifies a repository create as two committed transitions, and
    // both must come from the shared pinned builders rather than a second,
    // seam-local definition of the same classification. Scoped to the seam
    // because that is where the pair is built once for both sites.
    for builder in [
        "outbox_builders::repository_published(",
        "outbox_builders::branch_created(",
    ] {
        assert_eq!(
            GOVERNED_SEAM.matches(builder).count(),
            1,
            "the governed create seam must build {builder} through exactly one \
             call to the shared pinned builder"
        );
    }

    // The events must actually reach the coordinator. Scoped to the
    // `RepositoryCreateInput` literal for the same reason the branch-push pin
    // is scoped to its own: a file-wide check is both unsound and too weak.
    let literal = {
        let start = GOVERNED_SEAM
            .find("let input = RepositoryCreateInput {")
            .expect("the governed create seam must build its coordinator input as a literal");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n        };")
            .expect("the RepositoryCreateInput literal must terminate");
        &rest[..end]
    };
    assert!(
        literal.contains("\n            events,"),
        "the governed create must pass its built events to the coordinator; a \
         literal that sets `events: Vec::new()`, or omits the field, has \
         regressed to an unfed outbox"
    );
    assert!(
        !literal.contains("events: Vec::new()"),
        "the governed create must not regress to an unfed outbox"
    );
}

#[test]
fn the_three_still_unwired_sites_remain_explicitly_guarded() {
    for source in GUARDED_SITES {
        assert!(source.contains("reject_unwired_governed_operation("));
        // A guard without a recorded reason is how "not yet" becomes "nobody
        // remembers". Each of the three carries a BLOCKED marker naming its
        // exact missing artefact. The looser "points at the part that wires it"
        // alternative is gone with Part 3: every remaining guard is blocked on
        // a contract, not on effort.
        assert!(
            source.contains("BLOCKED(WP-116)"),
            "a guarded governed site must record why it is guarded"
        );
    }
}

#[test]
fn the_removed_inline_branch_push_definition_cannot_return() {
    const PUSH: &str = include_str!("../src/grpc/handlers/branch_push.rs");
    assert!(!PUSH.contains("blake3::Hasher::new()"));
    assert_eq!(PUSH.matches("CanonicalIntent::BranchPush").count(), 1);
}

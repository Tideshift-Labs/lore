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

/// The sites that still refuse governed carriage, after WP-116 Part 2 wired the
/// four metadata-CAS sites. Five, not nine.
///
/// Each is guarded for a different reason and they must not be collapsed into
/// one "not done yet" bucket: forwarded v1 create is fenced by CR-029's
/// CARRIAGE-02-LORE until a frozen authenticated forwarding contract exists,
/// both deletes are blocked on an unfrozen `delete_proof` derivation, and both
/// creates are Part 3's projection move. Every one carries its reason at the
/// call site.
const GUARDED_SITES: [&str; 5] = [
    include_str!("../src/grpc/handlers/repository_create.rs"),
    include_str!("../src/grpc/repository/v1/repository_create.rs"),
    include_str!("../src/grpc/forwarded_repository/v1/repository_create.rs"),
    include_str!("../src/grpc/handlers/repository_delete.rs"),
    include_str!("../src/grpc/repository/v1/repository_delete.rs"),
];

const WIRED_SITES: [Site; 6] = [
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

#[test]
fn the_five_still_unwired_sites_remain_explicitly_guarded() {
    for source in GUARDED_SITES {
        assert!(source.contains("reject_unwired_governed_operation("));
        // A guard without a recorded reason is how "not yet" becomes "nobody
        // remembers". Each of the five carries either a BLOCKED marker naming
        // its exact missing artefact or a note pointing at the part that wires
        // it.
        assert!(
            source.contains("BLOCKED(WP-116)") || source.contains("WP-116 Part 3"),
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

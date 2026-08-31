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

const GUARDED_SITES: [&str; 9] = [
    include_str!("../src/grpc/handlers/repository_create.rs"),
    include_str!("../src/grpc/repository/v1/repository_create.rs"),
    include_str!("../src/grpc/forwarded_repository/v1/repository_create.rs"),
    include_str!("../src/grpc/handlers/repository_delete.rs"),
    include_str!("../src/grpc/repository/v1/repository_delete.rs"),
    include_str!("../src/grpc/handlers/repository_metadata_set.rs"),
    include_str!("../src/grpc/repository/v1/repository_metadata_set.rs"),
    include_str!("../src/grpc/handlers/branch_metadata_set.rs"),
    include_str!("../src/grpc/revision/v1/branch_metadata_set.rs"),
];

const WIRED_SITES: [Site; 2] = [
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
    assert!(
        WIRED_SITES[1]
            .source
            .contains(".begin_obliterate(operation, repository.data())")
    );
}

#[test]
fn all_nine_unwireable_sites_remain_explicitly_guarded() {
    for source in GUARDED_SITES {
        assert!(source.contains("reject_unwired_governed_operation("));
    }
}

#[test]
fn the_removed_inline_branch_push_definition_cannot_return() {
    const PUSH: &str = include_str!("../src/grpc/handlers/branch_push.rs");
    assert!(!PUSH.contains("blake3::Hasher::new()"));
    assert_eq!(PUSH.matches("CanonicalIntent::BranchPush").count(), 1);
}

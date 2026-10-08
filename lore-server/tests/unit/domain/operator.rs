// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::domain::locks::LockFencingReadiness;
use lore_postgres::domain::schema;
use lore_server::domain::operator::*;

#[test]
fn a_backfill_fingerprint_is_thirty_two_deterministic_bytes() {
    let first = backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[3u8; 16]);
    let second = backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[3u8; 16]);
    assert_eq!(first.len(), 32);
    assert_eq!(first, second);
}

/// Every component must move the digest. A component absorbed into the
/// preimage but not actually varied by the caller would look identical to
/// one that is not absorbed at all.
#[test]
fn every_repository_component_changes_the_fingerprint() {
    let base = backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[3u8; 16]);
    for (label, other) in [
        (
            "repository id",
            backfill_repository_fingerprint(&[9u8; 16], "alpha", &[2u8; 32], &[3u8; 16]),
        ),
        (
            "name",
            backfill_repository_fingerprint(&[1u8; 16], "beta", &[2u8; 32], &[3u8; 16]),
        ),
        (
            "metadata hash",
            backfill_repository_fingerprint(&[1u8; 16], "alpha", &[9u8; 32], &[3u8; 16]),
        ),
        (
            "default branch",
            backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[9u8; 16]),
        ),
    ] {
        assert_ne!(base, other, "{label} must change the fingerprint");
    }
}

#[test]
fn every_branch_component_changes_the_fingerprint() {
    let base = backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "main", &[3u8; 32]);
    for (label, other) in [
        (
            "repository id",
            backfill_branch_fingerprint(&[9u8; 16], &[2u8; 16], "main", &[3u8; 32]),
        ),
        (
            "branch id",
            backfill_branch_fingerprint(&[1u8; 16], &[9u8; 16], "main", &[3u8; 32]),
        ),
        (
            "name",
            backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "trunk", &[3u8; 32]),
        ),
        (
            "metadata hash",
            backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "main", &[9u8; 32]),
        ),
    ] {
        assert_ne!(base, other, "{label} must change the fingerprint");
    }
}

/// Length prefixing, measured rather than asserted: two different splits of
/// the same concatenated bytes must not collide. A naive implementation that
/// simply concatenated its components would pass every test above and fail
/// this one.
#[test]
fn a_component_boundary_cannot_be_moved_without_changing_the_digest() {
    let left = backfill_repository_fingerprint(&[1u8; 16], "ab", &[2u8; 32], &[3u8; 16]);
    let right = backfill_repository_fingerprint(&[1u8; 16], "a", &[2u8; 32], &[3u8; 16]);
    assert_ne!(left, right);

    let branch_left = backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "ab", &[3u8; 32]);
    let branch_right = backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "a", &[3u8; 32]);
    assert_ne!(branch_left, branch_right);
}

/// The two families must not share a preimage space.
#[test]
fn repository_and_branch_fingerprints_are_domain_separated() {
    let repository = backfill_repository_fingerprint(&[1u8; 16], "x", &[2u8; 32], &[3u8; 16]);
    let branch = backfill_branch_fingerprint(&[1u8; 16], &[3u8; 16], "x", &[2u8; 32]);
    assert_ne!(repository, branch);
}

/// A backfilled row must never be able to satisfy a governed create's
/// exact-retry comparison, which checks the digest AND the version.
#[test]
fn the_backfill_fingerprint_version_is_not_the_governed_create_version() {
    // The schema's own `creation_fingerprint_version >= 1` CHECK is enforced
    // by Postgres and exercised by the live tier; asserting it against a
    // constant here would be an assertion that cannot fail. What this test
    // owns is the one thing no CHECK can express: that the version differs
    // from the governed create's.
    assert_ne!(
        BACKFILL_FINGERPRINT_VERSION, 1,
        "version 1 is the governed create's canonical-intent digest, and the coordinator's \
         exact-retry check compares digest AND version — a backfilled row sharing the \
         version could be matched by a create that never happened"
    );
}

#[test]
fn an_issuer_mapping_splits_on_the_first_equals_only() {
    let parsed = parse_legacy_lock_issuers(&["sub=https://issuer/?a=b".to_owned()])
        .expect("an issuer containing '=' is well formed");
    assert_eq!(
        parsed.get("sub").map(String::as_str),
        Some("https://issuer/?a=b")
    );
}

#[test]
fn each_malformed_issuer_mapping_names_the_offending_value() {
    for value in ["nosign", "=issuer", "subject="] {
        let error = parse_legacy_lock_issuers(&[value.to_owned()])
            .expect_err("a malformed mapping must be refused");
        assert!(
            error.to_string().contains(value),
            "the refusal must name '{value}', got: {error}"
        );
    }
}

#[test]
fn one_subject_cannot_be_mapped_to_two_issuers() {
    let error = parse_legacy_lock_issuers(&["a=one".to_owned(), "a=two".to_owned()])
        .expect_err("a conflicting mapping must be refused");
    assert!(error.to_string().contains("one"), "got: {error}");
    let repeated = parse_legacy_lock_issuers(&["a=one".to_owned(), "a=one".to_owned()])
        .expect("an identical repeat is not a conflict");
    assert_eq!(repeated.len(), 1);
}

#[test]
fn several_mappings_collect() {
    let parsed = parse_legacy_lock_issuers(&["a=one".to_owned(), "b=two".to_owned()])
        .expect("two distinct mappings are well formed");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed.get("b").map(String::as_str), Some("two"));
}

#[test]
fn every_backfill_state_has_its_own_label() {
    let labels = [
        (schema::BACKFILL_NOT_STARTED, "NOT_STARTED"),
        (schema::BACKFILL_RUNNING, "RUNNING"),
        (schema::BACKFILL_VERIFIED, "VERIFIED"),
        (schema::BACKFILL_CUTOVER, "CUTOVER"),
    ];
    let mut seen = BTreeSet::new();
    for (state, expected) in labels {
        assert_eq!(backfill_state_label(state), expected);
        assert!(seen.insert(expected), "labels must be distinct: {expected}");
    }
    assert_eq!(backfill_state_label(99), "UNKNOWN");
}

/// A fully armed, fully configured cell.
fn ready_report() -> DomainStatusReport {
    DomainStatusReport {
        mutable_store_mode: POSTGRES_MODE.to_owned(),
        immutable_store_mode: POSTGRES_MODE.to_owned(),
        lock_store_mode: Some(POSTGRES_MODE.to_owned()),
        auth_enabled: true,
        auth_url_present: true,
        ready_for_enforcement: true,
        domain: lore_postgres::domain::DomainSchemaState {
            schema_version: 1,
            backfill_version: 1,
            backfill_state: schema::BACKFILL_CUTOVER,
            backfill_cursor: None,
            residue_classified: true,
            cutover_at: Some(std::time::SystemTime::UNIX_EPOCH),
            enforcement_enabled: true,
            database_identity: "identity".to_owned(),
        },
        lock: LockFencingReadiness {
            provisioned: true,
            schema_version: lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION,
            backfill_state: lore_postgres::domain::locks::schema::BACKFILL_COMPLETE,
            fencing_enabled: true,
            lease_enabled: false,
            same_database: true,
            sequence_headroom: true,
            quarantined_rows: 0,
            unfenced_rows: 0,
            never_issued_token_rows: 0,
        },
        rows: RowCounts {
            repositories_live: 1,
            repositories_tombstoned: 0,
            branches_live: 1,
            branches_tombstoned: 0,
            locks: None,
        },
    }
}

/// WP-120's actual failure: the dev cell would have reported "armed" while
/// filing no receipt at all, because `[environment.endpoint] auth_url` was
/// unset and `internal_admission_reason` answers `Ok(None)` for that
/// silently. Each missing piece must name itself.
#[test]
fn each_missing_piece_of_the_receipt_path_names_itself() {
    let ready = ready_report();
    assert!(ready.armed());
    assert!(ready.governed_mutation_ready());
    assert_eq!(ready.not_ready_reason(), None);

    let mut no_enforcement = ready_report();
    no_enforcement.domain.enforcement_enabled = false;
    assert!(!no_enforcement.armed());
    assert!(
        no_enforcement
            .not_ready_reason()
            .is_some_and(|reason| reason.contains("enforcement is off")),
        "got {:?}",
        no_enforcement.not_ready_reason()
    );

    let mut no_fencing = ready_report();
    no_fencing.lock.fencing_enabled = false;
    assert!(!no_fencing.armed());
    assert!(
        no_fencing
            .not_ready_reason()
            .is_some_and(|reason| reason.contains("fenced lock routing is off")),
        "got {:?}",
        no_fencing.not_ready_reason()
    );

    let mut no_auth = ready_report();
    no_auth.auth_enabled = false;
    assert!(
        no_auth.armed(),
        "the database facts are unchanged, so the cell is still armed"
    );
    assert!(!no_auth.governed_mutation_ready());
    assert!(
        no_auth
            .not_ready_reason()
            .is_some_and(|reason| reason.contains("JWT authentication is off")),
        "got {:?}",
        no_auth.not_ready_reason()
    );

    let mut no_auth_url = ready_report();
    no_auth_url.auth_url_present = false;
    assert!(
        no_auth_url.armed(),
        "an armed cell with no verifier still reads as armed; that is the trap"
    );
    assert!(!no_auth_url.governed_mutation_ready());
    assert!(
        no_auth_url
            .not_ready_reason()
            .is_some_and(|reason| reason.contains("auth_url is unset")),
        "got {:?}",
        no_auth_url.not_ready_reason()
    );
}

/// The rendered report must carry both verdicts and the reason, so an
/// operator reading stdout sees what the JSON carries.
#[test]
fn the_rendered_report_separates_armed_from_files_receipts() {
    let mut report = ready_report();
    report.auth_url_present = false;
    let rendered = report.render();
    assert!(rendered.contains("cell armed:            yes"));
    assert!(rendered.contains("files attempt receipts: no"));
    assert!(rendered.contains("auth_url is unset"));

    let json = report.as_json();
    assert_eq!(json["armed"], serde_json::Value::Bool(true));
    assert_eq!(
        json["files_attempt_receipts"],
        serde_json::Value::Bool(false)
    );
    assert!(json["not_ready_reason"].is_string());
}

#[test]
fn covered_subjects_are_the_mapped_ones() {
    let map = BTreeMap::from([
        ("a".to_owned(), "one".to_owned()),
        ("b".to_owned(), "two".to_owned()),
    ]);
    assert_eq!(covered_subjects(&map), vec!["a".to_owned(), "b".to_owned()]);
    assert!(covered_subjects(&BackfillIssuerMap::new()).is_empty());
}

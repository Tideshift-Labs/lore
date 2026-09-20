// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline schema and typed-state controls for Phase 6A provider-write claims.

use std::time::Duration;

use lore_postgres::domain::fragments::FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS;
use lore_postgres::domain::fragments::FragmentLifecycleReadiness;
use lore_postgres::domain::fragments::FragmentWriteCapability;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteClaimKind;
use lore_postgres::domain::fragments::FragmentWriteClaimPruneBatch;
use lore_postgres::domain::fragments::FragmentWriteClaimState;
use lore_postgres::domain::fragments::MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH;
use lore_postgres::domain::fragments::schema::FRAGMENT_SCHEMA;
use lore_postgres::domain::fragments::schema::FRAGMENT_SCHEMA_RELATIONS;
use lore_postgres::domain::fragments::schema::FRAGMENT_SCHEMA_VERSION;

const MIGRATION_0002: &str = include_str!("../migrations/0002_fragment_promotion_send_claims.sql");

const MIGRATION: &str = include_str!("../migrations/0001_init.sql");

/// Collapse a run of whitespace to one space, so a pin against DDL text is
/// tolerant of `rustfmt`/alignment reflow without weakening what it checks.
/// Mirrors `domain_migration_parity.rs`'s helper of the same name.
fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn claim_block(source: &str) -> &str {
    let start = source
        .find("-- Durable per-attempt provider-write claim.")
        .expect("claim schema start");
    let tail = &source[start..];
    // Stop right after the terminal-prune index, not at "-- Singleton.". That
    // was a safe anchor before WP-115/L1: the original `CREATE TABLE` plus its
    // two indexes were the whole claim region in both declarations. WP-115's
    // promotion-claim extension (`kind`/`source_epoch`/`source_manifest_id`)
    // now sits between this point and "-- Singleton." in `FRAGMENT_SCHEMA`
    // only -- DECISION 3 keeps `migrations/0001_init.sql` unmodified and puts
    // the extension in the new `0002_fragment_promotion_send_claims.sql`
    // instead, so a byte-identity comparison including it would compare text
    // one declaration never carries. That extension's own agreement is pinned
    // separately below, at the granularity its independently-worded
    // surrounding comments actually allow.
    let end_anchor = "WHERE state IN (2, 4);";
    let end = tail.find(end_anchor).expect("claim schema end") + end_anchor.len();
    tail[..end].trim()
}

#[test]
fn runtime_and_migration_claim_ddl_are_byte_identical_and_relation_complete() {
    assert_eq!(claim_block(FRAGMENT_SCHEMA), claim_block(MIGRATION));
    assert!(
        FRAGMENT_SCHEMA_RELATIONS.contains(&"lore_fragment_write_claims"),
        "schema presence attestation omitted the claim relation"
    );
}

#[test]
fn claim_schema_binds_every_identity_lineage_key_body_and_deadline_field() {
    let claim = claim_block(FRAGMENT_SCHEMA);
    for required in [
        "logical_request_id bytea",
        "octet_length(logical_request_id) = 16",
        "attempt_id         bytea",
        "octet_length(attempt_id) = 16",
        "hash               bytea",
        "epoch              bigint",
        "fence              bigint",
        "authority          smallint",
        "authority = 2",
        "object_key         text",
        "body_blake3        bytea",
        "octet_length(body_blake3) = 32",
        "body_size          bigint",
        "body_size >= 0 AND body_size <= 262144",
        "send_not_after     timestamptz",
        "hard_not_after     timestamptz",
        "prepared_at        timestamptz",
        "authorized_at      timestamptz",
        "settled_at         timestamptz",
        "PRIMARY KEY (logical_request_id, attempt_id)",
        "send_not_after > prepared_at AND hard_not_after > send_not_after",
    ] {
        assert!(
            claim.contains(required),
            "claim schema omitted {required:?}"
        );
    }
    assert!(
        !claim.contains("authority IN (1, 2)"),
        "a provider-write claim must never admit Staged authority"
    );
}

#[test]
fn stored_state_shape_and_barrier_index_match_the_closed_typed_vocabulary() {
    let expected = [
        (FragmentWriteClaimState::Prepared, 0, true),
        (FragmentWriteClaimState::Sending, 1, true),
        (FragmentWriteClaimState::Decisive, 2, false),
        (FragmentWriteClaimState::Ambiguous, 3, true),
        (FragmentWriteClaimState::NoSend, 4, false),
    ];
    for (state, bits, blocks) in expected {
        assert_eq!(state.bits(), bits);
        assert_eq!(FragmentWriteClaimState::from_bits(bits).ok(), Some(state));
        assert_eq!(state.blocks_until_hard_expiry(), blocks);
    }
    assert!(FragmentWriteClaimState::from_bits(-1).is_err());
    assert!(FragmentWriteClaimState::from_bits(5).is_err());

    let claim = claim_block(FRAGMENT_SCHEMA);
    assert!(
        claim.contains("state              smallint    NOT NULL CHECK (state BETWEEN 0 AND 4)")
    );
    assert!(
        claim.contains("state IN (2, 3) AND authorized_at IS NOT NULL AND settled_at IS NOT NULL")
    );
    assert!(claim.contains("state = 4 AND settled_at IS NOT NULL"));
    assert!(claim.contains("WHERE state IN (0, 1, 3)"));
    assert!(claim.contains("lore_fragment_write_claims_terminal_prune"));
    assert!(claim.contains("WHERE state IN (2, 4)"));
    assert!(claim.contains("REVOKE ALL ON TABLE lore_fragment_write_claims FROM PUBLIC;"));

    for required in [
        "provider_body_blake3 bytea",
        "provider_body_size bigint",
        "provider_claim_fence bigint",
        "lore_fragment_epoch_provider_body_shape",
        "provider_write_authority_revision text",
        "write_claims_required_at timestamptz",
        "lore_fragment_write_capability_shape",
    ] {
        assert!(
            FRAGMENT_SCHEMA.contains(required),
            "schema omitted {required:?}"
        );
        assert!(
            MIGRATION.contains(required),
            "migration omitted {required:?}"
        );
    }

    // The base migration seeds 3; the claim bootstrap seeds 4. Both the
    // composed runtime stage schema and migration 0003 then raise to 5.
    assert!(
        collapse_whitespace(MIGRATION).contains("3 AS schema_version"),
        "migrations/0001_init.sql must still seed the base revision 3"
    );
    assert!(
        collapse_whitespace(FRAGMENT_SCHEMA).contains("4 AS schema_version"),
        "the claim schema must retain its base revision"
    );
    for stage_schema in [
        include_str!("../src/domain/fragments/stage_schema.rs"),
        include_str!("../migrations/0003_fragment_stage_custody.sql"),
    ] {
        let compact: String = stage_schema.split_whitespace().collect();
        assert!(compact.contains("SETschema_version=5"));
    }
    for rotation_schema in [
        include_str!("../src/domain/fragments/stage_rotation_schema.rs"),
        include_str!("../migrations/0004_fragment_stage_policy_rotation.sql"),
    ] {
        let compact: String = rotation_schema.split_whitespace().collect();
        assert!(compact.contains(&format!("SETschema_version={FRAGMENT_SCHEMA_VERSION}")));
    }

    // D10 NARROW (owner ruling): a promotion send claim never authorizes a
    // new disposition value. `lore_fragment_epochs.disposition` must stay
    // closed at exactly (0, 1, 2) -- widening it to admit a fourth
    // (RETAINED_REMOTE-shaped) value would be the broad reading the owner
    // rejected, and nothing else in this crate would notice the CHECK
    // drifting silently.
    assert!(
        FRAGMENT_SCHEMA.contains("CHECK (disposition IN (0, 1, 2))"),
        "D10 NARROW: lore_fragment_epochs.disposition must not gain a fourth value"
    );
}

#[test]
fn claim_input_rejects_unbound_identity_body_and_deadline_shapes() {
    let valid = || {
        FragmentWriteClaimInput::new(
            [1; 16],
            [2; 16],
            [3; 32],
            262_144,
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
    };
    assert!(
        valid().is_ok(),
        "the exact fragment cap must remain representable"
    );

    for (logical_request_id, attempt_id, reason) in [
        ([0; 16], [2; 16], "logical request"),
        ([1; 16], [0; 16], "attempt"),
    ] {
        let error = FragmentWriteClaimInput::new(
            logical_request_id,
            attempt_id,
            [3; 32],
            1,
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .expect_err("a zero claim identity must be refused");
        assert!(
            error.to_string().contains("identifiers must be nonzero"),
            "{reason}: {error}"
        );
    }

    let oversized = FragmentWriteClaimInput::new(
        [1; 16],
        [2; 16],
        [3; 32],
        262_145,
        Duration::from_millis(1),
        Duration::from_millis(1),
    )
    .expect_err("a body above the direct fragment cap must be refused");
    assert!(oversized.to_string().contains("exceeds 262144 bytes"));

    for (send_window, late_effect_bound, reason) in [
        (Duration::ZERO, Duration::from_millis(1), "send window"),
        (
            Duration::from_millis(1),
            Duration::ZERO,
            "late-effect bound",
        ),
        (
            Duration::from_millis(FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS + 1),
            Duration::from_millis(1),
            "bounded send window",
        ),
    ] {
        let error = FragmentWriteClaimInput::new(
            [1; 16],
            [2; 16],
            [3; 32],
            1,
            send_window,
            late_effect_bound,
        )
        .expect_err("invalid claim timing must be refused");
        let message = error.to_string();
        if reason == "bounded send window" {
            assert!(
                message.contains("fragment write send timeout exceeds"),
                "{reason}: {error}"
            );
        } else {
            assert!(
                message.contains("must be between 1 and"),
                "{reason}: {error}"
            );
        }
    }

    assert!(
        FragmentWriteClaimInput::new(
            [1; 16],
            [2; 16],
            [3; 32],
            1,
            Duration::from_millis(FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS),
            Duration::from_millis(FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS),
        )
        .is_ok(),
        "the exact shared five-minute send maximum must remain representable"
    );
}

// ---------------------------------------------------------------------------
// L1 (WP-114/WP-115): durable promotion send claim, offline pins.
//
// These run in the DEFAULT tier -- no `#[ignore]`, no database. The live
// coordinator behavior (admission, authorization, barrier, latch, publication)
// is in `fragment_promotion_send_claim.rs`, run through
// `run-fragment-lifecycle-live.ps1`.
// ---------------------------------------------------------------------------

/// `FragmentWriteClaimKind` is the new closed vocabulary distinguishing a
/// direct-write claim from a promotion claim in the `kind` column
/// (`schema.rs`'s `kind smallint NOT NULL DEFAULT 0 CHECK (kind IN (0, 1))`).
/// `DEFAULT 0` is what makes every pre-existing direct-write row legal without
/// a backfill, so `DirectWrite` must decode `0` and `Promotion` must decode
/// `1`; nothing else is representable.
#[test]
fn write_claim_kind_round_trips_and_stays_inside_the_two_value_check() {
    for (kind, bits) in [
        (FragmentWriteClaimKind::DirectWrite, 0),
        (FragmentWriteClaimKind::Promotion, 1),
    ] {
        assert_eq!(kind.bits(), bits);
        assert_eq!(FragmentWriteClaimKind::from_bits(bits).ok(), Some(kind));
    }
    assert!(
        FragmentWriteClaimKind::from_bits(2).is_err(),
        "kind is a closed two-value vocabulary; the schema CHECK is `kind IN (0, 1)`"
    );
    assert!(FragmentWriteClaimKind::from_bits(-1).is_err());
}

/// B4: a cell provisioned at schema_version 3 and never re-migrated must
/// route legacy against a version-4 binary rather than half-enable and fail
/// at runtime with SQLSTATE 42703 on the first promotion.
/// `ready_for_lifecycle`'s clean-init arm is the one path this bites --
/// its floor moved from `>= 3` to `>= 4` specifically because
/// `FRAGMENT_SCHEMA_RELATIONS`'s relation-level probe cannot see a missing
/// column.
#[test]
fn ready_for_lifecycle_clean_init_arm_requires_schema_version_at_least_four() {
    let ready_capability = FragmentWriteCapability::ClaimsRequired {
        provider_write_authority_revision: "write-claims-v1".to_owned(),
    };
    let mut readiness = FragmentLifecycleReadiness {
        provisioned: true,
        schema_version: 3,
        backfill_state: lore_postgres::domain::fragments::schema::BACKFILL_NOT_STARTED,
        clean_initialized: true,
        cutover_at_present: false,
        lifecycle_enabled: true,
        write_capability: ready_capability,
        same_database: true,
        sequence_headroom: true,
        unresolved_rows: 0,
    };
    assert!(
        !readiness.ready_for_lifecycle(),
        "a version-3 cell must not half-enable on the clean-init path against a version-4 binary"
    );
    readiness.schema_version = FRAGMENT_SCHEMA_VERSION;
    assert!(
        readiness.ready_for_lifecycle(),
        "a version-{FRAGMENT_SCHEMA_VERSION} cell with every other clean-init precondition met \
         must be ready"
    );
}

/// The claim CHECK's width/range tests, and the DEFAULT that keeps every
/// pre-existing direct-write row legal without a backfill. Asserted against
/// both declarations: `FRAGMENT_SCHEMA` (the boot-time path, also what an
/// existing cell re-applies idempotently on every boot) and the new
/// out-of-band migration `0002_fragment_promotion_send_claims.sql` (DECISION
/// 3: a new numbered file rather than an edit to `0001_init.sql`, so an
/// already-provisioned cell is not silently skipped).
#[test]
fn promotion_claim_columns_and_shape_check_are_declared_in_both_the_schema_and_the_0002_migration()
{
    for (label, ddl) in [
        ("fragment_schema::FRAGMENT_SCHEMA", FRAGMENT_SCHEMA),
        (
            "migrations/0002_fragment_promotion_send_claims.sql",
            MIGRATION_0002,
        ),
    ] {
        let collapsed = collapse_whitespace(ddl);
        for required in [
            "kind smallint NOT NULL DEFAULT 0 CHECK (kind IN (0, 1))",
            "source_epoch",
            "source_manifest_id",
            "octet_length(source_manifest_id) = 32",
            "lore_fragment_write_claim_promotion_shape",
            "(kind = 1) = (source_epoch IS NOT NULL)",
            "(kind = 1) = (source_manifest_id IS NOT NULL)",
            "(kind = 0 OR source_epoch < epoch)",
        ] {
            assert!(
                collapsed.contains(&collapse_whitespace(required)),
                "{label} must declare `{required}`"
            );
        }
    }
    // The claim's exact fragment cap is unchanged by this seam: a promotion
    // claim is bound by the same CHECK, on the same column, as a direct-write
    // claim.
    assert!(FRAGMENT_SCHEMA.contains("body_size >= 0 AND body_size <= 262144"));
    // No new index, and the two existing partial indexes' WHERE clauses stay
    // literal-for-literal: widening `hash` to `(hash, kind)` or adding `kind`
    // to either predicate would break the SQL-literal partial-index
    // implication proof pinned by
    // `stored_state_shape_and_barrier_index_match_the_closed_typed_vocabulary`
    // and by `fragment_write_claim_source_pins.rs`.
    let collapsed_schema = collapse_whitespace(FRAGMENT_SCHEMA);
    assert!(collapsed_schema.contains(&collapse_whitespace(
        "CREATE INDEX IF NOT EXISTS lore_fragment_write_claims_barrier \
         ON lore_fragment_write_claims (hash, epoch, fence, hard_not_after) \
         WHERE state IN (0, 1, 3)"
    )));
    assert!(collapsed_schema.contains(&collapse_whitespace(
        "CREATE INDEX IF NOT EXISTS lore_fragment_write_claims_terminal_prune \
         ON lore_fragment_write_claims (settled_at, logical_request_id, attempt_id) \
         WHERE state IN (2, 4)"
    )));
}

#[test]
fn prune_batch_is_bounded_and_requires_a_positive_database_retention_window() {
    assert!(FragmentWriteClaimPruneBatch::new(1, Duration::from_millis(1)).is_ok());
    assert!(
        FragmentWriteClaimPruneBatch::new(
            MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH,
            Duration::from_millis(1),
        )
        .is_ok()
    );
    for max_claims in [0, MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH + 1] {
        assert!(
            FragmentWriteClaimPruneBatch::new(max_claims, Duration::from_millis(1)).is_err(),
            "invalid prune batch {max_claims} was accepted"
        );
    }
    assert!(FragmentWriteClaimPruneBatch::new(1, Duration::ZERO).is_err());
}

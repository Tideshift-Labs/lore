// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline schema and typed-state controls for Phase 6A provider-write claims.

use std::time::Duration;

use lore_postgres::domain::fragments::FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteClaimPruneBatch;
use lore_postgres::domain::fragments::FragmentWriteClaimState;
use lore_postgres::domain::fragments::MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH;
use lore_postgres::domain::fragments::schema::FRAGMENT_SCHEMA;
use lore_postgres::domain::fragments::schema::FRAGMENT_SCHEMA_RELATIONS;

const MIGRATION: &str = include_str!("../migrations/0001_init.sql");

fn claim_block(source: &str) -> &str {
    let start = source
        .find("-- Durable per-attempt provider-write claim.")
        .expect("claim schema start");
    let tail = &source[start..];
    let end = tail.find("-- Singleton.").expect("claim schema end");
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
        "2                                                                       AS schema_version",
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

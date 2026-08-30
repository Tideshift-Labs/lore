// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 mediated-operation proof schema (WP-116 Phase 2).
//!
//! Separated from [`crate::domain::schema`] because it is a distinct subsystem:
//! the dispatch-possibility fence, the reserve-release tombstone, the completion
//! marker, and the per-namespace sequence/prune-range accounting that let the
//! control plane release a charged reservation with proof rather than with a
//! guess. The lifecycle rows in `schema.rs` stand alone without it.
//!
//! **Non-overlap of prune ranges is enforced by the bounded marker-prune merge
//! transaction, not by an exclusion constraint.** A GiST `EXCLUDE` over
//! `(namespace..., int8range(start, end))` would need the `btree_gist`
//! extension, and `CREATE EXTENSION` is not something boot-time DDL may assume
//! it can run on a managed cell database. The intended design is that every
//! insert and merge holds the namespace row lock, which serialises the whole
//! family, with the unique indexes on `start_sequence` and `end_sequence` as a
//! backstop against a duplicated bound.
//!
//! The catalog remains only a backstop: a direct SQL writer can insert a
//! general overlap that shares neither exact bound. Production writes therefore
//! go only through the namespace-locked merge in `maintenance`.
//!
//! **The interval algebra is associative and commutative** because a range
//! stores only namespace, epoch, the three revisions, inclusive bounds, checked
//! count, `generation = end_sequence`, canonical minimum created time, row/byte
//! charge, and its own digest. It deliberately stores no marker leaves, peaks,
//! predecessor/successor digest, cached high-water, update or commit time,
//! WAL/LSN, or synthetic row ID, so a zero-, one-, or two-neighbour merge over a
//! fixed interval set yields the same result in any order.

/// Proof-namespace lifecycle: capacity reserved, no Lore row yet.
pub const NAMESPACE_STATE_ACTIVE: i16 = 0;
/// Draining toward retirement; admission against this epoch rejects.
pub const NAMESPACE_STATE_DRAINING: i16 = 1;
/// Retired. A fresh random epoch may now materialize with a new revision tuple.
pub const NAMESPACE_STATE_RETIRED: i16 = 2;

/// Mediated-proof DDL. Idempotent; applied under the shared schema advisory lock.
pub const MEDIATED_SCHEMA: &str = r#"
-- ---------------------------------------------------------------------------
-- Dispatch-possibility fence
-- ---------------------------------------------------------------------------

-- Installed in the SAME transaction that first creates PREPARED or any ordinary
-- receipt, and before mutation dispatch can become possible. Its presence is
-- what lets a terminal-only stale finalize answer
-- INELIGIBLE_RECEIPT_OR_DISPATCH_POSSIBLE instead of manufacturing a
-- NOT_APPLIED for an operation that may in fact have run. Only the Phase 1
-- attach transaction may physically delete a fence, and it must insert the
-- matching reserve-release tombstone in that same transaction.
CREATE TABLE IF NOT EXISTS lore_domain_operation_dispatch_possibility_fences (
    verified_issuer               text        NOT NULL,
    authenticated_subject         text        NOT NULL,
    tenant_scope_key              bytea       NOT NULL,
    operation_id                  bytea       NOT NULL CHECK (octet_length(operation_id) = 16),

    method                        text        NOT NULL,
    scope                         bytea       NOT NULL,
    fingerprint_version           integer     NOT NULL CHECK (fingerprint_version >= 1),
    fingerprint                   bytea       NOT NULL CHECK (octet_length(fingerprint) = 32),
    canonical_intent_digest       bytea       NOT NULL
                                              CHECK (octet_length(canonical_intent_digest) = 32),
    authorization_id              bytea       NOT NULL,
    authorization_revision        bigint      NOT NULL CHECK (authorization_revision >= 0),
    verification_nonce            bytea       NOT NULL
                                              CHECK (octet_length(verification_nonce) = 32),
    bound_fields_digest           bytea       NOT NULL
                                              CHECK (octet_length(bound_fields_digest) = 32),
    consumed_ticket_sha256        bytea       NOT NULL
                                              CHECK (octet_length(consumed_ticket_sha256) = 32),
    expected_claim_identity_digest bytea      NOT NULL
                                              CHECK (octet_length(expected_claim_identity_digest) = 32),

    created_revision              bigint      NOT NULL CHECK (created_revision >= 0),
    created_at                    timestamptz NOT NULL,

    terminal_status_ack_digest    bytea       CHECK (terminal_status_ack_digest IS NULL
                                                     OR octet_length(terminal_status_ack_digest) = 32),
    terminal_status_revision      bigint,
    terminal_status_ack_at        timestamptz,
    receipt_final_prune_digest    bytea       CHECK (receipt_final_prune_digest IS NULL
                                                     OR octet_length(receipt_final_prune_digest) = 32),
    receipt_final_pruned_at       timestamptz,
    fence_prune_digest            bytea       CHECK (fence_prune_digest IS NULL
                                                     OR octet_length(fence_prune_digest) = 32),
    fence_pruned_at               timestamptz,
    resolved_dependency_at        timestamptz,
    safe_prune_after              timestamptz NOT NULL,

    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key, operation_id),

    -- A terminal-status acknowledgement is all-or-nothing: an ATTACHED-to-
    -- nonterminal or unacknowledged status must retain the decisive receipt
    -- across restart, so a half-written ack is not a representable state.
    CONSTRAINT lore_domain_fences_terminal_ack_shape CHECK (
        (terminal_status_ack_digest IS NULL
            AND terminal_status_revision IS NULL
            AND terminal_status_ack_at IS NULL)
     OR (terminal_status_ack_digest IS NOT NULL
            AND terminal_status_revision IS NOT NULL
            AND terminal_status_ack_at IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS lore_domain_fences_dependency_prune
    ON lore_domain_operation_dispatch_possibility_fences
       (resolved_dependency_at, safe_prune_after);

-- ---------------------------------------------------------------------------
-- Reserve-release tombstone
-- ---------------------------------------------------------------------------

-- Replaces the fence, under the same full receipt key, once the receipt is
-- final-pruned. Platform first records ACTIVE_RELEASE_INTENT while still
-- charged; Phase 2 acknowledges that intent before the active slot is released.
-- The historical claim stays charged through RELEASE_INTENT.
CREATE TABLE IF NOT EXISTS lore_domain_operation_reserve_release_tombstones (
    verified_issuer                 text        NOT NULL,
    authenticated_subject           text        NOT NULL,
    tenant_scope_key                bytea       NOT NULL,
    operation_id                    bytea       NOT NULL CHECK (octet_length(operation_id) = 16),

    method                          text        NOT NULL,
    scope                           bytea       NOT NULL,
    fingerprint_version             integer     NOT NULL CHECK (fingerprint_version >= 1),
    fingerprint                     bytea       NOT NULL CHECK (octet_length(fingerprint) = 32),
    canonical_intent_digest         bytea       NOT NULL
                                                CHECK (octet_length(canonical_intent_digest) = 32),
    authorization_id                bytea       NOT NULL,
    authorization_revision          bigint      NOT NULL CHECK (authorization_revision >= 0),
    claim_id                        bytea       NOT NULL,
    claim_revision                  bigint      NOT NULL CHECK (claim_revision >= 0),

    reserve_charge_revision         bigint      NOT NULL CHECK (reserve_charge_revision >= 0),
    reserve_charge_nonce            bytea       NOT NULL
                                                CHECK (octet_length(reserve_charge_nonce) = 32),
    tombstone_reservation_revision  bigint      NOT NULL
                                                CHECK (tombstone_reservation_revision >= 0),
    tombstone_reservation_nonce     bytea       NOT NULL
                                                CHECK (octet_length(tombstone_reservation_nonce) = 32),

    terminal_ack_digest             bytea       NOT NULL
                                                CHECK (octet_length(terminal_ack_digest) = 32),
    receipt_prune_digest            bytea       NOT NULL
                                                CHECK (octet_length(receipt_prune_digest) = 32),
    fence_prune_digest              bytea       NOT NULL
                                                CHECK (octet_length(fence_prune_digest) = 32),
    phase1_response                 bytea       NOT NULL
                                                CHECK (octet_length(phase1_response) <= 4096),
    phase1_request_digest           bytea       NOT NULL
                                                CHECK (octet_length(phase1_request_digest) = 32),
    phase1_verification_digest      bytea       NOT NULL
                                                CHECK (octet_length(phase1_verification_digest) = 32),
    terminal_outcome                smallint    NOT NULL,
    terminal_receipt_sha256         bytea       NOT NULL
                                                CHECK (octet_length(terminal_receipt_sha256) = 32),
    platform_terminal_status_revision bigint    NOT NULL CHECK (platform_terminal_status_revision >= 0),
    platform_acknowledged_at        timestamptz NOT NULL,
    release_proof_reservation_revision bigint   NOT NULL CHECK (release_proof_reservation_revision >= 0),
    release_proof_reservation_nonce bytea       NOT NULL
                                                CHECK (octet_length(release_proof_reservation_nonce) = 32),

    active_release_intent_digest    bytea       CHECK (active_release_intent_digest IS NULL
                                                       OR octet_length(active_release_intent_digest) = 32),
    active_release_intent_revision  bigint      CHECK (active_release_intent_revision IS NULL
                                                       OR active_release_intent_revision >= 0),
    active_release_intent_nonce     bytea       CHECK (active_release_intent_nonce IS NULL
                                                       OR octet_length(active_release_intent_nonce) = 32),
    active_release_intent_ack_at    timestamptz,
    historical_release_intent       boolean     NOT NULL DEFAULT false,
    platform_release_revision       bigint,
    release_ack_at                  timestamptz,

    created_at                      timestamptz NOT NULL,
    compact_after                   timestamptz NOT NULL,
    final_prune_after               timestamptz NOT NULL,
    tombstone_digest                bytea       NOT NULL
                                                CHECK (octet_length(tombstone_digest) = 32),

    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key, operation_id),

    CONSTRAINT lore_domain_tombstones_release_ack_shape CHECK (
        (release_ack_at IS NULL     AND platform_release_revision IS NULL)
     OR (release_ack_at IS NOT NULL AND platform_release_revision IS NOT NULL)
    ),
    CONSTRAINT lore_domain_tombstones_active_intent_shape CHECK (
        (active_release_intent_digest IS NULL
            AND active_release_intent_revision IS NULL
            AND active_release_intent_nonce IS NULL
            AND active_release_intent_ack_at IS NULL)
     OR (active_release_intent_digest IS NOT NULL
            AND active_release_intent_revision IS NOT NULL
            AND active_release_intent_nonce IS NOT NULL
            AND active_release_intent_ack_at IS NOT NULL)
    ),
    CONSTRAINT lore_domain_tombstones_retention_order CHECK (
        final_prune_after >= compact_after AND compact_after >= created_at
    )
);
-- One release acknowledgement per charge: the charge identity is
-- (authorization, revision, nonce) and it may be released exactly once.
CREATE UNIQUE INDEX IF NOT EXISTS lore_domain_tombstones_one_per_charge
    ON lore_domain_operation_reserve_release_tombstones
       (authorization_id, reserve_charge_revision, reserve_charge_nonce);
CREATE INDEX IF NOT EXISTS lore_domain_tombstones_retention
    ON lore_domain_operation_reserve_release_tombstones
       (release_ack_at, compact_after, final_prune_after);

-- ---------------------------------------------------------------------------
-- Completion markers, namespaces, and prune ranges
-- ---------------------------------------------------------------------------

-- The tombstone row and this marker are exchanged in ONE transaction. The
-- marker digest alone permits the platform to release the historical claim; the
-- marker itself requires no platform acknowledgement and prunes locally after
-- the frozen safe retention. Canonical completion ACK bytes are retained only
-- until final prune, after which a post-prune response is derived from the
-- authoritative containing range plus the exact request binding.
CREATE TABLE IF NOT EXISTS lore_domain_operation_tombstone_release_completion_markers (
    verified_issuer                text        NOT NULL,
    authenticated_subject          text        NOT NULL,
    tenant_scope_key               bytea       NOT NULL,
    operation_id                   bytea       NOT NULL CHECK (octet_length(operation_id) = 16),

    namespace_epoch                bytea       NOT NULL CHECK (octet_length(namespace_epoch) = 16),
    sequence                       bigint      NOT NULL CHECK (sequence >= 1),

    tombstone_digest               bytea       NOT NULL
                                               CHECK (octet_length(tombstone_digest) = 32),
    release_intent_digest          bytea       NOT NULL
                                               CHECK (octet_length(release_intent_digest) = 32),
    final_prune_digest             bytea       NOT NULL
                                               CHECK (octet_length(final_prune_digest) = 32),
    final_prune_after              timestamptz NOT NULL,
    marker_reservation_revision    bigint      NOT NULL CHECK (marker_reservation_revision >= 0),
    marker_reservation_nonce       bytea       NOT NULL
                                               CHECK (octet_length(marker_reservation_nonce) = 32),
    completion_request_binding     bytea       NOT NULL
                                               CHECK (octet_length(completion_request_binding) = 32),
    completion_request_digest      bytea       NOT NULL
                                               CHECK (octet_length(completion_request_digest) = 32),
    completion_verification_digest bytea       NOT NULL
                                               CHECK (octet_length(completion_verification_digest) = 32),
    completion_ack                 bytea       CHECK (completion_ack IS NULL
                                                      OR octet_length(completion_ack) <= 4096),
    marker_digest                  bytea       NOT NULL CHECK (octet_length(marker_digest) = 32),
    byte_charge                    bigint      NOT NULL CHECK (byte_charge >= 0),
    created_at                     timestamptz NOT NULL,
    retain_until                   timestamptz NOT NULL,

    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key, operation_id),
    CONSTRAINT lore_domain_markers_retention_order CHECK (retain_until >= created_at)
);
-- Gapless u64 allocation per namespace epoch: the sequence is unique, and it is
-- checked before insert as well so a recomputation mismatch cannot slip through.
CREATE UNIQUE INDEX IF NOT EXISTS lore_domain_markers_namespace_sequence
    ON lore_domain_operation_tombstone_release_completion_markers
       (verified_issuer, authenticated_subject, tenant_scope_key, namespace_epoch, sequence);
CREATE INDEX IF NOT EXISTS lore_domain_markers_retention
    ON lore_domain_operation_tombstone_release_completion_markers (retain_until);

-- One row per represented Lore-local proof namespace epoch. It pins the
-- immutable revision tuple, owns the completion-marker sequence, and carries the
-- per-namespace fragment/retained/outstanding counters whose inequality
-- F_n <= R_n + O_n + 1 is a readiness gate. Lore owns the epoch, the claim
-- binding, the ranges, and its own counter revisions; it owns no platform fence
-- generation or platform counter.
CREATE TABLE IF NOT EXISTS lore_domain_proof_namespaces (
    verified_issuer                 text        NOT NULL,
    authenticated_subject           text        NOT NULL,
    tenant_scope_key                bytea       NOT NULL,
    org_uuid                        bytea       NOT NULL CHECK (octet_length(org_uuid) = 16),
    epoch                           bytea       NOT NULL CHECK (octet_length(epoch) = 16),

    protocol_revision               integer     NOT NULL CHECK (protocol_revision >= 1),
    quota_revision                  integer     NOT NULL CHECK (quota_revision >= 1),
    marker_interval_schema_revision integer     NOT NULL
                                                CHECK (marker_interval_schema_revision = 3),

    claim_revision                  bigint      NOT NULL CHECK (claim_revision >= 0),
    claim_nonce                     bytea       NOT NULL CHECK (octet_length(claim_nonce) = 32),

    next_sequence                   bigint      NOT NULL CHECK (next_sequence >= 1),
    high_water                      bigint      NOT NULL CHECK (high_water >= 0),
    retained_marker_count           bigint      NOT NULL CHECK (retained_marker_count >= 0),
    outstanding_proof_claims        bigint      NOT NULL CHECK (outstanding_proof_claims >= 0),
    fragment_count                  bigint      NOT NULL CHECK (fragment_count >= 0),

    state                           smallint    NOT NULL CHECK (state IN (0, 1, 2)),
    materialization_receipt         bytea       CHECK (materialization_receipt IS NULL
                                                       OR octet_length(materialization_receipt) <= 4096),
    materialization_request_digest  bytea       NOT NULL
                                                CHECK (octet_length(materialization_request_digest) = 32),
    materialization_verification_digest bytea   NOT NULL
                                                CHECK (octet_length(materialization_verification_digest) = 32),
    materialization_response_digest bytea       NOT NULL
                                                CHECK (octet_length(materialization_response_digest) = 32),
    namespace_revision              bigint      NOT NULL CHECK (namespace_revision >= 1),
    materialized_global_counter_revision bigint NOT NULL CHECK (materialized_global_counter_revision >= 0),
    materialized_org_counter_revision bigint    NOT NULL CHECK (materialized_org_counter_revision >= 0),
    created_at                      timestamptz NOT NULL,
    updated_at                      timestamptz NOT NULL,

    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key, epoch),

    -- The potential-gap inequality. Marker prune atomically decrements R and
    -- transfers that reservation to the post-merge F, so this holds across the
    -- prune as well as at rest.
    CONSTRAINT lore_domain_proof_namespaces_fragment_bound CHECK (
        fragment_count <= retained_marker_count + outstanding_proof_claims + 1
    ),
    CONSTRAINT lore_domain_proof_namespaces_high_water CHECK (high_water < next_sequence)
);
-- At most one non-retired epoch per namespace. A fresh epoch may only be
-- materialized after the previous one is retired under its original tuple.
CREATE UNIQUE INDEX IF NOT EXISTS lore_domain_proof_namespaces_one_live_epoch
    ON lore_domain_proof_namespaces
       (verified_issuer, authenticated_subject, tenant_scope_key)
    WHERE state <> 2;

-- Lore-local global counters. Distinct from the platform's claim counters, which
-- Lore never reads or writes. N in F_global <= R_global + O_global + N is the
-- policy-bounded count of Lore-local represented namespace rows, not a count of
-- platform namespace claims.
CREATE TABLE IF NOT EXISTS lore_domain_proof_global_counters (
    id                        smallint    NOT NULL PRIMARY KEY CHECK (id = 1),
    counter_revision          bigint      NOT NULL CHECK (counter_revision >= 0),
    quota_revision            integer     NOT NULL CHECK (quota_revision >= 1),
    represented_namespace_rows bigint     NOT NULL CHECK (represented_namespace_rows >= 0),
    retained_marker_count     bigint      NOT NULL CHECK (retained_marker_count >= 0),
    outstanding_proof_claims  bigint      NOT NULL CHECK (outstanding_proof_claims >= 0),
    fragment_count            bigint      NOT NULL CHECK (fragment_count >= 0),
    fragment_bytes            bigint      NOT NULL CHECK (fragment_bytes >= 0),
    marker_bytes              bigint      NOT NULL CHECK (marker_bytes >= 0),
    reconciled_at             timestamptz,
    updated_at                timestamptz NOT NULL,
    CONSTRAINT lore_domain_proof_global_fragment_bound CHECK (
        fragment_count <= retained_marker_count + outstanding_proof_claims
                          + represented_namespace_rows
    )
);
-- Boot-time mediated-schema installation makes the advertised lifecycle
-- surface usable on a fresh cell. Re-running setup preserves live counters.
INSERT INTO lore_domain_proof_global_counters (
    id, counter_revision, quota_revision, represented_namespace_rows,
    retained_marker_count, outstanding_proof_claims, fragment_count,
    fragment_bytes, marker_bytes, reconciled_at, updated_at
) VALUES (1, 0, 1, 0, 0, 0, 0, 0, 0, NULL, clock_timestamp())
ON CONFLICT (id) DO NOTHING;

-- Lore-local organization counters are independent from the global counter.
-- A namespace materialization increments both exactly once; retirement
-- decrements both exactly once in the same transaction.
CREATE TABLE IF NOT EXISTS lore_domain_proof_org_counters (
    org_uuid                   bytea       NOT NULL PRIMARY KEY
                                           CHECK (octet_length(org_uuid) = 16),
    counter_revision           bigint      NOT NULL CHECK (counter_revision >= 0),
    quota_revision             integer     NOT NULL CHECK (quota_revision >= 1),
    represented_namespace_rows bigint      NOT NULL CHECK (represented_namespace_rows >= 0),
    retained_marker_count      bigint      NOT NULL CHECK (retained_marker_count >= 0),
    fragment_count             bigint      NOT NULL CHECK (fragment_count >= 0),
    fragment_bytes             bigint      NOT NULL CHECK (fragment_bytes >= 0),
    marker_bytes               bigint      NOT NULL CHECK (marker_bytes >= 0),
    updated_at                 timestamptz NOT NULL
);

-- Merged prune ranges over pruned completion-marker sequences. Field algebra is
-- exactly CR-029's: namespace, immutable epoch, protocol/quota/interval-schema
-- revisions, inclusive bounds, checked count, generation = end_sequence,
-- canonical created_at_ms, row charge one, recomputed byte charge, and an
-- independent domain-marker-prune-interval-v3 digest. Nothing else, so merges
-- are associative and commutative.
CREATE TABLE IF NOT EXISTS lore_domain_tombstone_marker_prune_ranges (
    verified_issuer                 text        NOT NULL,
    authenticated_subject           text        NOT NULL,
    tenant_scope_key                bytea       NOT NULL,
    epoch                           bytea       NOT NULL CHECK (octet_length(epoch) = 16),

    protocol_revision               integer     NOT NULL CHECK (protocol_revision >= 1),
    quota_revision                  integer     NOT NULL CHECK (quota_revision >= 1),
    marker_interval_schema_revision integer     NOT NULL
                                                CHECK (marker_interval_schema_revision = 3),

    start_sequence                  bigint      NOT NULL CHECK (start_sequence >= 1),
    end_sequence                    bigint      NOT NULL CHECK (end_sequence >= 1),
    sequence_count                  bigint      NOT NULL CHECK (sequence_count >= 1),
    generation                      bigint      NOT NULL,
    created_at_ms                   bigint      NOT NULL CHECK (created_at_ms >= 0),
    row_charge                      integer     NOT NULL CHECK (row_charge = 1),
    byte_charge                     bigint      NOT NULL CHECK (byte_charge >= 0),
    interval_digest                 bytea       NOT NULL
                                                CHECK (octet_length(interval_digest) = 32),

    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key, epoch, start_sequence),

    CONSTRAINT lore_domain_prune_ranges_bounds CHECK (end_sequence >= start_sequence),
    CONSTRAINT lore_domain_prune_ranges_count CHECK (
        sequence_count = end_sequence - start_sequence + 1
    ),
    CONSTRAINT lore_domain_prune_ranges_generation CHECK (generation = end_sequence)
);
-- The end bound is unique too, so a merge that miscomputes one side collides
-- instead of silently creating a second range that claims the same tail.
CREATE UNIQUE INDEX IF NOT EXISTS lore_domain_prune_ranges_end
    ON lore_domain_tombstone_marker_prune_ranges
       (verified_issuer, authenticated_subject, tenant_scope_key, epoch, end_sequence);

-- Additive upgrade path for cells that booted the guarded maintenance schema.
-- The guarded handlers could not create lifecycle rows, so sentinel defaults
-- can only affect manually seeded data. Such rows fail exact runtime binding.
ALTER TABLE lore_domain_operation_reserve_release_tombstones
    ADD COLUMN IF NOT EXISTS canonical_intent_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(canonical_intent_digest) = 32),
    ADD COLUMN IF NOT EXISTS phase1_request_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(phase1_request_digest) = 32),
    ADD COLUMN IF NOT EXISTS phase1_verification_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(phase1_verification_digest) = 32),
    ADD COLUMN IF NOT EXISTS terminal_outcome smallint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS terminal_receipt_sha256 bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(terminal_receipt_sha256) = 32),
    ADD COLUMN IF NOT EXISTS platform_terminal_status_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS platform_acknowledged_at timestamptz NOT NULL DEFAULT '-infinity',
    ADD COLUMN IF NOT EXISTS release_proof_reservation_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS release_proof_reservation_nonce bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(release_proof_reservation_nonce) = 32),
    ADD COLUMN IF NOT EXISTS active_release_intent_revision bigint
        CHECK (active_release_intent_revision IS NULL OR active_release_intent_revision >= 0),
    ADD COLUMN IF NOT EXISTS active_release_intent_nonce bytea
        CHECK (active_release_intent_nonce IS NULL OR octet_length(active_release_intent_nonce) = 32);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'lore_domain_tombstones_active_intent_shape'
          AND conrelid = 'lore_domain_operation_reserve_release_tombstones'::regclass
    ) THEN
        ALTER TABLE lore_domain_operation_reserve_release_tombstones
            ADD CONSTRAINT lore_domain_tombstones_active_intent_shape CHECK (
                (active_release_intent_digest IS NULL
                    AND active_release_intent_revision IS NULL
                    AND active_release_intent_nonce IS NULL
                    AND active_release_intent_ack_at IS NULL)
             OR (active_release_intent_digest IS NOT NULL
                    AND active_release_intent_revision IS NOT NULL
                    AND active_release_intent_nonce IS NOT NULL
                    AND active_release_intent_ack_at IS NOT NULL)
            );
    END IF;
END
$$;

ALTER TABLE lore_domain_operation_tombstone_release_completion_markers
    ADD COLUMN IF NOT EXISTS completion_request_binding bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(completion_request_binding) = 32),
    ADD COLUMN IF NOT EXISTS completion_request_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(completion_request_digest) = 32),
    ADD COLUMN IF NOT EXISTS completion_verification_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(completion_verification_digest) = 32),
    ADD COLUMN IF NOT EXISTS byte_charge bigint NOT NULL DEFAULT 0 CHECK (byte_charge >= 0),
    ADD COLUMN IF NOT EXISTS final_prune_after timestamptz NOT NULL DEFAULT '-infinity';

ALTER TABLE lore_domain_proof_namespaces
    ADD COLUMN IF NOT EXISTS org_uuid bytea NOT NULL
        DEFAULT decode(repeat('00', 16), 'hex') CHECK (octet_length(org_uuid) = 16),
    ADD COLUMN IF NOT EXISTS materialization_request_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(materialization_request_digest) = 32),
    ADD COLUMN IF NOT EXISTS materialization_verification_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(materialization_verification_digest) = 32),
    ADD COLUMN IF NOT EXISTS materialization_response_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(materialization_response_digest) = 32),
    ADD COLUMN IF NOT EXISTS namespace_revision bigint NOT NULL DEFAULT 1 CHECK (namespace_revision >= 1),
    ADD COLUMN IF NOT EXISTS materialized_global_counter_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS materialized_org_counter_revision bigint NOT NULL DEFAULT 0;
"#;

-- SPDX-FileCopyrightText: 2026 Epic Games, Inc.
-- SPDX-FileCopyrightText: 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- CR-007 — canonical schema for the off-AWS (off-DynamoDB) loreserver data-plane
-- backend. One Postgres database per region cell backs all three coordination
-- stores: mutable (branch-tip CAS), immutable coordination, and lock. Immutable
-- fragment bytes and their authoritative representation metadata live together
-- on S3-compatible objects, not here.
--
-- The store implementations also self-bootstrap these exact tables via
-- `CREATE TABLE IF NOT EXISTS` at startup (see each `*_store.rs`), so this file
-- is the provisioning/bootstrap artifact for tooling that prefers to apply the
-- schema out-of-band. It is idempotent.

-- Mutable store: strongly-consistent single-key compare-and-swap (branch tips).
CREATE TABLE IF NOT EXISTS lore_mutable (
    partition bytea    NOT NULL,
    key_type  smallint NOT NULL,
    key       bytea    NOT NULL,
    value     bytea    NOT NULL,
    PRIMARY KEY (partition, key_type, key)
);

-- Lock store: exclusivity is the PRIMARY KEY; the three indexes back the
-- supported LockQuery filters (the DynamoDB "3 GSIs" map 1:1 — INV-R §5). No
-- TTL/lease: locks persist until explicitly released.
CREATE TABLE IF NOT EXISTS lore_locks (
    repository  bytea  NOT NULL,
    branch      bytea  NOT NULL,
    hash        bytea  NOT NULL,
    owner       text   NOT NULL,
    description text   NOT NULL,
    locked_at   bigint NOT NULL,
    PRIMARY KEY (repository, branch, hash)
);
CREATE INDEX IF NOT EXISTS lore_locks_owner_repo_branch ON lore_locks (owner, repository, branch);
CREATE INDEX IF NOT EXISTS lore_locks_repo_branch       ON lore_locks (repository, branch);
CREATE INDEX IF NOT EXISTS lore_locks_repo_branch_desc  ON lore_locks (repository, branch, description);

-- Immutable store coordination. Fragment bytes and representation metadata live
-- in S3-compatible object storage. Postgres keeps associations, mutable lifecycle
-- state, and an exact but rebuildable metering projection.
--
-- lore_fragments: one row per (hash, repository, context) association. The PK
-- B-tree serves the leftmost-prefix existence reads — hash (MatchHash),
-- (hash, repository) (MatchPartition), full (MatchFull) — and the by-hash
-- refcount. The one secondary index inverts the leading column so a whole
-- repository's fragment set is reachable without a sequential scan, which is
-- what the per-repository storage-stats aggregate (CR-016) reads.
CREATE TABLE IF NOT EXISTS lore_fragments (
    hash       bytea NOT NULL,
    repository bytea NOT NULL,
    context    bytea NOT NULL,
    PRIMARY KEY (hash, repository, context)
);
CREATE INDEX IF NOT EXISTS lore_fragments_repo_hash ON lore_fragments (repository, hash);

-- lore_fragment_state: mutable readability/obliteration lifecycle only.
CREATE TABLE IF NOT EXISTS lore_fragment_state (
    hash  bytea  NOT NULL PRIMARY KEY,
    -- 0 Stored; 512 Obliterating children; 1 deleting payload versions; 256 tombstone.
    state bigint NOT NULL CHECK (state IN (0, 1, 256, 512))
);

-- lore_fragment_metering: non-authoritative projection of the representation
-- carried on the corresponding S3 object, synchronized on writes/copies and
-- rebuildable from object metadata. It exists only for exact set-based stats.
CREATE TABLE IF NOT EXISTS lore_fragment_metering (
    hash          bytea  NOT NULL PRIMARY KEY,
    payload_flags bigint NOT NULL CHECK (payload_flags >= 0 AND payload_flags <= 4294967295),
    size_payload bigint NOT NULL CHECK (size_payload >= 0),
    size_content bigint NOT NULL CHECK (size_content >= 0)
);

-- ---------------------------------------------------------------------------
-- CR-029 / CR-032 (WP-116 Phase 2) — domain transactions and the outbox base.
--
-- Byte-equivalent copy of the runtime DDL declared in:
--   src/domain/schema.rs           (SCHEMA)
--   src/domain/schema_mediated.rs  (MEDIATED_SCHEMA)
--   src/domain/outbox/schema.rs    (OUTBOX_SCHEMA)
--
-- As with the CR-007 blocks above, a schema change here is TWO edits in one
-- commit: the Rust const and this file. The migration/runtime parity test in
-- tests/domain_migration_parity.rs applies each path to its own database and
-- compares the resulting catalog, so drift between them fails a gate rather
-- than reaching a cell.
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- Repository and branch lifecycle
-- ---------------------------------------------------------------------------

-- One row per repository identity, live or tombstoned. Identities are never
-- reused: the tombstone row is the permanent fence that stops a delayed delete
-- or push from targeting a later object with the same ID.
CREATE TABLE IF NOT EXISTS lore_domain_repositories (
    repository_id                bytea       NOT NULL PRIMARY KEY
                                             CHECK (octet_length(repository_id) = 16),
    state                        smallint    NOT NULL CHECK (state IN (0, 1)),
    generation                   bigint      NOT NULL CHECK (generation >= 1),
    name                         text        NOT NULL,
    metadata_hash                bytea       NOT NULL CHECK (octet_length(metadata_hash) = 32),
    default_branch_id            bytea       NOT NULL CHECK (octet_length(default_branch_id) = 16),
    creation_fingerprint_version integer     NOT NULL CHECK (creation_fingerprint_version >= 1),
    creation_fingerprint         bytea       NOT NULL CHECK (octet_length(creation_fingerprint) = 32),
    delete_proof                 bytea       CHECK (delete_proof IS NULL
                                                    OR octet_length(delete_proof) = 32),
    created_at                   timestamptz NOT NULL,
    deleted_at                   timestamptz,
    CONSTRAINT lore_domain_repositories_tombstone_evidence CHECK (
        (state = 0 AND deleted_at IS NULL     AND delete_proof IS NULL)
     OR (state = 1 AND deleted_at IS NOT NULL AND delete_proof IS NOT NULL)
    )
);

-- Live repository names. Exact bytes are the key: repository::mutable_name_key
-- does not fold case. Removed in the same transaction that tombstones its owner,
-- so a name is recyclable only after the prior owner is tombstoned.
CREATE TABLE IF NOT EXISTS lore_domain_repository_names (
    name                  text        NOT NULL PRIMARY KEY,
    repository_id         bytea       NOT NULL
                                      REFERENCES lore_domain_repositories (repository_id),
    repository_generation bigint      NOT NULL CHECK (repository_generation >= 1),
    created_at            timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS lore_domain_repository_names_repo
    ON lore_domain_repository_names (repository_id);

-- One row per branch identity within a repository, live or tombstoned. A branch
-- tombstone keeps its last record so delete stays idempotent; push never
-- resurrects it and re-creation requires a fresh branch ID.
CREATE TABLE IF NOT EXISTS lore_domain_branches (
    repository_id                bytea       NOT NULL
                                             REFERENCES lore_domain_repositories (repository_id),
    branch_id                    bytea       NOT NULL CHECK (octet_length(branch_id) = 16),
    repository_generation        bigint      NOT NULL CHECK (repository_generation >= 1),
    state                        smallint    NOT NULL CHECK (state IN (0, 1)),
    generation                   bigint      NOT NULL CHECK (generation >= 1),
    name                         text        NOT NULL,
    metadata_hash                bytea       NOT NULL CHECK (octet_length(metadata_hash) = 32),
    latest_hash                  bytea       NOT NULL CHECK (octet_length(latest_hash) = 32),
    creation_fingerprint_version integer     NOT NULL CHECK (creation_fingerprint_version >= 1),
    creation_fingerprint         bytea       NOT NULL CHECK (octet_length(creation_fingerprint) = 32),
    delete_proof                 bytea       CHECK (delete_proof IS NULL
                                                    OR octet_length(delete_proof) = 32),
    created_at                   timestamptz NOT NULL,
    deleted_at                   timestamptz,
    PRIMARY KEY (repository_id, branch_id),
    CONSTRAINT lore_domain_branches_tombstone_evidence CHECK (
        (state = 0 AND deleted_at IS NULL     AND delete_proof IS NULL)
     OR (state = 1 AND deleted_at IS NOT NULL AND delete_proof IS NOT NULL)
    )
);

-- Live branch names, keyed on the folded name because branch::mutable_name_key
-- hashes name.to_lowercase(). display_name carries the authored spelling and is
-- not part of the key, so Feature and feature cannot both be live.
CREATE TABLE IF NOT EXISTS lore_domain_branch_names (
    repository_id         bytea       NOT NULL,
    name_key              text        NOT NULL,
    display_name          text        NOT NULL,
    branch_id             bytea       NOT NULL,
    repository_generation bigint      NOT NULL CHECK (repository_generation >= 1),
    branch_generation     bigint      NOT NULL CHECK (branch_generation >= 1),
    created_at            timestamptz NOT NULL,
    PRIMARY KEY (repository_id, name_key),
    FOREIGN KEY (repository_id, branch_id)
        REFERENCES lore_domain_branches (repository_id, branch_id)
);
CREATE INDEX IF NOT EXISTS lore_domain_branch_names_branch
    ON lore_domain_branch_names (repository_id, branch_id);

-- ---------------------------------------------------------------------------
-- Domain operation receipts
-- ---------------------------------------------------------------------------

-- The prepare/consume admission ledger and the terminal receipt are ONE state
-- machine on ONE row, not two records. domain_operation_prepare inserts or
-- exact-loads it as PREPARED with an opaque consume token; the mutation
-- transaction locks it first (F-032-3 position 0), verifies the token, and
-- atomically replaces PREPARED with a terminal APPLIED / NOT_APPLIED. A terminal
-- row is immutable, and lookup never returns the token.
CREATE TABLE IF NOT EXISTS lore_domain_operation_receipts (
    verified_issuer            text        NOT NULL,
    authenticated_subject      text        NOT NULL,
    tenant_scope_key           bytea       NOT NULL,
    operation_id               bytea       NOT NULL CHECK (octet_length(operation_id) = 16),

    method                     text        NOT NULL,
    scope                      bytea       NOT NULL,
    fingerprint_version        integer     NOT NULL CHECK (fingerprint_version >= 1),
    fingerprint                bytea       NOT NULL CHECK (octet_length(fingerprint) = 32),
    canonical_intent_digest    bytea       NOT NULL
                                           CHECK (octet_length(canonical_intent_digest) = 32),

    state                      smallint    NOT NULL CHECK (state IN (0, 1)),
    consume_token              bytea       CHECK (consume_token IS NULL
                                                  OR octet_length(consume_token) = 32),
    outcome                    smallint    CHECK (outcome IS NULL OR outcome IN (0, 1)),
    not_applied_reason_version integer     CHECK (not_applied_reason_version IS NULL
                                                  OR not_applied_reason_version >= 1),
    not_applied_reason         text,

    -- Server-only witnesses. Evidence, never fingerprint inputs.
    authorization_id           bytea,
    authorization_revision     bigint,
    verification_nonce         bytea       CHECK (verification_nonce IS NULL
                                                  OR octet_length(verification_nonce) = 32),
    bound_fields_digest        bytea       CHECK (bound_fields_digest IS NULL
                                                  OR octet_length(bound_fields_digest) = 32),
    consumed_ticket_sha256     bytea       CHECK (consumed_ticket_sha256 IS NULL
                                                  OR octet_length(consumed_ticket_sha256) = 32),
    execution_witness          bytea       CHECK (execution_witness IS NULL
                                                  OR octet_length(execution_witness) <= 4096),

    -- Terminal-only exact public result and permanent identity evidence.
    public_result              bytea       CHECK (public_result IS NULL
                                                  OR octet_length(public_result) <= 4096),
    resource_id                bytea,
    resource_generation        bigint,
    resource_fingerprint       bytea       CHECK (resource_fingerprint IS NULL
                                                  OR octet_length(resource_fingerprint) = 32),
    tombstone_proof            bytea       CHECK (tombstone_proof IS NULL
                                                  OR octet_length(tombstone_proof) = 32),

    uuid_timestamp             timestamptz NOT NULL,
    prepared_at                timestamptz NOT NULL,
    hard_expires_at            timestamptz NOT NULL,
    committed_at               timestamptz,
    full_result_expires_at     timestamptz,
    compact_expires_at         timestamptz,
    compacted                  boolean     NOT NULL DEFAULT false,

    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key, operation_id),

    CONSTRAINT lore_domain_operation_receipts_state_shape CHECK (
        (state = 0
            AND consume_token IS NOT NULL
            AND outcome IS NULL
            AND committed_at IS NULL
            AND not_applied_reason_version IS NULL
            AND not_applied_reason IS NULL
            AND public_result IS NULL)
     OR (state = 1
            AND consume_token IS NULL
            AND outcome IS NOT NULL
            AND committed_at IS NOT NULL
            AND full_result_expires_at IS NOT NULL
            AND compact_expires_at IS NOT NULL)
    ),
    CONSTRAINT lore_domain_operation_receipts_not_applied_reason CHECK (
        outcome IS DISTINCT FROM 1
     OR (not_applied_reason_version IS NOT NULL AND not_applied_reason IS NOT NULL)
    ),
    CONSTRAINT lore_domain_operation_receipts_applied_reason CHECK (
        outcome IS DISTINCT FROM 0
     OR (not_applied_reason_version IS NULL AND not_applied_reason IS NULL)
    ),
    CONSTRAINT lore_domain_operation_receipts_compact_shape CHECK (
        compacted = false OR (state = 1 AND execution_witness IS NULL)
    )
);

-- The bounded sweeper and every prepare/get/consume touch drive PREPARED rows
-- past their 15-minute hard expiry, so process loss cannot wedge one forever.
CREATE INDEX IF NOT EXISTS lore_domain_operation_receipts_prepared_expiry
    ON lore_domain_operation_receipts (hard_expires_at)
    WHERE state = 0;
-- Retention: full result for 30 days, compact evidence to the later-of deadline.
CREATE INDEX IF NOT EXISTS lore_domain_operation_receipts_retention
    ON lore_domain_operation_receipts (full_result_expires_at, compact_expires_at)
    WHERE state = 1;

-- Compact future-rejection markers. A complete decisive result in themselves:
-- they keep returning COMMITTED NOT_APPLIED through their later-of prune
-- deadline instead of degrading to EXPIRED at day 30. No consume token, no
-- domain effect, no parent foreign key.
CREATE TABLE IF NOT EXISTS lore_domain_operation_future_rejections (
    verified_issuer       text        NOT NULL,
    authenticated_subject text        NOT NULL,
    tenant_scope_key      bytea       NOT NULL,
    operation_id          bytea       NOT NULL CHECK (octet_length(operation_id) = 16),
    method                text        NOT NULL,
    scope                 bytea       NOT NULL,
    fingerprint_version   integer     NOT NULL CHECK (fingerprint_version >= 1),
    fingerprint           bytea       NOT NULL CHECK (octet_length(fingerprint) = 32),
    reason_version        integer     NOT NULL CHECK (reason_version >= 1),
    reason                text        NOT NULL,
    uuid_timestamp        timestamptz NOT NULL,
    rejected_at           timestamptz NOT NULL,
    prune_after           timestamptz NOT NULL,
    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key, operation_id)
);
CREATE INDEX IF NOT EXISTS lore_domain_operation_future_rejections_prune
    ON lore_domain_operation_future_rejections (prune_after);

-- FUTURE_REJECT_QUOTA_V1 admission backpressure. Locked as an ordinary row lock
-- under UPSERT by future-rejection admission and by bounded prune/cleanup only.
-- Those transactions write no receipt, domain, or outbox row, so this row is a
-- disjoint single-row lock outside the F-032-3 chain. No parent foreign key.
CREATE TABLE IF NOT EXISTS lore_domain_operation_future_reject_quotas (
    verified_issuer       text        NOT NULL,
    authenticated_subject text        NOT NULL,
    tenant_scope_key      bytea       NOT NULL,
    quota_version         integer     NOT NULL,
    retained_count        bigint      NOT NULL CHECK (retained_count >= 0
                                                      AND retained_count <= 1024),
    bucket_start          timestamptz NOT NULL,
    bucket_count          bigint      NOT NULL CHECK (bucket_count >= 0
                                                      AND bucket_count <= 64),
    updated_at            timestamptz NOT NULL,
    PRIMARY KEY (verified_issuer, authenticated_subject, tenant_scope_key)
);

-- ---------------------------------------------------------------------------
-- Migration / backfill / cutover state
-- ---------------------------------------------------------------------------

-- Singleton. Domain writes fail closed until backfill completes and the cutover
-- marker is set; readiness refuses enforcement before both.
CREATE TABLE IF NOT EXISTS lore_domain_schema_state (
    id                  smallint    NOT NULL PRIMARY KEY CHECK (id = 1),
    schema_version      bigint      NOT NULL CHECK (schema_version >= 1),
    backfill_version    bigint      NOT NULL CHECK (backfill_version >= 0),
    backfill_state      smallint    NOT NULL CHECK (backfill_state IN (0, 1, 2, 3)),
    backfill_cursor     bytea,
    residue_classified  boolean     NOT NULL DEFAULT false,
    cutover_at          timestamptz,
    enforcement_enabled boolean     NOT NULL DEFAULT false,
    database_identity   text        NOT NULL,
    updated_at          timestamptz NOT NULL,
    CONSTRAINT lore_domain_schema_state_cutover_shape CHECK (
        (backfill_state = 3) = (cutover_at IS NOT NULL)
    ),
    CONSTRAINT lore_domain_schema_state_enforcement_needs_cutover CHECK (
        enforcement_enabled = false OR backfill_state = 3
    )
);
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
-- One row per classified domain event, appended inside the mutation
-- transaction that caused it. F-032-3 puts this insert LAST in the shared row-
-- lock order, after the receipt, repository, branch, lock-namespace, fragment,
-- and association segments.
CREATE TABLE IF NOT EXISTS lore_outbox_events (
    event_id               uuid        NOT NULL PRIMARY KEY,
    cell_id                text        NOT NULL,
    idempotency_key        bytea       NOT NULL CHECK (octet_length(idempotency_key) = 32),

    repository_id          bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    repository_generation  bigint      NOT NULL CHECK (repository_generation >= 1),

    event_kind             text        NOT NULL,
    aggregate_kind         text        NOT NULL,
    aggregate_id           bytea       NOT NULL CHECK (octet_length(aggregate_id) <= 64),
    aggregate_version      bytea       NOT NULL CHECK (octet_length(aggregate_version) <= 256),

    payload_schema_version integer     NOT NULL CHECK (payload_schema_version >= 1),
    payload                bytea       NOT NULL CHECK (octet_length(payload) <= 65536),

    state                  text        NOT NULL
                                       CHECK (state IN ('pending', 'broker_accepted', 'consumer_safe')),
    created_at             timestamptz NOT NULL,
    available_at           timestamptz NOT NULL,

    -- An exact mutation retry finds the original row instead of appending a
    -- duplicate. The key is BLAKE3 over the versioned canonical tuple of cell,
    -- event kind, repository, aggregate identity, and committed aggregate
    -- version; it carries no secret, user-supplied path, fragment bytes,
    -- certificate identity, or unbounded payload.
    CONSTRAINT lore_outbox_events_cell_idempotency UNIQUE (cell_id, idempotency_key)
);
-- The relay's scan path (WP-119). Created now, while the table is empty, so
-- WP-119 never has to build it CONCURRENTLY against a populated cell.
CREATE INDEX IF NOT EXISTS lore_outbox_events_dispatch
    ON lore_outbox_events (state, available_at);
CREATE INDEX IF NOT EXISTS lore_outbox_events_repository
    ON lore_outbox_events (repository_id, repository_generation);

-- Singleton. Read at boot for startup validation and for SCHEMA-116's
-- database-identity/cutover marker.
CREATE TABLE IF NOT EXISTS lore_outbox_schema_state (
    id                       smallint    NOT NULL PRIMARY KEY CHECK (id = 1),
    migration_version        bigint      NOT NULL CHECK (migration_version >= 1),
    backfill_version         bigint      NOT NULL CHECK (backfill_version >= 0),
    producer_compat_floor    integer     NOT NULL CHECK (producer_compat_floor >= 1),
    relay_compat_floor       integer     NOT NULL CHECK (relay_compat_floor >= 1),
    consumer_compat_floor    integer     NOT NULL CHECK (consumer_compat_floor >= 1),
    cutover_at               timestamptz,
    -- Inert until SCHEMA-119 defines its semantics; see the module docs.
    retention_policy_version integer,
    updated_at               timestamptz NOT NULL
);

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 domain schema — the Postgres-owned repository/branch lifecycle,
//! generation, tombstone, and operation-receipt rows (WP-116 Phase 2).
//!
//! **Two declarations, one shape.** As with the three CR-007 stores, this
//! `SCHEMA` const is applied at boot by [`crate::pool::ensure_schema`] under the
//! shared advisory lock, and `migrations/0001_init.sql` carries a byte-equivalent
//! copy for out-of-band provisioning. A change here is two edits, in one commit.
//!
//! **No index here may block a populated cell.** `ensure_schema` runs its DDL
//! inside a transaction and therefore cannot build `CONCURRENTLY`. Every table
//! below is created empty by this WP, so its indexes are created with it and cost
//! nothing. Any *later* index on a table that has accumulated rows follows the
//! `lore-postgres` out-of-band `CONCURRENTLY` procedure and validates
//! `pg_index.indisvalid` before the binary rolls.
//!
//! **Isolation is READ COMMITTED** (the Postgres default; CR-029 R-SHOULD-3).
//! Every exact-upsert/exact-load step is `INSERT ... ON CONFLICT` taken under the
//! row lock named by CR-032's F-032-3 lock order, never a read-then-write.
//!
//! **Name normalisation is per entity** (CR-029 R-BLOCK-3), matching the fork:
//! a live branch name keys on `lowercase(name)` (`lore-revision/src/branch.rs:477`)
//! with the authored spelling kept as a separate non-key column, while a live
//! repository name keys on exact bytes (`lore-revision/src/repository.rs:3264`).

/// Version of the domain schema declared by [`SCHEMA`]. Recorded in
/// `lore_domain_schema_state.schema_version`; a server whose compiled value is
/// below the stored value refuses to enable enforcement.
pub const DOMAIN_SCHEMA_VERSION: i64 = 1;

/// `marker_interval_schema_revision` is fixed at 3 by receipt protocol v2. It is
/// stored and digested but derived from the protocol revision rather than
/// assigned its own wire tag (CR-029).
pub const MARKER_INTERVAL_SCHEMA_REVISION: i32 = 3;

/// Repository/branch row state: live.
pub const STATE_LIVE: i16 = 0;
/// Repository/branch row state: tombstoned. The identity is permanently retired.
pub const STATE_TOMBSTONED: i16 = 1;

/// `lore_domain_operation_receipts.state`: admitted, not yet decided.
pub const RECEIPT_STATE_PREPARED: i16 = 0;
/// `lore_domain_operation_receipts.state`: terminal and immutable.
pub const RECEIPT_STATE_COMMITTED: i16 = 1;

/// Committed receipt outcome: the mutation happened.
pub const RECEIPT_OUTCOME_APPLIED: i16 = 0;
/// Committed receipt outcome: it decisively did not, with a versioned reason.
pub const RECEIPT_OUTCOME_NOT_APPLIED: i16 = 1;

/// `FUTURE_REJECT_QUOTA_V1`: retained exact markers permitted in one namespace.
pub const FUTURE_REJECT_QUOTA_RETAINED_MAX: i64 = 1_024;
/// `FUTURE_REJECT_QUOTA_V1`: newly admitted distinct markers per fixed UTC hour.
pub const FUTURE_REJECT_QUOTA_HOURLY_MAX: i64 = 64;
/// Version stamped on every `lore_domain_operation_future_reject_quotas` row.
pub const FUTURE_REJECT_QUOTA_VERSION: i32 = 1;

/// Backfill has not begun.
pub const BACKFILL_NOT_STARTED: i16 = 0;
/// Backfill is running; enforcement must stay off.
pub const BACKFILL_RUNNING: i16 = 1;
/// Backfill finished and its projection check passed.
pub const BACKFILL_VERIFIED: i16 = 2;
/// Cutover marker set; enforcement may be requested.
pub const BACKFILL_CUTOVER: i16 = 3;

/// Domain DDL. Idempotent; applied under the shared schema advisory lock.
pub const SCHEMA: &str = r#"
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

-- WP-120: the client's own attempt identity for one dispatched mutation.
--
-- ALTER rather than a column in the CREATE TABLE above, and that is load-bearing rather than
-- stylistic. Every CREATE TABLE here is IF NOT EXISTS, so on any database that already has the
-- receipts table the whole body is skipped in silence: a column added inside it would exist on a
-- freshly installed cell and be missing on every cell that has ever run, with nothing to say so
-- until an INSERT failed in production. ALTER ... ADD COLUMN IF NOT EXISTS runs on both.
--
-- Nullable on purpose. A client older than WP-120 sends no attempt id, and a receipt without one
-- is an ordinary receipt rather than a defective one, so there is no default to backfill and
-- nothing to migrate.
ALTER TABLE lore_domain_operation_receipts
    ADD COLUMN IF NOT EXISTS client_attempt_id bytea
    CHECK (client_attempt_id IS NULL OR octet_length(client_attempt_id) = 16);

-- Namespaced deliberately, and this is the security-bearing part of the change.
--
-- The lookup that uses this index resolves the principal from the caller's verified token and
-- takes only the attempt id from the request. Leading with the two identity columns means the
-- index cannot serve a probe that supplies an attempt id alone, so its shape matches the authority
-- the query is allowed to exercise. An index on client_attempt_id by itself would make a
-- cross-principal scan the cheap plan, which is exactly the query that must never be cheap.
--
-- tenant_scope_key is deliberately NOT in the prefix. It sub-partitions one principal's own rows
-- rather than separating principals, so including it would buy no isolation while forcing the
-- caller to restate a scope it may not be able to reconstruct after losing a response.
--
-- Partial, because a row without an attempt id can never be found through it.
CREATE INDEX IF NOT EXISTS lore_domain_operation_receipts_client_attempt
    ON lore_domain_operation_receipts
       (verified_issuer, authenticated_subject, client_attempt_id)
    WHERE client_attempt_id IS NOT NULL;
"#;

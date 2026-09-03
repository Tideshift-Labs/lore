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
-- CR-030 fenced lock authority (SCHEMA-117)
-- ---------------------------------------------------------------------------

ALTER TABLE lore_domain_repositories
    ADD COLUMN IF NOT EXISTS lock_generation bigint NOT NULL DEFAULT 1
        CHECK (lock_generation >= 1);
ALTER TABLE lore_domain_branches
    ADD COLUMN IF NOT EXISTS lock_generation bigint NOT NULL DEFAULT 1
        CHECK (lock_generation >= 1);

ALTER TABLE lore_locks
    ADD COLUMN IF NOT EXISTS repository_lock_generation bigint,
    ADD COLUMN IF NOT EXISTS branch_lock_generation bigint,
    ADD COLUMN IF NOT EXISTS owner_issuer text,
    ADD COLUMN IF NOT EXISTS owner_subject text,
    ADD COLUMN IF NOT EXISTS acting_issuer text,
    ADD COLUMN IF NOT EXISTS acting_subject text,
    ADD COLUMN IF NOT EXISTS ownership_token bytea,
    ADD COLUMN IF NOT EXISTS fence bigint,
    ADD COLUMN IF NOT EXISTS acquired_at timestamptz,
    ADD COLUMN IF NOT EXISTS renewed_at timestamptz,
    ADD COLUMN IF NOT EXISTS expires_at timestamptz;

DO $lock_constraints$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'lore_locks_repository_width'
    ) THEN
        ALTER TABLE lore_locks ADD CONSTRAINT lore_locks_repository_width
            CHECK (octet_length(repository) = 16);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'lore_locks_branch_width'
    ) THEN
        ALTER TABLE lore_locks ADD CONSTRAINT lore_locks_branch_width
            CHECK (octet_length(branch) = 16);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'lore_locks_fenced_shape'
    ) THEN
        ALTER TABLE lore_locks ADD CONSTRAINT lore_locks_fenced_shape CHECK (
            (repository_lock_generation IS NULL
             AND branch_lock_generation IS NULL
             AND owner_issuer IS NULL AND owner_subject IS NULL
             AND acting_issuer IS NULL AND acting_subject IS NULL
             AND ownership_token IS NULL AND fence IS NULL
             AND acquired_at IS NULL AND renewed_at IS NULL AND expires_at IS NULL)
         OR (repository_lock_generation >= 1
             AND branch_lock_generation >= 1
             AND owner_issuer IS NOT NULL AND owner_subject IS NOT NULL
             AND octet_length(ownership_token) = 32
             AND fence >= 1
             AND acquired_at IS NOT NULL AND renewed_at IS NOT NULL
             AND renewed_at >= acquired_at
             AND (expires_at IS NULL OR expires_at > renewed_at))
        );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'lore_locks_acting_pair_shape'
    ) THEN
        ALTER TABLE lore_locks ADD CONSTRAINT lore_locks_acting_pair_shape CHECK (
            (acting_issuer IS NULL) = (acting_subject IS NULL)
        );
    END IF;
END
$lock_constraints$;

CREATE SEQUENCE IF NOT EXISTS lore_domain_lock_fence_seq AS bigint START WITH 1 INCREMENT BY 1;

CREATE TABLE IF NOT EXISTS lore_domain_lock_namespaces (
    repository_id              bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    branch_id                  bytea       NOT NULL CHECK (octet_length(branch_id) = 16),
    repository_lock_generation bigint      NOT NULL CHECK (repository_lock_generation >= 1),
    branch_lock_generation     bigint      NOT NULL CHECK (branch_lock_generation >= 1),
    last_applied_fence         bigint      NOT NULL DEFAULT 0 CHECK (last_applied_fence >= 0),
    created_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, branch_id),
    FOREIGN KEY (repository_id, branch_id)
        REFERENCES lore_domain_branches (repository_id, branch_id)
);

CREATE TABLE IF NOT EXISTS lore_domain_lock_backfill_quarantine (
    repository_id bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    branch_id      bytea       NOT NULL CHECK (octet_length(branch_id) = 16),
    resource_hash  bytea       NOT NULL,
    legacy_subject text        NOT NULL,
    reason         text        NOT NULL,
    quarantined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, branch_id, resource_hash)
);

CREATE TABLE IF NOT EXISTS lore_domain_lock_schema_state (
    id                      smallint    NOT NULL PRIMARY KEY CHECK (id = 1),
    schema_version          bigint      NOT NULL CHECK (schema_version >= 1),
    backfill_state          smallint    NOT NULL CHECK (backfill_state IN (0, 1, 2)),
    backfill_cursor         bytea,
    cutover_at              timestamptz,
    fencing_enabled         boolean     NOT NULL DEFAULT false,
    lease_enabled           boolean     NOT NULL DEFAULT false,
    database_identity       text        NOT NULL,
    sequence_headroom_fence bigint      CHECK (sequence_headroom_fence >= 1),
    updated_at              timestamptz NOT NULL,
    CONSTRAINT lore_domain_lock_schema_cutover_shape CHECK (
        (backfill_state = 2 AND cutover_at IS NOT NULL AND sequence_headroom_fence IS NOT NULL)
        OR (backfill_state <> 2 AND cutover_at IS NULL AND fencing_enabled = false)
    ),
    CONSTRAINT lore_domain_lock_schema_enable_shape CHECK (
        fencing_enabled = false
        OR (backfill_state = 2 AND cutover_at IS NOT NULL AND sequence_headroom_fence IS NOT NULL)
    )
);

INSERT INTO lore_domain_lock_schema_state (
    id, schema_version, backfill_state, database_identity, updated_at
)
SELECT 1,
       1,
       0,
       control.system_identifier::text || ':' || database.oid::text || ':' || current_database(),
       clock_timestamp()
  FROM pg_control_system() AS control
  JOIN pg_database AS database ON database.datname = current_database()
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION lore_domain_repository_lock_generation_before_update()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF (OLD.state = 0 AND NEW.state = 1)
       OR (NEW.generation <> OLD.generation
           AND NEW.state = OLD.state
           AND NEW.name IS NOT DISTINCT FROM OLD.name
           AND NEW.metadata_hash IS NOT DISTINCT FROM OLD.metadata_hash
           AND NEW.default_branch_id IS NOT DISTINCT FROM OLD.default_branch_id) THEN
        NEW.lock_generation := OLD.lock_generation + 1;
    END IF;
    RETURN NEW;
END
$fn$;

CREATE OR REPLACE FUNCTION lore_domain_repository_lock_generation_after_update()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.lock_generation <> OLD.lock_generation THEN
        UPDATE lore_domain_lock_namespaces
           SET repository_lock_generation = NEW.lock_generation,
               updated_at = clock_timestamp()
         WHERE repository_id = NEW.repository_id;
    END IF;
    RETURN NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION lore_domain_branch_lock_namespace_after_insert()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    INSERT INTO lore_domain_lock_namespaces (
        repository_id, branch_id, repository_lock_generation, branch_lock_generation
    )
    SELECT NEW.repository_id, NEW.branch_id, repository.lock_generation, NEW.lock_generation
      FROM lore_domain_repositories AS repository
     WHERE repository.repository_id = NEW.repository_id
    ON CONFLICT (repository_id, branch_id) DO NOTHING;
    RETURN NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION lore_domain_branch_lock_generation_before_update()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF OLD.state = 0 AND NEW.state = 1 THEN
        NEW.lock_generation := OLD.lock_generation + 1;
    END IF;
    RETURN NEW;
END
$fn$;

CREATE OR REPLACE FUNCTION lore_domain_branch_lock_generation_after_update()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.lock_generation <> OLD.lock_generation THEN
        UPDATE lore_domain_lock_namespaces
           SET branch_lock_generation = NEW.lock_generation,
               updated_at = clock_timestamp()
         WHERE repository_id = NEW.repository_id AND branch_id = NEW.branch_id;
    END IF;
    RETURN NULL;
END
$fn$;

DO $lock_triggers$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'lore_domain_repository_lock_generation_before') THEN
        CREATE TRIGGER lore_domain_repository_lock_generation_before
        BEFORE UPDATE ON lore_domain_repositories
        FOR EACH ROW EXECUTE FUNCTION lore_domain_repository_lock_generation_before_update();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'lore_domain_repository_lock_generation_after') THEN
        CREATE TRIGGER lore_domain_repository_lock_generation_after
        AFTER UPDATE ON lore_domain_repositories
        FOR EACH ROW EXECUTE FUNCTION lore_domain_repository_lock_generation_after_update();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'lore_domain_branch_lock_namespace_insert') THEN
        CREATE TRIGGER lore_domain_branch_lock_namespace_insert
        AFTER INSERT ON lore_domain_branches
        FOR EACH ROW EXECUTE FUNCTION lore_domain_branch_lock_namespace_after_insert();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'lore_domain_branch_lock_generation_before') THEN
        CREATE TRIGGER lore_domain_branch_lock_generation_before
        BEFORE UPDATE ON lore_domain_branches
        FOR EACH ROW EXECUTE FUNCTION lore_domain_branch_lock_generation_before_update();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'lore_domain_branch_lock_generation_after') THEN
        CREATE TRIGGER lore_domain_branch_lock_generation_after
        AFTER UPDATE ON lore_domain_branches
        FOR EACH ROW EXECUTE FUNCTION lore_domain_branch_lock_generation_after_update();
    END IF;
END
$lock_triggers$;

CREATE INDEX IF NOT EXISTS lore_locks_fenced_owner_repo_branch
    ON lore_locks (owner_issuer, owner_subject, repository, branch)
    WHERE owner_issuer IS NOT NULL;
CREATE INDEX IF NOT EXISTS lore_locks_fenced_expiry
    ON lore_locks (expires_at)
    WHERE expires_at IS NOT NULL;

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

-- ---------------------------------------------------------------------------
-- SCHEMA-119 relay extension (CR-032; WP-119 Step A)
--
-- Extends the WP-116 base **in place**. There is no parallel intent store: the
-- relay claim, publication result, and dead letter rows of CR-032's persistent
-- model attach to the same `lore_outbox_events` row the mutation transaction
-- wrote, so an event has exactly one durable identity for its whole life.
--
-- Every column is added with `ADD COLUMN IF NOT EXISTS` so an existing empty
-- cell upgrades in place. Cells are empty everywhere today (no outbox row has
-- ever been written in production), so this DDL runs inside the boot-time
-- `ensure_schema` transaction and no index here needs `CONCURRENTLY`.
ALTER TABLE lore_outbox_events
    -- Relay claim. `claim_generation` starts at 0 and increases on every claim,
    -- so a stale worker comparing against an older generation can never
    -- acknowledge, reschedule, or dead-letter a newer claim.
    ADD COLUMN IF NOT EXISTS claim_generation bigint NOT NULL DEFAULT 0
        CHECK (claim_generation >= 0),
    ADD COLUMN IF NOT EXISTS claim_owner text
        CHECK (octet_length(claim_owner) BETWEEN 1 AND 128),
    ADD COLUMN IF NOT EXISTS claim_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 0
        CHECK (attempt_count >= 0),
    ADD COLUMN IF NOT EXISTS last_error_class text
        CHECK (octet_length(last_error_class) BETWEEN 1 AND 64),
    -- Publication result. CR-032's "next attempt time" is the base row's
    -- existing `available_at`; it is not duplicated here.
    ADD COLUMN IF NOT EXISTS stream_identity text
        CHECK (octet_length(stream_identity) BETWEEN 1 AND 128),
    ADD COLUMN IF NOT EXISTS stream_epoch bigint
        CHECK (stream_epoch >= 1),
    ADD COLUMN IF NOT EXISTS broker_sequence bigint
        CHECK (broker_sequence >= 0),
    ADD COLUMN IF NOT EXISTS gateway_response_id text
        CHECK (octet_length(gateway_response_id) BETWEEN 1 AND 128),
    ADD COLUMN IF NOT EXISTS publisher_contract_version integer
        CHECK (publisher_contract_version >= 1),
    ADD COLUMN IF NOT EXISTS broker_accepted_at timestamptz;

DO $outbox_relay_constraints$
BEGIN
    -- Both directions, and both TOTALLY. `broker_accepted`/`consumer_safe`
    -- must carry the FULL publication result, and a `pending` row must carry
    -- NONE of it: `release_for_retry` and the epoch-reset requeue both return a
    -- row to `pending`, and a leftover stream identity or broker sequence there
    -- reads to a later reader as proof of an acceptance that was withdrawn.
    --
    -- Written as a CASE rather than the shorter
    -- `(state IN (...)) = (every column IS NOT NULL)`. That equality looks
    -- like it says the same thing and does not: a pending row carrying ONE
    -- leftover column makes both sides false and satisfies it. Measured on
    -- PostgreSQL 16.15 -- `UPDATE ... SET stream_identity = 's'` on a pending
    -- row was accepted under the equality form and is rejected under this one.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_events_publication_shape'
          AND conrelid = 'lore_outbox_events'::regclass
    ) THEN
        ALTER TABLE lore_outbox_events
            ADD CONSTRAINT lore_outbox_events_publication_shape CHECK (
                CASE WHEN state = 'pending'
                     THEN (stream_identity IS NULL
                           AND stream_epoch IS NULL
                           AND broker_sequence IS NULL
                           AND gateway_response_id IS NULL
                           AND publisher_contract_version IS NULL
                           AND broker_accepted_at IS NULL)
                     ELSE (stream_identity IS NOT NULL
                           AND stream_epoch IS NOT NULL
                           AND broker_sequence IS NOT NULL
                           AND gateway_response_id IS NOT NULL
                           AND publisher_contract_version IS NOT NULL
                           AND broker_accepted_at IS NOT NULL)
                END
            );
    END IF;
    -- A lease is an owner and an expiry together or neither. A half-set lease
    -- is either un-expirable (owner, no expiry) or ownerless but reserved
    -- (expiry, no owner); both make the reclaim rule unstateable.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_events_claim_shape'
          AND conrelid = 'lore_outbox_events'::regclass
    ) THEN
        ALTER TABLE lore_outbox_events
            ADD CONSTRAINT lore_outbox_events_claim_shape CHECK (
                (claim_owner IS NULL) = (claim_expires_at IS NULL)
            );
    END IF;
    -- The cell identity is a SUBJECT TOKEN, not just a column: every subject is
    -- `lore.v1.cell.<cell_id>.repo.<repository_hex>.<class>`. A value carrying a
    -- dot, a space, or a wildcard would restructure the subject rather than be
    -- rejected by it, so the notification-plane contract pins the charset
    -- alongside the width and this is the backstop behind `append`'s own check.
    -- The base CREATE TABLE declares `cell_id text` with no bound at all.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_events_cell_id_shape'
          AND conrelid = 'lore_outbox_events'::regclass
    ) THEN
        ALTER TABLE lore_outbox_events
            ADD CONSTRAINT lore_outbox_events_cell_id_shape CHECK (
                cell_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
                AND octet_length(cell_id) <= 63
            );
    END IF;
END
$outbox_relay_constraints$;

-- Eligible unpublished work, for the relay scan.
--
-- The predicate is a SQL **literal**, and every statement meaning to use it
-- spells `state = 'pending'` literally too. A bound parameter (`state = $1`,
-- `state = ANY($1)`) returns the same rows and passes every test, but the
-- planner uses a partial index only when it can prove the query predicate
-- implies the index predicate, and under a generic plan it cannot prove that
-- from a parameter. No non-partial index leads with `available_at`, so the
-- fallback is a sequential scan of the whole table.
CREATE INDEX IF NOT EXISTS lore_outbox_events_pending_available
    ON lore_outbox_events (available_at, event_id)
    WHERE state = 'pending';
-- Oldest-unpublished age for readiness and admission, answered index-only from
-- the leading column rather than by scanning the pending set.
CREATE INDEX IF NOT EXISTS lore_outbox_events_pending_created
    ON lore_outbox_events (created_at)
    WHERE state = 'pending';
-- There is deliberately NO partial expression index on octet_length(payload)
-- for the admission byte budget, though it is the obvious thing to add.
-- Measured on PostgreSQL 16.15 over 18,000 pending rows with 8 KiB payloads:
-- with such an index the byte probe reads 600 shared buffers in 4.9 ms, and
-- without it 602 in 4.7 ms. PostgreSQL does not satisfy octet_length(payload)
-- from the expression index (the plan is an Index Scan, never Index Only), and
-- it does not need to -- octet_length reads the length out of the TOAST pointer
-- in the main tuple without detoasting, so the cost already scales with the
-- pending ROW count rather than with payload bytes. The index would add write
-- amplification on every append and every state transition and buy nothing.
-- Do not add it back without a measurement that contradicts this one.
-- Expired claims. Partial on `IS NOT NULL`, so it holds only rows a relay
-- currently owns -- bounded by the claim batch size times the number of live
-- workers rather than by the table.
CREATE INDEX IF NOT EXISTS lore_outbox_events_claim_expiry
    ON lore_outbox_events (claim_expires_at)
    WHERE claim_expires_at IS NOT NULL;
-- Broker-epoch reset: every retained not-yet-safe row published to one stream
-- identity and epoch. Literal predicate, same reason as above.
CREATE INDEX IF NOT EXISTS lore_outbox_events_accepted_stream
    ON lore_outbox_events (stream_identity, stream_epoch, event_id)
    WHERE state = 'broker_accepted';

-- Terminal rows, moved out of `lore_outbox_events` so the relay scan never
-- walks past them and no poison row blocks a later one. The copy is immutable
-- evidence: every identity and payload column is carried verbatim, and an
-- operator disposition never deletes it.
--
-- **Any later column or constraint on this table is an `ALTER`, never an edit
-- to the body below.** `CREATE TABLE IF NOT EXISTS` silently skips a changed
-- body on a database that already has the table, so a column added inside the
-- parentheses reaches a fresh cell and no existing one -- and the first
-- statement that references it fails with `column ... does not exist` rather
-- than returning a typed outcome. That is not hypothetical: the six columns
-- and two constraints now applied by the `ALTER`/`DO` blocks below were first
-- written inside this body, and an independent reviewer demonstrated exactly
-- that failure by dropping them and re-running this DDL. The migration-parity
-- test cannot catch it, because both of its sides are fresh installs.
--
-- **The `ALTER`/`DO` blocks are only safe for ADDING, and carry the same trap
-- for CHANGING.** `ADD COLUMN IF NOT EXISTS` skips a column that exists,
-- whatever its type or CHECK now says, and the `IF NOT EXISTS (SELECT 1 FROM
-- pg_constraint WHERE conname = ...)` guards skip a constraint whose body has
-- since been edited. Both leave the OLD definition in place on every existing
-- cell while a fresh one gets the new -- the same silent divergence, one level
-- down. Editing an existing column or constraint here therefore needs its own
-- explicitly-named migration step, not an edit in place. This applies to the
-- `lore_outbox_events` blocks above just as much as to the ones below.
CREATE TABLE IF NOT EXISTS lore_outbox_dead_letters (
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

    created_at             timestamptz NOT NULL,
    attempt_count          integer     NOT NULL CHECK (attempt_count >= 0),

    terminal_class         text        NOT NULL
                                       CHECK (octet_length(terminal_class) BETWEEN 1 AND 64),
    first_failed_at        timestamptz NOT NULL,
    last_failed_at         timestamptz NOT NULL,

    disposition            text        NOT NULL
                                       CHECK (disposition IN ('parked', 'requeued', 'obsolete')),
    disposition_reason     text        CHECK (octet_length(disposition_reason) <= 1024),
    disposition_at         timestamptz,
    disposition_actor      text        CHECK (octet_length(disposition_actor) BETWEEN 1 AND 256),

    -- `parked` is the un-dispositioned state, so it is exactly the state with
    -- no disposition timestamp, and a disposition always names who made it.
    CONSTRAINT lore_outbox_dead_letters_disposition_shape CHECK (
        (disposition = 'parked') = (disposition_at IS NULL)
        AND (disposition_at IS NULL) = (disposition_actor IS NULL)
    )
);

ALTER TABLE lore_outbox_dead_letters
    -- The claim generation the row carried when it was dead-lettered.
    --
    -- Load-bearing, not diagnostic. `claim_generation` is the ONLY relay fence,
    -- and it lives on `lore_outbox_events` -- a row that leaves that table and
    -- comes back would restart the counter, so a worker still holding the old
    -- generation would compare equal against the reinstated row and act on a
    -- claim it lost. Requeue therefore reinstates at this value PLUS ONE.
    --
    -- The DEFAULT is a formality: `dead_letter` copies the event row's own
    -- generation under the same `FOR UPDATE` that read it, so every row this
    -- crate writes carries a real value. The default can only be reached by a
    -- row that predates this column, and no such row exists anywhere -- this
    -- table is created for the first time by `SCHEMA-119`.
    ADD COLUMN IF NOT EXISTS claim_generation bigint NOT NULL DEFAULT 0
        CHECK (claim_generation >= 0),
    -- How many terminal-failure cycles this dead letter has recorded: 1 on the
    -- first, incremented when a requeued row fails terminally again.
    --
    -- Keyed by `event_id`, which is what makes it a cycle count for THIS
    -- durable row rather than for the logical event. A producer that re-appends
    -- after a dead-letter mints a fresh `event_id`, so the same
    -- `(cell_id, idempotency_key)` can end up with two dead-letter rows each
    -- counting 1.
    ADD COLUMN IF NOT EXISTS dead_letter_count integer NOT NULL DEFAULT 1
        CHECK (dead_letter_count >= 1),
    -- The disposition this row carried before its most recent re-dead-letter.
    --
    -- A requeued event that fails terminally again has to return to `parked`,
    -- or it would never appear in the operator queue again. Overwriting the
    -- disposition in place would delete the record of the decision that put it
    -- back in flight, which is the audit trail an operator needs in order not
    -- to make the same call twice. One level is retained; `dead_letter_count`
    -- says how many were not.
    ADD COLUMN IF NOT EXISTS previous_disposition text
        CHECK (previous_disposition IN ('parked', 'requeued', 'obsolete')),
    ADD COLUMN IF NOT EXISTS previous_disposition_reason text
        CHECK (octet_length(previous_disposition_reason) <= 1024),
    ADD COLUMN IF NOT EXISTS previous_disposition_at timestamptz,
    ADD COLUMN IF NOT EXISTS previous_disposition_actor text
        CHECK (octet_length(previous_disposition_actor) BETWEEN 1 AND 256);

DO $outbox_dead_letter_constraints$
BEGIN
    -- The retained prior decision is whole or absent, never half, and it obeys
    -- the same "parked carries no timestamp" rule as the live one. A CASE, not
    -- a chain of equalities: `previous_disposition IS NULL` makes an `IN` test
    -- yield NULL, a CHECK passes on NULL, and the clause meant to force the
    -- other three columns empty would quietly not apply.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_dead_letters_previous_disposition_shape'
          AND conrelid = 'lore_outbox_dead_letters'::regclass
    ) THEN
        ALTER TABLE lore_outbox_dead_letters
            ADD CONSTRAINT lore_outbox_dead_letters_previous_disposition_shape CHECK (
                CASE WHEN previous_disposition IS NULL
                     THEN (previous_disposition_reason IS NULL
                           AND previous_disposition_at IS NULL
                           AND previous_disposition_actor IS NULL)
                     WHEN previous_disposition = 'parked'
                     THEN (previous_disposition_at IS NULL
                           AND previous_disposition_actor IS NULL)
                     ELSE (previous_disposition_at IS NOT NULL
                           AND previous_disposition_actor IS NOT NULL)
                END
            );
    END IF;
    -- A row that has never been re-dead-lettered has no prior decision to
    -- retain, and one that has must have had a disposition to supersede --
    -- `dead_letter` only ever runs against an event row, which only requeue
    -- can put back, and requeue always writes a disposition.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_dead_letters_redelivery_shape'
          AND conrelid = 'lore_outbox_dead_letters'::regclass
    ) THEN
        ALTER TABLE lore_outbox_dead_letters
            ADD CONSTRAINT lore_outbox_dead_letters_redelivery_shape CHECK (
                (dead_letter_count = 1) = (previous_disposition IS NULL)
            );
    END IF;
END
$outbox_dead_letter_constraints$;

-- Operator queue: parked rows awaiting a disposition, oldest failure first.
CREATE INDEX IF NOT EXISTS lore_outbox_dead_letters_operations
    ON lore_outbox_dead_letters (disposition, last_failed_at);

-- ---------------------------------------------------------------------------
-- SCHEMA-119 Step C: receiver membership, checkpoints, and reset generations
--
-- CR-032's "Receiver membership projection" row, split into the four durable
-- facts it actually is: the per-cell counters every compare-and-set anchors on,
-- one row per receiver generation, one checkpoint row per
-- (stream, epoch, receiver, generation), and the reset evidence that fences
-- the whole cell.
--
-- These four tables are created here for the FIRST time, so their
-- `CREATE TABLE` bodies are the whole declaration. Every LATER change to one of
-- them is an `ALTER`, never an edit inside the parentheses: a
-- `CREATE TABLE IF NOT EXISTS` body is silently skipped on a database that
-- already has the table, so an edited body would reach a fresh cell and no
-- existing one. The `lore_outbox_dead_letters` block above is the worked
-- example of both the trap and the repair.
-- ---------------------------------------------------------------------------

-- Per-cell counters. One row per cell, and the compare-and-set anchor for
-- every membership change: `membership_version` is what the evaluator, the
-- reaper, and every checkpoint report compare against, so a concurrent join,
-- retirement, or reset makes their write fail and retry rather than mix two
-- membership snapshots in one safety decision.
--
-- `current_stream_identity`/`current_stream_epoch` are the cell's AUTHORITATIVE
-- current placement, not a receiver's captured view. The readiness CAS rereads
-- them and succeeds only when they still equal what that generation captured,
-- and the reset service validates a report's old tuple against them. They are
-- nullable only before the cell's first placement is recorded; a cell in that
-- state has no receiver that can be ready.
CREATE TABLE IF NOT EXISTS lore_outbox_membership_state (
    cell_id                    text        NOT NULL PRIMARY KEY,
    membership_version         bigint      NOT NULL CHECK (membership_version >= 1),
    next_membership_generation bigint      NOT NULL CHECK (next_membership_generation >= 1),
    reset_generation           bigint      NOT NULL CHECK (reset_generation >= 0),
    current_stream_identity    text
                                           CHECK (octet_length(current_stream_identity) BETWEEN 1 AND 128),
    current_stream_epoch       bigint      CHECK (current_stream_epoch >= 1),
    current_placement_revision bigint      NOT NULL CHECK (current_placement_revision >= 0),
    updated_at                 timestamptz NOT NULL,

    -- Same subject-token grammar as `lore_outbox_events.cell_id`; a cell whose
    -- membership row and event rows disagreed on the identity would evaluate
    -- one cell's safety against another cell's membership.
    CONSTRAINT lore_outbox_membership_state_cell_id_shape CHECK (
        cell_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
        AND octet_length(cell_id) <= 63
    ),
    -- A placement is an identity and an epoch together or neither. Half a
    -- placement makes the readiness CAS and the reset service's old-tuple
    -- validation unstateable.
    CONSTRAINT lore_outbox_membership_state_stream_shape CHECK (
        (current_stream_identity IS NULL) = (current_stream_epoch IS NULL)
    )
);

-- One row per receiver GENERATION, never per receiver. Name reuse never
-- inherits a checkpoint, which is exactly why `membership_generation` is in the
-- primary key: a replacement at a greater generation is a different row with no
-- frontier of its own until it captures, baselines, and drains.
--
-- Generation 0 is reserved for the reset fence's `required_placeholder`, a row
-- that exists to make the required set non-empty while no real replacement has
-- joined yet. It can never be ready, so it blocks every safety evaluation for
-- as long as it stands.
CREATE TABLE IF NOT EXISTS lore_outbox_receiver_membership (
    cell_id                  text        NOT NULL,
    receiver_identity        text        NOT NULL
                                         CHECK (octet_length(receiver_identity) BETWEEN 1 AND 128),
    membership_generation    bigint      NOT NULL CHECK (membership_generation >= 0),
    membership_version       bigint      NOT NULL CHECK (membership_version >= 1),
    state                    text        NOT NULL
                                         CHECK (state IN ('joining', 'ready', 'draining',
                                                          'retired', 'required_placeholder')),
    captured_stream_identity text
                                         CHECK (octet_length(captured_stream_identity) BETWEEN 1 AND 128),
    captured_stream_epoch    bigint      CHECK (captured_stream_epoch >= 1),
    captured_start_sequence  bigint      CHECK (captured_start_sequence >= 0),
    baseline_at              timestamptz,
    ready_at                 timestamptz,
    created_at               timestamptz NOT NULL,
    updated_at               timestamptz NOT NULL,

    PRIMARY KEY (cell_id, receiver_identity, membership_generation),

    -- The captured position is one fact in three columns. A half-captured row
    -- would let a baseline be taken against an epoch nothing recorded.
    CONSTRAINT lore_outbox_receiver_membership_capture_shape CHECK (
        (captured_stream_identity IS NULL) = (captured_stream_epoch IS NULL)
        AND (captured_stream_identity IS NULL) = (captured_start_sequence IS NULL)
    ),
    -- The contract's ordered bootstrap, expressed as a shape rather than a
    -- procedure: capture, then baseline, then ready. A CASE rather than a chain
    -- of equalities, for the reason the publication-shape constraint above
    -- records: an equality form is satisfied by a row that is wrong on both
    -- sides at once.
    CONSTRAINT lore_outbox_receiver_membership_lifecycle_shape CHECK (
        CASE WHEN state = 'required_placeholder'
             THEN (membership_generation = 0
                   AND captured_stream_identity IS NULL
                   AND baseline_at IS NULL
                   AND ready_at IS NULL)
             WHEN state IN ('ready', 'draining')
             THEN (membership_generation >= 1
                   AND captured_stream_identity IS NOT NULL
                   AND baseline_at IS NOT NULL
                   AND ready_at IS NOT NULL)
             WHEN state = 'joining'
             THEN (membership_generation >= 1 AND ready_at IS NULL)
             ELSE membership_generation >= 1
        END
    )
);
-- The current generation for one receiver: the greatest generation it has.
CREATE INDEX IF NOT EXISTS lore_outbox_receiver_membership_current
    ON lore_outbox_receiver_membership (cell_id, receiver_identity, membership_generation DESC);
-- The required set and the fence probe read only rows that are not retired.
-- Literal predicate, and every statement meaning to use it spells
-- `state <> 'retired'` literally too: the planner uses a partial index only
-- when it can prove the query predicate implies the index predicate, and under
-- a generic plan it cannot prove that from a bound parameter.
CREATE INDEX IF NOT EXISTS lore_outbox_receiver_membership_live
    ON lore_outbox_receiver_membership (cell_id, membership_generation)
    WHERE state <> 'retired';

-- The checkpoint vector, keyed exactly as the notification-plane contract pins
-- it: stream identity, stream epoch, receiver identity, membership generation.
-- A frontier from a prior epoch says nothing about the current one, which is
-- why the epoch is in the key rather than a column beside it.
--
-- `contiguous_frontier` is the highest broker sequence at or below which every
-- event is applied or refetched. It never advances across an unresolved gap:
-- `gaps` and `poison` are the explicit blockers, and `report_checkpoint`
-- refuses a frontier that has passed the lowest of them.
CREATE TABLE IF NOT EXISTS lore_outbox_checkpoints (
    stream_identity       text        NOT NULL
                                      CHECK (octet_length(stream_identity) BETWEEN 1 AND 128),
    stream_epoch          bigint      NOT NULL CHECK (stream_epoch >= 1),
    receiver_identity     text        NOT NULL
                                      CHECK (octet_length(receiver_identity) BETWEEN 1 AND 128),
    membership_generation bigint      NOT NULL CHECK (membership_generation >= 1),
    cell_id               text        NOT NULL,
    membership_version    bigint      NOT NULL CHECK (membership_version >= 1),
    contiguous_frontier   bigint      NOT NULL CHECK (contiguous_frontier >= 0),
    -- Unresolved gaps and poison dispositions, as PARALLEL typed arrays rather
    -- than one jsonb document. Two reasons, both practical: this crate has no
    -- JSON dependency and adding one to carry four integers per blocker is not
    -- a trade worth making, and a `bigint[]` reads back through the driver as a
    -- `Vec<i64>` with the database enforcing the element type, where a jsonb
    -- document would be re-parsed by hand on every read.
    --
    -- `gap_starts[i]`/`gap_ends[i]` are one inclusive unresolved range;
    -- `poison_sequences[i]`/`poison_classes[i]` are one parked disposition.
    gap_starts            bigint[]    NOT NULL,
    gap_ends              bigint[]    NOT NULL,
    poison_sequences      bigint[]    NOT NULL,
    poison_classes        text[]      NOT NULL,
    reported_at           timestamptz NOT NULL,
    projection_at         timestamptz NOT NULL,

    PRIMARY KEY (stream_identity, stream_epoch, receiver_identity, membership_generation),

    -- Bounded on the element count, on the pairing between the two halves of
    -- each blocker, on element nullability, and on the serialized size of the
    -- one variable-width column.
    --
    -- The element count alone bounds nothing: one poison class may carry an
    -- arbitrarily long string, and this projection is read on every safety
    -- evaluation. `coalesce(array_length(...), 0)` because an empty array's
    -- length is NULL, not 0, and a CHECK passes on NULL -- the unbounded case
    -- would be the one that quietly did not apply.
    CONSTRAINT lore_outbox_checkpoints_blocker_bounds CHECK (
        coalesce(array_length(gap_starts, 1), 0) = coalesce(array_length(gap_ends, 1), 0)
        AND coalesce(array_length(gap_starts, 1), 0) <= 256
        AND coalesce(array_length(poison_sequences, 1), 0)
            = coalesce(array_length(poison_classes, 1), 0)
        AND coalesce(array_length(poison_sequences, 1), 0) <= 256
        AND array_position(gap_starts, NULL::bigint) IS NULL
        AND array_position(gap_ends, NULL::bigint) IS NULL
        AND array_position(poison_sequences, NULL::bigint) IS NULL
        AND array_position(poison_classes, NULL::text) IS NULL
        AND octet_length(poison_classes::text) <= 16384
    )
);
CREATE INDEX IF NOT EXISTS lore_outbox_checkpoints_cell
    ON lore_outbox_checkpoints (cell_id, stream_identity, stream_epoch);

-- Reset evidence, the stored acknowledgement, and the cell fence.
--
-- `ack_bytes` holds the SERIALIZED `StreamResetAckV1` produced in the receipt
-- transaction, and an equivalent retry replays exactly those bytes. That is a
-- storage rule, not a re-serialization rule: protobuf serialization is not
-- canonical, so re-encoding the same fields across library versions can differ
-- and the contract requires byte-identity.
--
-- The two unique constraints are the concurrency mechanism, not merely
-- integrity: equivalent detectors race on them, the winner commits, and every
-- loser rereads the stored ack and returns it verbatim with the winner's
-- assigned generation.
CREATE TABLE IF NOT EXISTS lore_outbox_reset_generations (
    cell_id               text        NOT NULL,
    reset_generation      bigint      NOT NULL CHECK (reset_generation >= 1),
    detection_id          text        NOT NULL
                                      CHECK (octet_length(detection_id) BETWEEN 1 AND 64),
    reset_fingerprint     bytea       NOT NULL CHECK (octet_length(reset_fingerprint) = 32),
    broker_reset_identity text        NOT NULL
                                      CHECK (octet_length(broker_reset_identity) BETWEEN 1 AND 256),
    old_stream_identity   text        NOT NULL
                                      CHECK (octet_length(old_stream_identity) BETWEEN 1 AND 128),
    old_stream_epoch      bigint      NOT NULL CHECK (old_stream_epoch >= 1),
    new_stream_identity   text        NOT NULL
                                      CHECK (octet_length(new_stream_identity) BETWEEN 1 AND 128),
    new_stream_epoch      bigint      NOT NULL CHECK (new_stream_epoch >= 1),
    -- `ResetReasonV1`, 1..=5. The proto3 zero value exists only because proto3
    -- requires one and never appears in a valid report, so it is excluded here
    -- rather than stored and re-rejected later.
    reason_code           integer     NOT NULL CHECK (reason_code BETWEEN 1 AND 5),
    placement_revision    bigint      NOT NULL CHECK (placement_revision >= 0),
    -- Retained as evidence, and deliberately NOT part of duplicate equality:
    -- two reports of one physical reset differ here and are the same detection.
    detected_at_unix_ms   bigint      NOT NULL,
    -- The stable emitter principal derived from the caller's SPIFFE ID / SAN,
    -- not the leaf certificate: certificates rotate and the authorization this
    -- record replays an ack to must outlive a rotation.
    emitter_identity      text        NOT NULL
                                      CHECK (octet_length(emitter_identity) BETWEEN 1 AND 256),
    evidence_id           text        NOT NULL
                                      CHECK (octet_length(evidence_id) BETWEEN 1 AND 64),
    ack_bytes             bytea       NOT NULL
                                      CHECK (octet_length(ack_bytes) BETWEEN 1 AND 4096),
    state                 text        NOT NULL
                                      CHECK (state IN ('reset_in_progress', 'cleared')),
    persisted_at          timestamptz NOT NULL,
    cleared_at            timestamptz,

    PRIMARY KEY (cell_id, reset_generation),
    CONSTRAINT lore_outbox_reset_generations_detection UNIQUE (cell_id, detection_id),
    CONSTRAINT lore_outbox_reset_generations_fingerprint UNIQUE (cell_id, reset_fingerprint),
    CONSTRAINT lore_outbox_reset_generations_clear_shape CHECK (
        (state = 'cleared') = (cleared_at IS NOT NULL)
    ),
    -- A successor that equals its predecessor is not a reset. The contract is
    -- explicit that an in-place rollback is not expressible in this transport
    -- and must not be forced into one.
    CONSTRAINT lore_outbox_reset_generations_successor_shape CHECK (
        (new_stream_identity, new_stream_epoch)
            IS DISTINCT FROM (old_stream_identity, old_stream_epoch)
    )
);
-- At most one reset in progress per cell, enforced by the database rather than
-- by the service's own read: the fence is what makes `consumer_safe` evaluation
-- and pruning fail, and two concurrent fences would each believe they own it.
CREATE UNIQUE INDEX IF NOT EXISTS lore_outbox_reset_generations_fence
    ON lore_outbox_reset_generations (cell_id)
    WHERE state = 'reset_in_progress';
-- Successor validation reads every transition already accepted FROM one old
-- tuple, and every tuple already retired as a predecessor.
CREATE INDEX IF NOT EXISTS lore_outbox_reset_generations_old_stream
    ON lore_outbox_reset_generations (cell_id, old_stream_identity, old_stream_epoch);
CREATE INDEX IF NOT EXISTS lore_outbox_reset_generations_new_stream
    ON lore_outbox_reset_generations (cell_id, new_stream_identity, new_stream_epoch);

-- The evaluator's scan: accepted rows on one stream and epoch at or below a
-- safe sequence. `lore_outbox_events_accepted_stream` leads with `event_id`
-- after the stream pair, so it answers the epoch-reset sweep but cannot bound
-- this one by sequence. Literal predicate, same reason as every other partial
-- index in this schema.
CREATE INDEX IF NOT EXISTS lore_outbox_events_accepted_sequence
    ON lore_outbox_events (stream_identity, stream_epoch, broker_sequence)
    WHERE state = 'broker_accepted';
-- Retention: the oldest consumer-safe rows first, bounded by the prune batch.
CREATE INDEX IF NOT EXISTS lore_outbox_events_safe_retention
    ON lore_outbox_events (created_at, event_id)
    WHERE state = 'consumer_safe';

-- ---------------------------------------------------------------------------
-- CR-031 fragment lifecycle authority (SCHEMA-118)
--
-- Byte-equivalent copy of the runtime DDL declared in:
--   src/domain/fragments/schema.rs  (FRAGMENT_SCHEMA)
--
-- Migration-owned. Deliberately NOT part of the immutable store's legacy
-- self-bootstrap SCHEMA above, and not applied by PostgresDomainStore::connect:
-- a cell this migration has not reached must boot and answer on the legacy
-- route rather than silently cut over on a binary roll.
--
-- As with every other block here, a schema change is TWO edits in one commit:
-- the Rust const and this file. tests/domain_migration_parity.rs applies each
-- path to its own database and compares the resulting catalog.
-- ---------------------------------------------------------------------------
-- The two push witnesses are columns on the existing repository row, not a new
-- lockable row class: F-032-3's order gains no position from them, and a push
-- that already locks the repository row reads both for free.
--
-- `content_association_generation` moves on association create/copy/tombstone.
-- `fragment_lifecycle_generation` moves on a readable/unreadable transition of
-- any fragment this repository has a live association to.
ALTER TABLE lore_domain_repositories
    ADD COLUMN IF NOT EXISTS content_association_generation bigint NOT NULL DEFAULT 1
        CHECK (content_association_generation >= 1),
    ADD COLUMN IF NOT EXISTS fragment_lifecycle_generation bigint NOT NULL DEFAULT 1
        CHECK (fragment_lifecycle_generation >= 1);

-- One monotonic source for every fragment epoch and every operation fence.
-- Gaps are valid: a fence is an ordering token, not a count.
CREATE SEQUENCE IF NOT EXISTS lore_fragment_fence_seq AS bigint START WITH 1 INCREMENT BY 1;

-- Lifecycle head: the sole current-epoch pointer for one FragmentId.
--
-- States: 1 PreparingStage, 2 PreparingRemote, 3 Staged, 4 Remote,
--         5 DeletingChildren, 6 DeletingPayload, 7 Missing, 8 Tombstoned.
-- Only 3 and 4 are readable, and the CHECK below makes "readable without a
-- manifest" unrepresentable rather than merely unlikely.
CREATE TABLE IF NOT EXISTS lore_fragment_lifecycle (
    hash             bytea       NOT NULL PRIMARY KEY,
    current_epoch    bigint      NOT NULL CHECK (current_epoch >= 1),
    state            smallint    NOT NULL CHECK (state BETWEEN 1 AND 8),
    manifest_id      bytea       CHECK (manifest_id IS NULL
                                        OR octet_length(manifest_id) = 32),
    last_fence       bigint      NOT NULL CHECK (last_fence >= 1),
    -- RESERVED, always NULL until Phase 5. CR-031's model names an active
    -- operation, but no CR-029 domain operation ID reaches this layer yet, and
    -- nothing writes this column. The shape is declared now so adding it later
    -- is not an ALTER under ensure_schema on a populated cell.
    active_operation bytea       CHECK (active_operation IS NULL
                                        OR octet_length(active_operation) = 16),
    diagnostic_class smallint    NOT NULL DEFAULT 0 CHECK (diagnostic_class BETWEEN 0 AND 5),
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT lore_fragment_lifecycle_readable_shape CHECK (
        (state IN (3, 4)) = (manifest_id IS NOT NULL)
    ),
    CONSTRAINT lore_fragment_lifecycle_diagnostic_shape CHECK (
        state = 7 OR diagnostic_class = 0
    )
);

-- Epoch representation. Immutable once written: a repair publishes a GREATER
-- epoch and quarantines its predecessor, it never rewrites this row. That is
-- what lets a delayed operation revalidate an exact manifest rather than trust
-- a mutable current view.
CREATE TABLE IF NOT EXISTS lore_fragment_epochs (
    hash          bytea       NOT NULL,
    epoch         bigint      NOT NULL CHECK (epoch >= 1),
    authority     smallint    NOT NULL CHECK (authority IN (1, 2)),
    object_key    text        NOT NULL CHECK (length(object_key) > 0),
    manifest_id   bytea       NOT NULL CHECK (octet_length(manifest_id) = 32),
    size_payload  bigint      NOT NULL CHECK (size_payload > 0),
    size_content  bigint      NOT NULL CHECK (size_content > 0),
    decoded_hash  bytea       NOT NULL CHECK (octet_length(decoded_hash) > 0),
    payload_flags bigint      NOT NULL CHECK (payload_flags >= 0
                                              AND payload_flags <= 4294967295),
    provider_body_blake3 bytea CHECK (provider_body_blake3 IS NULL
                                      OR octet_length(provider_body_blake3) = 32),
    provider_body_size bigint CHECK (provider_body_size IS NULL
                                     OR (provider_body_size >= 0
                                         AND provider_body_size <= 262144)),
    provider_claim_fence bigint CHECK (provider_claim_fence IS NULL
                                       OR provider_claim_fence >= 1),
    fence         bigint      NOT NULL CHECK (fence >= 1),
    validated_at  timestamptz,
    disposition   smallint    NOT NULL DEFAULT 0 CHECK (disposition IN (0, 1, 2)),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (hash, epoch),
    CONSTRAINT lore_fragment_epoch_provider_body_shape CHECK (
        (provider_body_blake3 IS NULL) = (provider_body_size IS NULL)
        AND (provider_body_blake3 IS NULL) = (provider_claim_fence IS NULL)
    )
);

-- Association: binds (FragmentId, repository, context). It never binds a
-- physical fragment epoch, so a repair that changes the representation leaves
-- every association untouched, and reads always resolve through the head.
CREATE TABLE IF NOT EXISTS lore_fragment_associations (
    hash                  bytea       NOT NULL,
    repository_id         bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    context               bytea       NOT NULL,
    association_epoch     bigint      NOT NULL CHECK (association_epoch >= 1),
    state                 smallint    NOT NULL CHECK (state IN (0, 1)),
    repository_generation bigint      NOT NULL CHECK (repository_generation >= 1),
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (hash, repository_id, context)
);

-- Inverts the leading column so a whole repository's association set is
-- reachable without a sequential scan (the CR-016 stats read's access path).
CREATE INDEX IF NOT EXISTS lore_fragment_associations_repository
    ON lore_fragment_associations (repository_id, hash);

-- The shared-hash fanout path. A readable/unreadable transition must visit
-- every repository with a LIVE association to that hash, in sorted repository
-- order; this partial index is what makes that set both cheap to take and cheap
-- to MEASURE before mutating, which is the admission bound CR-031 requires.
CREATE INDEX IF NOT EXISTS lore_fragment_associations_live_fanout
    ON lore_fragment_associations (hash, repository_id)
    WHERE state = 0;

-- Epoch-aware, association-aware metering. Repairable data, never existence
-- authority: a missing or stale row degrades a stats answer, it never makes a
-- fragment readable or unreadable.
CREATE TABLE IF NOT EXISTS lore_fragment_lifecycle_metering (
    hash          bytea       NOT NULL PRIMARY KEY,
    epoch         bigint      NOT NULL CHECK (epoch >= 1),
    payload_flags bigint      NOT NULL CHECK (payload_flags >= 0
                                              AND payload_flags <= 4294967295),
    size_payload  bigint      NOT NULL CHECK (size_payload >= 0),
    size_content  bigint      NOT NULL CHECK (size_content >= 0),
    authority     smallint    NOT NULL CHECK (authority IN (1, 2)),
    verified_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Staged-reader lease. Scoped to `Staged` epochs ONLY, because that is the one
-- representation local cleanup can remove out from under a reader. A `Remote`
-- read takes no lease at all and revalidates read-only after byte I/O, which is
-- what keeps the hottest read path free of write amplification (R-SHOULD-6).
--
-- One lease covers a BATCH of fragments for one hydration request; the member
-- table is what makes it a batch rather than a row per 256 KiB read.
CREATE TABLE IF NOT EXISTS lore_fragment_staged_leases (
    lease_id     bytea       NOT NULL PRIMARY KEY CHECK (octet_length(lease_id) = 16),
    reader_fence bigint      NOT NULL CHECK (reader_fence >= 1),
    deadline     timestamptz NOT NULL,
    terminal     boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS lore_fragment_staged_lease_members (
    lease_id bytea  NOT NULL REFERENCES lore_fragment_staged_leases (lease_id) ON DELETE CASCADE,
    hash     bytea  NOT NULL,
    epoch    bigint NOT NULL CHECK (epoch >= 1),
    PRIMARY KEY (lease_id, hash)
);

-- Cleanup reads this to find the live readers of one staged epoch.
CREATE INDEX IF NOT EXISTS lore_fragment_staged_lease_members_epoch
    ON lore_fragment_staged_lease_members (hash, epoch);

-- Expired-lease reaping without a sequential scan over terminal rows.
CREATE INDEX IF NOT EXISTS lore_fragment_staged_leases_deadline
    ON lore_fragment_staged_leases (deadline)
    WHERE terminal = false;

-- Durable per-attempt provider-write claim. The lifecycle head is always
-- locked before a row in this table (both are LockClass::Fragments). A claim
-- binds the exact logical request, attempt, head lineage, object key, and body
-- before any provider I/O. Prepared, Sending, and Ambiguous remain barriers
-- until hard_not_after; Decisive and NoSend are terminal and nonblocking. A
-- provider write always targets Remote authority (2).
CREATE TABLE IF NOT EXISTS lore_fragment_write_claims (
    logical_request_id bytea       NOT NULL CHECK (octet_length(logical_request_id) = 16),
    attempt_id         bytea       NOT NULL CHECK (octet_length(attempt_id) = 16),
    hash               bytea       NOT NULL,
    epoch              bigint      NOT NULL CHECK (epoch >= 1),
    fence              bigint      NOT NULL CHECK (fence >= 1),
    authority          smallint    NOT NULL CHECK (authority = 2),
    object_key         text        NOT NULL CHECK (length(object_key) > 0),
    body_blake3        bytea       NOT NULL CHECK (octet_length(body_blake3) = 32),
    body_size          bigint      NOT NULL CHECK (body_size >= 0 AND body_size <= 262144),
    state              smallint    NOT NULL CHECK (state BETWEEN 0 AND 4),
    send_not_after     timestamptz NOT NULL,
    hard_not_after     timestamptz NOT NULL,
    prepared_at        timestamptz NOT NULL,
    authorized_at      timestamptz,
    settled_at         timestamptz,
    PRIMARY KEY (logical_request_id, attempt_id),
    CONSTRAINT lore_fragment_write_claim_deadline_shape CHECK (
        send_not_after > prepared_at AND hard_not_after > send_not_after
    ),
    CONSTRAINT lore_fragment_write_claim_state_shape CHECK (
        (state = 0 AND authorized_at IS NULL AND settled_at IS NULL)
     OR (state = 1 AND authorized_at IS NOT NULL AND settled_at IS NULL)
     OR (state IN (2, 3) AND authorized_at IS NOT NULL AND settled_at IS NOT NULL)
     OR (state = 4 AND settled_at IS NOT NULL)
    )
);

REVOKE ALL ON TABLE lore_fragment_write_claims FROM PUBLIC;

CREATE INDEX IF NOT EXISTS lore_fragment_write_claims_barrier
    ON lore_fragment_write_claims (hash, epoch, fence, hard_not_after)
    WHERE state IN (0, 1, 3);

CREATE INDEX IF NOT EXISTS lore_fragment_write_claims_terminal_prune
    ON lore_fragment_write_claims (settled_at, logical_request_id, attempt_id)
    WHERE state IN (2, 4);

-- Singleton. Read at boot for readiness, and the cutover marker's home.
--
-- The two CHECKs make the unsafe combinations unrepresentable: routing cannot be
-- enabled without a completed backfill, a classified residue set, the cutover
-- marker, and proved sequence headroom. The typed readiness check is the gate;
-- these are the backstop.
CREATE TABLE IF NOT EXISTS lore_fragment_schema_state (
    id                      smallint    NOT NULL PRIMARY KEY CHECK (id = 1),
    schema_version          bigint      NOT NULL CHECK (schema_version >= 1),
    backfill_version        bigint      NOT NULL CHECK (backfill_version >= 0),
    backfill_state          smallint    NOT NULL CHECK (backfill_state IN (0, 1, 2, 3)),
    backfill_cursor         bytea,
    verified_fragments      bigint      NOT NULL DEFAULT 0 CHECK (verified_fragments >= 0),
    residue_classified      boolean     NOT NULL DEFAULT false,
    cutover_at              timestamptz,
    lifecycle_enabled       boolean     NOT NULL DEFAULT false,
    write_capability        smallint    NOT NULL DEFAULT 0 CHECK (write_capability IN (0, 1)),
    provider_write_authority_revision text,
    write_claims_required_at timestamptz,
    database_identity       text        NOT NULL,
    sequence_headroom_fence bigint      CHECK (sequence_headroom_fence >= 1),
    updated_at              timestamptz NOT NULL,
    CONSTRAINT lore_fragment_schema_cutover_shape CHECK (
        (backfill_state = 3 AND cutover_at IS NOT NULL AND residue_classified
         AND sequence_headroom_fence IS NOT NULL)
        OR (backfill_state <> 3 AND cutover_at IS NULL AND lifecycle_enabled = false)
    ),
    CONSTRAINT lore_fragment_schema_enable_shape CHECK (
        lifecycle_enabled = false
        OR (backfill_state = 3 AND cutover_at IS NOT NULL AND residue_classified
            AND sequence_headroom_fence IS NOT NULL)
    ),
    CONSTRAINT lore_fragment_write_capability_shape CHECK (
        (write_capability = 0 AND provider_write_authority_revision IS NULL
                              AND write_claims_required_at IS NULL)
        OR (write_capability = 1
            AND length(provider_write_authority_revision) BETWEEN 1 AND 64
            AND write_claims_required_at IS NOT NULL)
    )
);

INSERT INTO lore_fragment_schema_state (
    id, schema_version, backfill_version, backfill_state, database_identity, updated_at
)
-- The schema_version literal below is aliased so `seed_schema_version_matches_the_constant`
-- can pin it against FRAGMENT_SCHEMA_VERSION. `bootstrap()` binds the constant, this
-- seed cannot, and parity compares catalog shape rather than row contents -- so without
-- that test a version bump would diverge silently between the two paths (INV-EF P2-9).
SELECT 1                                                                       AS id,
       2                                                                       AS schema_version,
       0                                                                       AS backfill_version,
       0                                                                       AS backfill_state,
       control.system_identifier::text || ':' || database.oid::text || ':' || current_database()
                                                                               AS database_identity,
       clock_timestamp()                                                       AS updated_at
  FROM pg_control_system() AS control
  JOIN pg_database AS database ON database.datname = current_database()
ON CONFLICT (id) DO NOTHING;

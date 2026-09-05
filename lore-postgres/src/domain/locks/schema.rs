// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Migration-owned schema for CR-030's fenced Postgres lock authority.
//!
//! This block is applied with the other domain DDL under the shared boot-time
//! advisory lock. It deliberately does not extend the legacy lock store's
//! self-bootstrap `SCHEMA`: a legacy-only store stays legacy, while a domain
//! coordinator can prove the fenced schema and cutover state before use.

/// First server-only lock-fencing schema revision.
pub const LOCK_SCHEMA_VERSION: i64 = 1;

/// Whether WP-120's public lock mutation contract exists on this build.
///
/// This is the arming gate for fenced routing, and it is deliberately a
/// compile-time constant rather than configuration: no operator action may
/// reach the armed state before the code that makes it serviceable exists.
///
/// # Why this is now `true`
///
/// WP-120 (2026-09-04) built the SERVER half.
/// `lore-server/src/grpc/lock_service.rs` routes all three mutations through
/// [`crate::domain::locks::PostgresLockCoordinator`]: `Lock` and `AdminLock`
/// return each row's 32-byte ownership token to the caller that acquired it,
/// `Unlock` requires that token and reaches `release`, and the `ForceUnlock` RPC
/// reaches `force_release`, which deliberately does **not** require a token so
/// an administrator can always clear a row.
///
/// The follow-on lane (2026-09-05) built the CLIENT half, which is what this
/// constant was waiting for. `lore-revision/src/attempt_store.rs` gives the CLI
/// and the embedding library a durable `AttemptStore` in the repository's
/// `.lore/` directory; `lore lock acquire` records every token the server issues
/// before it reports success, and presents a stored one when it re-locks a row
/// it already holds; `lore lock release` presents the stored token per resource
/// and clears it only on a confirmed release. The desktop injects its own
/// implementation of the same trait over the journal it already keeps.
///
/// So an armed cell's `Unlock` now arrives carrying the token the acquire was
/// issued, which is the property whose absence this constant guarded: the
/// INV-EE P0-2 shape of a lock nobody but an administrator can release.
///
/// One thing the flip does **not** claim. A client that predates the token
/// contract — a stock upstream build, or an older fork build — still sends no
/// token, and its `Unlock` is refused on an armed cell with a message naming
/// `ForceUnlock` as the remedy. That is a version floor for a cell an operator
/// chooses to arm, not a residual defect: the refusal is decisive, it happens
/// before any mutation, and it names what to do.
///
/// # The residual this flip does not close
///
/// BLOCKED(WP-120): a **cutover-converted** row is not releasable by its own
/// owner even once the client can present tokens.
/// [`crate::domain::locks::PostgresLockCoordinator::backfill`] mints a random
/// `ownership_token` for every legacy row it converts and discards it, so the
/// owner holds nothing to present, and `acquire_or_renew` refuses a tokenless
/// re-acquire over a current row even to that row's own owner. Such a lock can
/// only be cleared through `ForceUnlock` by a principal holding the `migrate`
/// permission.
///
/// The operator precondition for cutover is therefore: **drain live legacy locks
/// first, or expect to force-release them.** `BackfillReport.converted` is the
/// count to watch — a cutover that converted zero rows has no residual at all.
///
/// PIN(WP-120, 2026-09-04): closing it needs a way to record that a converted
/// row's token was never issued, which the `lore_locks_fenced_shape` CHECK below
/// does not admit (it requires exactly 32 bytes whenever the fenced columns are
/// set). A sentinel token value is **not** an option: `token_matches` would
/// accept it from any caller, handing everyone the authority to release every
/// converted lock. That is a SCHEMA-117 amendment plus a CR-030 amendment, both
/// on the owner list, neither frozen here.
///
/// This constant no longer gates that residual, so the operator precondition
/// above is now a **cutover** precondition an operator has to meet, rather than
/// something the build refuses on their behalf.
pub const PUBLIC_MUTATION_CONTRACT_AVAILABLE: bool = true;

/// The reason `enable_fencing` gives while [`PUBLIC_MUTATION_CONTRACT_AVAILABLE`]
/// is false. Named so a test can assert the refusal rather than match prose.
///
/// Kept, and kept accurate, though nothing reaches it on this build. The
/// constant it explains is the arming gate, and a gate whose refusal message was
/// deleted the first time it opened is a gate that cannot be closed again
/// without re-deciding what it should say.
pub const PUBLIC_MUTATION_CONTRACT_MISSING: &str = concat!(
    "fenced lock routing cannot be armed until a client that keeps and presents per-resource ",
    "lock ownership tokens ships: the server half is built, but a released client sends no ",
    "token on Unlock, so every lock on an armed cell would be unreleasable by its owner"
);

/// Backfill has not started.
pub const BACKFILL_NOT_STARTED: i16 = 0;
/// Backfill is resumable but incomplete.
pub const BACKFILL_RUNNING: i16 = 1;
/// Every legacy row is mapped or quarantined and sequence headroom is proved.
pub const BACKFILL_COMPLETE: i16 = 2;

/// Runtime copy of the SCHEMA-117 DDL. Keep byte-for-byte semantics aligned
/// with `migrations/0001_init.sql`.
pub const LOCK_SCHEMA: &str = r#"
-- ---------------------------------------------------------------------------
-- CR-030 fenced lock authority (SCHEMA-117)
-- ---------------------------------------------------------------------------

-- The domain coordinator connects before the legacy lock-store plugin. A
-- fresh cell therefore needs the base table here as well as in the migration.
-- The legacy store's own CREATE TABLE remains unchanged and becomes a no-op.
CREATE TABLE IF NOT EXISTS lore_locks (
    repository bytea  NOT NULL,
    branch     bytea  NOT NULL,
    hash       bytea  NOT NULL,
    owner      text   NOT NULL,
    description text  NOT NULL,
    locked_at  bigint NOT NULL,
    PRIMARY KEY (repository, branch, hash)
);

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
    repository_id             bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    branch_id                 bytea       NOT NULL CHECK (octet_length(branch_id) = 16),
    repository_lock_generation bigint     NOT NULL CHECK (repository_lock_generation >= 1),
    branch_lock_generation    bigint      NOT NULL CHECK (branch_lock_generation >= 1),
    last_applied_fence        bigint      NOT NULL DEFAULT 0 CHECK (last_applied_fence >= 0),
    created_at                timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at                timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, branch_id),
    FOREIGN KEY (repository_id, branch_id)
        REFERENCES lore_domain_branches (repository_id, branch_id)
);

CREATE TABLE IF NOT EXISTS lore_domain_lock_backfill_quarantine (
    repository_id bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    branch_id     bytea       NOT NULL CHECK (octet_length(branch_id) = 16),
    resource_hash bytea       NOT NULL,
    legacy_subject text       NOT NULL,
    reason         text       NOT NULL,
    quarantined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, branch_id, resource_hash)
);

CREATE TABLE IF NOT EXISTS lore_domain_lock_schema_state (
    id                         smallint    NOT NULL PRIMARY KEY CHECK (id = 1),
    schema_version             bigint      NOT NULL CHECK (schema_version >= 1),
    backfill_state             smallint    NOT NULL CHECK (backfill_state IN (0, 1, 2)),
    backfill_cursor            bytea,
    cutover_at                 timestamptz,
    fencing_enabled            boolean     NOT NULL DEFAULT false,
    lease_enabled              boolean     NOT NULL DEFAULT false,
    database_identity          text        NOT NULL,
    sequence_headroom_fence    bigint      CHECK (sequence_headroom_fence >= 1),
    updated_at                 timestamptz NOT NULL,
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

-- Dedicated lock generations move only on lock-identity invalidation. A
-- repository generation-only update is the current obliteration-begin shape;
-- metadata/default-branch changes alter another column and do not invalidate
-- locks. Branch tombstone is the branch invalidation point.
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
"#;

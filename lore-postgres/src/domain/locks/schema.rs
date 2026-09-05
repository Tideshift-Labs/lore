// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Migration-owned schema for CR-030's fenced Postgres lock authority.
//!
//! This block is applied with the other domain DDL under the shared boot-time
//! advisory lock. It deliberately does not extend the legacy lock store's
//! self-bootstrap `SCHEMA`: a legacy-only store stays legacy, while a domain
//! coordinator can prove the fenced schema and cutover state before use.

/// Current server-only lock-fencing schema revision.
///
/// Revision 1 was the WP-117 shape. Revision 2 is CR-030's P-030-3 amendment:
/// `lore_locks.token_never_issued` plus the `lore_locks_fenced_shape_v2` CHECK
/// that admits a cutover-converted row whose token was never issued.
///
/// [`LOCK_SCHEMA`] rolls a revision-1 cell forward in place, so a cell upgrades
/// when that DDL next runs rather than needing a second cutover. The literal in
/// that DDL's seed cannot reference this constant;
/// `tests/domain_migration_parity.rs` pins the two together.
///
/// # Upgrading an ARMED revision-1 cell is a full stop, not a rolling upgrade
///
/// The DDL is migration-owned (CR-030 N-7), so it does not run at ordinary boot,
/// and neither order of operations is safe while both binaries are live:
///
/// * Roll the binary first and an armed revision-1 cell refuses to route fenced
///   traffic, because `resolve_lock_fencing` compares the stored revision to
///   this constant for equality. That refusal is deliberate — this binary must
///   not interpret a shape it predates — but it is a refusal.
/// * Migrate first and the stored revision reads 2, so any revision-1 binary
///   still running hits the same equality from the other side.
///
/// An unarmed cell has neither problem: it routes legacy throughout, and
/// `readiness` probes for the new column rather than naming it, so a revision-1
/// database answers instead of failing the statement. Since no production cell
/// is armed today, that is the path every cell actually takes. An operator
/// arming a cell that is already armed at revision 1 stops it, migrates, and
/// starts it.
pub const LOCK_SCHEMA_VERSION: i64 = 2;

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
/// # The cutover residual, and how revision 2 records it
///
/// A **cutover-converted** row was never releasable by its own owner, even once
/// the client could present tokens.
/// [`crate::domain::locks::PostgresLockCoordinator::backfill`] used to mint a
/// random `ownership_token` for every legacy row it converted and then discard
/// it, so the owner held nothing to present, and `acquire_or_renew` refuses a
/// tokenless re-acquire over a current row even to that row's own owner. Nobody
/// at all held those tokens.
///
/// PIN(CR-030 P-030-3, 2026-09-05): that is now recorded as an **explicit
/// absence** rather than as a value nobody holds. `backfill` writes
/// `ownership_token = NULL` together with `token_never_issued = true`, a
/// combination `lore_locks_fenced_shape_v2` below admits and admits only in that
/// pairing: a fenced row is either a 32-byte token with the flag false, or a
/// NULL token with the flag true, never anything else. `token_matches` refuses
/// **every** caller on such a row, so it stays unreleasable by possession, and
/// `acquire_or_renew` refuses a re-acquire over it whether or not the caller
/// offers a token. On an ARMED cell the tokenless, `owner`-gated `ForceUnlock`
/// is then the only way to clear one, which is what it was before — the change
/// is that the row now says so instead of implying it through a token that
/// exists and matches nothing.
///
/// "On an armed cell" is a real qualifier, not throat-clearing. Between
/// `backfill` and `arm_fenced_routing` a cell still routes every lock RPC to the
/// legacy store (`crate::store::lock_store`), which matches on the row's plain
/// `owner` text and knows nothing about tokens, so in that window a converted
/// row is releasable the ordinary way. That is unchanged by this amendment and
/// is not a hole in it — it is the same window in which the legacy store is the
/// authority for every lock on the cell — but a claim that only an
/// administrator can *ever* clear such a row would be false there.
///
/// A **sentinel token value** stays refused by design, and this is the reason
/// the encoding is an absence rather than a reserved constant: `token_matches`
/// would accept a sentinel from any caller, handing everyone the authority to
/// release every converted lock.
///
/// The operator precondition for cutover is unchanged and is still worth
/// meeting: **drain live legacy locks first, or expect to force-release them.**
/// `BackfillReport.converted` is the count to watch, and a cutover that
/// converted zero rows has no residual at all. What revision 2 adds is that the
/// residual is now countable after the fact —
/// `LockFencingReadiness::never_issued_token_rows`, which `loreserver domain
/// status` prints — rather than being indistinguishable from an ordinary held
/// lock.
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
    ADD COLUMN IF NOT EXISTS expires_at timestamptz,
    -- Schema revision 2 (CR-030 P-030-3). True only on a cutover-converted row
    -- whose ownership token was never issued to anybody. Paired with a NULL
    -- `ownership_token` by `lore_locks_fenced_shape_v2` below, so the absence is
    -- recorded rather than encoded as a sentinel value any caller could present.
    ADD COLUMN IF NOT EXISTS token_never_issued boolean NOT NULL DEFAULT false;

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
    -- Schema revision 2 replaces the revision-1 shape in place. Dropping first
    -- is what makes an already-armed cell upgrade on its next boot instead of
    -- keeping a constraint that forbids the very row `backfill` now writes.
    -- Both statements are guarded on the catalog, so re-running this DDL over an
    -- already-upgraded cell does nothing, and only the first boot after the
    -- upgrade pays the ADD CONSTRAINT validation scan. That scan holds ACCESS
    -- EXCLUSIVE on `lore_locks` for its duration, which is the same cost the
    -- revision-1 constraint already paid on a fresh cell; `lore_locks` holds one
    -- row per held lock, not per object, so the scan is bounded by how many
    -- locks the cell is holding rather than by its content.
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'lore_locks_fenced_shape'
    ) THEN
        ALTER TABLE lore_locks DROP CONSTRAINT lore_locks_fenced_shape;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'lore_locks_fenced_shape_v2'
    ) THEN
        ALTER TABLE lore_locks ADD CONSTRAINT lore_locks_fenced_shape_v2 CHECK (
            (repository_lock_generation IS NULL
             AND branch_lock_generation IS NULL
             AND owner_issuer IS NULL AND owner_subject IS NULL
             AND acting_issuer IS NULL AND acting_subject IS NULL
             AND ownership_token IS NULL AND fence IS NULL
             AND acquired_at IS NULL AND renewed_at IS NULL AND expires_at IS NULL
             AND token_never_issued = false)
         OR (repository_lock_generation IS NOT NULL AND repository_lock_generation >= 1
             AND branch_lock_generation IS NOT NULL AND branch_lock_generation >= 1
             AND owner_issuer IS NOT NULL AND owner_subject IS NOT NULL
             -- The explicit IS NOT NULL is load-bearing, not redundant with the
             -- width test beside it. `octet_length(NULL) = 32` is NULL, not
             -- false, so without it a row with the flag clear and no token makes
             -- the whole CHECK evaluate to NULL -- which a CHECK constraint
             -- ADMITS. The revision-1 shape had the same hole; it only became
             -- reachable once a NULL token stopped meaning "legacy row".
             AND ((token_never_issued = false
                   AND ownership_token IS NOT NULL
                   AND octet_length(ownership_token) = 32)
               OR (token_never_issued = true AND ownership_token IS NULL))
             -- Same three-valued-logic hazard as the token width above, and the
             -- same fix: `NULL >= 1` is NULL, so a fenced row with a NULL fence
             -- or a NULL generation made this arm NULL and the CHECK admitted
             -- it. Every reader fails closed on such a row, so this closes a
             -- representable-but-unreachable state rather than a live defect --
             -- which is the point, because CR-030's whole shape argument is that
             -- an illegal row should be unrepresentable, not merely unreached.
             AND fence IS NOT NULL AND fence >= 1
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
-- The schema_version literal below is aliased so a parity test can pin it
-- against LOCK_SCHEMA_VERSION. This seed is raw SQL and cannot reference the
-- constant, and the migration/runtime parity gate compares catalog shape rather
-- than row contents -- so without that pin a version bump would diverge
-- silently between the two paths.
SELECT 1                                                                       AS id,
       2                                                                       AS schema_version,
       0                                                                       AS backfill_state,
       control.system_identifier::text || ':' || database.oid::text || ':' || current_database()
                                                                               AS database_identity,
       clock_timestamp()                                                       AS updated_at
  FROM pg_control_system() AS control
  JOIN pg_database AS database ON database.datname = current_database()
ON CONFLICT (id) DO NOTHING;

-- Roll a revision-1 cell forward in place. The DDL above has already installed
-- the revision-2 shape by the time this runs, so the row is recording what the
-- database now is rather than promising a later step. `arm_fenced_routing`
-- compares this value to the compiled constant for equality, so an already-armed
-- revision-1 cell would refuse a re-arm without this.
UPDATE lore_domain_lock_schema_state
   SET schema_version = 2, updated_at = clock_timestamp()
 WHERE id = 1 AND schema_version < 2;

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

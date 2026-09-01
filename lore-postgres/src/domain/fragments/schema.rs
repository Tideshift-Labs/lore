// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Migration-owned schema for CR-031's fragment lifecycle authority (SCHEMA-118).
//!
//! This block is applied with the other domain DDL under the shared boot-time
//! advisory lock. It deliberately does **not** extend the legacy immutable
//! store's self-bootstrap `SCHEMA` (`store/immutable_store.rs`): a legacy-only
//! store stays legacy and keeps answering from `lore_fragments` plus
//! `lore_fragment_state`, while a cell that has been migrated can prove its
//! schema, cutover state, and sequence headroom before the coordinator routes
//! anything through it.
//!
//! Two declarations, one shape. As with CR-029's `domain/schema.rs` and
//! CR-030's `domain/locks/schema.rs`, [`FRAGMENT_SCHEMA`] is applied at boot by
//! [`crate::pool::ensure_schema`] and `migrations/0001_init.sql` carries a
//! byte-equivalent copy for out-of-band provisioning. **A change here is two
//! edits, in one commit**, and `tests/domain_migration_parity.rs` fails the gate
//! if they drift.

/// First server-only fragment lifecycle schema revision. Recorded in
/// `lore_fragment_schema_state.schema_version`; a server whose compiled value is
/// below the stored value refuses to enable lifecycle routing.
pub const FRAGMENT_SCHEMA_VERSION: i64 = 1;

/// Backfill has not begun.
pub const BACKFILL_NOT_STARTED: i16 = 0;
/// Backfill is running; lifecycle routing must stay off.
pub const BACKFILL_RUNNING: i16 = 1;
/// Backfill finished and resolver agreement passed.
pub const BACKFILL_VERIFIED: i16 = 2;
/// Cutover marker set; lifecycle routing may be requested.
pub const BACKFILL_CUTOVER: i16 = 3;

/// Exact byte length of `lore_fragment_staged_leases.lease_id`.
///
/// The DDL below carries the same bound as `octet_length(lease_id) = 16`. This
/// constant exists so the coordinator can refuse a wrong-length id as typed
/// [`crate::domain::errors::DomainError::InvalidInput`] **before** any database
/// work, rather than letting the CHECK surface a bare 23514 the caller cannot
/// act on (INV-EF P2-6). `the_staged_lease_id_length_matches_the_schema_check`
/// pins the two together.
pub const STAGED_LEASE_ID_LEN: usize = 16;

/// `lore_fragment_associations.state`: the association is live and readable.
pub const ASSOCIATION_LIVE: i16 = 0;
/// `lore_fragment_associations.state`: tombstoned.
///
/// The **epoch** is never revived: a later bind of the same triple takes a
/// greater association epoch, so no reader can be handed a stale one. The
/// **row** is reused in place — `create_association` upserts
/// `ON CONFLICT (hash, repository_id, context) DO UPDATE`, flipping the state
/// back to live under the new epoch rather than inserting a second row. An
/// earlier version of this comment said "never revived" without that
/// distinction, which described the row rule as something the code does not do
/// (INV-EF P2-10).
pub const ASSOCIATION_TOMBSTONED: i16 = 1;

/// `lore_fragment_epochs.authority`: a finalized durable staged file plus its
/// committed manifest is representation authority.
pub const AUTHORITY_STAGED: i16 = 1;
/// `lore_fragment_epochs.authority`: the exact immutable provider object named
/// by the manifest, with validated metadata, is representation authority.
pub const AUTHORITY_REMOTE: i16 = 2;

/// `lore_fragment_epochs.disposition`: eligible to be the current epoch.
pub const DISPOSITION_CURRENT_ELIGIBLE: i16 = 0;
/// `lore_fragment_epochs.disposition`: superseded by a repair successor. Retained
/// as evidence, never revived, and reclaimable only by a later GC package.
pub const DISPOSITION_QUARANTINED: i16 = 1;
/// `lore_fragment_epochs.disposition`: physical bytes are proved gone.
pub const DISPOSITION_PURGED: i16 = 2;

/// `lore_fragment_lifecycle.diagnostic_class`: no diagnosis recorded.
pub const DIAGNOSTIC_NONE: i16 = 0;
/// The expected authority was observed absent.
pub const DIAGNOSTIC_ABSENT: i16 = 1;
/// The expected authority was present but truncated.
pub const DIAGNOSTIC_TRUNCATED: i16 = 2;
/// The expected authority was present, whole, and did not match its manifest.
pub const DIAGNOSTIC_CORRUPT: i16 = 3;
/// Structural validation of the stored representation failed.
pub const DIAGNOSTIC_INVALID_STRUCTURE: i16 = 4;
/// The representation uses a defined compressor this build cannot decode, so it
/// is unrepairable **here** rather than corrupt. A cell built without the
/// `oodle` feature reports this for a legacy Oodle2 object (CR-031 R-SHOULD-9);
/// it is deliberately distinct from [`DIAGNOSTIC_CORRUPT`] because the remedy is
/// a differently-built binary, not a repair.
pub const DIAGNOSTIC_UNREPAIRABLE_ENCODING: i16 = 5;

/// The relations whose presence decides whether SCHEMA-118 reached a database.
///
/// A relation-level probe, not a schema check. It exists only to separate "the
/// migration never ran here" from "it ran and something is missing". The
/// columns, indexes, and constraints [`FRAGMENT_SCHEMA`] also installs fail
/// closed on their own — a missing column is SQLSTATE 42703 out of the readiness
/// query itself.
///
/// The legacy CR-007 tables (`lore_fragments`, `lore_fragment_state`,
/// `lore_fragment_metering`) are deliberately excluded: the immutable store
/// self-bootstraps them, so they exist on every Postgres-mode cell and their
/// presence proves nothing about this migration.
pub const FRAGMENT_SCHEMA_RELATIONS: [&str; 7] = [
    "lore_fragment_lifecycle",
    "lore_fragment_epochs",
    "lore_fragment_associations",
    "lore_fragment_lifecycle_metering",
    "lore_fragment_staged_leases",
    "lore_fragment_staged_lease_members",
    "lore_fragment_schema_state",
];

/// Runtime copy of the SCHEMA-118 DDL. Keep byte-for-byte semantics aligned
/// with `migrations/0001_init.sql`.
pub const FRAGMENT_SCHEMA: &str = r#"
-- ---------------------------------------------------------------------------
-- CR-031 fragment lifecycle authority (SCHEMA-118)
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
    fence         bigint      NOT NULL CHECK (fence >= 1),
    validated_at  timestamptz,
    disposition   smallint    NOT NULL DEFAULT 0 CHECK (disposition IN (0, 1, 2)),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (hash, epoch)
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
       1                                                                       AS schema_version,
       0                                                                       AS backfill_version,
       0                                                                       AS backfill_state,
       control.system_identifier::text || ':' || database.oid::text || ':' || current_database()
                                                                               AS database_identity,
       clock_timestamp()                                                       AS updated_at
  FROM pg_control_system() AS control
  JOIN pg_database AS database ON database.datname = current_database()
ON CONFLICT (id) DO NOTHING;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// Two paths write `lore_fragment_schema_state.schema_version` and only one
    /// of them can reference the constant: `bootstrap()` binds
    /// [`FRAGMENT_SCHEMA_VERSION`], while the seed inside [`FRAGMENT_SCHEMA`] is
    /// raw SQL with a literal. The migration/runtime parity test compares
    /// catalog *shape*, not row contents, so nothing else would notice a bump
    /// applied to one and not the other (INV-EF P2-9).
    /// Pull the aliased `schema_version` literal out of one DDL body.
    fn seeded_schema_version(ddl: &str, source: &str) -> i64 {
        let line = ddl
            .lines()
            .find(|line| line.contains("AS schema_version"))
            .unwrap_or_else(|| {
                panic!("{source} must alias its schema_version literal so this test can find it")
            });
        line.split_whitespace()
            .next()
            .and_then(|token| token.parse().ok())
            .unwrap_or_else(|| {
                panic!("{source}'s aliased schema_version column must lead with an integer literal")
            })
    }

    #[test]
    fn seed_schema_version_matches_the_constant() {
        let literal = seeded_schema_version(FRAGMENT_SCHEMA, "the FRAGMENT_SCHEMA seed");
        assert_eq!(
            literal, FRAGMENT_SCHEMA_VERSION,
            "the FRAGMENT_SCHEMA seed writes schema_version {literal} but bootstrap() binds \
             FRAGMENT_SCHEMA_VERSION = {FRAGMENT_SCHEMA_VERSION}; bump both or neither"
        );
    }

    /// The Rust-side pin above is only half the guard.
    ///
    /// **Three** places carry this version: `bootstrap()` binds the constant,
    /// [`FRAGMENT_SCHEMA`] seeds a literal, and `migrations/0001_init.sql`
    /// carries its own copy of that seed. Migration/runtime parity compares
    /// catalog *shape*, not row contents, so a bump applied to the Rust const
    /// alone would still diverge from the migration silently — which is the
    /// risk INV-EF P2-9 actually named, and which pinning only the const leaves
    /// open.
    #[test]
    fn the_migration_seeds_the_same_schema_version_as_the_runtime_const() {
        let migration = include_str!("../../../migrations/0001_init.sql");
        assert_eq!(
            seeded_schema_version(migration, "migrations/0001_init.sql"),
            FRAGMENT_SCHEMA_VERSION,
            "the migration's fragment schema-state seed has drifted from \
             FRAGMENT_SCHEMA_VERSION; a schema change is two edits in one commit"
        );
    }

    /// [`STAGED_LEASE_ID_LEN`] and the DDL's `octet_length(lease_id) = 16`
    /// CHECK are the same bound written twice: the Rust side turns a
    /// wrong-length id into typed `InvalidInput` before any database work, and
    /// the CHECK is the backstop for anything that reaches the table another
    /// way. Drift between them would let the Rust guard admit an id the
    /// database then refuses with a bare 23514, which is exactly the shape
    /// INV-EF P2-6 flagged.
    #[test]
    fn the_staged_lease_id_length_matches_the_schema_check() {
        let expected = format!("octet_length(lease_id) = {STAGED_LEASE_ID_LEN}");
        assert!(
            FRAGMENT_SCHEMA.contains(&expected),
            "FRAGMENT_SCHEMA must carry `{expected}`; STAGED_LEASE_ID_LEN and the CHECK have drifted"
        );
        let migration = include_str!("../../../migrations/0001_init.sql");
        assert!(
            migration.contains(&expected),
            "migrations/0001_init.sql must carry `{expected}` too; a schema change is two edits \
             in one commit"
        );
    }

    #[test]
    fn the_probe_array_holds_every_fragment_table_and_no_sequence() {
        // The fence sequence is deliberately outside the array: `to_regclass`
        // would find it, but presence of a sequence says nothing about whether
        // the tables installed. Miscounting this is what INV-EF P2-13 caught in
        // the skill's prose.
        assert_eq!(FRAGMENT_SCHEMA_RELATIONS.len(), 7);
        assert!(
            !FRAGMENT_SCHEMA_RELATIONS.contains(&"lore_fragment_fence_seq"),
            "the fence sequence must stay out of the relation-presence probe"
        );
        for relation in FRAGMENT_SCHEMA_RELATIONS {
            assert!(
                FRAGMENT_SCHEMA.contains(relation),
                "{relation} is probed for but never created by FRAGMENT_SCHEMA"
            );
        }
    }
}

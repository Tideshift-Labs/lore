// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032 outbox schema — the base plus `SCHEMA-119`'s relay and Step C
//! extensions.
//!
//! F-032-2 froze the split: WP-116 landed `Outbox event` and `Outbox schema
//! state`; `Relay claim`, `Publication result`, `Dead letter`, and
//! `Receiver membership projection` were WP-119's at `SCHEMA-119`. All four are
//! now here — the claim and publication result as columns on the same event
//! row, the dead letter as its own table, and the membership projection as
//! Step C's four tables: the per-cell counters, one row per receiver
//! generation, the checkpoint vector, and the reset evidence that fences a
//! cell.
//!
//! Both declarations of this schema must stay in lockstep:
//! [`OUTBOX_SCHEMA`] is the boot-time path and
//! `lore-postgres/migrations/0001_init.sql` is the out-of-band provisioning
//! path. `tests/domain_migration_parity.rs` compares the catalogs they produce.
//!
//! Two field decisions are F-032-2's, recorded there and repeated here because
//! they look like over-reach at this distance and are not:
//!
//! * `retention_policy_version` was created **inert and unset** even though
//!   retention policy is WP-119-owned. `lore-postgres` applies schema through
//!   boot-time DDL inside a transaction, so a second DDL pass over a populated
//!   cell is the expensive option; adding the column once avoided it. Step C
//!   gives it a meaning ([`RETENTION_POLICY_VERSION`]) and
//!   [`super::stamp_cutover`] writes it, so it is no longer inert.
//! * `consumer_safe` is in the state enum from the first migration even though
//!   only WP-119 can ever set it, because the alternative is a type change on a
//!   populated table for no benefit.

/// Base outbox API/schema version. Version 1 was WP-116's
/// `OUTBOX-BASE-API-READY` handoff; version 2 is `SCHEMA-119` Step A's in-place
/// relay extension (claim, publication result, dead letter) plus the typed
/// [`super::AggregateVersion`] encoding; version 3 is Step C's receiver
/// membership, checkpoint vector, and reset-generation tables.
///
/// `PostgresDomainStore::ensure_state_rows` seeds all three compatibility
/// floors from this constant on a *fresh* cell, so a fresh cell's
/// `relay_compat_floor` is 3. An already-provisioned cell keeps the floor it was
/// seeded with (the insert is `ON CONFLICT DO NOTHING`), which may be 1 or 2.
pub const OUTBOX_BASE_API_VERSION: i32 = 3;

/// The relay contract version this build implements.
///
/// Deliberately the same number as [`OUTBOX_BASE_API_VERSION`], because the
/// schema-state singleton seeds `relay_compat_floor` from that constant and a
/// relay whose own version were lower than the floor its own boot wrote would
/// refuse to start on a cell it just provisioned.
pub const OUTBOX_RELAY_SCHEMA_VERSION: i32 = 3;

/// The retention policy version this build implements, stamped onto
/// `lore_outbox_schema_state.retention_policy_version` at cutover.
///
/// The column was created inert by F-032-2 with its semantics deferred to
/// `SCHEMA-119`. Version 1 is CR-032's initial policy, unchanged from the CR:
/// consumer-safe rows are reapable only after
/// [`super::prune::MIN_RETENTION_AGE`] *and* a checkpoint vector proving every
/// required current receiver generation safe; dead letters are retained at
/// least [`super::prune::MIN_DEAD_LETTER_RETENTION`] and never leave without an
/// operator disposition; pending rows are never age-pruned.
pub const RETENTION_POLICY_VERSION: i32 = 1;

/// Whether this build's relay may run against a cell whose schema-state row
/// carries `relay_compat_floor`.
///
/// A floor is the *minimum* contract version every participant must speak, so
/// the test is `implemented >= floor`. A build older than the floor must refuse
/// rather than publish under a contract it does not implement; a build newer
/// than the floor is compatible, which is what lets an upgraded cell (floor 1
/// or 2) run this relay (version 3).
pub const fn relay_is_compatible(relay_compat_floor: i32) -> bool {
    OUTBOX_RELAY_SCHEMA_VERSION >= relay_compat_floor
}

/// Hard cap on `lore_outbox_events.payload`, frozen by F-032-2. The payload
/// carries identity/version data a consumer needs in order to invalidate or
/// refetch — never repository content.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// A row created by a mutation transaction. The only state WP-116 can write.
pub const OUTBOX_STATE_PENDING: &str = "pending";
/// Set by WP-119's gateway acknowledgement. Never written by this package.
pub const OUTBOX_STATE_BROKER_ACCEPTED: &str = "broker_accepted";
/// Set by WP-119's bounded evaluator ([`super::evaluator`]) once the event's
/// broker sequence is at or below every required current receiver generation's
/// contiguous acknowledgement frontier, under one membership snapshot version.
/// Never inferred from a broker acknowledgement.
pub const OUTBOX_STATE_CONSUMER_SAFE: &str = "consumer_safe";

/// Domain separator for the `idempotency_key` BLAKE3 tuple. Versioned so a later
/// tuple change is a new key space rather than a silent collision.
pub const IDEMPOTENCY_KEY_DOMAIN_V1: &[u8] = b"lore-outbox-idempotency-v1\0";

// ---------------------------------------------------------------------------
// Frozen widths from the notification-plane contract (SCHEMA-119)
// ---------------------------------------------------------------------------
//
// `lorehub/docs/contracts/lore-notification-plane.md` pins these as *widths*
// (amendment A-13 defers the value sets, not the bounds), and the envelope's
// size accounting is derived from them. A producer whose field exceeds one of
// these would be appended here and then be unpublishable at the gateway, so the
// bound belongs at append time.

/// `cell_id`, at most 63 characters (contract, subject grammar and envelope
/// size accounting; amendment A-8).
///
/// The `cell_id` is not only an envelope field — it is a **subject token**:
/// every subject is `lore.v1.cell.<cell_id>.repo.<repository_hex>.<class>`. A
/// value carrying a `.`, a space, or a wildcard would not merely be invalid,
/// it would restructure the subject, so the contract pins the charset as well
/// as the width and [`is_valid_cell_id`] enforces both.
pub const MAX_CELL_ID_BYTES: usize = 63;

/// Whether `cell_id` matches the contract's pinned
/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$` and fits [`MAX_CELL_ID_BYTES`].
///
/// Hand-written rather than a regex: the pattern is a DNS label, the crate has
/// no regex dependency, and adding one to check seven bytes of grammar is not
/// a trade worth making.
pub fn is_valid_cell_id(cell_id: &str) -> bool {
    if cell_id.is_empty() || cell_id.len() > MAX_CELL_ID_BYTES {
        return false;
    }
    // ASCII-only by construction: every permitted byte is ASCII, so a
    // multi-byte character fails the `is_ascii_*` tests rather than slipping
    // through a char-count/byte-count mismatch.
    let bytes = cell_id.as_bytes();
    let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    if !alphanumeric(first) || !alphanumeric(last) {
        return false;
    }
    bytes.iter().all(|&b| alphanumeric(b) || b == b'-')
}

/// `event_kind`, at most 64 UTF-8 bytes (contract, DURABLE_INVALIDATION body).
/// The base `CREATE TABLE` declares `event_kind text` with no width CHECK, so
/// this is enforced in `validate()` only.
pub const MAX_EVENT_KIND_BYTES: usize = 64;
/// `aggregate_kind`, at most 64 UTF-8 bytes (contract, same body). Also
/// enforced in `validate()` only.
pub const MAX_AGGREGATE_KIND_BYTES: usize = 64;

/// `claim_owner`, matching the schema CHECK. A relay worker identity, not an
/// actor or a repository.
pub const MAX_CLAIM_OWNER_BYTES: usize = 128;
/// `last_error_class`, matching the schema CHECK. A bounded classification, not
/// a message.
pub const MAX_ERROR_CLASS_BYTES: usize = 64;
/// `stream_identity`, matching the schema CHECK.
pub const MAX_STREAM_IDENTITY_BYTES: usize = 128;
/// `gateway_response_id`, matching the schema CHECK.
pub const MAX_GATEWAY_RESPONSE_ID_BYTES: usize = 128;
/// `terminal_class` on a dead letter, matching the schema CHECK.
pub const MAX_TERMINAL_CLASS_BYTES: usize = 64;
/// `disposition_reason` on a dead letter, matching the schema CHECK.
pub const MAX_DISPOSITION_REASON_BYTES: usize = 1024;
/// `disposition_actor` on a dead letter, matching the schema CHECK.
pub const MAX_DISPOSITION_ACTOR_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// Step C: receiver membership, checkpoints, and reset generations
// ---------------------------------------------------------------------------

/// A receiver generation that has been allocated but is not yet ready. It may
/// or may not have captured its position; it has certainly not proved a
/// baseline and drained.
pub const MEMBERSHIP_STATE_JOINING: &str = "joining";
/// A receiver generation that captured a position, took an authoritative
/// baseline, drained from that position, and passed the readiness
/// compare-and-set against the cell's current stream identity and epoch. Only
/// these count toward consumer safety.
pub const MEMBERSHIP_STATE_READY: &str = "ready";
/// A ready generation that is shutting down. Still required, because it is
/// still consuming; it retires only after its final checkpoint.
pub const MEMBERSHIP_STATE_DRAINING: &str = "draining";
/// A generation that no longer participates. A retired generation cannot
/// checkpoint, cannot advance readiness, and can never satisfy its successor's
/// requirement.
pub const MEMBERSHIP_STATE_RETIRED: &str = "retired";
/// The reset fence's stand-in for a replacement that has not joined yet.
///
/// It exists so the required set is never empty during a reset. An empty
/// required set must never read as "everyone is caught up", and this row makes
/// that impossible by construction rather than by a rule the evaluator has to
/// remember.
pub const MEMBERSHIP_STATE_REQUIRED_PLACEHOLDER: &str = "required_placeholder";

/// The reserved `receiver_identity` of the reset fence's placeholder row.
pub const REQUIRED_REPLACEMENT_PLACEHOLDER: &str = "required-replacement-placeholder";
/// The reserved `membership_generation` of that placeholder row. Every real
/// generation is 1 or greater.
pub const PLACEHOLDER_GENERATION: i64 = 0;

/// A reset that has been accepted and whose replacement generation has not yet
/// proved itself. While one exists, `consumer_safe` advancement and pruning
/// fail for that cell even when ordinary membership is empty.
pub const RESET_STATE_IN_PROGRESS: &str = "reset_in_progress";
/// A reset whose required replacement generation persisted a fresh baseline
/// checkpoint and passed readiness compare-and-set at the new epoch.
pub const RESET_STATE_CLEARED: &str = "cleared";

/// `receiver_identity`, matching the schema CHECK on both the membership and
/// checkpoint tables.
pub const MAX_RECEIVER_IDENTITY_BYTES: usize = 128;
/// `detection_id`, matching the schema CHECK. A UUID in its 36-character
/// hyphenated form fits with room to spare; the bound is the contract's
/// `evidence_id` width reused, not a UUID length.
pub const MAX_DETECTION_ID_BYTES: usize = 64;
/// `evidence_id`, "at most 64 characters" in the notification-plane contract.
pub const MAX_EVIDENCE_ID_BYTES: usize = 64;
/// `broker_reset_identity`, matching the schema CHECK.
pub const MAX_BROKER_RESET_IDENTITY_BYTES: usize = 256;
/// The authenticated emitter principal, matching the schema CHECK.
pub const MAX_EMITTER_IDENTITY_BYTES: usize = 256;
/// The stored `StreamResetAckV1` bytes, matching the schema CHECK. The ack has
/// seven small scalar fields, so this is two orders of magnitude of headroom
/// rather than a tight fit.
pub const MAX_RESET_ACK_BYTES: usize = 4096;
/// Explicit unresolved gap ranges or poison dispositions per checkpoint report,
/// matching the schema CHECK on both `gaps` and `poison`.
pub const MAX_CHECKPOINT_BLOCKERS: usize = 256;
/// Serialized size of one blocker array, matching the schema CHECK.
pub const MAX_CHECKPOINT_BLOCKER_BYTES: usize = 16 * 1024;

/// A dead letter awaiting an operator disposition. The state `dead_letter`
/// writes.
pub const DEAD_LETTER_PARKED: &str = "parked";
/// The operator returned the row to `pending` with its original stable keys.
pub const DEAD_LETTER_REQUEUED: &str = "requeued";
/// The operator proved the authoritative state makes the event unnecessary.
/// The evidence row is retained; only the disposition changes.
pub const DEAD_LETTER_OBSOLETE: &str = "obsolete";

/// Outbox base DDL. Idempotent; applied under the shared schema advisory lock.
pub const OUTBOX_SCHEMA: &str = r#"
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
-- Phase 8 operator replay audit (CR-032; WP-119 Phase 8)
--
-- CR-032: "Replay reuses the original event and idempotency keys and records an
-- operator/reason audit field." The audit lives ON the row rather than in a
-- side table, because what an operator needs when they find a pending row that
-- should have published days ago is why it is pending again, and a join they
-- have to remember to write is a fact they will read without.
--
-- `ADD COLUMN IF NOT EXISTS`, never an edit to a `CREATE TABLE IF NOT EXISTS`
-- body: that body is silently skipped on a database that already has the table.
ALTER TABLE lore_outbox_events
    ADD COLUMN IF NOT EXISTS replay_count integer NOT NULL DEFAULT 0
        CHECK (replay_count >= 0),
    ADD COLUMN IF NOT EXISTS replayed_at timestamptz,
    ADD COLUMN IF NOT EXISTS replay_actor text
        CHECK (octet_length(replay_actor) BETWEEN 1 AND 256),
    ADD COLUMN IF NOT EXISTS replay_reason text
        CHECK (octet_length(replay_reason) BETWEEN 1 AND 1024);

DO $outbox_replay_constraints$
BEGIN
    -- The three audit facts are one fact. A row carrying an actor with no
    -- reason, or a replay count with no actor, records that a replay happened
    -- while withholding the half CR-032 actually requires -- and the operator
    -- procedure ends at "clear the event-readiness incident", which needs the
    -- reason to clear it against.
    --
    -- Three pairwise equalities rather than one grouped predicate, for the same
    -- reason `lore_outbox_events_publication_shape` is a CASE: an equality
    -- between two disjunctions is satisfied by a row that sets exactly one
    -- column on each side.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_events_replay_shape'
          AND conrelid = 'lore_outbox_events'::regclass
    ) THEN
        ALTER TABLE lore_outbox_events
            ADD CONSTRAINT lore_outbox_events_replay_shape CHECK (
                (replayed_at IS NULL) = (replay_actor IS NULL)
                AND (replayed_at IS NULL) = (replay_reason IS NULL)
                AND (replayed_at IS NULL) = (replay_count = 0)
            );
    END IF;
END
$outbox_replay_constraints$;

-- The replay window scan: broker-accepted rows for one cell inside CR-032's
-- 24-hour window. Literal predicate, same reason as every other partial index
-- in this schema -- and no non-partial index leads with `broker_accepted_at`,
-- so a bound-parameter spelling of the state falls back to a sequential scan of
-- the whole table.
--
-- `cell_id` leads because every operator command is scoped to the configured
-- cell before it is scoped to anything else, so the equality that can never be
-- absent is the one that should cut the scan first.
CREATE INDEX IF NOT EXISTS lore_outbox_events_replay_window
    ON lore_outbox_events (cell_id, broker_accepted_at, event_id)
    WHERE state = 'broker_accepted';
-- Operator inspection of one repository, scoped to the cell. The base
-- `lore_outbox_events_repository` index leads with `repository_id` and carries
-- no cell, so it answers a producer's own lookup but cannot bound an operator
-- listing to the configured cell without a filter step.
CREATE INDEX IF NOT EXISTS lore_outbox_events_operator_repository
    ON lore_outbox_events (cell_id, repository_id, created_at, event_id);

-- ---------------------------------------------------------------------------
-- Unpublished-since, and the replay audit's survival through a dead letter
-- (CR-032; WP-119 Phase 8, reviewer findings 1 and 2)
--
-- `unpublished_since` is the instant a row entered its CURRENT publication
-- cycle. It is what CR-032's "oldest-unpublished age" actually means, and it is
-- not `created_at`.
--
-- The distinction had no observable effect until Phase 8 gave an operator a way
-- to return a published row to `pending`. A row created seven days ago and
-- replayed one second ago is one second behind, not seven days; measuring from
-- `created_at` made the replay itself report a week-old backlog, which is above
-- both the 30-second readiness threshold and the five-minute admission limit —
-- so the recovery command closed the cell's own write admission the moment it
-- succeeded. Measured on PostgreSQL 16: one replayed row, sole pending row,
-- `oldest_pending_age = 604831s`.
--
-- `available_at` was the tempting existing column and is wrong for this: the
-- retry backoff moves it forward on every failed attempt, so a row that has
-- been failing for hours would report an age near zero and hide exactly the
-- stuck backlog the probe exists to find.
--
-- The `DEFAULT clock_timestamp()` is load-bearing rather than cosmetic. It is
-- evaluated per row on any INSERT that does not name the column, so the
-- producer-side `append()` path and `requeue_dead_letter`'s reinstating
-- `INSERT ... SELECT` both get the correct value without either statement
-- having to know this column exists.
--
-- **This ALTER rewrites the table on a populated cell, and the boot-time
-- `ensure_schema` transaction is where it would run.** `clock_timestamp()` is
-- VOLATILE, and PostgreSQL's add-a-column-with-a-default fast path applies only
-- to a non-volatile default; a volatile one is a full rewrite holding ACCESS
-- EXCLUSIVE. So is the index below, which is built non-CONCURRENTLY because
-- `ensure_schema` runs inside a transaction and cannot do otherwise.
--
-- Both are safe today for the reason the SCHEMA-119 block above records: no
-- outbox row has ever been written in production, so every cell applies this to
-- an empty table. That is a fact about today, not a property of this DDL. If a
-- populated cell ever has to take this migration, do the column and the index
-- out of band first -- the index with CONCURRENTLY, checking
-- `pg_index.indisvalid` afterwards -- and only then roll the binary, exactly as
-- the schema-bootstrap rules for this crate require.
ALTER TABLE lore_outbox_events
    ADD COLUMN IF NOT EXISTS unpublished_since timestamptz NOT NULL
        DEFAULT clock_timestamp();

-- The age probe reads this column, not `created_at`. Partial on the literal
-- `state = 'pending'`, same rule as every other partial index here.
--
-- `lore_outbox_events_pending_created` is deliberately KEPT rather than
-- replaced: it still answers the `created_at, event_id` scan order, and
-- dropping an index inside the boot-time `ensure_schema` transaction is a
-- different and riskier operation than adding one.
CREATE INDEX IF NOT EXISTS lore_outbox_events_pending_unpublished
    ON lore_outbox_events (unpublished_since)
    WHERE state = 'pending';

-- The replay audit follows the event onto the dead-letter table.
--
-- Without these, the audit CR-032 requires is lost on precisely the path an
-- incident review would ask about: a replayed row that then failed terminally
-- copies to `lore_outbox_dead_letters`, and a later requeue reinstates it with
-- `replay_count = 0` and a null actor. Reproduced before the fix.
--
-- The evidence copy is immutable, so these are carried verbatim by
-- `dead_letter` and carried back verbatim by `requeue_dead_letter`; nothing
-- recomputes them.
ALTER TABLE lore_outbox_dead_letters
    ADD COLUMN IF NOT EXISTS replay_count integer NOT NULL DEFAULT 0
        CHECK (replay_count >= 0),
    ADD COLUMN IF NOT EXISTS replayed_at timestamptz,
    ADD COLUMN IF NOT EXISTS replay_actor text
        CHECK (octet_length(replay_actor) BETWEEN 1 AND 256),
    ADD COLUMN IF NOT EXISTS replay_reason text
        CHECK (octet_length(replay_reason) <= 1024);

DO $outbox_dead_letter_replay_constraints$
BEGIN
    -- The same three-way shape the live table carries, for the same reason.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_dead_letters_replay_shape'
          AND conrelid = 'lore_outbox_dead_letters'::regclass
    ) THEN
        ALTER TABLE lore_outbox_dead_letters
            ADD CONSTRAINT lore_outbox_dead_letters_replay_shape CHECK (
                (replayed_at IS NULL) = (replay_actor IS NULL)
                AND (replayed_at IS NULL) = (replay_reason IS NULL)
                AND (replayed_at IS NULL) = (replay_count = 0)
            );
    END IF;
END
$outbox_dead_letter_replay_constraints$;
"#;

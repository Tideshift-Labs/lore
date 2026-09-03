// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032 outbox schema — the base plus `SCHEMA-119`'s relay extension.
//!
//! F-032-2 froze the split: WP-116 landed `Outbox event` and `Outbox schema
//! state`; `Relay claim`, `Publication result`, `Dead letter`, and
//! `Receiver membership projection` were WP-119's at `SCHEMA-119`. Three of
//! those four are now here — the claim and publication result as columns on the
//! same event row, and the dead letter as its own table. The receiver
//! membership/checkpoint projection is Step C and is still absent, so nothing
//! in this crate can yet write `consumer_safe`.
//!
//! Both declarations of this schema must stay in lockstep:
//! [`OUTBOX_SCHEMA`] is the boot-time path and
//! `lore-postgres/migrations/0001_init.sql` is the out-of-band provisioning
//! path. `tests/domain_migration_parity.rs` compares the catalogs they produce.
//!
//! Two field decisions are F-032-2's, recorded there and repeated here because
//! they look like over-reach at this distance and are not:
//!
//! * `retention_policy_version` is created **inert and unset** even though
//!   retention policy is WP-119-owned. `lore-postgres` applies schema through
//!   boot-time DDL inside a transaction, so a second DDL pass over a populated
//!   cell is the expensive option; adding the column once avoids it. Reversible
//!   at `SCHEMA-119` while it is still unset.
//! * `consumer_safe` is in the state enum from the first migration even though
//!   only WP-119 can ever set it, because the alternative is a type change on a
//!   populated table for no benefit.

/// Base outbox API/schema version. Version 1 was WP-116's
/// `OUTBOX-BASE-API-READY` handoff; version 2 is `SCHEMA-119`'s in-place relay
/// extension (claim, publication result, dead letter) plus the typed
/// [`super::AggregateVersion`] encoding.
///
/// `PostgresDomainStore::ensure_state_rows` seeds all three compatibility
/// floors from this constant on a *fresh* cell, so a fresh cell's
/// `relay_compat_floor` is 2. An already-provisioned cell keeps the floor it was
/// seeded with (the insert is `ON CONFLICT DO NOTHING`), which is 1.
pub const OUTBOX_BASE_API_VERSION: i32 = 2;

/// The relay contract version this build implements.
///
/// Deliberately the same number as [`OUTBOX_BASE_API_VERSION`], because the
/// schema-state singleton seeds `relay_compat_floor` from that constant and a
/// relay whose own version were lower than the floor its own boot wrote would
/// refuse to start on a cell it just provisioned.
pub const OUTBOX_RELAY_SCHEMA_VERSION: i32 = 2;

/// Whether this build's relay may run against a cell whose schema-state row
/// carries `relay_compat_floor`.
///
/// A floor is the *minimum* contract version every participant must speak, so
/// the test is `implemented >= floor`. A build older than the floor must refuse
/// rather than publish under a contract it does not implement; a build newer
/// than the floor is compatible, which is what lets an upgraded cell (floor 1)
/// run this relay (version 2).
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
/// Set by WP-119's bounded evaluator. Never written by this package.
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
"#;

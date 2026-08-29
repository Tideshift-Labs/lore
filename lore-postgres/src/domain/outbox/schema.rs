// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032 outbox **base** schema — the two rows WP-116 lands, and only those.
//!
//! F-032-2 freezes the split: WP-116 lands `Outbox event` and `Outbox schema
//! state`. `Relay claim`, `Publication result`, `Dead letter`, and
//! `Receiver membership projection` are WP-119's, landed at `SCHEMA-119`. There
//! is no relay worker in this package, so nothing here ever leaves `pending`.
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

/// Base outbox API/schema version published with `OUTBOX-BASE-API-READY`.
/// WP-117 and WP-118 compile their transaction-local producers against exactly
/// this value; WP-119 accepts ownership of it at `SCHEMA-119` and extends it in
/// place rather than creating a parallel intent store.
pub const OUTBOX_BASE_API_VERSION: i32 = 1;

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
"#;

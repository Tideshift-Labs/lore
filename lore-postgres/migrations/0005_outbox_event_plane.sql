-- SPDX-FileCopyrightText: 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- Event plane mode: the cell marker, its audit log, and the retired-row evidence
-- (notification-plane contract amendment A-32, "Event plane modes").
--
-- This file is the ONLY declaration of these two tables. The boot-time path
-- (`lore_postgres::domain::outbox::event_plane::EVENT_PLANE_SCHEMA`) is an
-- `include_str!` of this file, so the two cannot drift.
--
-- Both tables are new. Every later change to either is an `ALTER`, never an edit
-- inside a `CREATE TABLE IF NOT EXISTS` body: that body is silently skipped on a
-- database that already has the table.

-- One row per plane change for a cell. The marker is the row with the highest
-- `transition_seq`. A cell with no row is `durable`, which is the state every
-- cell was in before this table existed, so an existing cell boots unchanged.
--
-- The table is append-only. Each row is also the audit record of its change:
-- who ordered it, why, and how many outbox rows it retired.
CREATE TABLE IF NOT EXISTS lore_outbox_event_plane_transitions (
    cell_id          text        NOT NULL,
    transition_seq   bigint      NOT NULL CHECK (transition_seq >= 1),
    from_plane       text        NOT NULL CHECK (from_plane IN ('live_only', 'durable')),
    to_plane         text        NOT NULL CHECK (to_plane IN ('live_only', 'durable')),
    actor            text        NOT NULL CHECK (octet_length(actor) BETWEEN 1 AND 256),
    reason           text        NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 1024),
    retired_rows     bigint      NOT NULL CHECK (retired_rows >= 0),
    transitioned_at  timestamptz NOT NULL,

    PRIMARY KEY (cell_id, transition_seq),

    CONSTRAINT lore_outbox_event_plane_transitions_cell_id_shape CHECK (
        cell_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
        AND octet_length(cell_id) <= 63
    ),
    -- A transition changes the plane. A no-op switch writes nothing.
    CONSTRAINT lore_outbox_event_plane_transitions_changes CHECK (from_plane <> to_plane),
    -- Only a switch to live_only retires rows.
    CONSTRAINT lore_outbox_event_plane_transitions_retire_shape CHECK (
        to_plane = 'live_only' OR retired_rows = 0
    )
);

-- The evidence copy of every outbox row a switch to live_only retired.
--
-- A retired row left `lore_outbox_events` in the same transaction that wrote
-- this copy and its transition row. Every identity, payload, publication-result
-- and replay-audit column is carried verbatim. Nothing deletes from this table.
--
-- Only `broker_accepted` and `consumer_safe` rows are retired, so the whole
-- publication result is always present. A `pending` row refuses the switch.
CREATE TABLE IF NOT EXISTS lore_outbox_retired_events (
    event_id                   uuid        NOT NULL PRIMARY KEY,
    cell_id                    text        NOT NULL,
    transition_seq             bigint      NOT NULL,
    idempotency_key            bytea       NOT NULL CHECK (octet_length(idempotency_key) = 32),

    repository_id              bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    repository_generation      bigint      NOT NULL CHECK (repository_generation >= 1),

    event_kind                 text        NOT NULL,
    aggregate_kind             text        NOT NULL,
    aggregate_id               bytea       NOT NULL CHECK (octet_length(aggregate_id) <= 64),
    aggregate_version          bytea       NOT NULL CHECK (octet_length(aggregate_version) <= 256),

    payload_schema_version     integer     NOT NULL CHECK (payload_schema_version >= 1),
    payload                    bytea       NOT NULL CHECK (octet_length(payload) <= 65536),

    state_at_retirement        text        NOT NULL
                                           CHECK (state_at_retirement IN ('broker_accepted', 'consumer_safe')),
    created_at                 timestamptz NOT NULL,
    unpublished_since          timestamptz NOT NULL,
    claim_generation           bigint      NOT NULL CHECK (claim_generation >= 0),
    attempt_count              integer     NOT NULL CHECK (attempt_count >= 0),

    stream_identity            text        NOT NULL CHECK (octet_length(stream_identity) BETWEEN 1 AND 128),
    stream_epoch               bigint      NOT NULL CHECK (stream_epoch >= 1),
    broker_sequence            bigint      NOT NULL CHECK (broker_sequence >= 0),
    gateway_response_id        text        NOT NULL CHECK (octet_length(gateway_response_id) BETWEEN 1 AND 128),
    publisher_contract_version integer     NOT NULL CHECK (publisher_contract_version >= 1),
    broker_accepted_at         timestamptz NOT NULL,

    replay_count               integer     NOT NULL CHECK (replay_count >= 0),
    replayed_at                timestamptz,
    replay_actor               text        CHECK (octet_length(replay_actor) BETWEEN 1 AND 256),
    replay_reason              text        CHECK (octet_length(replay_reason) BETWEEN 1 AND 1024),

    disposition                text        NOT NULL CHECK (disposition = 'retired_live_only'),
    disposition_actor          text        NOT NULL CHECK (octet_length(disposition_actor) BETWEEN 1 AND 256),
    disposition_reason         text        NOT NULL CHECK (octet_length(disposition_reason) BETWEEN 1 AND 1024),
    disposition_at             timestamptz NOT NULL,

    -- Every retired row names the audited transition that retired it.
    CONSTRAINT lore_outbox_retired_events_transition
        FOREIGN KEY (cell_id, transition_seq)
        REFERENCES lore_outbox_event_plane_transitions (cell_id, transition_seq)
);

CREATE INDEX IF NOT EXISTS lore_outbox_retired_events_transition_rows
    ON lore_outbox_retired_events (cell_id, transition_seq);

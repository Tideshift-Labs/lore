-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- WP-115 K11: per-replica stage liveness for `/lb_health`.
--
-- Each `role = "stage"` replica writes a small file to its own mount of the
-- shared stage and counts each write that fully succeeds. It publishes that
-- count here, with a process incarnation id, so a restart starts a new
-- sequence. A replica answers 503 `stage_unavailable_local` only when its own
-- stage is stale and, after it went stale, it saw a peer's count go up.
--
-- The publisher's statement never lowers a stored count, and it accepts a
-- higher one only when the success is recent and the statement runs within
-- the publisher's own timeout. `progressed_at` is the database time of the
-- last accepted increase. So a delayed or replayed statement cannot make old
-- progress look new.
--
-- This file is the ONLY declaration of this table. The boot-time path
-- (`lore_postgres::domain::fragments::STAGE_LIVENESS_SCHEMA`) is an
-- `include_str!` of this file, so the two cannot drift.
--
-- Additive: one new table, no change to any existing relation. A draining
-- replica deletes its row. The publisher deletes rows that have not been
-- published for an hour, so restarts do not grow the table.
CREATE TABLE IF NOT EXISTS lore_domain_write_behind_stage_progress (
    cell_id text NOT NULL,
    replica_id text NOT NULL,
    incarnation text NOT NULL,
    progress bigint NOT NULL,
    progressed_at timestamptz NOT NULL,
    published_at timestamptz NOT NULL,
    PRIMARY KEY (cell_id, replica_id),
    CONSTRAINT lore_domain_write_behind_stage_progress_bounded CHECK (
        octet_length(cell_id) BETWEEN 1 AND 128
        AND octet_length(replica_id) BETWEEN 1 AND 128
        AND octet_length(incarnation) BETWEEN 1 AND 64
        AND progress >= 0
    )
);

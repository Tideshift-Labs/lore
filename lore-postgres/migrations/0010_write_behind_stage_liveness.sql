-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- WP-115 K11: per-replica stage liveness for `/lb_health`.
--
-- Each `role = "stage"` replica writes a small file to its own mount of the
-- shared stage, and publishes here when that last worked. A replica answers
-- 503 `stage_unavailable_local` only when its own stage is stale and at least
-- one peer of the same cell is fresh. "Fresh" is computed in SQL from the
-- database clock, so host clock skew does not matter.
--
-- This file is the ONLY declaration of this table. The boot-time path
-- (`lore_postgres::domain::fragments::STAGE_LIVENESS_SCHEMA`) is an
-- `include_str!` of this file, so the two cannot drift.
--
-- Additive: one new table, no change to any existing relation. A replica that
-- departs stops publishing, so its `last_good_at` ages and it stops counting as
-- a fresh peer. The publisher deletes rows that have not been published for an
-- hour, so restarts do not grow the table.
CREATE TABLE IF NOT EXISTS lore_domain_write_behind_liveness (
    cell_id text NOT NULL,
    replica_id text NOT NULL,
    last_good_at timestamptz NOT NULL,
    published_at timestamptz NOT NULL,
    PRIMARY KEY (cell_id, replica_id),
    CONSTRAINT lore_domain_write_behind_liveness_bounded CHECK (
        octet_length(cell_id) BETWEEN 1 AND 128
        AND octet_length(replica_id) BETWEEN 1 AND 128
    )
);

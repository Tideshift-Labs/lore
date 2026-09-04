-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-114 CD-8 cell-scale retention: the schema edge.
-- Runtime code never installs this artifact. Migration 0024 installs and attests it.
--
-- CR-033 D5 deferred retention migrations 0004 through 0006, and recorded the consequence as a
-- fail-closed activation prerequisite: the cell authority's evidence rows grow with no prune path.
-- CD-8 decided that those three are REPLACED for a cell rather than installed as-is or resized.
-- The rationale belongs with the code that acts on it and is written once, in
-- `src/cell_retention.rs`; this header states only what the decision means for DDL.
--
-- The tables this migration indexes are 0007's, not 0002's. That is the whole point. 0002's four
-- retention tables hold a *global continuity ledger's* full and compact records, and nothing in the
-- cell install set writes `object_dispatch_full_record_ownership` at all. The rows that actually
-- grow without bound in a cell are one `object_dispatch_requests` row per logical request, plus its
-- attempts, spool objects, payload purges and fetch leases, plus one
-- `object_dispatch_provider_charge_grants` row per charged provider attempt.
--
-- This migration adds no table, no column, and no constraint. It adds exactly the four indexes a
-- bounded batch prune needs, and each is here because without it a prune pass degrades to a
-- sequential scan of a table that by construction is the largest one in the schema.
--
-- **Index 1 selects the candidates.** 0007 already carries
-- `object_dispatch_requests_closure_idx (phase, closure_committed_at_unix_ms)`, which is leading on
-- `phase` and therefore serves a per-phase probe rather than one ordered pass over the terminal
-- phases. The prune wants the oldest closed requests across all three terminal phases in one
-- ordered scan, so the partial index inverts that: the phase set moves into the predicate and the
-- closure clock leads the key.
--
-- The predicate is spelled with literal phase values, and the procedure in 0024 spells its own
-- `WHERE` clause the same way, deliberately. The planner uses a partial index only when it can
-- prove the query predicate implies the index predicate, and it can prove that only against
-- literals. `phase = ANY($1)` returns identical rows, passes every live case, and silently plans a
-- sequential scan. See the `lore-postgres` skill's "A partial index is unreachable from a bound
-- parameter under a generic plan"; that crate paid for this lesson on its own terminal-prune index.
--
-- **Indexes 2 and 3 are the foreign-key side, and they are not an optimisation.** Deleting a parent
-- row makes PostgreSQL verify that no child references it, once per referencing constraint and once
-- per deleted row. Without an index whose leading column is one of the child's foreign-key columns,
-- that verification is a sequential scan of the child table, per pruned request. Exactly two child
-- tables lack one today:
--
--   * `object_dispatch_attempts` carries (logical_request_id, attempt_id, attempt_state), which
--     serves the two-column and three-column request foreign keys, but nothing leads with
--     `provider_boundary_id` for the (provider_boundary_id, logical_request_id, attempt_id) one.
--   * `object_dispatch_spool_objects` indexes lifecycle and purge state, never the bound request.
--     Its own primary key leads with (logical_request_id, attempt_id), which serves the prune's
--     delete and its withhold probe; the foreign key is declared on the `bound_request_*` columns,
--     which nothing indexes. Index 3 is for the constraint, not for the delete.
--
-- Three tables already have what they need and deliberately get nothing here.
-- `object_dispatch_fetch_leases` leads its UNIQUE with (logical_request_id, attempt_id);
-- `object_dispatch_provider_charge_grants` leads its budget index with `provider_boundary_id` and
-- its attempt key likewise; and `object_dispatch_payload_purges` already declares
-- `UNIQUE (logical_request_id, attempt_id, payload_kind)`, whose index leads with the two columns
-- the prune keys on. A fourth index on that table was written and removed during review: it would
-- have duplicated that unique index exactly, and the header claim that justified it -- that the
-- purge table "indexes purge state and cell, never the request" -- was simply false.
--
-- 0002 and 0007 are frozen artifacts with pinned digests and are not edited (CR-033 D6 hard rule 1).
-- This migration only adds objects beside them.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE INDEX object_dispatch_requests_cell_retention_idx
  ON object_store_retention.object_dispatch_requests
  (closure_committed_at_unix_ms, logical_request_id, attempt_id)
  WHERE phase IN (5, 6, 7);

CREATE INDEX object_dispatch_attempts_cell_retention_idx
  ON object_store_retention.object_dispatch_attempts
  (provider_boundary_id, logical_request_id, attempt_id);

CREATE INDEX object_dispatch_spool_objects_cell_retention_idx
  ON object_store_retention.object_dispatch_spool_objects
  (bound_request_logical_request_id, bound_request_attempt_id);

COMMIT;

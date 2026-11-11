-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- WP-115 drain guard: a process that reads the shared stage (the drain worker,
-- or a web stage replica) may read a staged file it cannot find as absent, and
-- so mark the fragment Missing, only when the web replica process that staged
-- it is proven to write that reader's own stage directory.
--
-- `lore_domain_write_behind_stagers`: which web replica process (replica id
-- and incarnation) staged each staged representation (hash, epoch). It is
-- written in the same transaction as the stage custody reservation. A
-- representation with no row here (staged by an older binary, by a replica
-- with stage liveness off, or by a full-role replica) is never read as absent
-- by a guarded reader.
--
-- The proof that a stager writes the reader's directory is a challenge and an
-- echo, both FILES under `<stage>/liveness/`, never stored in Postgres (see
-- the "Drain guard" module docs of `lore-server/src/stage_liveness.rs`). The
-- confirmations live in the reader's memory, for its current incarnation
-- only.
--
-- This file is the ONLY declaration of this relation. The boot-time path
-- (`lore_postgres::domain::fragments::DRAIN_GUARD_SCHEMA`) is an
-- `include_str!` of this file. Additive only: one new table, so a binary one
-- revision behind is unaffected. The drain worker prunes stager rows whose
-- representation has no live custody row.
CREATE TABLE IF NOT EXISTS lore_domain_write_behind_stagers (
    hash bytea NOT NULL,
    epoch bigint NOT NULL,
    replica_id text NOT NULL,
    incarnation text NOT NULL,
    PRIMARY KEY (hash, epoch),
    CONSTRAINT lore_domain_write_behind_stagers_bounded CHECK (
        octet_length(hash) = 32
        AND epoch >= 0
        AND octet_length(replica_id) BETWEEN 1 AND 128
        AND octet_length(incarnation) BETWEEN 1 AND 64
    )
);

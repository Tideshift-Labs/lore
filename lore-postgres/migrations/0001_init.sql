-- SPDX-FileCopyrightText: 2026 Epic Games, Inc.
-- SPDX-License-Identifier: MIT
--
-- CR-007 — canonical schema for the off-AWS (off-DynamoDB) loreserver data-plane
-- backend. One Postgres database per region cell backs all three coordination
-- stores: mutable (branch-tip CAS), immutable METADATA (fragment index), and
-- lock. Immutable fragment BYTES live in S3-compatible object storage, not here.
--
-- The store implementations also self-bootstrap these exact tables via
-- `CREATE TABLE IF NOT EXISTS` at startup (see each `*_store.rs`), so this file
-- is the provisioning/bootstrap artifact for tooling that prefers to apply the
-- schema out-of-band. It is idempotent.

-- Mutable store: strongly-consistent single-key compare-and-swap (branch tips).
CREATE TABLE IF NOT EXISTS lore_mutable (
    partition bytea    NOT NULL,
    key_type  smallint NOT NULL,
    key       bytea    NOT NULL,
    value     bytea    NOT NULL,
    PRIMARY KEY (partition, key_type, key)
);

-- Lock store: exclusivity is the PRIMARY KEY; the three indexes back the
-- supported LockQuery filters (the DynamoDB "3 GSIs" map 1:1 — INV-R §5). No
-- TTL/lease: locks persist until explicitly released.
CREATE TABLE IF NOT EXISTS lore_locks (
    repository  bytea  NOT NULL,
    branch      bytea  NOT NULL,
    hash        bytea  NOT NULL,
    owner       text   NOT NULL,
    description text   NOT NULL,
    locked_at   bigint NOT NULL,
    PRIMARY KEY (repository, branch, hash)
);
CREATE INDEX IF NOT EXISTS lore_locks_owner_repo_branch ON lore_locks (owner, repository, branch);
CREATE INDEX IF NOT EXISTS lore_locks_repo_branch       ON lore_locks (repository, branch);
CREATE INDEX IF NOT EXISTS lore_locks_repo_branch_desc  ON lore_locks (repository, branch, description);

-- Immutable store metadata. Fragment BYTES live in S3-compatible object storage;
-- only the index lives here.
--
-- lore_fragments: one row per (hash, repository, context) association. The PK
-- B-tree serves the leftmost-prefix existence reads — hash (MatchHash),
-- (hash, repository) (MatchPartition), full (MatchFull) — and the by-hash
-- refcount, so no secondary indexes are required.
CREATE TABLE IF NOT EXISTS lore_fragments (
    hash       bytea NOT NULL,
    repository bytea NOT NULL,
    context    bytea NOT NULL,
    PRIMARY KEY (hash, repository, context)
);

-- lore_fragment_metadata: one row per fragment hash (global dedup,
-- content-addressed) carrying the Fragment flags/sizes.
CREATE TABLE IF NOT EXISTS lore_fragment_metadata (
    hash         bytea  NOT NULL PRIMARY KEY,
    flags        bigint NOT NULL,
    size_payload bigint NOT NULL,
    size_content bigint NOT NULL
);

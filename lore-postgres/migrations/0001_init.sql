-- SPDX-FileCopyrightText: 2026 Epic Games, Inc.
-- SPDX-License-Identifier: MIT
--
-- CR-007 — canonical schema for the off-AWS (off-DynamoDB) loreserver data-plane
-- backend. One Postgres database per region cell backs all three coordination
-- stores: mutable (branch-tip CAS), immutable coordination, and lock. Immutable
-- fragment bytes and their authoritative representation metadata live together
-- on S3-compatible objects, not here.
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

-- Immutable store coordination. Fragment bytes and representation metadata live
-- in S3-compatible object storage. Postgres keeps associations, mutable lifecycle
-- state, and an exact but rebuildable metering projection.
--
-- lore_fragments: one row per (hash, repository, context) association. The PK
-- B-tree serves the leftmost-prefix existence reads — hash (MatchHash),
-- (hash, repository) (MatchPartition), full (MatchFull) — and the by-hash
-- refcount. The one secondary index inverts the leading column so a whole
-- repository's fragment set is reachable without a sequential scan, which is
-- what the per-repository storage-stats aggregate (CR-016) reads.
CREATE TABLE IF NOT EXISTS lore_fragments (
    hash       bytea NOT NULL,
    repository bytea NOT NULL,
    context    bytea NOT NULL,
    PRIMARY KEY (hash, repository, context)
);
CREATE INDEX IF NOT EXISTS lore_fragments_repo_hash ON lore_fragments (repository, hash);

-- lore_fragment_state: mutable readability/obliteration lifecycle only.
CREATE TABLE IF NOT EXISTS lore_fragment_state (
    hash  bytea  NOT NULL PRIMARY KEY,
    -- 0 Stored; 512 Obliterating children; 1 deleting payload versions; 256 tombstone.
    state bigint NOT NULL CHECK (state IN (0, 1, 256, 512))
);

-- lore_fragment_metering: non-authoritative projection of the representation
-- carried on the corresponding S3 object, synchronized on writes/copies and
-- rebuildable from object metadata. It exists only for exact set-based stats.
CREATE TABLE IF NOT EXISTS lore_fragment_metering (
    hash          bytea  NOT NULL PRIMARY KEY,
    payload_flags bigint NOT NULL CHECK (payload_flags >= 0 AND payload_flags <= 4294967295),
    size_payload bigint NOT NULL CHECK (size_payload >= 0),
    size_content bigint NOT NULL CHECK (size_content >= 0)
);

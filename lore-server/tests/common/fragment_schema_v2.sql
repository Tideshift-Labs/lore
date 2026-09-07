-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- Frozen inactive SCHEMA-118 v2 fixture, extracted verbatim from
-- git d4ce7359:lore-postgres/src/domain/fragments/schema.rs FRAGMENT_SCHEMA.
-- Keep separate from current schema so this test proves the real upgrade path.

-- ---------------------------------------------------------------------------
-- CR-031 fragment lifecycle authority (SCHEMA-118)
-- ---------------------------------------------------------------------------

-- The three push scalars are columns on the existing repository row, not a new
-- lockable row class: F-032-3's order gains no position from them, and a push
-- that already locks the repository row reads them without another row lock.
--
-- `content_association_generation` moves on association create/copy/tombstone.
-- `content_membership_invalidation_generation` excludes fresh absent-key additions.
-- `fragment_lifecycle_generation` moves on a readable/unreadable transition of
-- any fragment this repository has a live association to.
ALTER TABLE lore_domain_repositories
    ADD COLUMN IF NOT EXISTS content_membership_invalidation_generation bigint NOT NULL DEFAULT 0
        CHECK (content_membership_invalidation_generation >= 0),
    ADD COLUMN IF NOT EXISTS content_association_generation bigint NOT NULL DEFAULT 1
        CHECK (content_association_generation >= 1),
    ADD COLUMN IF NOT EXISTS fragment_lifecycle_generation bigint NOT NULL DEFAULT 1
        CHECK (fragment_lifecycle_generation >= 1);

-- Empty until the explicit, irreversible membership writer fencing step.
CREATE TABLE IF NOT EXISTS lore_fragment_membership_protocol (
    id smallint PRIMARY KEY CHECK (id = 1),
    revision bigint NOT NULL CHECK (revision = 1)
);

-- One monotonic source for every fragment epoch and every operation fence.
-- Gaps are valid: a fence is an ordering token, not a count.
CREATE SEQUENCE IF NOT EXISTS lore_fragment_fence_seq AS bigint START WITH 1 INCREMENT BY 1;

-- Lifecycle head: the sole current-epoch pointer for one FragmentId.
--
-- States: 1 PreparingStage, 2 PreparingRemote, 3 Staged, 4 Remote,
--         5 DeletingChildren, 6 DeletingPayload, 7 Missing, 8 Tombstoned.
-- Only 3 and 4 are readable, and the CHECK below makes "readable without a
-- manifest" unrepresentable rather than merely unlikely.
CREATE TABLE IF NOT EXISTS lore_fragment_lifecycle (
    hash             bytea       NOT NULL PRIMARY KEY,
    current_epoch    bigint      NOT NULL CHECK (current_epoch >= 1),
    state            smallint    NOT NULL CHECK (state BETWEEN 1 AND 8),
    manifest_id      bytea       CHECK (manifest_id IS NULL
                                        OR octet_length(manifest_id) = 32),
    last_fence       bigint      NOT NULL CHECK (last_fence >= 1),
    -- RESERVED, always NULL until Phase 5. CR-031's model names an active
    -- operation, but no CR-029 domain operation ID reaches this layer yet, and
    -- nothing writes this column. The shape is declared now so adding it later
    -- is not an ALTER under ensure_schema on a populated cell.
    active_operation bytea       CHECK (active_operation IS NULL
                                        OR octet_length(active_operation) = 16),
    diagnostic_class smallint    NOT NULL DEFAULT 0 CHECK (diagnostic_class BETWEEN 0 AND 5),
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT lore_fragment_lifecycle_readable_shape CHECK (
        (state IN (3, 4)) = (manifest_id IS NOT NULL)
    ),
    CONSTRAINT lore_fragment_lifecycle_diagnostic_shape CHECK (
        state = 7 OR diagnostic_class = 0
    )
);

-- Epoch representation. Immutable once written: a repair publishes a GREATER
-- epoch and quarantines its predecessor, it never rewrites this row. That is
-- what lets a delayed operation revalidate an exact manifest rather than trust
-- a mutable current view.
CREATE TABLE IF NOT EXISTS lore_fragment_epochs (
    hash          bytea       NOT NULL,
    epoch         bigint      NOT NULL CHECK (epoch >= 1),
    authority     smallint    NOT NULL CHECK (authority IN (1, 2)),
    object_key    text        NOT NULL CHECK (length(object_key) > 0),
    manifest_id   bytea       NOT NULL CHECK (octet_length(manifest_id) = 32),
    size_payload  bigint      NOT NULL CHECK (size_payload > 0),
    size_content  bigint      NOT NULL CHECK (size_content > 0),
    decoded_hash  bytea       NOT NULL CHECK (octet_length(decoded_hash) > 0),
    payload_flags bigint      NOT NULL CHECK (payload_flags >= 0
                                              AND payload_flags <= 4294967295),
    provider_body_blake3 bytea CHECK (provider_body_blake3 IS NULL
                                      OR octet_length(provider_body_blake3) = 32),
    provider_body_size bigint CHECK (provider_body_size IS NULL
                                     OR (provider_body_size >= 0
                                         AND provider_body_size <= 262144)),
    provider_claim_fence bigint CHECK (provider_claim_fence IS NULL
                                       OR provider_claim_fence >= 1),
    fence         bigint      NOT NULL CHECK (fence >= 1),
    validated_at  timestamptz,
    disposition   smallint    NOT NULL DEFAULT 0 CHECK (disposition IN (0, 1, 2)),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (hash, epoch),
    CONSTRAINT lore_fragment_epoch_provider_body_shape CHECK (
        (provider_body_blake3 IS NULL) = (provider_body_size IS NULL)
        AND (provider_body_blake3 IS NULL) = (provider_claim_fence IS NULL)
    )
);

-- Association: binds (FragmentId, repository, context). It never binds a
-- physical fragment epoch, so a repair that changes the representation leaves
-- every association untouched, and reads always resolve through the head.
CREATE TABLE IF NOT EXISTS lore_fragment_associations (
    hash                  bytea       NOT NULL,
    repository_id         bytea       NOT NULL CHECK (octet_length(repository_id) = 16),
    context               bytea       NOT NULL,
    association_epoch     bigint      NOT NULL CHECK (association_epoch >= 1),
    state                 smallint    NOT NULL CHECK (state IN (0, 1)),
    repository_generation bigint      NOT NULL CHECK (repository_generation >= 1),
    created_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (hash, repository_id, context)
);

-- Inverts the leading column so a whole repository's association set is
-- reachable without a sequential scan (the CR-016 stats read's access path).
CREATE INDEX IF NOT EXISTS lore_fragment_associations_repository
    ON lore_fragment_associations (repository_id, hash);

-- The shared-hash fanout path. A readable/unreadable transition must visit
-- every repository with a LIVE association to that hash, in sorted repository
-- order; this partial index is what makes that set both cheap to take and cheap
-- to MEASURE before mutating, which is the admission bound CR-031 requires.
CREATE INDEX IF NOT EXISTS lore_fragment_associations_live_fanout
    ON lore_fragment_associations (hash, repository_id)
    WHERE state = 0;

-- Epoch-aware, association-aware metering. Repairable data, never existence
-- authority: a missing or stale row degrades a stats answer, it never makes a
-- fragment readable or unreadable.
CREATE TABLE IF NOT EXISTS lore_fragment_lifecycle_metering (
    hash          bytea       NOT NULL PRIMARY KEY,
    epoch         bigint      NOT NULL CHECK (epoch >= 1),
    payload_flags bigint      NOT NULL CHECK (payload_flags >= 0
                                              AND payload_flags <= 4294967295),
    size_payload  bigint      NOT NULL CHECK (size_payload >= 0),
    size_content  bigint      NOT NULL CHECK (size_content >= 0),
    authority     smallint    NOT NULL CHECK (authority IN (1, 2)),
    verified_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Staged-reader lease. Scoped to `Staged` epochs ONLY, because that is the one
-- representation local cleanup can remove out from under a reader. A `Remote`
-- read takes no lease at all and revalidates read-only after byte I/O, which is
-- what keeps the hottest read path free of write amplification (R-SHOULD-6).
--
-- One lease covers a BATCH of fragments for one hydration request; the member
-- table is what makes it a batch rather than a row per 256 KiB read.
CREATE TABLE IF NOT EXISTS lore_fragment_staged_leases (
    lease_id     bytea       NOT NULL PRIMARY KEY CHECK (octet_length(lease_id) = 16),
    reader_fence bigint      NOT NULL CHECK (reader_fence >= 1),
    deadline     timestamptz NOT NULL,
    terminal     boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS lore_fragment_staged_lease_members (
    lease_id bytea  NOT NULL REFERENCES lore_fragment_staged_leases (lease_id) ON DELETE CASCADE,
    hash     bytea  NOT NULL,
    epoch    bigint NOT NULL CHECK (epoch >= 1),
    PRIMARY KEY (lease_id, hash)
);

-- Cleanup reads this to find the live readers of one staged epoch.
CREATE INDEX IF NOT EXISTS lore_fragment_staged_lease_members_epoch
    ON lore_fragment_staged_lease_members (hash, epoch);

-- Expired-lease reaping without a sequential scan over terminal rows.
CREATE INDEX IF NOT EXISTS lore_fragment_staged_leases_deadline
    ON lore_fragment_staged_leases (deadline)
    WHERE terminal = false;

-- Durable per-attempt provider-write claim. The lifecycle head is always
-- locked before a row in this table (both are LockClass::Fragments). A claim
-- binds the exact logical request, attempt, head lineage, object key, and body
-- before any provider I/O. Prepared, Sending, and Ambiguous remain barriers
-- until hard_not_after; Decisive and NoSend are terminal and nonblocking. A
-- provider write always targets Remote authority (2).
CREATE TABLE IF NOT EXISTS lore_fragment_write_claims (
    logical_request_id bytea       NOT NULL CHECK (octet_length(logical_request_id) = 16),
    attempt_id         bytea       NOT NULL CHECK (octet_length(attempt_id) = 16),
    hash               bytea       NOT NULL,
    epoch              bigint      NOT NULL CHECK (epoch >= 1),
    fence              bigint      NOT NULL CHECK (fence >= 1),
    authority          smallint    NOT NULL CHECK (authority = 2),
    object_key         text        NOT NULL CHECK (length(object_key) > 0),
    body_blake3        bytea       NOT NULL CHECK (octet_length(body_blake3) = 32),
    body_size          bigint      NOT NULL CHECK (body_size >= 0 AND body_size <= 262144),
    state              smallint    NOT NULL CHECK (state BETWEEN 0 AND 4),
    send_not_after     timestamptz NOT NULL,
    hard_not_after     timestamptz NOT NULL,
    prepared_at        timestamptz NOT NULL,
    authorized_at      timestamptz,
    settled_at         timestamptz,
    PRIMARY KEY (logical_request_id, attempt_id),
    CONSTRAINT lore_fragment_write_claim_deadline_shape CHECK (
        send_not_after > prepared_at AND hard_not_after > send_not_after
    ),
    CONSTRAINT lore_fragment_write_claim_state_shape CHECK (
        (state = 0 AND authorized_at IS NULL AND settled_at IS NULL)
     OR (state = 1 AND authorized_at IS NOT NULL AND settled_at IS NULL)
     OR (state IN (2, 3) AND authorized_at IS NOT NULL AND settled_at IS NOT NULL)
     OR (state = 4 AND settled_at IS NOT NULL)
    )
);

REVOKE ALL ON TABLE lore_fragment_write_claims FROM PUBLIC;

CREATE INDEX IF NOT EXISTS lore_fragment_write_claims_barrier
    ON lore_fragment_write_claims (hash, epoch, fence, hard_not_after)
    WHERE state IN (0, 1, 3);

CREATE INDEX IF NOT EXISTS lore_fragment_write_claims_terminal_prune
    ON lore_fragment_write_claims (settled_at, logical_request_id, attempt_id)
    WHERE state IN (2, 4);

-- Singleton. Read at boot for readiness, and the cutover marker's home.
--
-- The two CHECKs make the unsafe combinations unrepresentable: routing cannot be
-- enabled without a completed backfill, a classified residue set, the cutover
-- marker, and proved sequence headroom. The typed readiness check is the gate;
-- these are the backstop.
CREATE TABLE IF NOT EXISTS lore_fragment_schema_state (
    id                      smallint    NOT NULL PRIMARY KEY CHECK (id = 1),
    schema_version          bigint      NOT NULL CHECK (schema_version >= 1),
    backfill_version        bigint      NOT NULL CHECK (backfill_version >= 0),
    backfill_state          smallint    NOT NULL CHECK (backfill_state IN (0, 1, 2, 3)),
    backfill_cursor         bytea,
    verified_fragments      bigint      NOT NULL DEFAULT 0 CHECK (verified_fragments >= 0),
    residue_classified      boolean     NOT NULL DEFAULT false,
    cutover_at              timestamptz,
    lifecycle_enabled       boolean     NOT NULL DEFAULT false,
    write_capability        smallint    NOT NULL DEFAULT 0 CHECK (write_capability IN (0, 1)),
    provider_write_authority_revision text,
    write_claims_required_at timestamptz,
    database_identity       text        NOT NULL,
    sequence_headroom_fence bigint      CHECK (sequence_headroom_fence >= 1),
    updated_at              timestamptz NOT NULL,
    CONSTRAINT lore_fragment_schema_cutover_shape CHECK (
        (backfill_state = 3 AND cutover_at IS NOT NULL AND residue_classified
         AND sequence_headroom_fence IS NOT NULL)
        OR (backfill_state <> 3 AND cutover_at IS NULL AND lifecycle_enabled = false)
    ),
    CONSTRAINT lore_fragment_schema_enable_shape CHECK (
        lifecycle_enabled = false
        OR (backfill_state = 3 AND cutover_at IS NOT NULL AND residue_classified
            AND sequence_headroom_fence IS NOT NULL)
    ),
    CONSTRAINT lore_fragment_write_capability_shape CHECK (
        (write_capability = 0 AND provider_write_authority_revision IS NULL
                              AND write_claims_required_at IS NULL)
        OR (write_capability = 1
            AND length(provider_write_authority_revision) BETWEEN 1 AND 64
            AND write_claims_required_at IS NOT NULL)
    )
);

INSERT INTO lore_fragment_schema_state (
    id, schema_version, backfill_version, backfill_state, database_identity, updated_at
)
-- The schema_version literal below is aliased so `seed_schema_version_matches_the_constant`
-- can pin it against FRAGMENT_SCHEMA_VERSION. `bootstrap()` binds the constant, this
-- seed cannot, and parity compares catalog shape rather than row contents -- so without
-- that test a version bump would diverge silently between the two paths (INV-EF P2-9).
SELECT 1                                                                       AS id,
       2                                                                       AS schema_version,
       0                                                                       AS backfill_version,
       0                                                                       AS backfill_state,
       control.system_identifier::text || ':' || database.oid::text || ':' || current_database()
                                                                               AS database_identity,
       clock_timestamp()                                                       AS updated_at
  FROM pg_control_system() AS control
  JOIN pg_database AS database ON database.datname = current_database()
ON CONFLICT (id) DO NOTHING;


-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark local retention authority.
-- Runtime code never installs this artifact. Provisioning must install and attest the exact bytes.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE SCHEMA object_store_retention AUTHORIZATION object_dispatch_retention_owner;

REVOKE ALL ON SCHEMA object_store_retention FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_retention_owner
  IN SCHEMA object_store_retention REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_retention_owner
  IN SCHEMA object_store_retention REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_retention_owner
  IN SCHEMA object_store_retention REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE DOMAIN object_store_retention.uint64 AS numeric(20, 0)
  CHECK (VALUE >= 0 AND VALUE <= 18446744073709551615);

CREATE DOMAIN object_store_retention.blake3_256 AS bytea
  CHECK (octet_length(VALUE) = 32);

CREATE TABLE object_store_retention.object_dispatch_retention_schema_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  schema_revision text NOT NULL UNIQUE
    CHECK (schema_revision = 'object-store-retention-authority-schema-v1'),
  migration_blake3 object_store_retention.blake3_256 NOT NULL,
  install_revision object_store_retention.uint64 NOT NULL CHECK (install_revision > 0),
  compact_sequence_high_water object_store_retention.uint64 NOT NULL DEFAULT 0,
  compact_sequence_revision object_store_retention.uint64 NOT NULL
    CHECK (compact_sequence_revision > 0),
  installed_at_unix_ms bigint NOT NULL CHECK (installed_at_unix_ms >= 0)
);

CREATE TABLE object_store_retention.object_dispatch_full_record_ownership (
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  authenticated_cell_id text NOT NULL CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  authenticated_tenant_id text NOT NULL CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  source_authority_blake3 object_store_retention.blake3_256 NOT NULL,
  full_record_rows object_store_retention.uint64 NOT NULL DEFAULT 1 CHECK (full_record_rows = 1),
  full_record_bytes object_store_retention.uint64 NOT NULL CHECK (full_record_bytes > 0),
  full_record_concurrency object_store_retention.uint64 NOT NULL DEFAULT 0
    CHECK (full_record_concurrency = 0),
  ownership_revision object_store_retention.uint64 NOT NULL CHECK (ownership_revision > 0),
  closure_committed_at_unix_ms bigint NOT NULL CHECK (closure_committed_at_unix_ms >= 0),
  created_at_unix_ms bigint NOT NULL CHECK (created_at_unix_ms >= 0),
  PRIMARY KEY (logical_request_id, attempt_id),
  UNIQUE (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id
  ),
  CHECK (closure_committed_at_unix_ms >= created_at_unix_ms)
);

CREATE TABLE object_store_retention.object_dispatch_record_storage_counters (
  scope_kind smallint NOT NULL CHECK (scope_kind IN (1, 2, 3)),
  scope_id text NOT NULL CHECK (octet_length(scope_id) BETWEEN 1 AND 1024),
  full_record_rows object_store_retention.uint64 NOT NULL DEFAULT 0,
  full_record_bytes object_store_retention.uint64 NOT NULL DEFAULT 0,
  compact_rows object_store_retention.uint64 NOT NULL DEFAULT 0,
  compact_bytes object_store_retention.uint64 NOT NULL DEFAULT 0,
  counter_revision object_store_retention.uint64 NOT NULL CHECK (counter_revision > 0),
  PRIMARY KEY (scope_kind, scope_id),
  CHECK (
    (scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1') OR
    (scope_kind IN (2, 3) AND scope_id <> 'object-store-full-to-compact-global-v1')
  )
);

CREATE TABLE object_store_retention.object_dispatch_compact_receipts (
  compact_sequence object_store_retention.uint64 PRIMARY KEY CHECK (compact_sequence > 0),
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  authenticated_cell_id text NOT NULL CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  authenticated_tenant_id text NOT NULL CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  source_authority_blake3 object_store_retention.blake3_256 NOT NULL,
  compact_receipt_bytes bytea NOT NULL CHECK (octet_length(compact_receipt_bytes) > 0),
  compact_blake3 object_store_retention.blake3_256 NOT NULL,
  compact_rows object_store_retention.uint64 NOT NULL DEFAULT 1 CHECK (compact_rows = 1),
  compact_bytes object_store_retention.uint64 NOT NULL CHECK (compact_bytes > 0),
  compact_concurrency object_store_retention.uint64 NOT NULL DEFAULT 0
    CHECK (compact_concurrency = 0),
  compaction_fingerprint object_store_retention.blake3_256 NOT NULL,
  transfer_fingerprint object_store_retention.blake3_256 NOT NULL UNIQUE,
  compacted_at_unix_ms bigint NOT NULL CHECK (compacted_at_unix_ms >= 0),
  compact_prune_after_unix_ms bigint NOT NULL CHECK (compact_prune_after_unix_ms >= 0),
  UNIQUE (logical_request_id, attempt_id),
  UNIQUE (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id
  ),
  CHECK (compact_bytes = octet_length(compact_receipt_bytes)),
  CHECK (compact_prune_after_unix_ms >= compacted_at_unix_ms)
);

CREATE INDEX object_dispatch_compact_receipts_prune_floor_idx
  ON object_store_retention.object_dispatch_compact_receipts
  (compact_prune_after_unix_ms, compact_sequence);
CREATE INDEX object_dispatch_compact_receipts_cell_lookup_idx
  ON object_store_retention.object_dispatch_compact_receipts
  (authenticated_cell_id, logical_request_id, attempt_id);
CREATE INDEX object_dispatch_compact_receipts_tenant_lookup_idx
  ON object_store_retention.object_dispatch_compact_receipts
  (authenticated_tenant_id, logical_request_id, attempt_id);

CREATE TABLE object_store_retention.object_dispatch_compact_prune_watermark (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  pruned_through_compact_sequence object_store_retention.uint64 NOT NULL DEFAULT 0,
  watermark_revision object_store_retention.uint64 NOT NULL CHECK (watermark_revision > 0),
  last_prune_fingerprint object_store_retention.blake3_256,
  last_compact_blake3 object_store_retention.blake3_256,
  last_pruned_at_unix_ms bigint CHECK (last_pruned_at_unix_ms >= 0),
  last_backup_revision text CHECK (
    last_backup_revision IS NULL OR octet_length(last_backup_revision) BETWEEN 1 AND 4294967295
  ),
  last_backup_manifest_blake3 object_store_retention.blake3_256,
  CHECK (
    (
      pruned_through_compact_sequence = 0 AND
      num_nonnulls(
        last_prune_fingerprint,
        last_compact_blake3,
        last_pruned_at_unix_ms,
        last_backup_revision,
        last_backup_manifest_blake3
      ) = 0
    ) OR
    (
      pruned_through_compact_sequence > 0 AND
      num_nonnulls(
        last_prune_fingerprint,
        last_compact_blake3,
        last_pruned_at_unix_ms,
        last_backup_revision,
        last_backup_manifest_blake3
      ) = 5
    )
  )
);

REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;
GRANT USAGE ON SCHEMA object_store_retention TO
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

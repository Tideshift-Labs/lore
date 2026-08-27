-- SPDX-License-Identifier: Apache-2.0
-- GENERATED: exact transactional composition of ../schema.sql then ../procedures.sql.
-- Regenerate whenever either source artifact changes; the contract test rejects drift.

BEGIN;
SET LOCAL ROLE object_dispatch_continuity_owner;

-- SPDX-License-Identifier: Apache-2.0
-- ObjectStoreAuthorityContinuityLedger schema, WP-121 Phase 2 dark-source slice.
-- This schema is intentionally independent of the restored control-plane authority database.

CREATE SCHEMA object_store_continuity AUTHORIZATION object_dispatch_continuity_owner;

REVOKE ALL ON SCHEMA object_store_continuity FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_continuity_owner
  IN SCHEMA object_store_continuity REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_continuity_owner
  IN SCHEMA object_store_continuity REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_continuity_owner
  IN SCHEMA object_store_continuity REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE DOMAIN object_store_continuity.uint64 AS numeric(20, 0)
  CHECK (VALUE >= 0 AND VALUE <= 18446744073709551615);

CREATE TYPE object_store_continuity.procedure_result_v1 AS (
  result_code text,
  state text,
  ownership_state text,
  authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64,
  continuity_token_id uuid,
  row_blake3 bytea,
  external_committed_at_unix_ms bigint
);

CREATE TABLE object_store_continuity.boundary_roles (
  provider_boundary_id text PRIMARY KEY,
  boundary_blake3 bytea NOT NULL UNIQUE CHECK (octet_length(boundary_blake3) = 32),
  login_role name NOT NULL UNIQUE,
  created_at_unix_ms bigint NOT NULL CHECK (created_at_unix_ms >= 0),
  CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  CHECK (login_role::text ~ '^odc_b_[a-z2-7]{52}$')
);

CREATE TABLE object_store_continuity.policies (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  policy_revision text NOT NULL UNIQUE CHECK (octet_length(policy_revision) BETWEEN 1 AND 1024),
  canonical_policy_bytes bytea NOT NULL,
  policy_blake3 bytea NOT NULL CHECK (octet_length(policy_blake3) = 32),
  max_rows_global object_store_continuity.uint64 NOT NULL,
  max_bytes_global object_store_continuity.uint64 NOT NULL,
  max_rows_per_boundary object_store_continuity.uint64 NOT NULL,
  max_bytes_per_boundary object_store_continuity.uint64 NOT NULL,
  low_water_reserve_rows object_store_continuity.uint64 NOT NULL,
  low_water_reserve_bytes object_store_continuity.uint64 NOT NULL,
  max_row_bytes object_store_continuity.uint64 NOT NULL,
  max_pruned_ranges_per_boundary object_store_continuity.uint64 NOT NULL,
  max_pruned_range_bytes object_store_continuity.uint64 NOT NULL,
  archive_batch_rows object_store_continuity.uint64 NOT NULL,
  prune_batch_rows object_store_continuity.uint64 NOT NULL,
  prune_interval_ms object_store_continuity.uint64 NOT NULL,
  max_epoch_high_water_bytes object_store_continuity.uint64 NOT NULL,
  policy_revision_counter object_store_continuity.uint64 NOT NULL,
  installed_at_unix_ms bigint NOT NULL CHECK (installed_at_unix_ms >= 0),
  CHECK (octet_length(canonical_policy_bytes) BETWEEN 1 AND 1048576),
  CHECK (max_rows_global > 0 AND max_bytes_global > 0),
  CHECK (max_rows_per_boundary > 0 AND max_bytes_per_boundary > 0),
  CHECK (low_water_reserve_rows < max_rows_global),
  CHECK (low_water_reserve_bytes < max_bytes_global),
  CHECK (low_water_reserve_rows < max_rows_per_boundary),
  CHECK (low_water_reserve_bytes < max_bytes_per_boundary),
  CHECK (max_row_bytes > 0 AND archive_batch_rows > 0 AND prune_batch_rows > 0),
  CHECK (prune_interval_ms > 0 AND max_epoch_high_water_bytes > 0)
);

CREATE TABLE object_store_continuity.global_counter (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  owned_rows object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_bytes object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_concurrency object_store_continuity.uint64 NOT NULL DEFAULT 0,
  counter_revision object_store_continuity.uint64 NOT NULL DEFAULT 0,
  continuity_storage_rows object_store_continuity.uint64 NOT NULL DEFAULT 0,
  continuity_storage_bytes object_store_continuity.uint64 NOT NULL DEFAULT 0,
  continuity_storage_counter_revision object_store_continuity.uint64 NOT NULL DEFAULT 0
);

CREATE TABLE object_store_continuity.boundary_counters (
  provider_boundary_id text PRIMARY KEY
    REFERENCES object_store_continuity.boundary_roles(provider_boundary_id),
  current_authority_epoch object_store_continuity.uint64 NOT NULL CHECK (current_authority_epoch > 0),
  continuity_seq_high_water object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_rows object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_bytes object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_concurrency object_store_continuity.uint64 NOT NULL DEFAULT 0,
  counter_revision object_store_continuity.uint64 NOT NULL DEFAULT 0,
  continuity_storage_rows object_store_continuity.uint64 NOT NULL DEFAULT 0,
  continuity_storage_bytes object_store_continuity.uint64 NOT NULL DEFAULT 0,
  continuity_storage_counter_revision object_store_continuity.uint64 NOT NULL DEFAULT 0,
  epoch_namespace_blake3 bytea NOT NULL CHECK (octet_length(epoch_namespace_blake3) = 32)
);

CREATE TABLE object_store_continuity.epoch_counters (
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL CHECK (authority_epoch > 0),
  continuity_seq_high_water object_store_continuity.uint64 NOT NULL DEFAULT 0,
  prune_commit_sequence_high_water object_store_continuity.uint64 NOT NULL DEFAULT 0,
  api_revision text NOT NULL CHECK (api_revision = 'object-store-authority-continuity-v1'),
  schema_revision text NOT NULL CHECK (schema_revision = 'object-store-authority-continuity-schema-v1'),
  continuity_contract_revision text NOT NULL,
  continuity_policy_revision text NOT NULL,
  max_pruned_ranges_per_boundary object_store_continuity.uint64 NOT NULL,
  max_pruned_range_bytes object_store_continuity.uint64 NOT NULL,
  archive_batch_rows object_store_continuity.uint64 NOT NULL,
  prune_batch_rows object_store_continuity.uint64 NOT NULL,
  prune_interval_ms object_store_continuity.uint64 NOT NULL,
  max_epoch_high_water_bytes object_store_continuity.uint64 NOT NULL,
  epoch_namespace_blake3 bytea NOT NULL CHECK (octet_length(epoch_namespace_blake3) = 32),
  retired boolean NOT NULL DEFAULT false,
  PRIMARY KEY (provider_boundary_id, authority_epoch),
  FOREIGN KEY (provider_boundary_id)
    REFERENCES object_store_continuity.boundary_counters(provider_boundary_id),
  CHECK (octet_length(continuity_contract_revision) BETWEEN 1 AND 1024),
  CHECK (octet_length(continuity_policy_revision) BETWEEN 1 AND 1024),
  CHECK (max_pruned_ranges_per_boundary > 0),
  CHECK (max_pruned_range_bytes > 0),
  CHECK (archive_batch_rows > 0),
  CHECK (prune_batch_rows > 0),
  CHECK (prune_interval_ms > 0),
  CHECK (max_epoch_high_water_bytes > 0)
);

CREATE TABLE object_store_continuity.cell_counters (
  provider_boundary_id text NOT NULL,
  authenticated_cell_id text NOT NULL,
  owned_rows object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_bytes object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_concurrency object_store_continuity.uint64 NOT NULL DEFAULT 0,
  counter_revision object_store_continuity.uint64 NOT NULL DEFAULT 0,
  PRIMARY KEY (provider_boundary_id, authenticated_cell_id),
  FOREIGN KEY (provider_boundary_id)
    REFERENCES object_store_continuity.boundary_counters(provider_boundary_id),
  CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024)
);

CREATE TABLE object_store_continuity.tenant_counters (
  provider_boundary_id text NOT NULL,
  authenticated_tenant_id text NOT NULL,
  owned_rows object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_bytes object_store_continuity.uint64 NOT NULL DEFAULT 0,
  owned_concurrency object_store_continuity.uint64 NOT NULL DEFAULT 0,
  counter_revision object_store_continuity.uint64 NOT NULL DEFAULT 0,
  PRIMARY KEY (provider_boundary_id, authenticated_tenant_id),
  FOREIGN KEY (provider_boundary_id)
    REFERENCES object_store_continuity.boundary_counters(provider_boundary_id),
  CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024)
);

CREATE TABLE object_store_continuity.intents (
  api_revision text NOT NULL
    CHECK (api_revision = 'object-store-authority-continuity-v1'),
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL CHECK (authority_epoch > 0),
  continuity_seq object_store_continuity.uint64 NOT NULL CHECK (continuity_seq > 0),
  continuity_token_id uuid NOT NULL,
  intent_kind text NOT NULL CHECK (intent_kind IN ('UUID_ADMISSION', 'DISPATCH_CAS')),
  authenticated_cell_id text NOT NULL,
  authenticated_tenant_id text NOT NULL,
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  put_reservation_fingerprint bytea,
  canonical_descriptor_fingerprint bytea,
  continuity_policy_revision text NOT NULL,
  operation_quota_class text NOT NULL,
  quota_rows object_store_continuity.uint64 NOT NULL,
  quota_bytes object_store_continuity.uint64 NOT NULL,
  quota_concurrency object_store_continuity.uint64 NOT NULL,
  quota_ownership_bytes bytea NOT NULL,
  quota_ownership_blake3 bytea NOT NULL CHECK (octet_length(quota_ownership_blake3) = 32),
  state text NOT NULL CHECK (state IN (
    'INTENT', 'BOUND', 'COMPLETED', 'NO_LOCAL_EFFECT', 'QUARANTINED',
    'AMBIGUOUS_DISPATCH', 'ADJUDICATION_PREPARED',
    'ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH'
  )),
  ownership_state text NOT NULL
    CHECK (ownership_state IN ('SHADOW_RESERVED', 'OWNERSHIP_RELEASED')),
  local_binding_blake3 bytea,
  terminal_evidence_blake3 bytea,
  adjudication_kind text CHECK (adjudication_kind IN ('NO_LOCAL_EFFECT', 'NO_DISPATCH')),
  external_created_at_unix_ms bigint NOT NULL CHECK (external_created_at_unix_ms >= 0),
  state_committed_at_unix_ms bigint NOT NULL CHECK (state_committed_at_unix_ms >= 0),
  retention_deadline_unix_ms bigint NOT NULL CHECK (retention_deadline_unix_ms >= 0),
  canonical_row_bytes bytea NOT NULL,
  row_blake3 bytea NOT NULL CHECK (octet_length(row_blake3) = 32),
  PRIMARY KEY (provider_boundary_id, authority_epoch, continuity_seq),
  UNIQUE (continuity_token_id),
  UNIQUE (
    provider_boundary_id, authenticated_cell_id, authenticated_tenant_id,
    logical_request_id, attempt_id, intent_kind
  ),
  FOREIGN KEY (provider_boundary_id)
    REFERENCES object_store_continuity.boundary_counters(provider_boundary_id),
  FOREIGN KEY (provider_boundary_id, authority_epoch)
    REFERENCES object_store_continuity.epoch_counters(provider_boundary_id, authority_epoch),
  CHECK (substring(continuity_token_id::text FROM 15 FOR 1) = '7'),
  CHECK (substring(continuity_token_id::text FROM 20 FOR 1) IN ('8', '9', 'a', 'b')),
  CHECK (substring(logical_request_id::text FROM 15 FOR 1) = '7'),
  CHECK (substring(logical_request_id::text FROM 20 FOR 1) IN ('8', '9', 'a', 'b')),
  CHECK (substring(attempt_id::text FROM 15 FOR 1) = '7'),
  CHECK (substring(attempt_id::text FROM 20 FOR 1) IN ('8', '9', 'a', 'b')),
  CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  CHECK (octet_length(continuity_policy_revision) BETWEEN 1 AND 1024),
  CHECK (octet_length(operation_quota_class) BETWEEN 1 AND 256),
  CHECK (quota_rows > 0 OR quota_bytes > 0 OR quota_concurrency > 0),
  CHECK (octet_length(quota_ownership_bytes) BETWEEN 1 AND 1048576),
  CHECK (octet_length(canonical_row_bytes) BETWEEN 1 AND 1048576),
  CHECK (local_binding_blake3 IS NULL OR octet_length(local_binding_blake3) = 32),
  CHECK (terminal_evidence_blake3 IS NULL OR octet_length(terminal_evidence_blake3) = 32),
  CHECK (state_committed_at_unix_ms >= external_created_at_unix_ms),
  CHECK ((intent_kind = 'UUID_ADMISSION') = (put_reservation_fingerprint IS NOT NULL)),
  CHECK ((intent_kind = 'DISPATCH_CAS') = (canonical_descriptor_fingerprint IS NOT NULL)),
  CHECK (put_reservation_fingerprint IS NULL OR octet_length(put_reservation_fingerprint) = 32),
  CHECK (
    canonical_descriptor_fingerprint IS NULL OR octet_length(canonical_descriptor_fingerprint) = 32
  ),
  CHECK (
    (state = 'INTENT' AND local_binding_blake3 IS NULL AND terminal_evidence_blake3 IS NULL)
    OR (state = 'BOUND' AND local_binding_blake3 IS NOT NULL AND terminal_evidence_blake3 IS NULL)
    OR (state = 'COMPLETED' AND local_binding_blake3 IS NOT NULL AND terminal_evidence_blake3 IS NOT NULL)
    OR (state = 'NO_LOCAL_EFFECT' AND local_binding_blake3 IS NULL AND terminal_evidence_blake3 IS NOT NULL)
    OR (state = 'QUARANTINED' AND terminal_evidence_blake3 IS NOT NULL)
    OR (state = 'AMBIGUOUS_DISPATCH' AND local_binding_blake3 IS NOT NULL AND terminal_evidence_blake3 IS NOT NULL)
    OR (state IN ('ADJUDICATION_PREPARED', 'ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH')
        AND terminal_evidence_blake3 IS NOT NULL)
  ),
  CHECK (
    (state IN ('INTENT', 'QUARANTINED', 'AMBIGUOUS_DISPATCH', 'ADJUDICATION_PREPARED')
      AND ownership_state = 'SHADOW_RESERVED')
    OR (state IN ('NO_LOCAL_EFFECT', 'ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH')
      AND ownership_state = 'OWNERSHIP_RELEASED')
    OR state IN ('BOUND', 'COMPLETED')
  ),
  CHECK (
    (state IN ('ADJUDICATION_PREPARED', 'ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH'))
      = (adjudication_kind IS NOT NULL)
  ),
  CHECK (state <> 'ADJUDICATED_NO_LOCAL_EFFECT' OR adjudication_kind = 'NO_LOCAL_EFFECT'),
  CHECK (state <> 'ADJUDICATED_NO_DISPATCH' OR adjudication_kind = 'NO_DISPATCH')
);

CREATE INDEX intents_boundary_state_idx
  ON object_store_continuity.intents(provider_boundary_id, state, authority_epoch, continuity_seq);
CREATE INDEX intents_retention_idx
  ON object_store_continuity.intents(retention_deadline_unix_ms, provider_boundary_id);

CREATE TABLE object_store_continuity.transition_receipts (
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL,
  continuity_seq object_store_continuity.uint64 NOT NULL,
  continuity_token_id uuid NOT NULL,
  actor text NOT NULL CHECK (actor IN ('RUNTIME', 'RECONCILER')),
  command_kind text NOT NULL,
  prior_state text NOT NULL,
  next_state text NOT NULL,
  next_ownership_state text NOT NULL
    CHECK (next_ownership_state IN ('SHADOW_RESERVED', 'OWNERSHIP_RELEASED')),
  expected_prior_row_blake3 bytea NOT NULL CHECK (octet_length(expected_prior_row_blake3) = 32),
  next_row_blake3 bytea NOT NULL CHECK (octet_length(next_row_blake3) = 32),
  local_binding_blake3 bytea CHECK (local_binding_blake3 IS NULL OR octet_length(local_binding_blake3) = 32),
  terminal_evidence_blake3 bytea
    CHECK (terminal_evidence_blake3 IS NULL OR octet_length(terminal_evidence_blake3) = 32),
  adjudication_kind text CHECK (adjudication_kind IN ('NO_LOCAL_EFFECT', 'NO_DISPATCH')),
  release_id uuid,
  release_basis_kind text
    CHECK (release_basis_kind IN ('COVERED_SNAPSHOT', 'NO_LOCAL_EFFECT', 'FINAL_ADJUDICATION')),
  release_basis_id text,
  release_basis_blake3 bytea
    CHECK (release_basis_blake3 IS NULL OR octet_length(release_basis_blake3) = 32),
  committed_at_unix_ms bigint NOT NULL CHECK (committed_at_unix_ms >= 0),
  canonical_receipt_bytes bytea NOT NULL CHECK (octet_length(canonical_receipt_bytes) > 32),
  receipt_blake3 bytea NOT NULL CHECK (octet_length(receipt_blake3) = 32),
  PRIMARY KEY (continuity_token_id, expected_prior_row_blake3),
  UNIQUE (continuity_token_id, next_row_blake3),
  FOREIGN KEY (provider_boundary_id, authority_epoch, continuity_seq)
    REFERENCES object_store_continuity.intents(provider_boundary_id, authority_epoch, continuity_seq),
  CHECK ((next_ownership_state = 'OWNERSHIP_RELEASED') = (release_id IS NOT NULL)),
  CHECK ((release_id IS NOT NULL) = (release_basis_kind IS NOT NULL)),
  CHECK ((release_id IS NOT NULL) = (release_basis_id IS NOT NULL)),
  CHECK ((release_id IS NOT NULL) = (release_basis_blake3 IS NOT NULL))
);

CREATE TABLE object_store_continuity.shadow_release_receipts (
  release_id uuid PRIMARY KEY,
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL,
  continuity_seq object_store_continuity.uint64 NOT NULL,
  continuity_token_id uuid NOT NULL UNIQUE,
  continuity_policy_revision text NOT NULL,
  quota_ownership_blake3 bytea NOT NULL CHECK (octet_length(quota_ownership_blake3) = 32),
  quota_rows object_store_continuity.uint64 NOT NULL,
  quota_bytes object_store_continuity.uint64 NOT NULL,
  quota_concurrency object_store_continuity.uint64 NOT NULL,
  global_scope_id text NOT NULL CHECK (global_scope_id = 'object-store-continuity-global-v1'),
  authenticated_cell_id text NOT NULL,
  authenticated_tenant_id text NOT NULL,
  release_basis_kind text NOT NULL
    CHECK (release_basis_kind IN ('COVERED_SNAPSHOT', 'NO_LOCAL_EFFECT', 'FINAL_ADJUDICATION')),
  basis_id text NOT NULL,
  basis_blake3 bytea NOT NULL CHECK (octet_length(basis_blake3) = 32),
  released_at_unix_ms bigint NOT NULL CHECK (released_at_unix_ms >= 0),
  global_counter_revision object_store_continuity.uint64 NOT NULL,
  boundary_counter_revision object_store_continuity.uint64 NOT NULL,
  cell_counter_revision object_store_continuity.uint64 NOT NULL,
  tenant_counter_revision object_store_continuity.uint64 NOT NULL,
  canonical_receipt_bytes bytea NOT NULL,
  receipt_blake3 bytea NOT NULL CHECK (octet_length(receipt_blake3) = 32),
  FOREIGN KEY (provider_boundary_id, authority_epoch, continuity_seq)
    REFERENCES object_store_continuity.intents(provider_boundary_id, authority_epoch, continuity_seq),
  CHECK (quota_rows > 0 OR quota_bytes > 0 OR quota_concurrency > 0),
  CHECK (octet_length(continuity_policy_revision) BETWEEN 1 AND 1024),
  CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  CHECK (substring(release_id::text FROM 15 FOR 1) = '7'),
  CHECK (substring(release_id::text FROM 20 FOR 1) IN ('8', '9', 'a', 'b'))
);

CREATE TABLE object_store_continuity.snapshots (
  snapshot_id uuid PRIMARY KEY,
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL,
  through_continuity_seq object_store_continuity.uint64 NOT NULL,
  authority_lsn pg_lsn NOT NULL,
  manifest_blake3 bytea NOT NULL CHECK (octet_length(manifest_blake3) = 32),
  recorded_at_unix_ms bigint NOT NULL CHECK (recorded_at_unix_ms >= 0),
  canonical_snapshot_bytes bytea NOT NULL CHECK (octet_length(canonical_snapshot_bytes) > 32),
  snapshot_blake3 bytea NOT NULL CHECK (octet_length(snapshot_blake3) = 32),
  UNIQUE (provider_boundary_id, authority_epoch, through_continuity_seq),
  FOREIGN KEY (provider_boundary_id)
    REFERENCES object_store_continuity.boundary_counters(provider_boundary_id),
  FOREIGN KEY (provider_boundary_id, authority_epoch)
    REFERENCES object_store_continuity.epoch_counters(provider_boundary_id, authority_epoch),
  CHECK (authority_epoch > 0 AND through_continuity_seq > 0),
  CHECK (substring(snapshot_id::text FROM 15 FOR 1) = '7'),
  CHECK (substring(snapshot_id::text FROM 20 FOR 1) IN ('8', '9', 'a', 'b'))
);

CREATE TABLE object_store_continuity.snapshot_coverages (
  snapshot_id uuid NOT NULL,
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL,
  continuity_seq object_store_continuity.uint64 NOT NULL,
  continuity_token_id uuid NOT NULL,
  local_binding_blake3 bytea NOT NULL CHECK (octet_length(local_binding_blake3) = 32),
  local_state_blake3 bytea NOT NULL CHECK (octet_length(local_state_blake3) = 32),
  local_quota_ownership_blake3 bytea NOT NULL
    CHECK (octet_length(local_quota_ownership_blake3) = 32),
  local_counter_revision object_store_continuity.uint64 NOT NULL,
  authority_lsn pg_lsn NOT NULL,
  manifest_blake3 bytea NOT NULL CHECK (octet_length(manifest_blake3) = 32),
  coverage_blake3 bytea NOT NULL CHECK (octet_length(coverage_blake3) = 32),
  canonical_coverage_bytes bytea NOT NULL CHECK (octet_length(canonical_coverage_bytes) > 32),
  recorded_at_unix_ms bigint NOT NULL CHECK (recorded_at_unix_ms >= 0),
  PRIMARY KEY (snapshot_id, continuity_token_id),
  UNIQUE (provider_boundary_id, authority_epoch, continuity_seq, snapshot_id),
  FOREIGN KEY (snapshot_id) REFERENCES object_store_continuity.snapshots(snapshot_id),
  FOREIGN KEY (provider_boundary_id, authority_epoch, continuity_seq)
    REFERENCES object_store_continuity.intents(provider_boundary_id, authority_epoch, continuity_seq),
  CHECK (local_counter_revision > 0)
);

CREATE TABLE object_store_continuity.pruned_ranges (
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL,
  start_sequence object_store_continuity.uint64 NOT NULL,
  end_sequence object_store_continuity.uint64 NOT NULL,
  row_count object_store_continuity.uint64 NOT NULL,
  api_revision text NOT NULL CHECK (api_revision = 'object-store-authority-continuity-v1'),
  schema_revision text NOT NULL CHECK (schema_revision = 'object-store-authority-continuity-schema-v1'),
  continuity_contract_revision text NOT NULL,
  continuity_policy_revision text NOT NULL,
  completed_count object_store_continuity.uint64 NOT NULL,
  no_local_effect_count object_store_continuity.uint64 NOT NULL,
  adjudicated_no_local_effect_count object_store_continuity.uint64 NOT NULL,
  adjudicated_no_dispatch_count object_store_continuity.uint64 NOT NULL,
  canonical_row_bytes_sum object_store_continuity.uint64 NOT NULL,
  canonical_row_bytes_min object_store_continuity.uint64 NOT NULL,
  canonical_row_bytes_max object_store_continuity.uint64 NOT NULL,
  quota_rows_sum object_store_continuity.uint64 NOT NULL,
  quota_rows_min object_store_continuity.uint64 NOT NULL,
  quota_rows_max object_store_continuity.uint64 NOT NULL,
  quota_bytes_sum object_store_continuity.uint64 NOT NULL,
  quota_bytes_min object_store_continuity.uint64 NOT NULL,
  quota_bytes_max object_store_continuity.uint64 NOT NULL,
  quota_concurrency_sum object_store_continuity.uint64 NOT NULL,
  quota_concurrency_min object_store_continuity.uint64 NOT NULL,
  quota_concurrency_max object_store_continuity.uint64 NOT NULL,
  created_at_min_unix_ms bigint NOT NULL CHECK (created_at_min_unix_ms >= 0),
  created_at_max_unix_ms bigint NOT NULL CHECK (created_at_max_unix_ms >= 0),
  closed_at_min_unix_ms bigint NOT NULL CHECK (closed_at_min_unix_ms >= 0),
  closed_at_max_unix_ms bigint NOT NULL CHECK (closed_at_max_unix_ms >= 0),
  prune_commit_sequence_min object_store_continuity.uint64 NOT NULL,
  prune_commit_sequence_max object_store_continuity.uint64 NOT NULL,
  pruned_at_min_unix_ms bigint NOT NULL CHECK (pruned_at_min_unix_ms >= 0),
  pruned_at_max_unix_ms bigint NOT NULL CHECK (pruned_at_max_unix_ms >= 0),
  canonical_interval_bytes bytea NOT NULL CHECK (octet_length(canonical_interval_bytes) > 32),
  interval_blake3 bytea NOT NULL CHECK (octet_length(interval_blake3) = 32),
  PRIMARY KEY (provider_boundary_id, authority_epoch, start_sequence, end_sequence),
  FOREIGN KEY (provider_boundary_id, authority_epoch)
    REFERENCES object_store_continuity.epoch_counters(provider_boundary_id, authority_epoch),
  CHECK (start_sequence > 0 AND end_sequence >= start_sequence),
  CHECK (row_count = end_sequence - start_sequence + 1),
  CHECK (
    completed_count + no_local_effect_count + adjudicated_no_local_effect_count
      + adjudicated_no_dispatch_count = row_count
  ),
  CHECK (octet_length(continuity_contract_revision) BETWEEN 1 AND 1024),
  CHECK (octet_length(continuity_policy_revision) BETWEEN 1 AND 1024),
  CHECK (canonical_row_bytes_min <= canonical_row_bytes_max),
  CHECK (quota_rows_min <= quota_rows_max),
  CHECK (quota_bytes_min <= quota_bytes_max),
  CHECK (quota_concurrency_min <= quota_concurrency_max),
  CHECK (created_at_min_unix_ms <= created_at_max_unix_ms),
  CHECK (closed_at_min_unix_ms <= closed_at_max_unix_ms),
  CHECK (prune_commit_sequence_min > 0),
  CHECK (prune_commit_sequence_min <= prune_commit_sequence_max),
  CHECK (pruned_at_min_unix_ms <= pruned_at_max_unix_ms)
);

CREATE INDEX pruned_ranges_containment_idx
  ON object_store_continuity.pruned_ranges(provider_boundary_id, authority_epoch, start_sequence, end_sequence);

CREATE TABLE object_store_continuity.retired_epoch_summaries (
  provider_boundary_id text NOT NULL,
  authority_epoch object_store_continuity.uint64 NOT NULL,
  start_sequence object_store_continuity.uint64 NOT NULL,
  final_sequence object_store_continuity.uint64 NOT NULL,
  row_count object_store_continuity.uint64 NOT NULL,
  api_revision text NOT NULL CHECK (api_revision = 'object-store-authority-continuity-v1'),
  schema_revision text NOT NULL CHECK (schema_revision = 'object-store-authority-continuity-schema-v1'),
  continuity_contract_revision text NOT NULL,
  continuity_policy_revision text NOT NULL,
  completed_count object_store_continuity.uint64 NOT NULL,
  no_local_effect_count object_store_continuity.uint64 NOT NULL,
  adjudicated_no_local_effect_count object_store_continuity.uint64 NOT NULL,
  adjudicated_no_dispatch_count object_store_continuity.uint64 NOT NULL,
  interval_checkpoint_blake3 bytea NOT NULL CHECK (octet_length(interval_checkpoint_blake3) = 32),
  created_at_min_unix_ms bigint NOT NULL CHECK (created_at_min_unix_ms >= 0),
  created_at_max_unix_ms bigint NOT NULL CHECK (created_at_max_unix_ms >= 0),
  closed_at_min_unix_ms bigint NOT NULL CHECK (closed_at_min_unix_ms >= 0),
  closed_at_max_unix_ms bigint NOT NULL CHECK (closed_at_max_unix_ms >= 0),
  pruned_at_min_unix_ms bigint NOT NULL CHECK (pruned_at_min_unix_ms >= 0),
  pruned_at_max_unix_ms bigint NOT NULL CHECK (pruned_at_max_unix_ms >= 0),
  prune_commit_sequence_max object_store_continuity.uint64 NOT NULL,
  covering_snapshot_id uuid NOT NULL,
  covering_snapshot_through_sequence object_store_continuity.uint64 NOT NULL,
  covering_snapshot_authority_lsn pg_lsn NOT NULL,
  covering_snapshot_manifest_blake3 bytea NOT NULL
    CHECK (octet_length(covering_snapshot_manifest_blake3) = 32),
  retirement_proof_blake3 bytea NOT NULL CHECK (octet_length(retirement_proof_blake3) = 32),
  canonical_summary_bytes bytea NOT NULL CHECK (octet_length(canonical_summary_bytes) > 32),
  summary_blake3 bytea NOT NULL CHECK (octet_length(summary_blake3) = 32),
  retired_at_unix_ms bigint NOT NULL CHECK (retired_at_unix_ms >= 0),
  PRIMARY KEY (provider_boundary_id, authority_epoch),
  FOREIGN KEY (provider_boundary_id, authority_epoch)
    REFERENCES object_store_continuity.epoch_counters(provider_boundary_id, authority_epoch),
  FOREIGN KEY (covering_snapshot_id) REFERENCES object_store_continuity.snapshots(snapshot_id),
  CHECK (start_sequence = 1),
  CHECK (final_sequence >= start_sequence),
  CHECK (row_count = final_sequence - start_sequence + 1),
  CHECK (
    completed_count + no_local_effect_count + adjudicated_no_local_effect_count
      + adjudicated_no_dispatch_count = row_count
  ),
  CHECK (octet_length(continuity_contract_revision) BETWEEN 1 AND 1024),
  CHECK (octet_length(continuity_policy_revision) BETWEEN 1 AND 1024),
  CHECK (created_at_min_unix_ms <= created_at_max_unix_ms),
  CHECK (closed_at_min_unix_ms <= closed_at_max_unix_ms),
  CHECK (pruned_at_min_unix_ms <= pruned_at_max_unix_ms),
  CHECK (retired_at_unix_ms >= pruned_at_max_unix_ms),
  CHECK (prune_commit_sequence_max > 0),
  CHECK (covering_snapshot_through_sequence >= final_sequence),
  CHECK (substring(covering_snapshot_id::text FROM 15 FOR 1) = '7'),
  CHECK (substring(covering_snapshot_id::text FROM 20 FOR 1) IN ('8', '9', 'a', 'b'))
);

INSERT INTO object_store_continuity.global_counter(singleton) VALUES (true);

ALTER TABLE object_store_continuity.boundary_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.boundary_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.policies FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.global_counter ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.global_counter FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.boundary_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.boundary_counters FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.epoch_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.epoch_counters FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.cell_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.cell_counters FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.tenant_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.tenant_counters FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.intents FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.transition_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.transition_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.shadow_release_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.shadow_release_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.snapshot_coverages ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.snapshot_coverages FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.pruned_ranges ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.pruned_ranges FORCE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.retired_epoch_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_store_continuity.retired_epoch_summaries FORCE ROW LEVEL SECURITY;

DO $policy$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'boundary_roles', 'policies', 'global_counter', 'boundary_counters', 'epoch_counters', 'cell_counters',
    'tenant_counters', 'intents', 'transition_receipts', 'shadow_release_receipts', 'snapshots',
    'snapshot_coverages', 'pruned_ranges',
    'retired_epoch_summaries'
  ]
  LOOP
    EXECUTE format(
      'CREATE POLICY owner_only ON object_store_continuity.%I USING (current_user = %L) WITH CHECK (current_user = %L)',
      table_name, 'object_dispatch_continuity_owner', 'object_dispatch_continuity_owner'
    );
  END LOOP;
END
$policy$;

REVOKE ALL ON ALL TABLES IN SCHEMA object_store_continuity FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA object_store_continuity FROM PUBLIC;

-- SPDX-License-Identifier: Apache-2.0
-- SECURITY DEFINER contract for ObjectStoreAuthorityContinuityLedger.

CREATE FUNCTION object_store_continuity.clock_unix_ms_v1()
RETURNS bigint
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
$$;

CREATE FUNCTION object_store_continuity.assert_api_revision_v1(api_revision text)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-authority-continuity-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.assert_serializable_write_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF current_setting('transaction_isolation') IS DISTINCT FROM 'serializable'
     OR current_setting('transaction_read_only') IS DISTINCT FROM 'off' THEN
    RAISE EXCEPTION 'SERIALIZABLE_READ_WRITE_TRANSACTION_REQUIRED' USING ERRCODE = '25000';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.assert_runtime_boundary_v1(provider_boundary_id text)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE mapped_boundary text;
BEGIN
  SELECT binding.provider_boundary_id
    INTO mapped_boundary
    FROM object_store_continuity.boundary_roles AS binding
   WHERE binding.login_role = session_user::name;
  IF mapped_boundary IS NULL OR mapped_boundary IS DISTINCT FROM provider_boundary_id THEN
    RAISE EXCEPTION 'BOUNDARY_AUTHORIZATION_MISMATCH' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.assert_reconciler_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_continuity_reconciler' THEN
    RAISE EXCEPTION 'RECONCILER_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.assert_migrator_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_continuity_migrator' THEN
    RAISE EXCEPTION 'MIGRATOR_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.canonical_u32_v1(value integer)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$ SELECT int4send(value) $$;

CREATE FUNCTION object_store_continuity.canonical_u64_v1(value object_store_continuity.uint64)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE remaining numeric(20, 0) := value;
DECLARE answer bytea := decode('0000000000000000', 'hex');
DECLARE index_value integer;
BEGIN
  FOR index_value IN REVERSE 7..0 LOOP
    answer := set_byte(answer, index_value, mod(remaining, 256)::integer);
    remaining := trunc(remaining / 256);
  END LOOP;
  RETURN answer;
END
$$;

CREATE FUNCTION object_store_continuity.canonical_text_v1(value text, maximum_bytes integer)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE payload bytea := convert_to(value, 'UTF8');
BEGIN
  IF octet_length(payload) = 0 OR octet_length(payload) > maximum_bytes THEN
    RAISE EXCEPTION 'CANONICAL_TEXT_LENGTH_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN object_store_continuity.canonical_u32_v1(octet_length(payload)) || payload;
END
$$;

CREATE FUNCTION object_store_continuity.state_code_v1(value text)
RETURNS integer
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT CASE value
    WHEN 'INTENT' THEN 1 WHEN 'BOUND' THEN 2 WHEN 'COMPLETED' THEN 3
    WHEN 'NO_LOCAL_EFFECT' THEN 4 WHEN 'QUARANTINED' THEN 5
    WHEN 'AMBIGUOUS_DISPATCH' THEN 6 WHEN 'ADJUDICATION_PREPARED' THEN 7
    WHEN 'ADJUDICATED_NO_LOCAL_EFFECT' THEN 8 WHEN 'ADJUDICATED_NO_DISPATCH' THEN 9
    ELSE NULL
  END
$$;

CREATE FUNCTION object_store_continuity.ownership_preimage_v1(
  policy_revision text, operation_quota_class text,
  quota_bytes object_store_continuity.uint64, quota_rows object_store_continuity.uint64,
  quota_concurrency object_store_continuity.uint64, provider_boundary_id text,
  authenticated_cell_id text, authenticated_tenant_id text
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT convert_to('object-store-continuity-quota-ownership-v1', 'UTF8') || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(policy_revision, 1024)
    || object_store_continuity.canonical_text_v1(operation_quota_class, 256)
    || object_store_continuity.canonical_u64_v1(quota_bytes)
    || object_store_continuity.canonical_u64_v1(quota_rows)
    || object_store_continuity.canonical_u64_v1(quota_concurrency)
    || object_store_continuity.canonical_text_v1('object-store-continuity-global-v1', 1024)
    || object_store_continuity.canonical_text_v1(provider_boundary_id, 1024)
    || object_store_continuity.canonical_text_v1(authenticated_cell_id, 1024)
    || object_store_continuity.canonical_text_v1(authenticated_tenant_id, 1024)
$$;

CREATE FUNCTION object_store_continuity.row_preimage_v1(
  api_revision text, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64, continuity_seq object_store_continuity.uint64,
  continuity_token_id uuid, intent_kind text, authenticated_cell_id text,
  authenticated_tenant_id text, logical_request_id uuid, attempt_id uuid,
  selected_fingerprint bytea, state text, ownership_state text, quota_ownership_blake3 bytea,
  external_created_at_unix_ms bigint, state_committed_at_unix_ms bigint,
  local_binding_blake3 bytea, terminal_evidence_blake3 bytea, adjudication_kind text
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE state_code integer := object_store_continuity.state_code_v1(state);
DECLARE kind_code integer;
DECLARE fingerprint_tag integer;
DECLARE ownership_code integer;
DECLARE adjudication_code integer;
DECLARE answer bytea;
BEGIN
  kind_code := CASE intent_kind WHEN 'UUID_ADMISSION' THEN 1 WHEN 'DISPATCH_CAS' THEN 2 END;
  fingerprint_tag := CASE intent_kind WHEN 'UUID_ADMISSION' THEN 11 WHEN 'DISPATCH_CAS' THEN 12 END;
  ownership_code := CASE ownership_state WHEN 'SHADOW_RESERVED' THEN 1 WHEN 'OWNERSHIP_RELEASED' THEN 2 END;
  adjudication_code := CASE adjudication_kind WHEN 'NO_LOCAL_EFFECT' THEN 1 WHEN 'NO_DISPATCH' THEN 2 END;
  IF state_code IS NULL OR kind_code IS NULL OR ownership_code IS NULL
     OR octet_length(selected_fingerprint) <> 32 OR octet_length(quota_ownership_blake3) <> 32
     OR external_created_at_unix_ms < 0 OR state_committed_at_unix_ms < 0 THEN
    RAISE EXCEPTION 'ROW_PREIMAGE_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  answer := convert_to('object-store-continuity-row-v1', 'UTF8') || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(api_revision, 1024)
    || object_store_continuity.canonical_text_v1(provider_boundary_id, 1024)
    || object_store_continuity.canonical_u64_v1(authority_epoch)
    || object_store_continuity.canonical_u64_v1(continuity_seq)
    || object_store_continuity.canonical_text_v1(continuity_token_id::text, 1024)
    || object_store_continuity.canonical_u32_v1(kind_code)
    || object_store_continuity.canonical_text_v1(authenticated_cell_id, 1024)
    || object_store_continuity.canonical_text_v1(authenticated_tenant_id, 1024)
    || object_store_continuity.canonical_text_v1(logical_request_id::text, 1024)
    || object_store_continuity.canonical_text_v1(attempt_id::text, 1024)
    || object_store_continuity.canonical_u32_v1(fingerprint_tag)
    || selected_fingerprint
    || object_store_continuity.canonical_u32_v1(state_code)
    || object_store_continuity.canonical_u32_v1(ownership_code)
    || quota_ownership_blake3
    || object_store_continuity.canonical_u64_v1(external_created_at_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(state_committed_at_unix_ms::numeric)
    || object_store_continuity.canonical_u32_v1(CASE WHEN local_binding_blake3 IS NULL THEN 0 ELSE 1 END);
  IF local_binding_blake3 IS NOT NULL THEN
    IF octet_length(local_binding_blake3) <> 32 THEN RAISE EXCEPTION 'INVALID_LOCAL_BINDING_DIGEST'; END IF;
    answer := answer || local_binding_blake3;
  END IF;
  answer := answer
    || object_store_continuity.canonical_u32_v1(CASE WHEN terminal_evidence_blake3 IS NULL THEN 0 ELSE 1 END);
  IF terminal_evidence_blake3 IS NOT NULL THEN
    IF octet_length(terminal_evidence_blake3) <> 32 THEN RAISE EXCEPTION 'INVALID_TERMINAL_EVIDENCE_DIGEST'; END IF;
    answer := answer || terminal_evidence_blake3;
  END IF;
  answer := answer
    || object_store_continuity.canonical_u32_v1(CASE WHEN adjudication_kind IS NULL THEN 0 ELSE 1 END);
  IF adjudication_kind IS NOT NULL THEN
    IF adjudication_code IS NULL THEN RAISE EXCEPTION 'INVALID_ADJUDICATION_KIND'; END IF;
    answer := answer || object_store_continuity.canonical_u32_v1(adjudication_code);
  END IF;
  RETURN answer;
END
$$;

CREATE FUNCTION object_store_continuity.release_preimage_v1(
  release_id uuid, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64, continuity_seq object_store_continuity.uint64,
  continuity_token_id uuid, policy_revision text, ownership_blake3 bytea,
  quota_bytes object_store_continuity.uint64, quota_rows object_store_continuity.uint64,
  quota_concurrency object_store_continuity.uint64, authenticated_cell_id text,
  authenticated_tenant_id text, release_basis_kind text, basis_id text, basis_blake3 bytea,
  released_at_unix_ms bigint, global_counter_revision object_store_continuity.uint64,
  boundary_counter_revision object_store_continuity.uint64,
  cell_counter_revision object_store_continuity.uint64,
  tenant_counter_revision object_store_continuity.uint64
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE basis_code integer;
BEGIN
  basis_code := CASE release_basis_kind
    WHEN 'COVERED_SNAPSHOT' THEN 1 WHEN 'NO_LOCAL_EFFECT' THEN 2
    WHEN 'FINAL_ADJUDICATION' THEN 3 END;
  IF basis_code IS NULL OR octet_length(ownership_blake3) <> 32
     OR octet_length(basis_blake3) <> 32 OR released_at_unix_ms < 0 THEN
    RAISE EXCEPTION 'RELEASE_PREIMAGE_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN convert_to('object-store-continuity-shadow-release-v1', 'UTF8') || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(release_id::text, 1024)
    || object_store_continuity.canonical_text_v1(provider_boundary_id, 1024)
    || object_store_continuity.canonical_u64_v1(authority_epoch)
    || object_store_continuity.canonical_u64_v1(continuity_seq)
    || object_store_continuity.canonical_text_v1(continuity_token_id::text, 1024)
    || object_store_continuity.canonical_text_v1(policy_revision, 1024)
    || ownership_blake3
    || object_store_continuity.canonical_u64_v1(quota_bytes)
    || object_store_continuity.canonical_u64_v1(quota_rows)
    || object_store_continuity.canonical_u64_v1(quota_concurrency)
    || object_store_continuity.canonical_text_v1('object-store-continuity-global-v1', 1024)
    || object_store_continuity.canonical_text_v1(provider_boundary_id, 1024)
    || object_store_continuity.canonical_text_v1(authenticated_cell_id, 1024)
    || object_store_continuity.canonical_text_v1(authenticated_tenant_id, 1024)
    || object_store_continuity.canonical_u32_v1(basis_code)
    || object_store_continuity.canonical_text_v1(basis_id, 1024)
    || basis_blake3
    || object_store_continuity.canonical_u32_v1(0)
    || object_store_continuity.canonical_u64_v1(released_at_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(global_counter_revision)
    || object_store_continuity.canonical_u64_v1(boundary_counter_revision)
    || object_store_continuity.canonical_u64_v1(cell_counter_revision)
    || object_store_continuity.canonical_u64_v1(tenant_counter_revision);
END
$$;

CREATE FUNCTION object_store_continuity.snapshot_coverage_preimage_v1(
  snapshot_id uuid, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64, continuity_seq object_store_continuity.uint64,
  continuity_token_id uuid, local_binding_blake3 bytea, local_state_blake3 bytea,
  local_quota_ownership_blake3 bytea, local_counter_revision object_store_continuity.uint64,
  authority_lsn pg_lsn, manifest_blake3 bytea, recorded_at_unix_ms bigint
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF octet_length(local_binding_blake3) <> 32 OR octet_length(local_state_blake3) <> 32
     OR octet_length(local_quota_ownership_blake3) <> 32
     OR octet_length(manifest_blake3) <> 32 OR recorded_at_unix_ms < 0 THEN
    RAISE EXCEPTION 'SNAPSHOT_COVERAGE_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN convert_to('object-store-continuity-snapshot-coverage-v1', 'UTF8') || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(snapshot_id::text, 1024)
    || object_store_continuity.canonical_text_v1(provider_boundary_id, 1024)
    || object_store_continuity.canonical_u64_v1(authority_epoch)
    || object_store_continuity.canonical_u64_v1(continuity_seq)
    || object_store_continuity.canonical_text_v1(continuity_token_id::text, 1024)
    || local_binding_blake3
    || local_state_blake3
    || local_quota_ownership_blake3
    || object_store_continuity.canonical_u64_v1(local_counter_revision)
    || object_store_continuity.canonical_text_v1(authority_lsn::text, 1024)
    || manifest_blake3
    || object_store_continuity.canonical_u64_v1(recorded_at_unix_ms::numeric);
END
$$;

CREATE FUNCTION object_store_continuity.snapshot_preimage_v1(
  snapshot_id uuid, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  through_continuity_seq object_store_continuity.uint64,
  authority_lsn pg_lsn, manifest_blake3 bytea, recorded_at_unix_ms bigint
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF authority_epoch = 0 OR through_continuity_seq = 0
     OR octet_length(manifest_blake3) <> 32 OR recorded_at_unix_ms < 0 THEN
    RAISE EXCEPTION 'SNAPSHOT_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN convert_to('object-store-continuity-snapshot-v1', 'UTF8') || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(snapshot_id::text, 1024)
    || object_store_continuity.canonical_text_v1(provider_boundary_id, 1024)
    || object_store_continuity.canonical_u64_v1(authority_epoch)
    || object_store_continuity.canonical_u64_v1(through_continuity_seq)
    || object_store_continuity.canonical_text_v1(authority_lsn::text, 1024)
    || manifest_blake3
    || object_store_continuity.canonical_u64_v1(recorded_at_unix_ms::numeric);
END
$$;

CREATE FUNCTION object_store_continuity.transition_receipt_preimage_v1(
  receipt_value object_store_continuity.transition_receipts
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE answer bytea;
BEGIN
  IF octet_length(receipt_value.expected_prior_row_blake3) <> 32
     OR octet_length(receipt_value.next_row_blake3) <> 32
     OR receipt_value.committed_at_unix_ms < 0 THEN
    RAISE EXCEPTION 'TRANSITION_RECEIPT_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  answer := convert_to('object-store-continuity-transition-receipt-v1', 'UTF8')
    || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(receipt_value.provider_boundary_id, 1024)
    || object_store_continuity.canonical_u64_v1(receipt_value.authority_epoch)
    || object_store_continuity.canonical_u64_v1(receipt_value.continuity_seq)
    || object_store_continuity.canonical_text_v1(receipt_value.continuity_token_id::text, 1024)
    || object_store_continuity.canonical_text_v1(receipt_value.actor, 32)
    || object_store_continuity.canonical_text_v1(receipt_value.command_kind, 256)
    || object_store_continuity.canonical_text_v1(receipt_value.prior_state, 64)
    || object_store_continuity.canonical_text_v1(receipt_value.next_state, 64)
    || object_store_continuity.canonical_text_v1(receipt_value.next_ownership_state, 64)
    || receipt_value.expected_prior_row_blake3
    || receipt_value.next_row_blake3;
  answer := answer
    || object_store_continuity.canonical_u32_v1(
      CASE WHEN receipt_value.local_binding_blake3 IS NULL THEN 0 ELSE 1 END
    );
  IF receipt_value.local_binding_blake3 IS NOT NULL THEN
    answer := answer || receipt_value.local_binding_blake3;
  END IF;
  answer := answer
    || object_store_continuity.canonical_u32_v1(
      CASE WHEN receipt_value.terminal_evidence_blake3 IS NULL THEN 0 ELSE 1 END
    );
  IF receipt_value.terminal_evidence_blake3 IS NOT NULL THEN
    answer := answer || receipt_value.terminal_evidence_blake3;
  END IF;
  answer := answer
    || object_store_continuity.canonical_u32_v1(
      CASE WHEN receipt_value.adjudication_kind IS NULL THEN 0 ELSE 1 END
    );
  IF receipt_value.adjudication_kind IS NOT NULL THEN
    answer := answer || object_store_continuity.canonical_text_v1(
      receipt_value.adjudication_kind, 64
    );
  END IF;
  answer := answer
    || object_store_continuity.canonical_u32_v1(
      CASE WHEN receipt_value.release_id IS NULL THEN 0 ELSE 1 END
    );
  IF receipt_value.release_id IS NOT NULL THEN
    answer := answer
      || object_store_continuity.canonical_text_v1(receipt_value.release_id::text, 1024)
      || object_store_continuity.canonical_text_v1(receipt_value.release_basis_kind, 64)
      || object_store_continuity.canonical_text_v1(receipt_value.release_basis_id, 1024)
      || receipt_value.release_basis_blake3;
  END IF;
  RETURN answer
    || object_store_continuity.canonical_u64_v1(receipt_value.committed_at_unix_ms::numeric);
END
$$;

-- The authority must install a reviewed BLAKE3 provider exposing public.blake3(bytea).
-- Absence or a non-32-byte answer fails closed. Readiness pins its owner, ACL and body digest.
CREATE FUNCTION object_store_continuity.blake3_v1(payload bytea)
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE answer bytea;
BEGIN
  IF to_regprocedure('public.blake3(bytea)') IS NULL THEN
    RAISE EXCEPTION 'BLAKE3_PROVIDER_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  EXECUTE 'SELECT public.blake3($1)' INTO STRICT answer USING payload;
  IF octet_length(answer) <> 32 THEN
    RAISE EXCEPTION 'BLAKE3_PROVIDER_INVALID_RESULT' USING ERRCODE = '55000';
  END IF;
  RETURN answer;
END
$$;

CREATE FUNCTION object_store_continuity.assert_blake3_v1(payload bytea, expected bytea)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF expected IS NULL OR octet_length(expected) <> 32
     OR object_store_continuity.blake3_v1(payload) IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'BLAKE3_MISMATCH' USING ERRCODE = '22000';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.assert_policy_materialization_v1(
  canonical_policy_bytes bytea,
  max_rows_global object_store_continuity.uint64,
  max_bytes_global object_store_continuity.uint64,
  max_rows_per_boundary object_store_continuity.uint64,
  max_bytes_per_boundary object_store_continuity.uint64,
  low_water_reserve_rows object_store_continuity.uint64,
  low_water_reserve_bytes object_store_continuity.uint64,
  max_row_bytes object_store_continuity.uint64,
  max_pruned_ranges_per_boundary object_store_continuity.uint64,
  max_pruned_range_bytes object_store_continuity.uint64,
  archive_batch_rows object_store_continuity.uint64,
  prune_batch_rows object_store_continuity.uint64,
  prune_interval_ms object_store_continuity.uint64,
  max_epoch_high_water_bytes object_store_continuity.uint64
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE accepted boolean;
BEGIN
  IF to_regprocedure(
    'public.object_store_continuity_validate_policy_v1(bytea,numeric,numeric,numeric,numeric,numeric,numeric,numeric,numeric,numeric,numeric,numeric,numeric,numeric)'
  ) IS NULL THEN
    RAISE EXCEPTION 'TYPED_POLICY_VALIDATOR_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  EXECUTE
    'SELECT public.object_store_continuity_validate_policy_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)'
    INTO STRICT accepted
    USING canonical_policy_bytes, max_rows_global::numeric, max_bytes_global::numeric,
      max_rows_per_boundary::numeric, max_bytes_per_boundary::numeric,
      low_water_reserve_rows::numeric, low_water_reserve_bytes::numeric, max_row_bytes::numeric,
      max_pruned_ranges_per_boundary::numeric, max_pruned_range_bytes::numeric,
      archive_batch_rows::numeric, prune_batch_rows::numeric, prune_interval_ms::numeric,
      max_epoch_high_water_bytes::numeric;
  IF accepted IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'POLICY_MATERIALIZATION_MISMATCH' USING ERRCODE = '22000';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.apply_storage_mutation_v1(
  provider_boundary_id text, mutation_mode text,
  deleted_rows object_store_continuity.uint64,
  deleted_bytes object_store_continuity.uint64,
  inserted_rows object_store_continuity.uint64,
  inserted_bytes object_store_continuity.uint64
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE policy object_store_continuity.policies%ROWTYPE;
DECLARE global_value object_store_continuity.global_counter%ROWTYPE;
DECLARE boundary_value object_store_continuity.boundary_counters%ROWTYPE;
DECLARE global_rows_after numeric;
DECLARE global_bytes_after numeric;
DECLARE boundary_rows_after numeric;
DECLARE boundary_bytes_after numeric;
DECLARE increases_rows boolean;
DECLARE increases_bytes boolean;
BEGIN
  IF mutation_mode NOT IN ('ADMISSION', 'MAINTENANCE') THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_MUTATION_MODE_INVALID' USING ERRCODE = '22023';
  END IF;
  IF mutation_mode = 'ADMISSION' AND (deleted_rows <> 0 OR deleted_bytes <> 0) THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_ADMISSION_DELETE_FORBIDDEN' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO policy FROM object_store_continuity.policies WHERE singleton FOR SHARE;
  SELECT * INTO global_value FROM object_store_continuity.global_counter WHERE singleton FOR UPDATE;
  SELECT * INTO boundary_value FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = apply_storage_mutation_v1.provider_boundary_id
   FOR UPDATE;
  IF policy.singleton IS NULL OR global_value.singleton IS NULL
     OR boundary_value.provider_boundary_id IS NULL THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_COUNTER_NAMESPACE_MISSING' USING ERRCODE = '55000';
  END IF;
  IF global_value.continuity_storage_rows < deleted_rows
     OR global_value.continuity_storage_bytes < deleted_bytes
     OR boundary_value.continuity_storage_rows < deleted_rows
     OR boundary_value.continuity_storage_bytes < deleted_bytes THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_COUNTER_UNDERFLOW' USING ERRCODE = '22000';
  END IF;
  global_rows_after := global_value.continuity_storage_rows - deleted_rows + inserted_rows;
  global_bytes_after := global_value.continuity_storage_bytes - deleted_bytes + inserted_bytes;
  boundary_rows_after := boundary_value.continuity_storage_rows - deleted_rows + inserted_rows;
  boundary_bytes_after := boundary_value.continuity_storage_bytes - deleted_bytes + inserted_bytes;
  IF global_rows_after > 18446744073709551615
     OR global_bytes_after > 18446744073709551615
     OR boundary_rows_after > 18446744073709551615
     OR boundary_bytes_after > 18446744073709551615 THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_COUNTER_OVERFLOW' USING ERRCODE = '22003';
  END IF;
  increases_rows := global_rows_after > global_value.continuity_storage_rows
    OR boundary_rows_after > boundary_value.continuity_storage_rows;
  increases_bytes := global_bytes_after > global_value.continuity_storage_bytes
    OR boundary_bytes_after > boundary_value.continuity_storage_bytes;
  IF (global_rows_after > policy.max_rows_global
       OR boundary_rows_after > policy.max_rows_per_boundary) AND increases_rows THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_ROW_CAPACITY_EXHAUSTED' USING ERRCODE = '53000';
  END IF;
  IF (global_bytes_after > policy.max_bytes_global
       OR boundary_bytes_after > policy.max_bytes_per_boundary) AND increases_bytes THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_BYTE_CAPACITY_EXHAUSTED' USING ERRCODE = '53000';
  END IF;
  IF mutation_mode = 'ADMISSION' AND (
    global_rows_after + policy.low_water_reserve_rows > policy.max_rows_global
    OR global_bytes_after + policy.low_water_reserve_bytes > policy.max_bytes_global
    OR boundary_rows_after + policy.low_water_reserve_rows > policy.max_rows_per_boundary
    OR boundary_bytes_after + policy.low_water_reserve_bytes > policy.max_bytes_per_boundary
  ) THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_LOW_WATER_EXHAUSTED' USING ERRCODE = '53000';
  END IF;
  UPDATE object_store_continuity.global_counter SET
    continuity_storage_rows = global_rows_after,
    continuity_storage_bytes = global_bytes_after,
    continuity_storage_counter_revision = continuity_storage_counter_revision + 1
  WHERE singleton;
  UPDATE object_store_continuity.boundary_counters SET
    continuity_storage_rows = boundary_rows_after,
    continuity_storage_bytes = boundary_bytes_after,
    continuity_storage_counter_revision = continuity_storage_counter_revision + 1
  WHERE object_store_continuity.boundary_counters.provider_boundary_id =
    apply_storage_mutation_v1.provider_boundary_id;
END
$$;

CREATE FUNCTION object_store_continuity.pruned_range_preimage_v2(
  range_value object_store_continuity.pruned_ranges
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF range_value.start_sequence = 0 OR range_value.end_sequence < range_value.start_sequence
     OR range_value.row_count IS DISTINCT FROM
       range_value.end_sequence - range_value.start_sequence + 1
     OR range_value.completed_count + range_value.no_local_effect_count
       + range_value.adjudicated_no_local_effect_count
       + range_value.adjudicated_no_dispatch_count IS DISTINCT FROM range_value.row_count
     OR range_value.created_at_min_unix_ms < 0
     OR range_value.created_at_max_unix_ms < range_value.created_at_min_unix_ms
     OR range_value.closed_at_min_unix_ms < 0
     OR range_value.closed_at_max_unix_ms < range_value.closed_at_min_unix_ms
     OR range_value.prune_commit_sequence_min = 0
     OR range_value.prune_commit_sequence_max < range_value.prune_commit_sequence_min
     OR range_value.pruned_at_min_unix_ms < 0
     OR range_value.pruned_at_max_unix_ms < range_value.pruned_at_min_unix_ms THEN
    RAISE EXCEPTION 'PRUNED_RANGE_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN convert_to('object-store-continuity-pruned-interval-v2', 'UTF8') || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(range_value.provider_boundary_id, 1024)
    || object_store_continuity.canonical_u64_v1(range_value.authority_epoch)
    || object_store_continuity.canonical_u64_v1(range_value.start_sequence)
    || object_store_continuity.canonical_u64_v1(range_value.end_sequence)
    || object_store_continuity.canonical_u64_v1(range_value.row_count)
    || object_store_continuity.canonical_text_v1(range_value.api_revision, 1024)
    || object_store_continuity.canonical_text_v1(range_value.schema_revision, 1024)
    || object_store_continuity.canonical_text_v1(range_value.continuity_contract_revision, 1024)
    || object_store_continuity.canonical_text_v1(range_value.continuity_policy_revision, 1024)
    || object_store_continuity.canonical_u64_v1(range_value.completed_count)
    || object_store_continuity.canonical_u64_v1(range_value.no_local_effect_count)
    || object_store_continuity.canonical_u64_v1(range_value.adjudicated_no_local_effect_count)
    || object_store_continuity.canonical_u64_v1(range_value.adjudicated_no_dispatch_count)
    || object_store_continuity.canonical_u64_v1(range_value.canonical_row_bytes_sum)
    || object_store_continuity.canonical_u64_v1(range_value.canonical_row_bytes_min)
    || object_store_continuity.canonical_u64_v1(range_value.canonical_row_bytes_max)
    || object_store_continuity.canonical_u64_v1(range_value.quota_rows_sum)
    || object_store_continuity.canonical_u64_v1(range_value.quota_rows_min)
    || object_store_continuity.canonical_u64_v1(range_value.quota_rows_max)
    || object_store_continuity.canonical_u64_v1(range_value.quota_bytes_sum)
    || object_store_continuity.canonical_u64_v1(range_value.quota_bytes_min)
    || object_store_continuity.canonical_u64_v1(range_value.quota_bytes_max)
    || object_store_continuity.canonical_u64_v1(range_value.quota_concurrency_sum)
    || object_store_continuity.canonical_u64_v1(range_value.quota_concurrency_min)
    || object_store_continuity.canonical_u64_v1(range_value.quota_concurrency_max)
    || object_store_continuity.canonical_u64_v1(range_value.created_at_min_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(range_value.created_at_max_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(range_value.closed_at_min_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(range_value.closed_at_max_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(range_value.prune_commit_sequence_min)
    || object_store_continuity.canonical_u64_v1(range_value.prune_commit_sequence_max)
    || object_store_continuity.canonical_u64_v1(range_value.pruned_at_min_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(range_value.pruned_at_max_unix_ms::numeric);
END
$$;

-- The deployment pins this validator's owner, ACL and body digest. It authenticates the retained
-- local compact binding and proves that no live local dependency still needs the external detail.
CREATE FUNCTION object_store_continuity.assert_archive_eligibility_v1(
  archive_proof_bytes bytea, archive_proof_blake3 bytea,
  intent_value object_store_continuity.intents, release_receipt_blake3 bytea
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE accepted boolean;
BEGIN
  IF octet_length(archive_proof_bytes) NOT BETWEEN 1 AND 1048576 THEN
    RAISE EXCEPTION 'ARCHIVE_PROOF_SIZE_INVALID' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_continuity.assert_blake3_v1(archive_proof_bytes, archive_proof_blake3);
  IF to_regprocedure(
    'public.object_store_continuity_validate_archive_v1(bytea,bytea,text,numeric,numeric,uuid,uuid,uuid,text,bytea,bytea,bytea,bytea)'
  ) IS NULL THEN
    RAISE EXCEPTION 'ARCHIVE_ELIGIBILITY_VALIDATOR_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  EXECUTE
    'SELECT public.object_store_continuity_validate_archive_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)'
    INTO STRICT accepted
    USING archive_proof_bytes, archive_proof_blake3, intent_value.provider_boundary_id,
      intent_value.authority_epoch::numeric, intent_value.continuity_seq::numeric,
      intent_value.continuity_token_id, intent_value.logical_request_id, intent_value.attempt_id,
      intent_value.intent_kind,
      coalesce(intent_value.put_reservation_fingerprint, intent_value.canonical_descriptor_fingerprint),
      intent_value.local_binding_blake3, intent_value.row_blake3, release_receipt_blake3;
  IF accepted IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'ARCHIVE_LOCAL_DEPENDENCY_OR_BINDING_MISMATCH' USING ERRCODE = '22000';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.retired_epoch_summary_preimage_v2(
  summary_value object_store_continuity.retired_epoch_summaries
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF summary_value.start_sequence <> 1
     OR summary_value.final_sequence < summary_value.start_sequence
     OR summary_value.row_count IS DISTINCT FROM
       summary_value.final_sequence - summary_value.start_sequence + 1
     OR summary_value.completed_count + summary_value.no_local_effect_count
       + summary_value.adjudicated_no_local_effect_count
       + summary_value.adjudicated_no_dispatch_count IS DISTINCT FROM summary_value.row_count
     OR summary_value.prune_commit_sequence_max = 0
     OR summary_value.covering_snapshot_through_sequence < summary_value.final_sequence
     OR summary_value.retired_at_unix_ms < summary_value.pruned_at_max_unix_ms THEN
    RAISE EXCEPTION 'RETIRED_EPOCH_SUMMARY_ARGUMENT_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN convert_to('object-store-continuity-retired-epoch-v2', 'UTF8') || decode('00', 'hex')
    || object_store_continuity.canonical_text_v1(summary_value.provider_boundary_id, 1024)
    || object_store_continuity.canonical_u64_v1(summary_value.authority_epoch)
    || object_store_continuity.canonical_u64_v1(summary_value.start_sequence)
    || object_store_continuity.canonical_u64_v1(summary_value.final_sequence)
    || object_store_continuity.canonical_u64_v1(summary_value.row_count)
    || object_store_continuity.canonical_text_v1(summary_value.api_revision, 1024)
    || object_store_continuity.canonical_text_v1(summary_value.schema_revision, 1024)
    || object_store_continuity.canonical_text_v1(summary_value.continuity_contract_revision, 1024)
    || object_store_continuity.canonical_text_v1(summary_value.continuity_policy_revision, 1024)
    || object_store_continuity.canonical_u64_v1(summary_value.completed_count)
    || object_store_continuity.canonical_u64_v1(summary_value.no_local_effect_count)
    || object_store_continuity.canonical_u64_v1(summary_value.adjudicated_no_local_effect_count)
    || object_store_continuity.canonical_u64_v1(summary_value.adjudicated_no_dispatch_count)
    || summary_value.interval_checkpoint_blake3
    || object_store_continuity.canonical_u64_v1(summary_value.created_at_min_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(summary_value.created_at_max_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(summary_value.closed_at_min_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(summary_value.closed_at_max_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(summary_value.pruned_at_min_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(summary_value.pruned_at_max_unix_ms::numeric)
    || object_store_continuity.canonical_u64_v1(summary_value.prune_commit_sequence_max)
    || object_store_continuity.canonical_text_v1(summary_value.covering_snapshot_id::text, 1024)
    || object_store_continuity.canonical_u64_v1(summary_value.covering_snapshot_through_sequence)
    || object_store_continuity.canonical_text_v1(summary_value.covering_snapshot_authority_lsn::text, 1024)
    || summary_value.covering_snapshot_manifest_blake3
    || summary_value.retirement_proof_blake3
    || object_store_continuity.canonical_u64_v1(summary_value.retired_at_unix_ms::numeric);
END
$$;

CREATE FUNCTION object_store_continuity.assert_epoch_retirement_eligibility_v2(
  retirement_proof_bytes bytea, retirement_proof_blake3 bytea,
  provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq_high_water object_store_continuity.uint64,
  interval_checkpoint_blake3 bytea, covering_snapshot_id uuid,
  covering_snapshot_manifest_blake3 bytea,
  prune_commit_sequence_high_water object_store_continuity.uint64
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE accepted boolean;
BEGIN
  IF octet_length(retirement_proof_bytes) NOT BETWEEN 1 AND 1048576 THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_PROOF_SIZE_INVALID' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_continuity.assert_blake3_v1(
    retirement_proof_bytes, retirement_proof_blake3
  );
  IF to_regprocedure(
    'public.object_store_continuity_validate_epoch_retirement_v2(bytea,bytea,text,numeric,numeric,bytea,uuid,bytea,numeric)'
  ) IS NULL THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_VALIDATOR_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  EXECUTE
    'SELECT public.object_store_continuity_validate_epoch_retirement_v2($1,$2,$3,$4,$5,$6,$7,$8,$9)'
    INTO STRICT accepted
    USING retirement_proof_bytes, retirement_proof_blake3, provider_boundary_id,
      authority_epoch::numeric, continuity_seq_high_water::numeric,
      interval_checkpoint_blake3, covering_snapshot_id, covering_snapshot_manifest_blake3,
      prune_commit_sequence_high_water::numeric;
  IF accepted IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_PROOF_REJECTED' USING ERRCODE = '22000';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.assert_retired_epoch_summary_v2(
  summary_value object_store_continuity.retired_epoch_summaries,
  epoch_value object_store_continuity.epoch_counters,
  snapshot_value object_store_continuity.snapshots
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NOT epoch_value.retired
     OR summary_value.provider_boundary_id IS DISTINCT FROM epoch_value.provider_boundary_id
     OR summary_value.authority_epoch IS DISTINCT FROM epoch_value.authority_epoch
     OR summary_value.api_revision IS DISTINCT FROM epoch_value.api_revision
     OR summary_value.schema_revision IS DISTINCT FROM epoch_value.schema_revision
     OR summary_value.continuity_contract_revision IS DISTINCT FROM
       epoch_value.continuity_contract_revision
     OR summary_value.continuity_policy_revision IS DISTINCT FROM epoch_value.continuity_policy_revision
     OR summary_value.start_sequence <> 1
     OR summary_value.final_sequence IS DISTINCT FROM epoch_value.continuity_seq_high_water
     OR summary_value.row_count IS DISTINCT FROM epoch_value.continuity_seq_high_water
     OR summary_value.prune_commit_sequence_max IS DISTINCT FROM
       epoch_value.prune_commit_sequence_high_water
     OR summary_value.covering_snapshot_id IS DISTINCT FROM snapshot_value.snapshot_id
     OR summary_value.provider_boundary_id IS DISTINCT FROM snapshot_value.provider_boundary_id
     OR summary_value.authority_epoch IS DISTINCT FROM snapshot_value.authority_epoch
     OR summary_value.covering_snapshot_through_sequence IS DISTINCT FROM
       snapshot_value.through_continuity_seq
     OR summary_value.covering_snapshot_authority_lsn IS DISTINCT FROM snapshot_value.authority_lsn
     OR summary_value.covering_snapshot_manifest_blake3 IS DISTINCT FROM snapshot_value.manifest_blake3
     OR summary_value.retired_at_unix_ms < summary_value.pruned_at_max_unix_ms THEN
    RAISE EXCEPTION 'RETIRED_EPOCH_SUMMARY_CHECKPOINT_MISMATCH' USING ERRCODE = '22000';
  END IF;
  PERFORM object_store_continuity.assert_blake3_v1(
    object_store_continuity.retired_epoch_summary_preimage_v2(summary_value),
    summary_value.summary_blake3
  );
  IF summary_value.canonical_summary_bytes IS DISTINCT FROM
      object_store_continuity.retired_epoch_summary_preimage_v2(summary_value)
        || summary_value.summary_blake3 THEN
    RAISE EXCEPTION 'RETIRED_EPOCH_SUMMARY_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.assert_pruned_range_nonoverlap_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP IS DISTINCT FROM 'INSERT' THEN
    RAISE EXCEPTION 'PRUNED_RANGE_ROWS_ARE_IMMUTABLE' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM object_store_continuity.pruned_ranges AS existing
     WHERE existing.provider_boundary_id = NEW.provider_boundary_id
       AND existing.authority_epoch = NEW.authority_epoch
       AND existing.start_sequence <= NEW.end_sequence
       AND existing.end_sequence >= NEW.start_sequence
  ) THEN
    RAISE EXCEPTION 'PRUNED_RANGE_OVERLAP' USING ERRCODE = '23P01';
  END IF;
  PERFORM object_store_continuity.assert_blake3_v1(
    object_store_continuity.pruned_range_preimage_v2(NEW), NEW.interval_blake3
  );
  IF NEW.canonical_interval_bytes IS DISTINCT FROM
      object_store_continuity.pruned_range_preimage_v2(NEW) || NEW.interval_blake3 THEN
    RAISE EXCEPTION 'PRUNED_RANGE_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER pruned_ranges_nonoverlap_v1
BEFORE INSERT OR UPDATE ON object_store_continuity.pruned_ranges
FOR EACH ROW EXECUTE FUNCTION object_store_continuity.assert_pruned_range_nonoverlap_v1();

CREATE FUNCTION object_store_continuity.assert_stored_row_v1(
  stored object_store_continuity.intents
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE ownership_preimage bytea;
DECLARE ownership_digest bytea;
DECLARE row_preimage bytea;
DECLARE row_digest bytea;
DECLARE selected_fingerprint bytea;
BEGIN
  ownership_preimage := object_store_continuity.ownership_preimage_v1(
    stored.continuity_policy_revision, stored.operation_quota_class, stored.quota_bytes,
    stored.quota_rows, stored.quota_concurrency, stored.provider_boundary_id,
    stored.authenticated_cell_id, stored.authenticated_tenant_id
  );
  ownership_digest := object_store_continuity.blake3_v1(ownership_preimage);
  IF stored.quota_ownership_blake3 IS DISTINCT FROM ownership_digest
     OR stored.quota_ownership_bytes IS DISTINCT FROM ownership_preimage || ownership_digest THEN
    RAISE EXCEPTION 'STORED_OWNERSHIP_DIGEST_MISMATCH' USING ERRCODE = 'XX001';
  END IF;
  selected_fingerprint := coalesce(
    stored.put_reservation_fingerprint, stored.canonical_descriptor_fingerprint
  );
  row_preimage := object_store_continuity.row_preimage_v1(
    stored.api_revision, stored.provider_boundary_id, stored.authority_epoch,
    stored.continuity_seq, stored.continuity_token_id, stored.intent_kind,
    stored.authenticated_cell_id, stored.authenticated_tenant_id, stored.logical_request_id,
    stored.attempt_id, selected_fingerprint, stored.state, stored.ownership_state,
    stored.quota_ownership_blake3, stored.external_created_at_unix_ms,
    stored.state_committed_at_unix_ms, stored.local_binding_blake3,
    stored.terminal_evidence_blake3, stored.adjudication_kind
  );
  row_digest := object_store_continuity.blake3_v1(row_preimage);
  IF stored.row_blake3 IS DISTINCT FROM row_digest
     OR stored.canonical_row_bytes IS DISTINCT FROM row_preimage || row_digest THEN
    RAISE EXCEPTION 'STORED_ROW_DIGEST_MISMATCH' USING ERRCODE = 'XX001';
  END IF;
END
$$;

CREATE FUNCTION object_store_continuity.uuid_v7_unix_ms_v1(value uuid)
RETURNS bigint
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE raw bytea;
BEGIN
  IF substring(value::text FROM 15 FOR 1) <> '7'
     OR substring(value::text FROM 20 FOR 1) NOT IN ('8', '9', 'a', 'b') THEN
    RAISE EXCEPTION 'INVALID_UUIDV7' USING ERRCODE = '22023';
  END IF;
  raw := decode(substring(replace(value::text, '-', '') FROM 1 FOR 12), 'hex');
  RETURN (get_byte(raw, 0)::bigint << 40)
       | (get_byte(raw, 1)::bigint << 32)
       | (get_byte(raw, 2)::bigint << 24)
       | (get_byte(raw, 3)::bigint << 16)
       | (get_byte(raw, 4)::bigint << 8)
       | get_byte(raw, 5)::bigint;
END
$$;

CREATE FUNCTION object_store_continuity.result_v1(
  row_value object_store_continuity.intents,
  result_code text
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT ROW(
    result_code,
    row_value.state,
    row_value.ownership_state,
    row_value.authority_epoch,
    row_value.continuity_seq,
    row_value.continuity_token_id,
    row_value.row_blake3,
    row_value.state_committed_at_unix_ms
  )::object_store_continuity.procedure_result_v1
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_get_by_token_v1(
  api_revision text,
  provider_boundary_id text,
  continuity_token_id uuid
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_continuity.intents%ROWTYPE;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  IF session_user = 'object_dispatch_continuity_reconciler' THEN
    PERFORM object_store_continuity.assert_reconciler_v1();
  ELSE
    PERFORM object_store_continuity.assert_runtime_boundary_v1(provider_boundary_id);
  END IF;
  SELECT * INTO stored
    FROM object_store_continuity.intents AS intent
   WHERE intent.continuity_token_id = object_store_continuity_get_by_token_v1.continuity_token_id
     AND intent.provider_boundary_id = object_store_continuity_get_by_token_v1.provider_boundary_id;
  IF NOT FOUND THEN
    RETURN ROW('NOT_FOUND', NULL, NULL, NULL, NULL, continuity_token_id, NULL,
      object_store_continuity.clock_unix_ms_v1())::object_store_continuity.procedure_result_v1;
  END IF;
  PERFORM object_store_continuity.assert_stored_row_v1(stored);
  RETURN object_store_continuity.result_v1(stored, 'FOUND');
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_begin_v1(
  api_revision text,
  expected_current_epoch object_store_continuity.uint64,
  continuity_token_id uuid,
  provider_boundary_id text,
  intent_kind text,
  authenticated_cell_id text,
  authenticated_tenant_id text,
  logical_request_id uuid,
  attempt_id uuid,
  selected_fingerprint bytea,
  expected_policy_revision text,
  operation_quota_class text,
  requested_rows object_store_continuity.uint64,
  requested_bytes object_store_continuity.uint64,
  requested_concurrency object_store_continuity.uint64,
  retention_deadline_unix_ms bigint
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_continuity.intents%ROWTYPE;
DECLARE boundary object_store_continuity.boundary_counters%ROWTYPE;
DECLARE epoch_value object_store_continuity.epoch_counters%ROWTYPE;
DECLARE policy object_store_continuity.policies%ROWTYPE;
DECLARE global_value object_store_continuity.global_counter%ROWTYPE;
DECLARE committed_at bigint;
DECLARE token_unix_ms bigint;
DECLARE allocated_seq object_store_continuity.uint64;
DECLARE ownership_preimage bytea;
DECLARE ownership_digest bytea;
DECLARE ownership_bytes bytea;
DECLARE row_preimage bytea;
DECLARE row_digest bytea;
DECLARE row_bytes bytea;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_runtime_boundary_v1(provider_boundary_id);
  IF intent_kind NOT IN ('UUID_ADMISSION', 'DISPATCH_CAS')
     OR selected_fingerprint IS NULL OR octet_length(selected_fingerprint) <> 32
     OR (requested_rows = 0 AND requested_bytes = 0 AND requested_concurrency = 0) THEN
    RAISE EXCEPTION 'INVALID_BEGIN_ARGUMENT' USING ERRCODE = '22023';
  END IF;

  -- Token lookup precedes age rejection so an old committed token remains exactly replayable.
  SELECT * INTO stored
    FROM object_store_continuity.intents AS intent
   WHERE intent.continuity_token_id = object_store_continuity_begin_v1.continuity_token_id
   FOR UPDATE;
  IF FOUND THEN
    PERFORM object_store_continuity.assert_stored_row_v1(stored);
    IF stored.provider_boundary_id IS DISTINCT FROM provider_boundary_id
       OR stored.authority_epoch IS DISTINCT FROM expected_current_epoch
       OR stored.intent_kind IS DISTINCT FROM intent_kind
       OR stored.authenticated_cell_id IS DISTINCT FROM authenticated_cell_id
       OR stored.authenticated_tenant_id IS DISTINCT FROM authenticated_tenant_id
       OR stored.logical_request_id IS DISTINCT FROM logical_request_id
       OR stored.attempt_id IS DISTINCT FROM attempt_id
       OR coalesce(stored.put_reservation_fingerprint, stored.canonical_descriptor_fingerprint)
          IS DISTINCT FROM selected_fingerprint
       OR stored.continuity_policy_revision IS DISTINCT FROM expected_policy_revision
       OR stored.operation_quota_class IS DISTINCT FROM operation_quota_class
       OR stored.quota_rows IS DISTINCT FROM requested_rows
       OR stored.quota_bytes IS DISTINCT FROM requested_bytes
       OR stored.quota_concurrency IS DISTINCT FROM requested_concurrency
       OR stored.retention_deadline_unix_ms IS DISTINCT FROM retention_deadline_unix_ms THEN
      RAISE EXCEPTION 'TOKEN_ARGUMENT_MISMATCH' USING ERRCODE = '23505';
    END IF;
    RETURN object_store_continuity.result_v1(stored, 'REPLAY');
  END IF;

  committed_at := object_store_continuity.clock_unix_ms_v1();
  token_unix_ms := object_store_continuity.uuid_v7_unix_ms_v1(continuity_token_id);
  PERFORM object_store_continuity.uuid_v7_unix_ms_v1(logical_request_id);
  PERFORM object_store_continuity.uuid_v7_unix_ms_v1(attempt_id);
  IF token_unix_ms < committed_at - 31536000000 THEN
    RAISE EXCEPTION 'EXPIRED_OR_UNKNOWN' USING ERRCODE = '22023';
  END IF;
  IF token_unix_ms > committed_at + 300000 THEN
    RAISE EXCEPTION 'UUIDV7_TIMESTAMP_TOO_FAR_IN_FUTURE' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO policy FROM object_store_continuity.policies WHERE singleton FOR SHARE;
  IF NOT FOUND OR policy.policy_revision IS DISTINCT FROM expected_policy_revision THEN
    RAISE EXCEPTION 'CONTINUITY_POLICY_REVISION_MISMATCH' USING ERRCODE = '40001';
  END IF;
  SELECT * INTO global_value FROM object_store_continuity.global_counter WHERE singleton FOR UPDATE;
  SELECT * INTO boundary
    FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = object_store_continuity_begin_v1.provider_boundary_id
   FOR UPDATE;
  IF NOT FOUND OR boundary.current_authority_epoch IS DISTINCT FROM expected_current_epoch THEN
    RAISE EXCEPTION 'AUTHORITY_EPOCH_MISMATCH' USING ERRCODE = '40001';
  END IF;
  SELECT * INTO epoch_value
    FROM object_store_continuity.epoch_counters AS epoch_counter
   WHERE epoch_counter.provider_boundary_id = object_store_continuity_begin_v1.provider_boundary_id
     AND epoch_counter.authority_epoch = object_store_continuity_begin_v1.expected_current_epoch
   FOR UPDATE;
  IF NOT FOUND OR epoch_value.retired
     OR epoch_value.api_revision IS DISTINCT FROM api_revision
     OR epoch_value.schema_revision IS DISTINCT FROM 'object-store-authority-continuity-schema-v1'
     OR epoch_value.continuity_contract_revision IS DISTINCT FROM
       'object-store-authority-continuity-contract-v1'
     OR epoch_value.continuity_policy_revision IS DISTINCT FROM expected_policy_revision
     OR epoch_value.max_pruned_ranges_per_boundary IS DISTINCT FROM policy.max_pruned_ranges_per_boundary
     OR epoch_value.max_pruned_range_bytes IS DISTINCT FROM policy.max_pruned_range_bytes
     OR epoch_value.archive_batch_rows IS DISTINCT FROM policy.archive_batch_rows
     OR epoch_value.prune_batch_rows IS DISTINCT FROM policy.prune_batch_rows
     OR epoch_value.prune_interval_ms IS DISTINCT FROM policy.prune_interval_ms
     OR epoch_value.max_epoch_high_water_bytes IS DISTINCT FROM policy.max_epoch_high_water_bytes
     OR epoch_value.epoch_namespace_blake3 IS DISTINCT FROM boundary.epoch_namespace_blake3
     OR epoch_value.continuity_seq_high_water IS DISTINCT FROM boundary.continuity_seq_high_water THEN
    RAISE EXCEPTION 'AUTHORITY_EPOCH_REVISION_OR_COUNTER_MISMATCH' USING ERRCODE = '40001';
  END IF;
  IF global_value.owned_rows + requested_rows + policy.low_water_reserve_rows > policy.max_rows_global
     OR global_value.owned_bytes + requested_bytes + policy.low_water_reserve_bytes > policy.max_bytes_global
     OR boundary.owned_rows + requested_rows > policy.max_rows_per_boundary
     OR boundary.owned_bytes + requested_bytes > policy.max_bytes_per_boundary THEN
    RAISE EXCEPTION 'CONTINUITY_CAPACITY_EXHAUSTED' USING ERRCODE = '53000';
  END IF;

  allocated_seq := epoch_value.continuity_seq_high_water + 1;
  ownership_preimage := object_store_continuity.ownership_preimage_v1(
    expected_policy_revision, operation_quota_class, requested_bytes, requested_rows,
    requested_concurrency, provider_boundary_id, authenticated_cell_id, authenticated_tenant_id
  );
  ownership_digest := object_store_continuity.blake3_v1(ownership_preimage);
  ownership_bytes := ownership_preimage || ownership_digest;
  row_preimage := object_store_continuity.row_preimage_v1(
    api_revision, provider_boundary_id, expected_current_epoch, allocated_seq, continuity_token_id,
    intent_kind, authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id,
    selected_fingerprint, 'INTENT', 'SHADOW_RESERVED', ownership_digest, committed_at, committed_at,
    NULL, NULL, NULL
  );
  row_digest := object_store_continuity.blake3_v1(row_preimage);
  row_bytes := row_preimage || row_digest;
  IF octet_length(row_bytes)::numeric > policy.max_row_bytes THEN
    RAISE EXCEPTION 'CONTINUITY_ROW_TOO_LARGE' USING ERRCODE = '54000';
  END IF;
  PERFORM object_store_continuity.apply_storage_mutation_v1(
    provider_boundary_id, 'ADMISSION', 0, 0, 1, octet_length(row_bytes)::numeric
  );
  UPDATE object_store_continuity.global_counter
     SET owned_rows = owned_rows + requested_rows,
         owned_bytes = owned_bytes + requested_bytes,
         owned_concurrency = owned_concurrency + requested_concurrency,
         counter_revision = counter_revision + 1
   WHERE singleton;
  UPDATE object_store_continuity.boundary_counters
     SET continuity_seq_high_water = allocated_seq,
         owned_rows = owned_rows + requested_rows,
         owned_bytes = owned_bytes + requested_bytes,
         owned_concurrency = owned_concurrency + requested_concurrency,
         counter_revision = counter_revision + 1
   WHERE object_store_continuity.boundary_counters.provider_boundary_id =
     object_store_continuity_begin_v1.provider_boundary_id;
  UPDATE object_store_continuity.epoch_counters
     SET continuity_seq_high_water = allocated_seq
   WHERE object_store_continuity.epoch_counters.provider_boundary_id =
       object_store_continuity_begin_v1.provider_boundary_id
     AND object_store_continuity.epoch_counters.authority_epoch =
       object_store_continuity_begin_v1.expected_current_epoch;
  INSERT INTO object_store_continuity.cell_counters(
    provider_boundary_id, authenticated_cell_id, owned_rows, owned_bytes, owned_concurrency,
    counter_revision
  ) VALUES (
    object_store_continuity_begin_v1.provider_boundary_id,
    object_store_continuity_begin_v1.authenticated_cell_id, requested_rows, requested_bytes,
    requested_concurrency, 1
  ) ON CONFLICT ON CONSTRAINT cell_counters_pkey DO UPDATE SET
    owned_rows = object_store_continuity.cell_counters.owned_rows + EXCLUDED.owned_rows,
    owned_bytes = object_store_continuity.cell_counters.owned_bytes + EXCLUDED.owned_bytes,
    owned_concurrency = object_store_continuity.cell_counters.owned_concurrency + EXCLUDED.owned_concurrency,
    counter_revision = object_store_continuity.cell_counters.counter_revision + 1;
  INSERT INTO object_store_continuity.tenant_counters(
    provider_boundary_id, authenticated_tenant_id, owned_rows, owned_bytes, owned_concurrency,
    counter_revision
  ) VALUES (
    object_store_continuity_begin_v1.provider_boundary_id,
    object_store_continuity_begin_v1.authenticated_tenant_id, requested_rows, requested_bytes,
    requested_concurrency, 1
  ) ON CONFLICT ON CONSTRAINT tenant_counters_pkey DO UPDATE SET
    owned_rows = object_store_continuity.tenant_counters.owned_rows + EXCLUDED.owned_rows,
    owned_bytes = object_store_continuity.tenant_counters.owned_bytes + EXCLUDED.owned_bytes,
    owned_concurrency = object_store_continuity.tenant_counters.owned_concurrency + EXCLUDED.owned_concurrency,
    counter_revision = object_store_continuity.tenant_counters.counter_revision + 1;

  INSERT INTO object_store_continuity.intents(
    api_revision, provider_boundary_id, authority_epoch, continuity_seq, continuity_token_id,
    intent_kind, authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id,
    put_reservation_fingerprint, canonical_descriptor_fingerprint, continuity_policy_revision,
    operation_quota_class, quota_rows, quota_bytes, quota_concurrency, quota_ownership_bytes,
    quota_ownership_blake3, state, ownership_state, external_created_at_unix_ms,
    state_committed_at_unix_ms, retention_deadline_unix_ms, canonical_row_bytes, row_blake3
  ) VALUES (
    api_revision, provider_boundary_id, expected_current_epoch, allocated_seq, continuity_token_id,
    intent_kind, authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id,
    CASE WHEN intent_kind = 'UUID_ADMISSION' THEN selected_fingerprint END,
    CASE WHEN intent_kind = 'DISPATCH_CAS' THEN selected_fingerprint END,
    expected_policy_revision, operation_quota_class, requested_rows, requested_bytes,
    requested_concurrency, ownership_bytes, ownership_digest, 'INTENT',
    'SHADOW_RESERVED', committed_at, committed_at, retention_deadline_unix_ms,
    row_bytes, row_digest
  ) RETURNING * INTO stored;
  RETURN object_store_continuity.result_v1(stored, 'CREATED');
END
$$;

CREATE FUNCTION object_store_continuity.transition_v1(
  api_revision text,
  actor text,
  command_kind text,
  provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64,
  continuity_token_id uuid,
  authenticated_cell_id text,
  authenticated_tenant_id text,
  logical_request_id uuid,
  attempt_id uuid,
  intent_kind text,
  selected_fingerprint bytea,
  expected_prior_row_blake3 bytea,
  expected_prior_state text,
  next_state text,
  next_ownership_state text,
  local_binding_blake3 bytea,
  terminal_evidence_blake3 bytea,
  adjudication_kind text,
  release_id uuid,
  release_basis_kind text,
  release_basis_id text,
  release_basis_blake3 bytea
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_continuity.intents%ROWTYPE;
DECLARE stored_release object_store_continuity.shadow_release_receipts%ROWTYPE;
DECLARE stored_transition object_store_continuity.transition_receipts%ROWTYPE;
DECLARE policy object_store_continuity.policies%ROWTYPE;
DECLARE committed_at bigint;
DECLARE global_revision object_store_continuity.uint64;
DECLARE boundary_revision object_store_continuity.uint64;
DECLARE cell_revision object_store_continuity.uint64;
DECLARE tenant_revision object_store_continuity.uint64;
DECLARE releasing boolean;
DECLARE next_row_preimage bytea;
DECLARE next_row_blake3 bytea;
DECLARE next_row_bytes bytea;
DECLARE release_preimage bytea;
DECLARE release_receipt_blake3 bytea;
DECLARE release_receipt_bytes bytea;
DECLARE transition_preimage bytea;
DECLARE transition_receipt_blake3 bytea;
DECLARE transition_receipt_bytes bytea;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  IF actor = 'RUNTIME' THEN
    PERFORM object_store_continuity.assert_runtime_boundary_v1(provider_boundary_id);
  ELSIF actor = 'RECONCILER' THEN
    PERFORM object_store_continuity.assert_reconciler_v1();
  ELSE
    RAISE EXCEPTION 'INVALID_CONTINUITY_ACTOR' USING ERRCODE = '42501';
  END IF;
  -- Canonical writer order is global storage, boundary storage, epoch/detail.
  -- This keeps transitions from deadlocking archive or epoch maintenance.
  PERFORM 1 FROM object_store_continuity.global_counter WHERE singleton FOR UPDATE;
  PERFORM 1 FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = transition_v1.provider_boundary_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_COUNTER_NAMESPACE_MISSING' USING ERRCODE = '55000';
  END IF;
  releasing := next_ownership_state = 'OWNERSHIP_RELEASED';
  IF releasing THEN
    IF release_id IS NULL OR release_basis_kind IS NULL OR release_basis_id IS NULL
       OR release_basis_blake3 IS NULL OR octet_length(release_basis_blake3) <> 32 THEN
      RAISE EXCEPTION 'RELEASE_RECEIPT_REQUIRED' USING ERRCODE = '22023';
    END IF;
    PERFORM object_store_continuity.uuid_v7_unix_ms_v1(release_id);
  ELSIF release_id IS NOT NULL OR release_basis_kind IS NOT NULL OR release_basis_id IS NOT NULL
     OR release_basis_blake3 IS NOT NULL THEN
    RAISE EXCEPTION 'RELEASE_RECEIPT_FORBIDDEN' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO stored
    FROM object_store_continuity.intents AS intent
   WHERE intent.provider_boundary_id = transition_v1.provider_boundary_id
     AND intent.authority_epoch = transition_v1.authority_epoch
     AND intent.continuity_seq = transition_v1.continuity_seq
     AND intent.continuity_token_id = transition_v1.continuity_token_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'CONTINUITY_INTENT_NOT_FOUND' USING ERRCODE = 'P0002'; END IF;
  PERFORM object_store_continuity.assert_stored_row_v1(stored);
  IF stored.logical_request_id IS DISTINCT FROM logical_request_id
     OR stored.authenticated_cell_id IS DISTINCT FROM authenticated_cell_id
     OR stored.authenticated_tenant_id IS DISTINCT FROM authenticated_tenant_id
     OR stored.attempt_id IS DISTINCT FROM attempt_id
     OR stored.intent_kind IS DISTINCT FROM intent_kind
     OR coalesce(stored.put_reservation_fingerprint, stored.canonical_descriptor_fingerprint)
        IS DISTINCT FROM selected_fingerprint THEN
    RAISE EXCEPTION 'CONTINUITY_IDENTITY_MISMATCH' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO stored_transition
    FROM object_store_continuity.transition_receipts AS receipt
   WHERE receipt.continuity_token_id = transition_v1.continuity_token_id
     AND receipt.expected_prior_row_blake3 = transition_v1.expected_prior_row_blake3;
  IF FOUND THEN
    IF stored_transition.actor IS DISTINCT FROM actor
       OR stored_transition.command_kind IS DISTINCT FROM command_kind
       OR stored_transition.prior_state IS DISTINCT FROM expected_prior_state
       OR stored_transition.next_state IS DISTINCT FROM next_state
       OR (next_ownership_state <> 'PRESERVE'
         AND stored_transition.next_ownership_state IS DISTINCT FROM next_ownership_state)
       OR stored_transition.local_binding_blake3 IS DISTINCT FROM local_binding_blake3
       OR stored_transition.terminal_evidence_blake3 IS DISTINCT FROM terminal_evidence_blake3
       OR stored_transition.adjudication_kind IS DISTINCT FROM adjudication_kind
       OR stored_transition.release_id IS DISTINCT FROM release_id
       OR stored_transition.release_basis_kind IS DISTINCT FROM release_basis_kind
       OR stored_transition.release_basis_id IS DISTINCT FROM release_basis_id
       OR stored_transition.release_basis_blake3 IS DISTINCT FROM release_basis_blake3 THEN
      RAISE EXCEPTION 'TRANSITION_RECEIPT_REPLAY_MISMATCH' USING ERRCODE = '23505';
    END IF;
    transition_preimage := object_store_continuity.transition_receipt_preimage_v1(
      stored_transition
    );
    PERFORM object_store_continuity.assert_blake3_v1(
      transition_preimage, stored_transition.receipt_blake3
    );
    IF stored_transition.canonical_receipt_bytes IS DISTINCT FROM
        transition_preimage || stored_transition.receipt_blake3 THEN
      RAISE EXCEPTION 'TRANSITION_RECEIPT_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
    END IF;
    IF releasing THEN
      SELECT * INTO stored_release
        FROM object_store_continuity.shadow_release_receipts AS receipt
       WHERE receipt.continuity_token_id = transition_v1.continuity_token_id;
      IF NOT FOUND OR stored_release.release_id IS DISTINCT FROM release_id
         OR stored_release.release_basis_kind IS DISTINCT FROM release_basis_kind
         OR stored_release.basis_id IS DISTINCT FROM release_basis_id
         OR stored_release.basis_blake3 IS DISTINCT FROM release_basis_blake3 THEN
        RAISE EXCEPTION 'RELEASE_RECEIPT_REPLAY_MISMATCH' USING ERRCODE = '23505';
      END IF;
      PERFORM object_store_continuity.assert_blake3_v1(
        object_store_continuity.release_preimage_v1(
        stored_release.release_id, stored_release.provider_boundary_id,
        stored_release.authority_epoch, stored_release.continuity_seq,
        stored_release.continuity_token_id, stored_release.continuity_policy_revision,
        stored_release.quota_ownership_blake3, stored_release.quota_bytes,
        stored_release.quota_rows, stored_release.quota_concurrency,
        stored_release.authenticated_cell_id, stored_release.authenticated_tenant_id,
        stored_release.release_basis_kind, stored_release.basis_id,
        stored_release.basis_blake3, stored_release.released_at_unix_ms,
        stored_release.global_counter_revision, stored_release.boundary_counter_revision,
        stored_release.cell_counter_revision, stored_release.tenant_counter_revision
        ), stored_release.receipt_blake3
      );
      IF stored_release.canonical_receipt_bytes IS DISTINCT FROM
          object_store_continuity.release_preimage_v1(
            stored_release.release_id, stored_release.provider_boundary_id,
            stored_release.authority_epoch, stored_release.continuity_seq,
            stored_release.continuity_token_id, stored_release.continuity_policy_revision,
            stored_release.quota_ownership_blake3, stored_release.quota_bytes,
            stored_release.quota_rows, stored_release.quota_concurrency,
            stored_release.authenticated_cell_id, stored_release.authenticated_tenant_id,
            stored_release.release_basis_kind, stored_release.basis_id,
            stored_release.basis_blake3, stored_release.released_at_unix_ms,
            stored_release.global_counter_revision, stored_release.boundary_counter_revision,
            stored_release.cell_counter_revision, stored_release.tenant_counter_revision
          ) || stored_release.receipt_blake3 THEN
        RAISE EXCEPTION 'RELEASE_RECEIPT_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
      END IF;
    END IF;
    RETURN ROW(
      'REPLAY', stored_transition.next_state, stored_transition.next_ownership_state,
      stored_transition.authority_epoch, stored_transition.continuity_seq,
      stored_transition.continuity_token_id, stored_transition.next_row_blake3,
      stored_transition.committed_at_unix_ms
    )::object_store_continuity.procedure_result_v1;
  END IF;
  IF next_ownership_state = 'PRESERVE' THEN
    next_ownership_state := stored.ownership_state;
  END IF;
  IF releasing AND stored.ownership_state IS DISTINCT FROM 'SHADOW_RESERVED' THEN
    RAISE EXCEPTION 'SHADOW_OWNERSHIP_ALREADY_RELEASED' USING ERRCODE = '22023';
  END IF;
  IF stored.row_blake3 IS DISTINCT FROM expected_prior_row_blake3
     OR stored.state IS DISTINCT FROM expected_prior_state THEN
    RAISE EXCEPTION 'EXPECTED_PRIOR_ROW_MISMATCH' USING ERRCODE = '40001';
  END IF;
  IF NOT (
    (actor = 'RUNTIME' AND command_kind = 'MARK_BOUND'
      AND stored.state = 'INTENT' AND next_state = 'BOUND')
    OR (actor = 'RUNTIME' AND command_kind = 'MARK_COMPLETED'
      AND stored.state = 'BOUND' AND next_state = 'COMPLETED')
    OR (actor = 'RUNTIME' AND command_kind = 'MARK_NO_LOCAL_EFFECT'
      AND stored.state = 'INTENT' AND next_state = 'NO_LOCAL_EFFECT')
    OR (actor = 'RECONCILER' AND command_kind = 'QUARANTINE'
      AND stored.state IN ('INTENT', 'BOUND') AND next_state = 'QUARANTINED')
    OR (actor = 'RECONCILER' AND command_kind = 'MARK_AMBIGUOUS_DISPATCH'
      AND stored.state = 'BOUND' AND next_state = 'AMBIGUOUS_DISPATCH')
    OR (actor = 'RECONCILER' AND command_kind = 'RELEASE_COVERED_SNAPSHOT'
      AND stored.state IN ('BOUND', 'COMPLETED') AND next_state = stored.state
      AND next_ownership_state = 'OWNERSHIP_RELEASED')
    OR (actor = 'RECONCILER' AND stored.state = 'QUARANTINED'
        AND command_kind = 'PREPARE_NO_LOCAL_EFFECT_ADJUDICATION'
        AND next_state = 'ADJUDICATION_PREPARED' AND adjudication_kind = 'NO_LOCAL_EFFECT')
    OR (actor = 'RECONCILER' AND stored.state = 'AMBIGUOUS_DISPATCH'
        AND command_kind = 'PREPARE_NO_DISPATCH_ADJUDICATION'
        AND next_state = 'ADJUDICATION_PREPARED' AND adjudication_kind = 'NO_DISPATCH')
    OR (actor = 'RECONCILER' AND stored.state = 'ADJUDICATION_PREPARED'
        AND command_kind = 'COMPLETE_NO_LOCAL_EFFECT'
        AND stored.adjudication_kind = 'NO_LOCAL_EFFECT'
        AND next_state = 'ADJUDICATED_NO_LOCAL_EFFECT')
    OR (actor = 'RECONCILER' AND stored.state = 'ADJUDICATION_PREPARED'
        AND command_kind = 'COMPLETE_NO_DISPATCH'
        AND stored.adjudication_kind = 'NO_DISPATCH'
        AND next_state = 'ADJUDICATED_NO_DISPATCH')
  ) THEN
    RAISE EXCEPTION 'FORBIDDEN_CONTINUITY_TRANSITION' USING ERRCODE = '22023';
  END IF;
  IF command_kind = 'MARK_BOUND' THEN
    IF stored.local_binding_blake3 IS NOT NULL OR local_binding_blake3 IS NULL
       OR octet_length(local_binding_blake3) <> 32 THEN
      RAISE EXCEPTION 'BOUND_BINDING_INVALID' USING ERRCODE = '22023';
    END IF;
  ELSIF local_binding_blake3 IS DISTINCT FROM stored.local_binding_blake3 THEN
    RAISE EXCEPTION 'LOCAL_BINDING_NOT_PRESERVED' USING ERRCODE = '22023';
  END IF;
  IF (next_state = 'NO_LOCAL_EFFECT' AND release_basis_kind <> 'NO_LOCAL_EFFECT')
     OR (next_state IN ('ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH')
       AND release_basis_kind <> 'FINAL_ADJUDICATION')
     OR (releasing AND next_state IN ('BOUND', 'COMPLETED')
       AND release_basis_kind <> 'COVERED_SNAPSHOT') THEN
    RAISE EXCEPTION 'RELEASE_BASIS_STATE_MISMATCH' USING ERRCODE = '22023';
  END IF;
  committed_at := object_store_continuity.clock_unix_ms_v1();
  next_row_preimage := object_store_continuity.row_preimage_v1(
    stored.api_revision, stored.provider_boundary_id, stored.authority_epoch, stored.continuity_seq,
    stored.continuity_token_id, stored.intent_kind, stored.authenticated_cell_id,
    stored.authenticated_tenant_id, stored.logical_request_id, stored.attempt_id,
    coalesce(stored.put_reservation_fingerprint, stored.canonical_descriptor_fingerprint),
    next_state, next_ownership_state, stored.quota_ownership_blake3,
    stored.external_created_at_unix_ms, committed_at, local_binding_blake3,
    terminal_evidence_blake3, adjudication_kind
  );
  next_row_blake3 := object_store_continuity.blake3_v1(next_row_preimage);
  next_row_bytes := next_row_preimage || next_row_blake3;
  SELECT * INTO policy FROM object_store_continuity.policies WHERE singleton FOR SHARE;
  IF NOT FOUND OR policy.policy_revision IS DISTINCT FROM stored.continuity_policy_revision
     OR octet_length(next_row_bytes)::numeric > policy.max_row_bytes THEN
    RAISE EXCEPTION 'CONTINUITY_POLICY_OR_ROW_LIMIT_MISMATCH' USING ERRCODE = '40001';
  END IF;
  IF releasing THEN
    UPDATE object_store_continuity.global_counter SET
      owned_rows = owned_rows - stored.quota_rows,
      owned_bytes = owned_bytes - stored.quota_bytes,
      owned_concurrency = owned_concurrency - stored.quota_concurrency,
      counter_revision = counter_revision + 1
    WHERE singleton AND owned_rows >= stored.quota_rows AND owned_bytes >= stored.quota_bytes
      AND owned_concurrency >= stored.quota_concurrency
    RETURNING counter_revision INTO global_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'GLOBAL_OWNERSHIP_UNDERFLOW' USING ERRCODE = '22000'; END IF;
    UPDATE object_store_continuity.boundary_counters SET
      owned_rows = owned_rows - stored.quota_rows,
      owned_bytes = owned_bytes - stored.quota_bytes,
      owned_concurrency = owned_concurrency - stored.quota_concurrency,
      counter_revision = counter_revision + 1
    WHERE object_store_continuity.boundary_counters.provider_boundary_id = stored.provider_boundary_id
      AND owned_rows >= stored.quota_rows AND owned_bytes >= stored.quota_bytes
      AND owned_concurrency >= stored.quota_concurrency
    RETURNING counter_revision INTO boundary_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'BOUNDARY_OWNERSHIP_UNDERFLOW' USING ERRCODE = '22000'; END IF;
    UPDATE object_store_continuity.cell_counters SET
      owned_rows = owned_rows - stored.quota_rows,
      owned_bytes = owned_bytes - stored.quota_bytes,
      owned_concurrency = owned_concurrency - stored.quota_concurrency,
      counter_revision = counter_revision + 1
    WHERE object_store_continuity.cell_counters.provider_boundary_id = stored.provider_boundary_id
      AND object_store_continuity.cell_counters.authenticated_cell_id = stored.authenticated_cell_id
      AND object_store_continuity.cell_counters.owned_rows >= stored.quota_rows
      AND object_store_continuity.cell_counters.owned_bytes >= stored.quota_bytes
      AND object_store_continuity.cell_counters.owned_concurrency >= stored.quota_concurrency
    RETURNING object_store_continuity.cell_counters.counter_revision INTO cell_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'CELL_OWNERSHIP_UNDERFLOW' USING ERRCODE = '22000'; END IF;
    UPDATE object_store_continuity.tenant_counters SET
      owned_rows = owned_rows - stored.quota_rows,
      owned_bytes = owned_bytes - stored.quota_bytes,
      owned_concurrency = owned_concurrency - stored.quota_concurrency,
      counter_revision = counter_revision + 1
    WHERE object_store_continuity.tenant_counters.provider_boundary_id = stored.provider_boundary_id
      AND object_store_continuity.tenant_counters.authenticated_tenant_id = stored.authenticated_tenant_id
      AND object_store_continuity.tenant_counters.owned_rows >= stored.quota_rows
      AND object_store_continuity.tenant_counters.owned_bytes >= stored.quota_bytes
      AND object_store_continuity.tenant_counters.owned_concurrency >= stored.quota_concurrency
    RETURNING object_store_continuity.tenant_counters.counter_revision INTO tenant_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'TENANT_OWNERSHIP_UNDERFLOW' USING ERRCODE = '22000'; END IF;
    release_preimage := object_store_continuity.release_preimage_v1(
      release_id, stored.provider_boundary_id, stored.authority_epoch, stored.continuity_seq,
      stored.continuity_token_id, stored.continuity_policy_revision,
      stored.quota_ownership_blake3, stored.quota_bytes, stored.quota_rows,
      stored.quota_concurrency, stored.authenticated_cell_id, stored.authenticated_tenant_id,
      release_basis_kind, release_basis_id, release_basis_blake3, committed_at,
      global_revision, boundary_revision, cell_revision, tenant_revision
    );
    release_receipt_blake3 := object_store_continuity.blake3_v1(release_preimage);
    release_receipt_bytes := release_preimage || release_receipt_blake3;
    INSERT INTO object_store_continuity.shadow_release_receipts(
      release_id, provider_boundary_id, authority_epoch, continuity_seq, continuity_token_id,
      continuity_policy_revision, quota_ownership_blake3, quota_rows, quota_bytes,
      quota_concurrency, global_scope_id, authenticated_cell_id, authenticated_tenant_id,
      release_basis_kind, basis_id, basis_blake3, released_at_unix_ms,
      global_counter_revision, boundary_counter_revision, cell_counter_revision,
      tenant_counter_revision, canonical_receipt_bytes, receipt_blake3
    ) VALUES (
      release_id, stored.provider_boundary_id, stored.authority_epoch, stored.continuity_seq,
      stored.continuity_token_id, stored.continuity_policy_revision,
      stored.quota_ownership_blake3, stored.quota_rows, stored.quota_bytes,
      stored.quota_concurrency, 'object-store-continuity-global-v1',
      stored.authenticated_cell_id, stored.authenticated_tenant_id,
      release_basis_kind, release_basis_id, release_basis_blake3,
      committed_at, global_revision, boundary_revision, cell_revision, tenant_revision,
      release_receipt_bytes, release_receipt_blake3
    );
  END IF;
  stored_transition.provider_boundary_id := stored.provider_boundary_id;
  stored_transition.authority_epoch := stored.authority_epoch;
  stored_transition.continuity_seq := stored.continuity_seq;
  stored_transition.continuity_token_id := stored.continuity_token_id;
  stored_transition.actor := actor;
  stored_transition.command_kind := command_kind;
  stored_transition.prior_state := expected_prior_state;
  stored_transition.next_state := next_state;
  stored_transition.next_ownership_state := next_ownership_state;
  stored_transition.expected_prior_row_blake3 := expected_prior_row_blake3;
  stored_transition.next_row_blake3 := next_row_blake3;
  stored_transition.local_binding_blake3 := local_binding_blake3;
  stored_transition.terminal_evidence_blake3 := terminal_evidence_blake3;
  stored_transition.adjudication_kind := adjudication_kind;
  stored_transition.release_id := release_id;
  stored_transition.release_basis_kind := release_basis_kind;
  stored_transition.release_basis_id := release_basis_id;
  stored_transition.release_basis_blake3 := release_basis_blake3;
  stored_transition.committed_at_unix_ms := committed_at;
  transition_preimage := object_store_continuity.transition_receipt_preimage_v1(stored_transition);
  transition_receipt_blake3 := object_store_continuity.blake3_v1(transition_preimage);
  transition_receipt_bytes := transition_preimage || transition_receipt_blake3;
  PERFORM object_store_continuity.apply_storage_mutation_v1(
    stored.provider_boundary_id, 'MAINTENANCE', 1,
    octet_length(stored.canonical_row_bytes)::numeric,
    CASE WHEN releasing THEN 3 ELSE 2 END,
    octet_length(next_row_bytes)::numeric + octet_length(transition_receipt_bytes)::numeric
      + CASE WHEN releasing THEN octet_length(release_receipt_bytes)::numeric ELSE 0 END
  );
  UPDATE object_store_continuity.intents SET
    state = next_state,
    ownership_state = next_ownership_state,
    local_binding_blake3 = transition_v1.local_binding_blake3,
    terminal_evidence_blake3 = transition_v1.terminal_evidence_blake3,
    adjudication_kind = transition_v1.adjudication_kind,
    state_committed_at_unix_ms = committed_at,
    canonical_row_bytes = next_row_bytes,
    row_blake3 = next_row_blake3
  WHERE object_store_continuity.intents.provider_boundary_id = transition_v1.provider_boundary_id
    AND object_store_continuity.intents.authority_epoch = transition_v1.authority_epoch
    AND object_store_continuity.intents.continuity_seq = transition_v1.continuity_seq
  RETURNING * INTO stored;
  INSERT INTO object_store_continuity.transition_receipts(
    provider_boundary_id, authority_epoch, continuity_seq, continuity_token_id, actor,
    command_kind, prior_state, next_state, next_ownership_state,
    expected_prior_row_blake3, next_row_blake3, local_binding_blake3,
    terminal_evidence_blake3, adjudication_kind, release_id, release_basis_kind,
    release_basis_id, release_basis_blake3, committed_at_unix_ms,
    canonical_receipt_bytes, receipt_blake3
  ) VALUES (
    stored.provider_boundary_id, stored.authority_epoch, stored.continuity_seq,
    stored.continuity_token_id, actor, command_kind, expected_prior_state, next_state,
    next_ownership_state, expected_prior_row_blake3, next_row_blake3, local_binding_blake3,
    terminal_evidence_blake3, adjudication_kind, release_id, release_basis_kind,
    release_basis_id, release_basis_blake3, committed_at,
    transition_receipt_bytes, transition_receipt_blake3
  );
  RETURN object_store_continuity.result_v1(stored, 'UPDATED');
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_mark_bound_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, local_binding_blake3 bytea
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT object_store_continuity.transition_v1($1, 'RUNTIME', 'MARK_BOUND', $2, $3, $4,
    $5, $6, $7, $8, $9, $10, $11, $12, 'INTENT', 'BOUND', 'PRESERVE',
    $13, NULL, NULL, NULL, NULL, NULL, NULL)
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_mark_completed_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, local_binding_blake3 bytea, terminal_evidence_blake3 bytea,
  expected_prior_state text DEFAULT 'BOUND'
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT object_store_continuity.transition_v1($1, 'RUNTIME', 'MARK_COMPLETED', $2, $3, $4,
    $5, $6, $7, $8, $9, $10, $11, $12, $15, 'COMPLETED', 'PRESERVE',
    $13, $14, NULL, NULL, NULL, NULL, NULL)
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_mark_no_local_effect_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, terminal_evidence_blake3 bytea,
  release_id uuid, release_basis_id text, release_basis_blake3 bytea
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT object_store_continuity.transition_v1($1, 'RUNTIME', 'MARK_NO_LOCAL_EFFECT', $2,
    $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'INTENT', 'NO_LOCAL_EFFECT',
    'OWNERSHIP_RELEASED', NULL, $13, NULL, $14, 'NO_LOCAL_EFFECT', $15, $16)
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_quarantine_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, expected_prior_state text, local_binding_blake3 bytea,
  terminal_evidence_blake3 bytea
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT object_store_continuity.transition_v1($1, 'RECONCILER', 'QUARANTINE', $2, $3,
    $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'QUARANTINED',
    'PRESERVE', $14, $15, NULL, NULL, NULL, NULL, NULL)
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_mark_ambiguous_dispatch_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, local_binding_blake3 bytea, terminal_evidence_blake3 bytea,
  expected_prior_state text DEFAULT 'BOUND'
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT object_store_continuity.transition_v1($1, 'RECONCILER', 'MARK_AMBIGUOUS_DISPATCH',
    $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $15,
    'AMBIGUOUS_DISPATCH', 'PRESERVE', $13, $14, NULL, NULL, NULL, NULL, NULL)
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_prepare_adjudication_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, expected_prior_state text, local_binding_blake3 bytea,
  terminal_evidence_blake3 bytea, adjudication_kind text
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT object_store_continuity.transition_v1($1, 'RECONCILER',
    CASE $16 WHEN 'NO_LOCAL_EFFECT' THEN 'PREPARE_NO_LOCAL_EFFECT_ADJUDICATION'
      WHEN 'NO_DISPATCH' THEN 'PREPARE_NO_DISPATCH_ADJUDICATION' ELSE 'INVALID' END,
    $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
    'ADJUDICATION_PREPARED', 'PRESERVE', $14, $15, $16, NULL, NULL, NULL, NULL)
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_complete_adjudication_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, local_binding_blake3 bytea,
  terminal_evidence_blake3 bytea, adjudication_kind text, final_state text,
  release_id uuid, release_basis_id text, release_basis_blake3 bytea
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT object_store_continuity.transition_v1($1, 'RECONCILER',
    CASE $15 WHEN 'NO_LOCAL_EFFECT' THEN 'COMPLETE_NO_LOCAL_EFFECT'
      WHEN 'NO_DISPATCH' THEN 'COMPLETE_NO_DISPATCH' ELSE 'INVALID' END,
    $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'ADJUDICATION_PREPARED',
    $16, 'OWNERSHIP_RELEASED', $13, $14, $15, $17, 'FINAL_ADJUDICATION', $18, $19)
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_record_snapshot_v1(
  api_revision text, snapshot_id uuid, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  through_continuity_seq object_store_continuity.uint64, authority_lsn pg_lsn,
  manifest_blake3 bytea, continuity_seq object_store_continuity.uint64,
  continuity_token_id uuid, local_binding_blake3 bytea, local_state_blake3 bytea,
  local_quota_ownership_blake3 bytea,
  local_counter_revision object_store_continuity.uint64
)
RETURNS TABLE(
  accepted_snapshot_id uuid,
  accepted_through_continuity_seq object_store_continuity.uint64,
  accepted_manifest_blake3 bytea,
  accepted_coverage_blake3 bytea,
  recorded_at_unix_ms bigint
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE stored object_store_continuity.intents%ROWTYPE;
DECLARE stored_snapshot object_store_continuity.snapshots%ROWTYPE;
DECLARE stored_coverage object_store_continuity.snapshot_coverages%ROWTYPE;
DECLARE prior_high_water object_store_continuity.uint64;
DECLARE coverage_preimage bytea;
DECLARE snapshot_preimage bytea;
DECLARE snapshot_digest bytea;
DECLARE inserted_snapshot boolean := false;
DECLARE inserted_coverage boolean := false;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_reconciler_v1();
  PERFORM object_store_continuity.uuid_v7_unix_ms_v1(snapshot_id);
  PERFORM object_store_continuity.uuid_v7_unix_ms_v1(continuity_token_id);
  IF octet_length(manifest_blake3) <> 32 OR through_continuity_seq < continuity_seq
     OR authority_lsn > pg_current_wal_lsn() THEN
    RAISE EXCEPTION 'SNAPSHOT_MANIFEST_INVALID' USING ERRCODE = '22023';
  END IF;
  PERFORM 1 FROM object_store_continuity.global_counter WHERE singleton FOR UPDATE;
  PERFORM 1 FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = object_store_continuity_record_snapshot_v1.provider_boundary_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_COUNTER_NAMESPACE_MISSING' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO stored
    FROM object_store_continuity.intents AS intent
   WHERE intent.provider_boundary_id = object_store_continuity_record_snapshot_v1.provider_boundary_id
     AND intent.authority_epoch = object_store_continuity_record_snapshot_v1.authority_epoch
     AND intent.continuity_seq = object_store_continuity_record_snapshot_v1.continuity_seq
     AND intent.continuity_token_id = object_store_continuity_record_snapshot_v1.continuity_token_id
   FOR SHARE;
  IF NOT FOUND OR stored.state NOT IN ('BOUND', 'COMPLETED')
     OR stored.local_binding_blake3 IS DISTINCT FROM local_binding_blake3
     OR stored.quota_ownership_blake3 IS DISTINCT FROM local_quota_ownership_blake3 THEN
    RAISE EXCEPTION 'SNAPSHOT_COVERAGE_IDENTITY_MISMATCH' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_continuity.assert_stored_row_v1(stored);

  SELECT * INTO stored_snapshot FROM object_store_continuity.snapshots AS snapshot
   WHERE snapshot.snapshot_id = object_store_continuity_record_snapshot_v1.snapshot_id
   FOR UPDATE;
  IF FOUND THEN
    IF stored_snapshot.provider_boundary_id IS DISTINCT FROM provider_boundary_id
       OR stored_snapshot.authority_epoch IS DISTINCT FROM authority_epoch
       OR stored_snapshot.through_continuity_seq IS DISTINCT FROM through_continuity_seq
       OR stored_snapshot.authority_lsn IS DISTINCT FROM authority_lsn
       OR stored_snapshot.manifest_blake3 IS DISTINCT FROM manifest_blake3 THEN
      RAISE EXCEPTION 'SNAPSHOT_REPLAY_MISMATCH' USING ERRCODE = '23505';
    END IF;
    snapshot_preimage := object_store_continuity.snapshot_preimage_v1(
      stored_snapshot.snapshot_id, stored_snapshot.provider_boundary_id,
      stored_snapshot.authority_epoch, stored_snapshot.through_continuity_seq,
      stored_snapshot.authority_lsn, stored_snapshot.manifest_blake3,
      stored_snapshot.recorded_at_unix_ms
    );
    PERFORM object_store_continuity.assert_blake3_v1(
      snapshot_preimage, stored_snapshot.snapshot_blake3
    );
    IF stored_snapshot.canonical_snapshot_bytes IS DISTINCT FROM
        snapshot_preimage || stored_snapshot.snapshot_blake3 THEN
      RAISE EXCEPTION 'SNAPSHOT_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
    END IF;
  ELSE
    SELECT snapshot.through_continuity_seq INTO prior_high_water
      FROM object_store_continuity.snapshots AS snapshot
     WHERE snapshot.provider_boundary_id = object_store_continuity_record_snapshot_v1.provider_boundary_id
       AND snapshot.authority_epoch = object_store_continuity_record_snapshot_v1.authority_epoch
     ORDER BY snapshot.through_continuity_seq DESC LIMIT 1 FOR UPDATE;
    IF FOUND AND through_continuity_seq <= prior_high_water THEN
      RAISE EXCEPTION 'SNAPSHOT_HIGH_WATER_NOT_ADVANCING' USING ERRCODE = '22023';
    END IF;
    recorded_at_unix_ms := object_store_continuity.clock_unix_ms_v1();
    snapshot_preimage := object_store_continuity.snapshot_preimage_v1(
      snapshot_id, provider_boundary_id, authority_epoch, through_continuity_seq,
      authority_lsn, manifest_blake3, recorded_at_unix_ms
    );
    snapshot_digest := object_store_continuity.blake3_v1(snapshot_preimage);
    INSERT INTO object_store_continuity.snapshots(
      snapshot_id, provider_boundary_id, authority_epoch, through_continuity_seq,
      authority_lsn, manifest_blake3, recorded_at_unix_ms,
      canonical_snapshot_bytes, snapshot_blake3
    ) VALUES (
      snapshot_id, provider_boundary_id, authority_epoch, through_continuity_seq,
      authority_lsn, manifest_blake3, recorded_at_unix_ms,
      snapshot_preimage || snapshot_digest, snapshot_digest
    ) RETURNING * INTO stored_snapshot;
    inserted_snapshot := true;
  END IF;

  SELECT * INTO stored_coverage FROM object_store_continuity.snapshot_coverages AS coverage
   WHERE coverage.snapshot_id = object_store_continuity_record_snapshot_v1.snapshot_id
     AND coverage.continuity_token_id = object_store_continuity_record_snapshot_v1.continuity_token_id;
  IF FOUND THEN
    IF stored_coverage.provider_boundary_id IS DISTINCT FROM provider_boundary_id
       OR stored_coverage.authority_epoch IS DISTINCT FROM authority_epoch
       OR stored_coverage.continuity_seq IS DISTINCT FROM continuity_seq
       OR stored_coverage.local_binding_blake3 IS DISTINCT FROM local_binding_blake3
       OR stored_coverage.local_state_blake3 IS DISTINCT FROM local_state_blake3
       OR stored_coverage.local_quota_ownership_blake3 IS DISTINCT FROM local_quota_ownership_blake3
       OR stored_coverage.local_counter_revision IS DISTINCT FROM local_counter_revision
       OR stored_coverage.authority_lsn IS DISTINCT FROM authority_lsn
       OR stored_coverage.manifest_blake3 IS DISTINCT FROM manifest_blake3 THEN
      RAISE EXCEPTION 'SNAPSHOT_COVERAGE_REPLAY_MISMATCH' USING ERRCODE = '23505';
    END IF;
    coverage_preimage := object_store_continuity.snapshot_coverage_preimage_v1(
      stored_coverage.snapshot_id, stored_coverage.provider_boundary_id,
      stored_coverage.authority_epoch, stored_coverage.continuity_seq,
      stored_coverage.continuity_token_id, stored_coverage.local_binding_blake3,
      stored_coverage.local_state_blake3, stored_coverage.local_quota_ownership_blake3,
      stored_coverage.local_counter_revision, stored_coverage.authority_lsn,
      stored_coverage.manifest_blake3, stored_coverage.recorded_at_unix_ms
    );
    PERFORM object_store_continuity.assert_blake3_v1(
      coverage_preimage, stored_coverage.coverage_blake3
    );
    IF stored_coverage.canonical_coverage_bytes IS DISTINCT FROM
        coverage_preimage || stored_coverage.coverage_blake3 THEN
      RAISE EXCEPTION 'SNAPSHOT_COVERAGE_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
    END IF;
  ELSE
    recorded_at_unix_ms := object_store_continuity.clock_unix_ms_v1();
    coverage_preimage := object_store_continuity.snapshot_coverage_preimage_v1(
      snapshot_id, provider_boundary_id, authority_epoch, continuity_seq, continuity_token_id,
      local_binding_blake3, local_state_blake3, local_quota_ownership_blake3,
      local_counter_revision, authority_lsn, manifest_blake3, recorded_at_unix_ms
    );
    accepted_coverage_blake3 := object_store_continuity.blake3_v1(coverage_preimage);
    INSERT INTO object_store_continuity.snapshot_coverages(
      snapshot_id, provider_boundary_id, authority_epoch, continuity_seq, continuity_token_id,
      local_binding_blake3, local_state_blake3, local_quota_ownership_blake3,
      local_counter_revision, authority_lsn, manifest_blake3, coverage_blake3,
      canonical_coverage_bytes, recorded_at_unix_ms
    ) VALUES (
      snapshot_id, provider_boundary_id, authority_epoch, continuity_seq, continuity_token_id,
      local_binding_blake3, local_state_blake3, local_quota_ownership_blake3,
      local_counter_revision, authority_lsn, manifest_blake3, accepted_coverage_blake3,
      coverage_preimage || accepted_coverage_blake3, recorded_at_unix_ms
    ) RETURNING * INTO stored_coverage;
    inserted_coverage := true;
  END IF;
  IF inserted_snapshot OR inserted_coverage THEN
    PERFORM object_store_continuity.apply_storage_mutation_v1(
      provider_boundary_id, 'MAINTENANCE', 0, 0,
      (CASE WHEN inserted_snapshot THEN 1 ELSE 0 END
        + CASE WHEN inserted_coverage THEN 1 ELSE 0 END)::numeric,
      (CASE WHEN inserted_snapshot
        THEN octet_length(stored_snapshot.canonical_snapshot_bytes) ELSE 0 END
        + CASE WHEN inserted_coverage
          THEN octet_length(stored_coverage.canonical_coverage_bytes) ELSE 0 END)::numeric
    );
  END IF;
  accepted_snapshot_id := stored_snapshot.snapshot_id;
  accepted_through_continuity_seq := stored_snapshot.through_continuity_seq;
  accepted_manifest_blake3 := stored_snapshot.manifest_blake3;
  accepted_coverage_blake3 := stored_coverage.coverage_blake3;
  recorded_at_unix_ms := stored_coverage.recorded_at_unix_ms;
  RETURN NEXT;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_release_shadow_ownership_v1(
  api_revision text, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid,
  attempt_id uuid, intent_kind text, selected_fingerprint bytea,
  expected_prior_row_blake3 bytea, expected_state text, snapshot_id uuid,
  expected_manifest_blake3 bytea, expected_coverage_blake3 bytea, release_id uuid
)
RETURNS object_store_continuity.procedure_result_v1
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE stored object_store_continuity.intents%ROWTYPE;
DECLARE coverage object_store_continuity.snapshot_coverages%ROWTYPE;
DECLARE snapshot object_store_continuity.snapshots%ROWTYPE;
DECLARE coverage_preimage bytea;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_reconciler_v1();
  PERFORM 1 FROM object_store_continuity.global_counter WHERE singleton FOR UPDATE;
  PERFORM 1 FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = object_store_continuity_release_shadow_ownership_v1.provider_boundary_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_COUNTER_NAMESPACE_MISSING' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO stored FROM object_store_continuity.intents AS intent
   WHERE intent.provider_boundary_id = object_store_continuity_release_shadow_ownership_v1.provider_boundary_id
     AND intent.authority_epoch = object_store_continuity_release_shadow_ownership_v1.authority_epoch
     AND intent.continuity_seq = object_store_continuity_release_shadow_ownership_v1.continuity_seq
     AND intent.continuity_token_id = object_store_continuity_release_shadow_ownership_v1.continuity_token_id
   FOR SHARE;
  IF NOT FOUND OR stored.state IS DISTINCT FROM expected_state
     OR stored.state NOT IN ('BOUND', 'COMPLETED') THEN
    RAISE EXCEPTION 'COVERED_RELEASE_STATE_MISMATCH' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_continuity.assert_stored_row_v1(stored);
  SELECT * INTO snapshot FROM object_store_continuity.snapshots AS value
   WHERE value.snapshot_id = object_store_continuity_release_shadow_ownership_v1.snapshot_id
     AND value.provider_boundary_id = object_store_continuity_release_shadow_ownership_v1.provider_boundary_id
     AND value.authority_epoch = object_store_continuity_release_shadow_ownership_v1.authority_epoch
     AND value.through_continuity_seq >= object_store_continuity_release_shadow_ownership_v1.continuity_seq;
  SELECT * INTO coverage FROM object_store_continuity.snapshot_coverages AS value
   WHERE value.snapshot_id = object_store_continuity_release_shadow_ownership_v1.snapshot_id
     AND value.continuity_token_id = object_store_continuity_release_shadow_ownership_v1.continuity_token_id
     AND value.provider_boundary_id = object_store_continuity_release_shadow_ownership_v1.provider_boundary_id
     AND value.authority_epoch = object_store_continuity_release_shadow_ownership_v1.authority_epoch
     AND value.continuity_seq = object_store_continuity_release_shadow_ownership_v1.continuity_seq;
  IF snapshot.snapshot_id IS NULL OR coverage.snapshot_id IS NULL
     OR snapshot.manifest_blake3 IS DISTINCT FROM expected_manifest_blake3
     OR coverage.manifest_blake3 IS DISTINCT FROM expected_manifest_blake3
     OR coverage.coverage_blake3 IS DISTINCT FROM expected_coverage_blake3
     OR coverage.local_binding_blake3 IS DISTINCT FROM stored.local_binding_blake3
     OR coverage.local_quota_ownership_blake3 IS DISTINCT FROM stored.quota_ownership_blake3
     OR coverage.authority_lsn IS DISTINCT FROM snapshot.authority_lsn THEN
    RAISE EXCEPTION 'COVERED_RELEASE_SNAPSHOT_MISMATCH' USING ERRCODE = '22023';
  END IF;
  coverage_preimage := object_store_continuity.snapshot_coverage_preimage_v1(
    coverage.snapshot_id, coverage.provider_boundary_id, coverage.authority_epoch,
    coverage.continuity_seq, coverage.continuity_token_id, coverage.local_binding_blake3,
    coverage.local_state_blake3, coverage.local_quota_ownership_blake3,
    coverage.local_counter_revision, coverage.authority_lsn, coverage.manifest_blake3,
    coverage.recorded_at_unix_ms
  );
  PERFORM object_store_continuity.assert_blake3_v1(coverage_preimage, coverage.coverage_blake3);
  IF coverage.canonical_coverage_bytes IS DISTINCT FROM
      coverage_preimage || coverage.coverage_blake3 THEN
    RAISE EXCEPTION 'COVERED_RELEASE_COVERAGE_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
  END IF;
  RETURN object_store_continuity.transition_v1(
    api_revision, 'RECONCILER', 'RELEASE_COVERED_SNAPSHOT', provider_boundary_id,
    authority_epoch, continuity_seq, continuity_token_id, authenticated_cell_id,
    authenticated_tenant_id, logical_request_id, attempt_id, intent_kind,
    selected_fingerprint, expected_prior_row_blake3, expected_state, expected_state,
    'OWNERSHIP_RELEASED', stored.local_binding_blake3, stored.terminal_evidence_blake3,
    stored.adjudication_kind, release_id, 'COVERED_SNAPSHOT', snapshot_id::text,
    coverage.coverage_blake3
  );
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(
  api_revision text, requested_provider_boundary_id text,
  requested_authority_epoch object_store_continuity.uint64,
  requested_continuity_seq object_store_continuity.uint64,
  requested_continuity_token_id uuid
)
RETURNS TABLE(
  receipt_provider_boundary_id text,
  receipt_authority_epoch object_store_continuity.uint64,
  receipt_continuity_seq object_store_continuity.uint64,
  receipt_continuity_token_id uuid,
  release_id uuid,
  receipt_blake3 bytea,
  released_at_unix_ms bigint
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE stored object_store_continuity.shadow_release_receipts%ROWTYPE;
DECLARE release_preimage bytea;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_reconciler_v1();
  SELECT * INTO stored FROM object_store_continuity.shadow_release_receipts AS receipt
   WHERE receipt.provider_boundary_id = requested_provider_boundary_id
     AND receipt.authority_epoch = requested_authority_epoch
     AND receipt.continuity_seq = requested_continuity_seq
     AND receipt.continuity_token_id = requested_continuity_token_id;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  release_preimage := object_store_continuity.release_preimage_v1(
    stored.release_id, stored.provider_boundary_id, stored.authority_epoch,
    stored.continuity_seq, stored.continuity_token_id, stored.continuity_policy_revision,
    stored.quota_ownership_blake3, stored.quota_bytes, stored.quota_rows,
    stored.quota_concurrency, stored.authenticated_cell_id, stored.authenticated_tenant_id,
    stored.release_basis_kind, stored.basis_id, stored.basis_blake3,
    stored.released_at_unix_ms, stored.global_counter_revision,
    stored.boundary_counter_revision, stored.cell_counter_revision,
    stored.tenant_counter_revision
  );
  PERFORM object_store_continuity.assert_blake3_v1(release_preimage, stored.receipt_blake3);
  IF stored.canonical_receipt_bytes IS DISTINCT FROM release_preimage || stored.receipt_blake3 THEN
    RAISE EXCEPTION 'SHADOW_RELEASE_RECEIPT_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
  END IF;
  receipt_provider_boundary_id := stored.provider_boundary_id;
  receipt_authority_epoch := stored.authority_epoch;
  receipt_continuity_seq := stored.continuity_seq;
  receipt_continuity_token_id := stored.continuity_token_id;
  release_id := stored.release_id;
  receipt_blake3 := stored.receipt_blake3;
  released_at_unix_ms := stored.released_at_unix_ms;
  RETURN NEXT;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_archive_prune_v1(
  api_revision text, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64, continuity_token_id uuid,
  expected_row_blake3 bytea, expected_release_receipt_blake3 bytea,
  archive_proof_bytes bytea, archive_proof_blake3 bytea
)
RETURNS TABLE(
  accepted_start_sequence object_store_continuity.uint64,
  accepted_end_sequence object_store_continuity.uint64,
  accepted_row_count object_store_continuity.uint64,
  prune_commit_sequence object_store_continuity.uint64,
  accepted_interval_blake3 bytea
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE epoch_value object_store_continuity.epoch_counters%ROWTYPE;
DECLARE stored object_store_continuity.intents%ROWTYPE;
DECLARE release_value object_store_continuity.shadow_release_receipts%ROWTYPE;
DECLARE left_range object_store_continuity.pruned_ranges%ROWTYPE;
DECLARE right_range object_store_continuity.pruned_ranges%ROWTYPE;
DECLARE merged object_store_continuity.pruned_ranges%ROWTYPE;
DECLARE has_left boolean := false;
DECLARE has_right boolean := false;
DECLARE range_count numeric;
DECLARE canonical_row_size object_store_continuity.uint64;
DECLARE committed_at bigint;
DECLARE required_retention_deadline bigint;
DECLARE interval_preimage bytea;
DECLARE release_preimage bytea;
DECLARE transition_value object_store_continuity.transition_receipts%ROWTYPE;
DECLARE coverage_value object_store_continuity.snapshot_coverages%ROWTYPE;
DECLARE evidence_preimage bytea;
DECLARE deleted_storage_rows numeric := 2;
DECLARE deleted_storage_bytes numeric;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_reconciler_v1();
  PERFORM object_store_continuity.uuid_v7_unix_ms_v1(continuity_token_id);
  IF octet_length(expected_row_blake3) <> 32
     OR octet_length(expected_release_receipt_blake3) <> 32 THEN
    RAISE EXCEPTION 'ARCHIVE_EXPECTED_DIGEST_INVALID' USING ERRCODE = '22023';
  END IF;

  PERFORM 1 FROM object_store_continuity.global_counter WHERE singleton FOR UPDATE;
  PERFORM 1 FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_STORAGE_COUNTER_NAMESPACE_MISSING' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO epoch_value FROM object_store_continuity.epoch_counters AS epoch_counter
   WHERE epoch_counter.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
     AND epoch_counter.authority_epoch = object_store_continuity_archive_prune_v1.authority_epoch
   FOR UPDATE;
  IF NOT FOUND OR epoch_value.retired
     OR epoch_value.api_revision IS DISTINCT FROM api_revision
     OR epoch_value.schema_revision IS DISTINCT FROM 'object-store-authority-continuity-schema-v1'
     OR epoch_value.continuity_contract_revision IS DISTINCT FROM
       'object-store-authority-continuity-contract-v1' THEN
    RAISE EXCEPTION 'ARCHIVE_EPOCH_REVISION_MISMATCH' USING ERRCODE = '40001';
  END IF;
  IF epoch_value.archive_batch_rows < 1 OR epoch_value.prune_batch_rows < 1 THEN
    RAISE EXCEPTION 'ARCHIVE_EPOCH_LIMITS_INVALID' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO stored FROM object_store_continuity.intents AS intent
   WHERE intent.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
     AND intent.authority_epoch = object_store_continuity_archive_prune_v1.authority_epoch
     AND intent.continuity_seq = object_store_continuity_archive_prune_v1.continuity_seq
     AND intent.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id
   FOR UPDATE;
  IF NOT FOUND OR stored.row_blake3 IS DISTINCT FROM expected_row_blake3
     OR stored.continuity_policy_revision IS DISTINCT FROM epoch_value.continuity_policy_revision
     OR stored.state NOT IN (
       'COMPLETED', 'NO_LOCAL_EFFECT', 'ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH'
     ) OR stored.ownership_state IS DISTINCT FROM 'OWNERSHIP_RELEASED' THEN
    RAISE EXCEPTION 'ARCHIVE_DETAIL_NOT_ELIGIBLE' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_continuity.assert_stored_row_v1(stored);

  SELECT * INTO release_value FROM object_store_continuity.shadow_release_receipts AS receipt
   WHERE receipt.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id
     AND receipt.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
     AND receipt.authority_epoch = object_store_continuity_archive_prune_v1.authority_epoch
     AND receipt.continuity_seq = object_store_continuity_archive_prune_v1.continuity_seq
   FOR UPDATE;
  IF NOT FOUND OR release_value.receipt_blake3 IS DISTINCT FROM expected_release_receipt_blake3
     OR release_value.continuity_policy_revision IS DISTINCT FROM stored.continuity_policy_revision
     OR release_value.quota_ownership_blake3 IS DISTINCT FROM stored.quota_ownership_blake3
     OR release_value.quota_rows IS DISTINCT FROM stored.quota_rows
     OR release_value.quota_bytes IS DISTINCT FROM stored.quota_bytes
     OR release_value.quota_concurrency IS DISTINCT FROM stored.quota_concurrency
     OR release_value.authenticated_cell_id IS DISTINCT FROM stored.authenticated_cell_id
     OR release_value.authenticated_tenant_id IS DISTINCT FROM stored.authenticated_tenant_id THEN
    RAISE EXCEPTION 'ARCHIVE_RELEASE_RECEIPT_MISMATCH' USING ERRCODE = '22023';
  END IF;
  release_preimage := object_store_continuity.release_preimage_v1(
    release_value.release_id, release_value.provider_boundary_id, release_value.authority_epoch,
    release_value.continuity_seq, release_value.continuity_token_id,
    release_value.continuity_policy_revision, release_value.quota_ownership_blake3,
    release_value.quota_bytes, release_value.quota_rows, release_value.quota_concurrency,
    release_value.authenticated_cell_id, release_value.authenticated_tenant_id,
    release_value.release_basis_kind, release_value.basis_id, release_value.basis_blake3,
    release_value.released_at_unix_ms, release_value.global_counter_revision,
    release_value.boundary_counter_revision, release_value.cell_counter_revision,
    release_value.tenant_counter_revision
  );
  PERFORM object_store_continuity.assert_blake3_v1(release_preimage, release_value.receipt_blake3);
  IF release_value.canonical_receipt_bytes IS DISTINCT FROM
      release_preimage || release_value.receipt_blake3 THEN
    RAISE EXCEPTION 'ARCHIVE_RELEASE_RECEIPT_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
  END IF;
  deleted_storage_bytes := octet_length(stored.canonical_row_bytes)
    + octet_length(release_value.canonical_receipt_bytes);
  FOR transition_value IN
    SELECT * FROM object_store_continuity.transition_receipts AS receipt
     WHERE receipt.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id
     FOR UPDATE
  LOOP
    evidence_preimage := object_store_continuity.transition_receipt_preimage_v1(transition_value);
    PERFORM object_store_continuity.assert_blake3_v1(
      evidence_preimage, transition_value.receipt_blake3
    );
    IF transition_value.canonical_receipt_bytes IS DISTINCT FROM
        evidence_preimage || transition_value.receipt_blake3 THEN
      RAISE EXCEPTION 'ARCHIVE_TRANSITION_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
    END IF;
    deleted_storage_rows := deleted_storage_rows + 1;
    deleted_storage_bytes := deleted_storage_bytes
      + octet_length(transition_value.canonical_receipt_bytes);
  END LOOP;
  FOR coverage_value IN
    SELECT * FROM object_store_continuity.snapshot_coverages AS coverage
     WHERE coverage.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id
     FOR UPDATE
  LOOP
    evidence_preimage := object_store_continuity.snapshot_coverage_preimage_v1(
      coverage_value.snapshot_id, coverage_value.provider_boundary_id,
      coverage_value.authority_epoch, coverage_value.continuity_seq,
      coverage_value.continuity_token_id, coverage_value.local_binding_blake3,
      coverage_value.local_state_blake3, coverage_value.local_quota_ownership_blake3,
      coverage_value.local_counter_revision, coverage_value.authority_lsn,
      coverage_value.manifest_blake3, coverage_value.recorded_at_unix_ms
    );
    PERFORM object_store_continuity.assert_blake3_v1(
      evidence_preimage, coverage_value.coverage_blake3
    );
    IF coverage_value.canonical_coverage_bytes IS DISTINCT FROM
        evidence_preimage || coverage_value.coverage_blake3 THEN
      RAISE EXCEPTION 'ARCHIVE_COVERAGE_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
    END IF;
    deleted_storage_rows := deleted_storage_rows + 1;
    deleted_storage_bytes := deleted_storage_bytes
      + octet_length(coverage_value.canonical_coverage_bytes);
  END LOOP;
  PERFORM object_store_continuity.assert_archive_eligibility_v1(
    archive_proof_bytes, archive_proof_blake3, stored, release_value.receipt_blake3
  );

  IF stored.external_created_at_unix_ms > 9223372036854775807 - 31622700000
     OR stored.state_committed_at_unix_ms > 9223372036854775807 - 31536000000 THEN
    RAISE EXCEPTION 'ARCHIVE_RETENTION_OVERFLOW' USING ERRCODE = '22003';
  END IF;
  required_retention_deadline := greatest(
    stored.retention_deadline_unix_ms,
    stored.external_created_at_unix_ms + 31622700000,
    stored.state_committed_at_unix_ms + 31536000000,
    release_value.released_at_unix_ms
  );
  committed_at := object_store_continuity.clock_unix_ms_v1();
  IF committed_at < required_retention_deadline THEN
    RAISE EXCEPTION 'ARCHIVE_RETENTION_NOT_REACHED' USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1 FROM object_store_continuity.pruned_ranges AS existing
     WHERE existing.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
       AND existing.authority_epoch = object_store_continuity_archive_prune_v1.authority_epoch
       AND existing.start_sequence <= object_store_continuity_archive_prune_v1.continuity_seq
       AND existing.end_sequence >= object_store_continuity_archive_prune_v1.continuity_seq
  ) THEN
    RAISE EXCEPTION 'ARCHIVE_SEQUENCE_ALREADY_PRUNED' USING ERRCODE = '23505';
  END IF;
  IF continuity_seq > 1 THEN
    SELECT * INTO left_range FROM object_store_continuity.pruned_ranges AS existing
     WHERE existing.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
       AND existing.authority_epoch = object_store_continuity_archive_prune_v1.authority_epoch
       AND existing.end_sequence = object_store_continuity_archive_prune_v1.continuity_seq - 1
     FOR UPDATE;
    has_left := FOUND;
  END IF;
  SELECT * INTO right_range FROM object_store_continuity.pruned_ranges AS existing
   WHERE existing.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
     AND existing.authority_epoch = object_store_continuity_archive_prune_v1.authority_epoch
     AND existing.start_sequence = object_store_continuity_archive_prune_v1.continuity_seq + 1
   FOR UPDATE;
  has_right := FOUND;
  IF (has_left AND (
       left_range.api_revision IS DISTINCT FROM epoch_value.api_revision
       OR left_range.schema_revision IS DISTINCT FROM epoch_value.schema_revision
       OR left_range.continuity_contract_revision IS DISTINCT FROM epoch_value.continuity_contract_revision
       OR left_range.continuity_policy_revision IS DISTINCT FROM epoch_value.continuity_policy_revision
     )) OR (has_right AND (
       right_range.api_revision IS DISTINCT FROM epoch_value.api_revision
       OR right_range.schema_revision IS DISTINCT FROM epoch_value.schema_revision
       OR right_range.continuity_contract_revision IS DISTINCT FROM epoch_value.continuity_contract_revision
       OR right_range.continuity_policy_revision IS DISTINCT FROM epoch_value.continuity_policy_revision
     )) THEN
    RAISE EXCEPTION 'ARCHIVE_ADJACENT_REVISION_MISMATCH' USING ERRCODE = '22000';
  END IF;

  prune_commit_sequence := epoch_value.prune_commit_sequence_high_water + 1;
  canonical_row_size := octet_length(stored.canonical_row_bytes)::numeric;
  merged.provider_boundary_id := provider_boundary_id;
  merged.authority_epoch := authority_epoch;
  merged.start_sequence := CASE WHEN has_left THEN left_range.start_sequence ELSE continuity_seq END;
  merged.end_sequence := CASE WHEN has_right THEN right_range.end_sequence ELSE continuity_seq END;
  merged.row_count := 1
    + CASE WHEN has_left THEN left_range.row_count ELSE 0 END
    + CASE WHEN has_right THEN right_range.row_count ELSE 0 END;
  merged.api_revision := epoch_value.api_revision;
  merged.schema_revision := epoch_value.schema_revision;
  merged.continuity_contract_revision := epoch_value.continuity_contract_revision;
  merged.continuity_policy_revision := epoch_value.continuity_policy_revision;
  merged.completed_count := CASE WHEN stored.state = 'COMPLETED' THEN 1 ELSE 0 END
    + CASE WHEN has_left THEN left_range.completed_count ELSE 0 END
    + CASE WHEN has_right THEN right_range.completed_count ELSE 0 END;
  merged.no_local_effect_count := CASE WHEN stored.state = 'NO_LOCAL_EFFECT' THEN 1 ELSE 0 END
    + CASE WHEN has_left THEN left_range.no_local_effect_count ELSE 0 END
    + CASE WHEN has_right THEN right_range.no_local_effect_count ELSE 0 END;
  merged.adjudicated_no_local_effect_count :=
    CASE WHEN stored.state = 'ADJUDICATED_NO_LOCAL_EFFECT' THEN 1 ELSE 0 END
    + CASE WHEN has_left THEN left_range.adjudicated_no_local_effect_count ELSE 0 END
    + CASE WHEN has_right THEN right_range.adjudicated_no_local_effect_count ELSE 0 END;
  merged.adjudicated_no_dispatch_count :=
    CASE WHEN stored.state = 'ADJUDICATED_NO_DISPATCH' THEN 1 ELSE 0 END
    + CASE WHEN has_left THEN left_range.adjudicated_no_dispatch_count ELSE 0 END
    + CASE WHEN has_right THEN right_range.adjudicated_no_dispatch_count ELSE 0 END;
  merged.canonical_row_bytes_sum := canonical_row_size
    + CASE WHEN has_left THEN left_range.canonical_row_bytes_sum ELSE 0 END
    + CASE WHEN has_right THEN right_range.canonical_row_bytes_sum ELSE 0 END;
  merged.canonical_row_bytes_min := least(
    canonical_row_size,
    CASE WHEN has_left THEN left_range.canonical_row_bytes_min ELSE canonical_row_size END,
    CASE WHEN has_right THEN right_range.canonical_row_bytes_min ELSE canonical_row_size END
  );
  merged.canonical_row_bytes_max := greatest(
    canonical_row_size,
    CASE WHEN has_left THEN left_range.canonical_row_bytes_max ELSE canonical_row_size END,
    CASE WHEN has_right THEN right_range.canonical_row_bytes_max ELSE canonical_row_size END
  );
  merged.quota_rows_sum := stored.quota_rows
    + CASE WHEN has_left THEN left_range.quota_rows_sum ELSE 0 END
    + CASE WHEN has_right THEN right_range.quota_rows_sum ELSE 0 END;
  merged.quota_rows_min := least(stored.quota_rows,
    CASE WHEN has_left THEN left_range.quota_rows_min ELSE stored.quota_rows END,
    CASE WHEN has_right THEN right_range.quota_rows_min ELSE stored.quota_rows END);
  merged.quota_rows_max := greatest(stored.quota_rows,
    CASE WHEN has_left THEN left_range.quota_rows_max ELSE stored.quota_rows END,
    CASE WHEN has_right THEN right_range.quota_rows_max ELSE stored.quota_rows END);
  merged.quota_bytes_sum := stored.quota_bytes
    + CASE WHEN has_left THEN left_range.quota_bytes_sum ELSE 0 END
    + CASE WHEN has_right THEN right_range.quota_bytes_sum ELSE 0 END;
  merged.quota_bytes_min := least(stored.quota_bytes,
    CASE WHEN has_left THEN left_range.quota_bytes_min ELSE stored.quota_bytes END,
    CASE WHEN has_right THEN right_range.quota_bytes_min ELSE stored.quota_bytes END);
  merged.quota_bytes_max := greatest(stored.quota_bytes,
    CASE WHEN has_left THEN left_range.quota_bytes_max ELSE stored.quota_bytes END,
    CASE WHEN has_right THEN right_range.quota_bytes_max ELSE stored.quota_bytes END);
  merged.quota_concurrency_sum := stored.quota_concurrency
    + CASE WHEN has_left THEN left_range.quota_concurrency_sum ELSE 0 END
    + CASE WHEN has_right THEN right_range.quota_concurrency_sum ELSE 0 END;
  merged.quota_concurrency_min := least(stored.quota_concurrency,
    CASE WHEN has_left THEN left_range.quota_concurrency_min ELSE stored.quota_concurrency END,
    CASE WHEN has_right THEN right_range.quota_concurrency_min ELSE stored.quota_concurrency END);
  merged.quota_concurrency_max := greatest(stored.quota_concurrency,
    CASE WHEN has_left THEN left_range.quota_concurrency_max ELSE stored.quota_concurrency END,
    CASE WHEN has_right THEN right_range.quota_concurrency_max ELSE stored.quota_concurrency END);
  merged.created_at_min_unix_ms := least(stored.external_created_at_unix_ms,
    CASE WHEN has_left THEN left_range.created_at_min_unix_ms ELSE stored.external_created_at_unix_ms END,
    CASE WHEN has_right THEN right_range.created_at_min_unix_ms ELSE stored.external_created_at_unix_ms END);
  merged.created_at_max_unix_ms := greatest(stored.external_created_at_unix_ms,
    CASE WHEN has_left THEN left_range.created_at_max_unix_ms ELSE stored.external_created_at_unix_ms END,
    CASE WHEN has_right THEN right_range.created_at_max_unix_ms ELSE stored.external_created_at_unix_ms END);
  merged.closed_at_min_unix_ms := least(stored.state_committed_at_unix_ms,
    CASE WHEN has_left THEN left_range.closed_at_min_unix_ms ELSE stored.state_committed_at_unix_ms END,
    CASE WHEN has_right THEN right_range.closed_at_min_unix_ms ELSE stored.state_committed_at_unix_ms END);
  merged.closed_at_max_unix_ms := greatest(stored.state_committed_at_unix_ms,
    CASE WHEN has_left THEN left_range.closed_at_max_unix_ms ELSE stored.state_committed_at_unix_ms END,
    CASE WHEN has_right THEN right_range.closed_at_max_unix_ms ELSE stored.state_committed_at_unix_ms END);
  merged.prune_commit_sequence_min := least(prune_commit_sequence,
    CASE WHEN has_left THEN left_range.prune_commit_sequence_min ELSE prune_commit_sequence END,
    CASE WHEN has_right THEN right_range.prune_commit_sequence_min ELSE prune_commit_sequence END);
  merged.prune_commit_sequence_max := greatest(prune_commit_sequence,
    CASE WHEN has_left THEN left_range.prune_commit_sequence_max ELSE prune_commit_sequence END,
    CASE WHEN has_right THEN right_range.prune_commit_sequence_max ELSE prune_commit_sequence END);
  merged.pruned_at_min_unix_ms := least(committed_at,
    CASE WHEN has_left THEN left_range.pruned_at_min_unix_ms ELSE committed_at END,
    CASE WHEN has_right THEN right_range.pruned_at_min_unix_ms ELSE committed_at END);
  merged.pruned_at_max_unix_ms := greatest(committed_at,
    CASE WHEN has_left THEN left_range.pruned_at_max_unix_ms ELSE committed_at END,
    CASE WHEN has_right THEN right_range.pruned_at_max_unix_ms ELSE committed_at END);
  interval_preimage := object_store_continuity.pruned_range_preimage_v2(merged);
  IF octet_length(interval_preimage)::numeric + 32 > epoch_value.max_pruned_range_bytes THEN
    RAISE EXCEPTION 'PRUNED_RANGE_TOO_LARGE' USING ERRCODE = '54000';
  END IF;
  merged.interval_blake3 := object_store_continuity.blake3_v1(interval_preimage);
  merged.canonical_interval_bytes := interval_preimage || merged.interval_blake3;

  SELECT count(*) INTO range_count FROM object_store_continuity.pruned_ranges AS existing
   WHERE existing.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id;
  range_count := range_count + 1 - CASE WHEN has_left THEN 1 ELSE 0 END
    - CASE WHEN has_right THEN 1 ELSE 0 END;
  IF range_count > epoch_value.max_pruned_ranges_per_boundary THEN
    RAISE EXCEPTION 'PRUNED_RANGE_CAPACITY_EXHAUSTED' USING ERRCODE = '53000';
  END IF;

  IF has_left THEN
    evidence_preimage := object_store_continuity.pruned_range_preimage_v2(left_range);
    PERFORM object_store_continuity.assert_blake3_v1(evidence_preimage, left_range.interval_blake3);
    IF left_range.canonical_interval_bytes IS DISTINCT FROM
        evidence_preimage || left_range.interval_blake3 THEN
      RAISE EXCEPTION 'ARCHIVE_LEFT_INTERVAL_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
    END IF;
    deleted_storage_rows := deleted_storage_rows + 1;
    deleted_storage_bytes := deleted_storage_bytes
      + octet_length(left_range.canonical_interval_bytes);
  END IF;
  IF has_right THEN
    evidence_preimage := object_store_continuity.pruned_range_preimage_v2(right_range);
    PERFORM object_store_continuity.assert_blake3_v1(evidence_preimage, right_range.interval_blake3);
    IF right_range.canonical_interval_bytes IS DISTINCT FROM
        evidence_preimage || right_range.interval_blake3 THEN
      RAISE EXCEPTION 'ARCHIVE_RIGHT_INTERVAL_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
    END IF;
    deleted_storage_rows := deleted_storage_rows + 1;
    deleted_storage_bytes := deleted_storage_bytes
      + octet_length(right_range.canonical_interval_bytes);
  END IF;
  PERFORM object_store_continuity.apply_storage_mutation_v1(
    provider_boundary_id, 'MAINTENANCE', deleted_storage_rows, deleted_storage_bytes,
    1, octet_length(merged.canonical_interval_bytes)::numeric
  );

  IF has_left THEN
    DELETE FROM object_store_continuity.pruned_ranges AS existing
     WHERE existing.provider_boundary_id = left_range.provider_boundary_id
       AND existing.authority_epoch = left_range.authority_epoch
       AND existing.start_sequence = left_range.start_sequence
       AND existing.end_sequence = left_range.end_sequence;
  END IF;
  IF has_right THEN
    DELETE FROM object_store_continuity.pruned_ranges AS existing
     WHERE existing.provider_boundary_id = right_range.provider_boundary_id
       AND existing.authority_epoch = right_range.authority_epoch
       AND existing.start_sequence = right_range.start_sequence
       AND existing.end_sequence = right_range.end_sequence;
  END IF;
  INSERT INTO object_store_continuity.pruned_ranges SELECT (merged).*;
  DELETE FROM object_store_continuity.transition_receipts AS receipt
   WHERE receipt.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id;
  DELETE FROM object_store_continuity.snapshot_coverages AS coverage
   WHERE coverage.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id;
  DELETE FROM object_store_continuity.shadow_release_receipts AS receipt
   WHERE receipt.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id;
  DELETE FROM object_store_continuity.intents AS intent
   WHERE intent.provider_boundary_id = object_store_continuity_archive_prune_v1.provider_boundary_id
     AND intent.authority_epoch = object_store_continuity_archive_prune_v1.authority_epoch
     AND intent.continuity_seq = object_store_continuity_archive_prune_v1.continuity_seq
     AND intent.continuity_token_id = object_store_continuity_archive_prune_v1.continuity_token_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ARCHIVE_DETAIL_DELETE_LOST' USING ERRCODE = '40001';
  END IF;
  UPDATE object_store_continuity.epoch_counters SET
    prune_commit_sequence_high_water = object_store_continuity_archive_prune_v1.prune_commit_sequence
  WHERE object_store_continuity.epoch_counters.provider_boundary_id =
      object_store_continuity_archive_prune_v1.provider_boundary_id
    AND object_store_continuity.epoch_counters.authority_epoch =
      object_store_continuity_archive_prune_v1.authority_epoch;

  accepted_start_sequence := merged.start_sequence;
  accepted_end_sequence := merged.end_sequence;
  accepted_row_count := merged.row_count;
  accepted_interval_blake3 := merged.interval_blake3;
  RETURN NEXT;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_read_pruned_interval_v2(
  api_revision text, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  continuity_seq object_store_continuity.uint64,
  expected_schema_revision text, expected_continuity_contract_revision text,
  expected_continuity_policy_revision text, expected_epoch_namespace_blake3 bytea
)
RETURNS SETOF object_store_continuity.pruned_ranges
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE epoch_value object_store_continuity.epoch_counters%ROWTYPE;
DECLARE stored_range object_store_continuity.pruned_ranges%ROWTYPE;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_reconciler_v1();
  IF octet_length(expected_epoch_namespace_blake3) <> 32 THEN
    RAISE EXCEPTION 'PRUNED_INTERVAL_NAMESPACE_DIGEST_INVALID' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO epoch_value FROM object_store_continuity.epoch_counters AS epoch_counter
   WHERE epoch_counter.provider_boundary_id = object_store_continuity_read_pruned_interval_v2.provider_boundary_id
     AND epoch_counter.authority_epoch = object_store_continuity_read_pruned_interval_v2.authority_epoch;
  IF NOT FOUND OR epoch_value.api_revision IS DISTINCT FROM api_revision
     OR epoch_value.schema_revision IS DISTINCT FROM expected_schema_revision
     OR epoch_value.continuity_contract_revision IS DISTINCT FROM expected_continuity_contract_revision
     OR epoch_value.continuity_policy_revision IS DISTINCT FROM expected_continuity_policy_revision
     OR epoch_value.epoch_namespace_blake3 IS DISTINCT FROM expected_epoch_namespace_blake3 THEN
    RAISE EXCEPTION 'PRUNED_INTERVAL_NAMESPACE_MISMATCH' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO stored_range FROM object_store_continuity.pruned_ranges AS existing
   WHERE existing.provider_boundary_id = object_store_continuity_read_pruned_interval_v2.provider_boundary_id
     AND existing.authority_epoch = object_store_continuity_read_pruned_interval_v2.authority_epoch
     AND existing.start_sequence <= object_store_continuity_read_pruned_interval_v2.continuity_seq
     AND existing.end_sequence >= object_store_continuity_read_pruned_interval_v2.continuity_seq;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'PRUNED_INTERVAL_NOT_FOUND' USING ERRCODE = '02000';
  END IF;
  PERFORM object_store_continuity.assert_blake3_v1(
    object_store_continuity.pruned_range_preimage_v2(stored_range), stored_range.interval_blake3
  );
  IF stored_range.canonical_interval_bytes IS DISTINCT FROM
      object_store_continuity.pruned_range_preimage_v2(stored_range)
        || stored_range.interval_blake3 THEN
    RAISE EXCEPTION 'PRUNED_INTERVAL_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
  END IF;
  RETURN NEXT stored_range;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_retire_epoch_v2(
  api_revision text, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  expected_epoch_namespace_blake3 bytea, expected_interval_checkpoint_blake3 bytea,
  covering_snapshot_id uuid, expected_snapshot_manifest_blake3 bytea,
  retirement_proof_bytes bytea, retirement_proof_blake3 bytea
)
RETURNS object_store_continuity.retired_epoch_summaries
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE boundary object_store_continuity.boundary_counters%ROWTYPE;
DECLARE epoch_value object_store_continuity.epoch_counters%ROWTYPE;
DECLARE active_range object_store_continuity.pruned_ranges%ROWTYPE;
DECLARE snapshot_value object_store_continuity.snapshots%ROWTYPE;
DECLARE summary_value object_store_continuity.retired_epoch_summaries%ROWTYPE;
DECLARE interval_count numeric;
DECLARE summary_preimage bytea;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_reconciler_v1();
  PERFORM object_store_continuity.uuid_v7_unix_ms_v1(covering_snapshot_id);
  IF octet_length(expected_epoch_namespace_blake3) <> 32
     OR octet_length(expected_interval_checkpoint_blake3) <> 32
     OR octet_length(expected_snapshot_manifest_blake3) <> 32
     OR octet_length(retirement_proof_blake3) <> 32 THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_EXPECTED_DIGEST_INVALID' USING ERRCODE = '22023';
  END IF;
  PERFORM 1 FROM object_store_continuity.global_counter WHERE singleton FOR UPDATE;
  SELECT * INTO boundary FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
   FOR UPDATE;
  SELECT * INTO epoch_value FROM object_store_continuity.epoch_counters AS epoch_counter
   WHERE epoch_counter.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
     AND epoch_counter.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch
   FOR UPDATE;
  IF boundary.provider_boundary_id IS NULL OR epoch_value.provider_boundary_id IS NULL
     OR epoch_value.api_revision IS DISTINCT FROM api_revision
     OR epoch_value.schema_revision IS DISTINCT FROM 'object-store-authority-continuity-schema-v1'
     OR epoch_value.continuity_contract_revision IS DISTINCT FROM
       'object-store-authority-continuity-contract-v1'
     OR epoch_value.epoch_namespace_blake3 IS DISTINCT FROM expected_epoch_namespace_blake3 THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_NAMESPACE_MISMATCH' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO summary_value FROM object_store_continuity.retired_epoch_summaries AS summary
   WHERE summary.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
     AND summary.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch;
  IF FOUND THEN
    IF NOT epoch_value.retired
       OR summary_value.interval_checkpoint_blake3 IS DISTINCT FROM expected_interval_checkpoint_blake3
       OR summary_value.covering_snapshot_id IS DISTINCT FROM covering_snapshot_id
       OR summary_value.covering_snapshot_manifest_blake3 IS DISTINCT FROM
         expected_snapshot_manifest_blake3
       OR summary_value.retirement_proof_blake3 IS DISTINCT FROM retirement_proof_blake3 THEN
      RAISE EXCEPTION 'EPOCH_RETIREMENT_REPLAY_MISMATCH' USING ERRCODE = '23505';
    END IF;
    SELECT * INTO snapshot_value FROM object_store_continuity.snapshots AS snapshot
     WHERE snapshot.snapshot_id = summary_value.covering_snapshot_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'EPOCH_RETIREMENT_REPLAY_SNAPSHOT_MISSING' USING ERRCODE = '22000';
    END IF;
    PERFORM object_store_continuity.assert_retired_epoch_summary_v2(
      summary_value, epoch_value, snapshot_value
    );
    RETURN summary_value;
  END IF;
  IF epoch_value.retired OR boundary.current_authority_epoch = authority_epoch
     OR epoch_value.continuity_seq_high_water = 0 THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_NOT_OLD_ACTIVE_NAMESPACE' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM object_store_continuity.intents AS intent
     WHERE intent.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
       AND intent.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch
  ) THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_LIVE_DETAIL_REMAINS' USING ERRCODE = '55000';
  END IF;
  SELECT count(*), min(existing.start_sequence), max(existing.end_sequence)
    INTO interval_count, active_range.start_sequence, active_range.end_sequence
    FROM object_store_continuity.pruned_ranges AS existing
   WHERE existing.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
     AND existing.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch;
  IF interval_count <> 1 OR active_range.start_sequence <> 1
     OR active_range.end_sequence IS DISTINCT FROM epoch_value.continuity_seq_high_water THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_INTERVAL_COVERAGE_INCOMPLETE' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO active_range FROM object_store_continuity.pruned_ranges AS existing
   WHERE existing.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
     AND existing.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch
     AND existing.start_sequence = 1
     AND existing.end_sequence = epoch_value.continuity_seq_high_water
   FOR UPDATE;
  IF NOT FOUND OR active_range.interval_blake3 IS DISTINCT FROM expected_interval_checkpoint_blake3
     OR active_range.api_revision IS DISTINCT FROM epoch_value.api_revision
     OR active_range.schema_revision IS DISTINCT FROM epoch_value.schema_revision
     OR active_range.continuity_contract_revision IS DISTINCT FROM
       epoch_value.continuity_contract_revision
     OR active_range.continuity_policy_revision IS DISTINCT FROM epoch_value.continuity_policy_revision
     OR active_range.prune_commit_sequence_max IS DISTINCT FROM epoch_value.prune_commit_sequence_high_water THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_INTERVAL_CHECKPOINT_MISMATCH' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_continuity.assert_blake3_v1(
    object_store_continuity.pruned_range_preimage_v2(active_range), active_range.interval_blake3
  );
  IF active_range.canonical_interval_bytes IS DISTINCT FROM
      object_store_continuity.pruned_range_preimage_v2(active_range)
        || active_range.interval_blake3 THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_INTERVAL_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000';
  END IF;
  SELECT * INTO snapshot_value FROM object_store_continuity.snapshots AS snapshot
   WHERE snapshot.snapshot_id = object_store_continuity_retire_epoch_v2.covering_snapshot_id
     AND snapshot.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
     AND snapshot.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch
     AND snapshot.through_continuity_seq >= epoch_value.continuity_seq_high_water;
  IF NOT FOUND OR snapshot_value.manifest_blake3 IS DISTINCT FROM expected_snapshot_manifest_blake3 THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_SNAPSHOT_MISMATCH' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_continuity.assert_epoch_retirement_eligibility_v2(
    retirement_proof_bytes, retirement_proof_blake3, provider_boundary_id, authority_epoch,
    epoch_value.continuity_seq_high_water, active_range.interval_blake3,
    snapshot_value.snapshot_id, snapshot_value.manifest_blake3,
    epoch_value.prune_commit_sequence_high_water
  );

  summary_value.provider_boundary_id := provider_boundary_id;
  summary_value.authority_epoch := authority_epoch;
  summary_value.start_sequence := active_range.start_sequence;
  summary_value.final_sequence := active_range.end_sequence;
  summary_value.row_count := active_range.row_count;
  summary_value.api_revision := active_range.api_revision;
  summary_value.schema_revision := active_range.schema_revision;
  summary_value.continuity_contract_revision := active_range.continuity_contract_revision;
  summary_value.continuity_policy_revision := active_range.continuity_policy_revision;
  summary_value.completed_count := active_range.completed_count;
  summary_value.no_local_effect_count := active_range.no_local_effect_count;
  summary_value.adjudicated_no_local_effect_count := active_range.adjudicated_no_local_effect_count;
  summary_value.adjudicated_no_dispatch_count := active_range.adjudicated_no_dispatch_count;
  summary_value.interval_checkpoint_blake3 := active_range.interval_blake3;
  summary_value.created_at_min_unix_ms := active_range.created_at_min_unix_ms;
  summary_value.created_at_max_unix_ms := active_range.created_at_max_unix_ms;
  summary_value.closed_at_min_unix_ms := active_range.closed_at_min_unix_ms;
  summary_value.closed_at_max_unix_ms := active_range.closed_at_max_unix_ms;
  summary_value.pruned_at_min_unix_ms := active_range.pruned_at_min_unix_ms;
  summary_value.pruned_at_max_unix_ms := active_range.pruned_at_max_unix_ms;
  summary_value.prune_commit_sequence_max := active_range.prune_commit_sequence_max;
  summary_value.covering_snapshot_id := snapshot_value.snapshot_id;
  summary_value.covering_snapshot_through_sequence := snapshot_value.through_continuity_seq;
  summary_value.covering_snapshot_authority_lsn := snapshot_value.authority_lsn;
  summary_value.covering_snapshot_manifest_blake3 := snapshot_value.manifest_blake3;
  summary_value.retirement_proof_blake3 := retirement_proof_blake3;
  summary_value.retired_at_unix_ms := object_store_continuity.clock_unix_ms_v1();
  summary_preimage := object_store_continuity.retired_epoch_summary_preimage_v2(summary_value);
  IF octet_length(summary_preimage)::numeric + 32 > epoch_value.max_epoch_high_water_bytes THEN
    RAISE EXCEPTION 'RETIRED_EPOCH_SUMMARY_TOO_LARGE' USING ERRCODE = '54000';
  END IF;
  summary_value.summary_blake3 := object_store_continuity.blake3_v1(summary_preimage);
  summary_value.canonical_summary_bytes := summary_preimage || summary_value.summary_blake3;
  PERFORM object_store_continuity.apply_storage_mutation_v1(
    provider_boundary_id, 'MAINTENANCE', 1,
    octet_length(active_range.canonical_interval_bytes)::numeric, 1,
    octet_length(summary_value.canonical_summary_bytes)::numeric
  );
  INSERT INTO object_store_continuity.retired_epoch_summaries SELECT (summary_value).*;
  DELETE FROM object_store_continuity.pruned_ranges AS existing
   WHERE existing.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id
     AND existing.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch
     AND existing.start_sequence = active_range.start_sequence
     AND existing.end_sequence = active_range.end_sequence;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_INTERVAL_DELETE_LOST' USING ERRCODE = '40001';
  END IF;
  UPDATE object_store_continuity.epoch_counters SET retired = true
   WHERE object_store_continuity.epoch_counters.provider_boundary_id =
       object_store_continuity_retire_epoch_v2.provider_boundary_id
     AND object_store_continuity.epoch_counters.authority_epoch =
       object_store_continuity_retire_epoch_v2.authority_epoch
     AND NOT retired;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'EPOCH_RETIREMENT_STATE_CAS_LOST' USING ERRCODE = '40001';
  END IF;
  epoch_value.retired := true;
  PERFORM object_store_continuity.assert_retired_epoch_summary_v2(
    summary_value, epoch_value, snapshot_value
  );
  RETURN summary_value;
END
$$;

-- A retired summary is a namespace checkpoint only. It is never per-operation membership proof.
CREATE FUNCTION object_store_continuity.object_store_continuity_read_retired_epoch_v2(
  api_revision text, provider_boundary_id text,
  authority_epoch object_store_continuity.uint64,
  expected_schema_revision text, expected_continuity_contract_revision text,
  expected_continuity_policy_revision text, expected_epoch_namespace_blake3 bytea
)
RETURNS SETOF object_store_continuity.retired_epoch_summaries
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE epoch_value object_store_continuity.epoch_counters%ROWTYPE;
DECLARE summary_value object_store_continuity.retired_epoch_summaries%ROWTYPE;
DECLARE snapshot_value object_store_continuity.snapshots%ROWTYPE;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_reconciler_v1();
  SELECT * INTO epoch_value FROM object_store_continuity.epoch_counters AS epoch_counter
   WHERE epoch_counter.provider_boundary_id = object_store_continuity_read_retired_epoch_v2.provider_boundary_id
     AND epoch_counter.authority_epoch = object_store_continuity_read_retired_epoch_v2.authority_epoch;
  IF NOT FOUND OR NOT epoch_value.retired
     OR epoch_value.api_revision IS DISTINCT FROM api_revision
     OR epoch_value.schema_revision IS DISTINCT FROM expected_schema_revision
     OR epoch_value.continuity_contract_revision IS DISTINCT FROM expected_continuity_contract_revision
     OR epoch_value.continuity_policy_revision IS DISTINCT FROM expected_continuity_policy_revision
     OR epoch_value.epoch_namespace_blake3 IS DISTINCT FROM expected_epoch_namespace_blake3 THEN
    RAISE EXCEPTION 'RETIRED_EPOCH_NAMESPACE_MISMATCH' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO summary_value FROM object_store_continuity.retired_epoch_summaries AS summary
   WHERE summary.provider_boundary_id = object_store_continuity_read_retired_epoch_v2.provider_boundary_id
     AND summary.authority_epoch = object_store_continuity_read_retired_epoch_v2.authority_epoch;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RETIRED_EPOCH_SUMMARY_NOT_FOUND' USING ERRCODE = '02000';
  END IF;
  SELECT * INTO snapshot_value FROM object_store_continuity.snapshots AS snapshot
   WHERE snapshot.snapshot_id = summary_value.covering_snapshot_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RETIRED_EPOCH_SUMMARY_SNAPSHOT_MISSING' USING ERRCODE = '22000';
  END IF;
  PERFORM object_store_continuity.assert_retired_epoch_summary_v2(
    summary_value, epoch_value, snapshot_value
  );
  RETURN NEXT summary_value;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_read_reconciliation_state_v1(
  api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64
)
RETURNS TABLE(
  current_authority_epoch object_store_continuity.uint64,
  continuity_seq_high_water object_store_continuity.uint64,
  owned_rows object_store_continuity.uint64,
  owned_bytes object_store_continuity.uint64,
  owned_concurrency object_store_continuity.uint64,
  latest_snapshot_id uuid,
  latest_snapshot_through_continuity_seq object_store_continuity.uint64,
  latest_snapshot_manifest_blake3 bytea
)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_reconciler_v1();
  RETURN QUERY
  SELECT counter.current_authority_epoch, counter.continuity_seq_high_water,
    counter.owned_rows, counter.owned_bytes, counter.owned_concurrency,
    snapshot.snapshot_id, snapshot.through_continuity_seq, snapshot.manifest_blake3
  FROM object_store_continuity.boundary_counters AS counter
  LEFT JOIN LATERAL (
    SELECT value.snapshot_id, value.through_continuity_seq, value.manifest_blake3
    FROM object_store_continuity.snapshots AS value
    WHERE value.provider_boundary_id = counter.provider_boundary_id
      AND value.authority_epoch = object_store_continuity_read_reconciliation_state_v1.authority_epoch
    ORDER BY value.through_continuity_seq DESC LIMIT 1
  ) AS snapshot ON true
  WHERE counter.provider_boundary_id = object_store_continuity_read_reconciliation_state_v1.provider_boundary_id
    AND counter.current_authority_epoch = object_store_continuity_read_reconciliation_state_v1.authority_epoch;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_read_epoch_v1(
  api_revision text, provider_boundary_id text
)
RETURNS TABLE(authority_epoch object_store_continuity.uint64, continuity_seq_high_water object_store_continuity.uint64)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_reconciler_v1();
  RETURN QUERY SELECT current_authority_epoch, object_store_continuity.boundary_counters.continuity_seq_high_water
    FROM object_store_continuity.boundary_counters
   WHERE object_store_continuity.boundary_counters.provider_boundary_id =
     object_store_continuity_read_epoch_v1.provider_boundary_id;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_allocate_epoch_v1(
  api_revision text, provider_boundary_id text, expected_current_epoch object_store_continuity.uint64,
  next_epoch object_store_continuity.uint64, epoch_namespace_blake3 bytea
)
RETURNS TABLE(authority_epoch object_store_continuity.uint64, continuity_seq_high_water object_store_continuity.uint64)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE boundary object_store_continuity.boundary_counters%ROWTYPE;
DECLARE old_epoch object_store_continuity.epoch_counters%ROWTYPE;
DECLARE current_policy object_store_continuity.policies%ROWTYPE;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_reconciler_v1();
  IF next_epoch <= expected_current_epoch OR octet_length(epoch_namespace_blake3) <> 32 THEN
    RAISE EXCEPTION 'INVALID_NEXT_EPOCH' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO boundary FROM object_store_continuity.boundary_counters AS counter
   WHERE counter.provider_boundary_id = object_store_continuity_allocate_epoch_v1.provider_boundary_id
   FOR UPDATE;
  IF NOT FOUND OR boundary.current_authority_epoch IS DISTINCT FROM expected_current_epoch THEN
    RAISE EXCEPTION 'EPOCH_CAS_OR_DRAIN_FAILED' USING ERRCODE = '40001';
  END IF;
  SELECT * INTO old_epoch FROM object_store_continuity.epoch_counters AS epoch_counter
   WHERE epoch_counter.provider_boundary_id = object_store_continuity_allocate_epoch_v1.provider_boundary_id
     AND epoch_counter.authority_epoch = object_store_continuity_allocate_epoch_v1.expected_current_epoch
   FOR UPDATE;
  IF NOT FOUND OR old_epoch.retired
     OR old_epoch.epoch_namespace_blake3 IS DISTINCT FROM boundary.epoch_namespace_blake3
     OR old_epoch.continuity_seq_high_water IS DISTINCT FROM boundary.continuity_seq_high_water
     OR EXISTS (
       SELECT 1 FROM object_store_continuity.intents AS intent
       WHERE intent.provider_boundary_id = object_store_continuity_allocate_epoch_v1.provider_boundary_id
         AND intent.authority_epoch = object_store_continuity_allocate_epoch_v1.expected_current_epoch
         AND intent.state NOT IN ('COMPLETED', 'NO_LOCAL_EFFECT', 'ADJUDICATED_NO_LOCAL_EFFECT',
           'ADJUDICATED_NO_DISPATCH')
     ) THEN
    RAISE EXCEPTION 'EPOCH_CAS_OR_DRAIN_FAILED' USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1 FROM object_store_continuity.epoch_counters AS epoch_counter
     WHERE epoch_counter.provider_boundary_id = object_store_continuity_allocate_epoch_v1.provider_boundary_id
       AND epoch_counter.authority_epoch >= object_store_continuity_allocate_epoch_v1.next_epoch
  ) THEN
    RAISE EXCEPTION 'NEXT_EPOCH_NOT_ABOVE_NAMESPACE_HIGH_WATER' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO current_policy FROM object_store_continuity.policies WHERE singleton FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_POLICY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  INSERT INTO object_store_continuity.epoch_counters(
    provider_boundary_id, authority_epoch, api_revision, schema_revision,
    continuity_contract_revision, continuity_policy_revision,
    max_pruned_ranges_per_boundary, max_pruned_range_bytes, archive_batch_rows,
    prune_batch_rows, prune_interval_ms, max_epoch_high_water_bytes, epoch_namespace_blake3
  ) VALUES (
    provider_boundary_id, next_epoch, api_revision,
    'object-store-authority-continuity-schema-v1',
    'object-store-authority-continuity-contract-v1', current_policy.policy_revision,
    current_policy.max_pruned_ranges_per_boundary, current_policy.max_pruned_range_bytes,
    current_policy.archive_batch_rows, current_policy.prune_batch_rows,
    current_policy.prune_interval_ms, current_policy.max_epoch_high_water_bytes,
    epoch_namespace_blake3
  );
  UPDATE object_store_continuity.boundary_counters SET
    current_authority_epoch = next_epoch,
    continuity_seq_high_water = 0,
    epoch_namespace_blake3 = object_store_continuity_allocate_epoch_v1.epoch_namespace_blake3,
    counter_revision = counter_revision + 1
  WHERE object_store_continuity.boundary_counters.provider_boundary_id =
      object_store_continuity_allocate_epoch_v1.provider_boundary_id
    AND current_authority_epoch = expected_current_epoch
  RETURNING current_authority_epoch, object_store_continuity.boundary_counters.continuity_seq_high_water
    INTO authority_epoch, continuity_seq_high_water;
  IF NOT FOUND THEN RAISE EXCEPTION 'EPOCH_CAS_OR_DRAIN_FAILED' USING ERRCODE = '40001'; END IF;
  RETURN NEXT;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_bind_boundary_role_v1(
  api_revision text, provider_boundary_id text, boundary_blake3 bytea, login_role name,
  initial_epoch object_store_continuity.uint64, epoch_namespace_blake3 bytea
)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE current_policy object_store_continuity.policies%ROWTYPE;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_migrator_v1();
  IF octet_length(boundary_blake3) <> 32 OR octet_length(epoch_namespace_blake3) <> 32
     OR login_role::text !~ '^odc_b_[a-z2-7]{52}$' OR initial_epoch = 0 THEN
    RAISE EXCEPTION 'INVALID_BOUNDARY_ROLE_BINDING' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO current_policy FROM object_store_continuity.policies WHERE singleton FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'CONTINUITY_POLICY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  INSERT INTO object_store_continuity.boundary_roles(
    provider_boundary_id, boundary_blake3, login_role, created_at_unix_ms
  ) VALUES (
    provider_boundary_id, boundary_blake3, login_role, object_store_continuity.clock_unix_ms_v1()
  );
  INSERT INTO object_store_continuity.boundary_counters(
    provider_boundary_id, current_authority_epoch, epoch_namespace_blake3
  ) VALUES (provider_boundary_id, initial_epoch, epoch_namespace_blake3);
  INSERT INTO object_store_continuity.epoch_counters(
    provider_boundary_id, authority_epoch, api_revision, schema_revision,
    continuity_contract_revision, continuity_policy_revision,
    max_pruned_ranges_per_boundary, max_pruned_range_bytes, archive_batch_rows,
    prune_batch_rows, prune_interval_ms, max_epoch_high_water_bytes, epoch_namespace_blake3
  ) VALUES (
    provider_boundary_id, initial_epoch, api_revision,
    'object-store-authority-continuity-schema-v1',
    'object-store-authority-continuity-contract-v1', current_policy.policy_revision,
    current_policy.max_pruned_ranges_per_boundary, current_policy.max_pruned_range_bytes,
    current_policy.archive_batch_rows, current_policy.prune_batch_rows,
    current_policy.prune_interval_ms, current_policy.max_epoch_high_water_bytes,
    epoch_namespace_blake3
  );
  EXECUTE format('GRANT USAGE ON SCHEMA object_store_continuity TO %I', login_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION object_store_continuity.object_store_continuity_begin_v1(text, object_store_continuity.uint64, uuid, text, text, text, text, uuid, uuid, bytea, text, text, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, bigint) TO %I',
    login_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION object_store_continuity.object_store_continuity_get_by_token_v1(text, text, uuid) TO %I', login_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION object_store_continuity.object_store_continuity_mark_bound_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, bytea) TO %I',
    login_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION object_store_continuity.object_store_continuity_mark_completed_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, bytea, bytea, text) TO %I',
    login_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION object_store_continuity.object_store_continuity_mark_no_local_effect_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, bytea, uuid, text, bytea) TO %I',
    login_role
  );
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_install_policy_v1(
  api_revision text, policy_revision text, canonical_policy_bytes bytea, policy_blake3 bytea,
  max_rows_global object_store_continuity.uint64, max_bytes_global object_store_continuity.uint64,
  max_rows_per_boundary object_store_continuity.uint64,
  max_bytes_per_boundary object_store_continuity.uint64,
  low_water_reserve_rows object_store_continuity.uint64,
  low_water_reserve_bytes object_store_continuity.uint64,
  max_row_bytes object_store_continuity.uint64,
  max_pruned_ranges_per_boundary object_store_continuity.uint64,
  max_pruned_range_bytes object_store_continuity.uint64,
  archive_batch_rows object_store_continuity.uint64,
  prune_batch_rows object_store_continuity.uint64,
  prune_interval_ms object_store_continuity.uint64,
  max_epoch_high_water_bytes object_store_continuity.uint64
)
RETURNS bytea
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_migrator_v1();
  PERFORM object_store_continuity.assert_blake3_v1(canonical_policy_bytes, policy_blake3);
  PERFORM object_store_continuity.assert_policy_materialization_v1(
    canonical_policy_bytes, max_rows_global, max_bytes_global, max_rows_per_boundary,
    max_bytes_per_boundary, low_water_reserve_rows, low_water_reserve_bytes, max_row_bytes,
    max_pruned_ranges_per_boundary, max_pruned_range_bytes, archive_batch_rows,
    prune_batch_rows, prune_interval_ms, max_epoch_high_water_bytes
  );
  INSERT INTO object_store_continuity.policies VALUES (
    true, policy_revision, canonical_policy_bytes, policy_blake3, max_rows_global,
    max_bytes_global, max_rows_per_boundary, max_bytes_per_boundary, low_water_reserve_rows,
    low_water_reserve_bytes, max_row_bytes, max_pruned_ranges_per_boundary,
    max_pruned_range_bytes, archive_batch_rows, prune_batch_rows, prune_interval_ms,
    max_epoch_high_water_bytes, 1, object_store_continuity.clock_unix_ms_v1()
  );
  RETURN policy_blake3;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_read_policy_v1(api_revision text)
RETURNS TABLE(policy_revision text, canonical_policy_bytes bytea, policy_blake3 bytea,
  policy_revision_counter object_store_continuity.uint64, installed_at_unix_ms bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_migrator_v1();
  RETURN QUERY SELECT p.policy_revision, p.canonical_policy_bytes, p.policy_blake3,
    p.policy_revision_counter, p.installed_at_unix_ms FROM object_store_continuity.policies AS p
    WHERE p.singleton;
END
$$;

CREATE FUNCTION object_store_continuity.object_store_continuity_cas_policy_v1(
  api_revision text, expected_policy_revision text, expected_policy_blake3 bytea,
  next_policy_revision text, next_canonical_policy_bytes bytea, next_policy_blake3 bytea
)
RETURNS bytea
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE current_policy object_store_continuity.policies%ROWTYPE;
BEGIN
  PERFORM object_store_continuity.assert_api_revision_v1(api_revision);
  PERFORM object_store_continuity.assert_serializable_write_v1();
  PERFORM object_store_continuity.assert_migrator_v1();
  PERFORM object_store_continuity.assert_blake3_v1(next_canonical_policy_bytes, next_policy_blake3);
  SELECT * INTO current_policy FROM object_store_continuity.policies
   WHERE singleton AND policy_revision = expected_policy_revision
     AND policy_blake3 = expected_policy_blake3
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'POLICY_CAS_FAILED' USING ERRCODE = '40001'; END IF;
  -- This first slice permits limit-preserving CAS only. A later typed 85-field procedure may
  -- change limits after proving they cannot undercut ownership, ambiguity or retention.
  PERFORM object_store_continuity.assert_policy_materialization_v1(
    next_canonical_policy_bytes, current_policy.max_rows_global,
    current_policy.max_bytes_global, current_policy.max_rows_per_boundary,
    current_policy.max_bytes_per_boundary, current_policy.low_water_reserve_rows,
    current_policy.low_water_reserve_bytes, current_policy.max_row_bytes,
    current_policy.max_pruned_ranges_per_boundary, current_policy.max_pruned_range_bytes,
    current_policy.archive_batch_rows, current_policy.prune_batch_rows,
    current_policy.prune_interval_ms, current_policy.max_epoch_high_water_bytes
  );
  UPDATE object_store_continuity.policies SET
    policy_revision = next_policy_revision,
    canonical_policy_bytes = next_canonical_policy_bytes,
    policy_blake3 = next_policy_blake3,
    policy_revision_counter = policy_revision_counter + 1,
    installed_at_unix_ms = object_store_continuity.clock_unix_ms_v1()
  WHERE singleton AND policy_revision = expected_policy_revision
    AND policy_blake3 = expected_policy_blake3
  RETURNING policy_blake3 INTO next_policy_blake3;
  IF NOT FOUND THEN RAISE EXCEPTION 'POLICY_CAS_FAILED' USING ERRCODE = '40001'; END IF;
  RETURN next_policy_blake3;
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_continuity FROM PUBLIC;
GRANT USAGE ON SCHEMA object_store_continuity TO
  object_dispatch_continuity_reconciler, object_dispatch_continuity_migrator;
GRANT EXECUTE ON FUNCTION
  object_store_continuity.object_store_continuity_get_by_token_v1(text, text, uuid),
  object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid),
  object_store_continuity.object_store_continuity_quarantine_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, text, bytea, bytea),
  object_store_continuity.object_store_continuity_mark_ambiguous_dispatch_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, bytea, bytea, text),
  object_store_continuity.object_store_continuity_prepare_adjudication_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, text, bytea, bytea, text),
  object_store_continuity.object_store_continuity_complete_adjudication_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, bytea, bytea, text, text, uuid, text, bytea),
  object_store_continuity.object_store_continuity_record_snapshot_v1(text, uuid, text, object_store_continuity.uint64, object_store_continuity.uint64, pg_lsn, bytea, object_store_continuity.uint64, uuid, bytea, bytea, bytea, object_store_continuity.uint64),
  object_store_continuity.object_store_continuity_release_shadow_ownership_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, text, text, uuid, uuid, text, bytea, bytea, text, uuid, bytea, bytea, uuid),
  object_store_continuity.object_store_continuity_archive_prune_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, bytea, bytea, bytea, bytea),
  object_store_continuity.object_store_continuity_read_pruned_interval_v2(text, text, object_store_continuity.uint64, object_store_continuity.uint64, text, text, text, bytea),
  object_store_continuity.object_store_continuity_retire_epoch_v2(text, text, object_store_continuity.uint64, bytea, bytea, uuid, bytea, bytea, bytea),
  object_store_continuity.object_store_continuity_read_retired_epoch_v2(text, text, object_store_continuity.uint64, text, text, text, bytea),
  object_store_continuity.object_store_continuity_read_reconciliation_state_v1(text, text, object_store_continuity.uint64),
  object_store_continuity.object_store_continuity_read_epoch_v1(text, text),
  object_store_continuity.object_store_continuity_allocate_epoch_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, bytea)
TO object_dispatch_continuity_reconciler;
GRANT EXECUTE ON FUNCTION
  object_store_continuity.object_store_continuity_bind_boundary_role_v1(text, text, bytea, name, object_store_continuity.uint64, bytea),
  object_store_continuity.object_store_continuity_install_policy_v1(text, text, bytea, bytea, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64, object_store_continuity.uint64),
  object_store_continuity.object_store_continuity_read_policy_v1(text),
  object_store_continuity.object_store_continuity_cas_policy_v1(text, text, bytea, text, bytea, bytea)
TO object_dispatch_continuity_migrator;
COMMIT;

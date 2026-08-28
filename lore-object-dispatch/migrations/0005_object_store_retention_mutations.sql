-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark serializable retention mutations.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TYPE object_store_retention.retention_transfer_mutation_v1 AS (
  result_code text,
  compact_record object_store_retention.object_dispatch_compact_receipts,
  schema_state object_store_retention.object_dispatch_retention_schema_state,
  global_counter object_store_retention.object_dispatch_record_storage_counters,
  cell_counter object_store_retention.object_dispatch_record_storage_counters,
  tenant_counter object_store_retention.object_dispatch_record_storage_counters
);

CREATE TYPE object_store_retention.retention_prune_mutation_v1 AS (
  result_code text,
  watermark object_store_retention.object_dispatch_compact_prune_watermark,
  global_counter object_store_retention.object_dispatch_record_storage_counters,
  cell_counter object_store_retention.object_dispatch_record_storage_counters,
  tenant_counter object_store_retention.object_dispatch_record_storage_counters
);

CREATE FUNCTION object_store_retention.assert_mutation_api_revision_v1(api_revision text)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-retention-mutations-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(
  api_revision text,
  requested_logical_request_id uuid,
  requested_attempt_id uuid,
  requested_provider_boundary_id text,
  requested_authenticated_cell_id text,
  requested_authenticated_tenant_id text,
  expected_source_authority_blake3 bytea,
  expected_ownership_revision object_store_retention.uint64,
  expected_compact_sequence_high_water object_store_retention.uint64,
  expected_compact_sequence_revision object_store_retention.uint64,
  expected_global_counter_revision object_store_retention.uint64,
  expected_cell_counter_revision object_store_retention.uint64,
  expected_tenant_counter_revision object_store_retention.uint64,
  requested_compact_receipt_bytes bytea,
  requested_compact_blake3 bytea,
  requested_compaction_fingerprint bytea,
  requested_transfer_fingerprint bytea,
  requested_compacted_at_unix_ms bigint,
  requested_compact_prune_after_unix_ms bigint
)
RETURNS object_store_retention.retention_transfer_mutation_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE full_record object_store_retention.object_dispatch_full_record_ownership%ROWTYPE;
DECLARE compact_record object_store_retention.object_dispatch_compact_receipts%ROWTYPE;
DECLARE global_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE cell_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE tenant_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE database_now_unix_ms bigint;
DECLARE has_full boolean;
DECLARE has_compact boolean;
BEGIN
  PERFORM object_store_retention.assert_retention_maintenance_v1();
  PERFORM object_store_retention.assert_mutation_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF requested_logical_request_id IS NULL OR requested_attempt_id IS NULL
     OR requested_provider_boundary_id IS NULL
     OR octet_length(requested_provider_boundary_id) NOT BETWEEN 1 AND 1024
     OR requested_authenticated_cell_id IS NULL
     OR octet_length(requested_authenticated_cell_id) NOT BETWEEN 1 AND 1024
     OR requested_authenticated_tenant_id IS NULL
     OR octet_length(requested_authenticated_tenant_id) NOT BETWEEN 1 AND 1024
     OR octet_length(expected_source_authority_blake3) IS DISTINCT FROM 32
     OR expected_ownership_revision IS NULL OR expected_ownership_revision = 0
     OR requested_compact_receipt_bytes IS NULL OR octet_length(requested_compact_receipt_bytes) = 0
     OR octet_length(requested_compact_blake3) IS DISTINCT FROM 32
     OR octet_length(requested_compaction_fingerprint) IS DISTINCT FROM 32
     OR octet_length(requested_transfer_fingerprint) IS DISTINCT FROM 32
     OR requested_compacted_at_unix_ms IS NULL OR requested_compacted_at_unix_ms < 0
     OR requested_compact_prune_after_unix_ms IS NULL
     OR requested_compact_prune_after_unix_ms < requested_compacted_at_unix_ms THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_INPUT_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton FOR UPDATE;
  SELECT * INTO full_record
    FROM object_store_retention.object_dispatch_full_record_ownership
   WHERE logical_request_id = requested_logical_request_id
     AND attempt_id = requested_attempt_id
   FOR UPDATE;
  has_full := FOUND;
  SELECT * INTO compact_record
    FROM object_store_retention.object_dispatch_compact_receipts
   WHERE logical_request_id = requested_logical_request_id
     AND attempt_id = requested_attempt_id
   FOR UPDATE;
  has_compact := FOUND;

  IF has_full AND has_compact THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_LIFECYCLE_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF has_compact THEN
    IF compact_record.provider_boundary_id IS DISTINCT FROM requested_provider_boundary_id
       OR compact_record.authenticated_cell_id IS DISTINCT FROM requested_authenticated_cell_id
       OR compact_record.authenticated_tenant_id IS DISTINCT FROM requested_authenticated_tenant_id
       OR compact_record.source_authority_blake3 IS DISTINCT FROM expected_source_authority_blake3
       OR compact_record.compact_receipt_bytes IS DISTINCT FROM requested_compact_receipt_bytes
       OR compact_record.compact_blake3 IS DISTINCT FROM requested_compact_blake3
       OR compact_record.compaction_fingerprint IS DISTINCT FROM requested_compaction_fingerprint
       OR compact_record.transfer_fingerprint IS DISTINCT FROM requested_transfer_fingerprint
       OR compact_record.compacted_at_unix_ms IS DISTINCT FROM requested_compacted_at_unix_ms
       OR compact_record.compact_prune_after_unix_ms IS DISTINCT FROM
          requested_compact_prune_after_unix_ms THEN
      RAISE EXCEPTION 'RETENTION_TRANSFER_REPLAY_CONFLICT' USING ERRCODE = '40001';
    END IF;
    SELECT * INTO STRICT global_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1';
    SELECT * INTO STRICT cell_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 2 AND scope_id = compact_record.authenticated_cell_id;
    SELECT * INTO STRICT tenant_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 3 AND scope_id = compact_record.authenticated_tenant_id;
    RETURN ROW(
      'REPLAY', compact_record, schema_state, global_counter, cell_counter, tenant_counter
    )::object_store_retention.retention_transfer_mutation_v1;
  END IF;
  IF EXISTS (
    SELECT 1 FROM object_store_retention.object_dispatch_compact_receipts
     WHERE transfer_fingerprint = requested_transfer_fingerprint
  ) THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_REPLAY_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF NOT has_full THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_LIFECYCLE_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF expected_compact_sequence_high_water IS NULL
     OR expected_compact_sequence_revision IS NULL OR expected_compact_sequence_revision = 0
     OR expected_global_counter_revision IS NULL OR expected_global_counter_revision = 0
     OR expected_cell_counter_revision IS NULL OR expected_cell_counter_revision = 0
     OR expected_tenant_counter_revision IS NULL OR expected_tenant_counter_revision = 0 THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_INPUT_INVALID' USING ERRCODE = '22023';
  END IF;
  IF full_record.provider_boundary_id IS DISTINCT FROM requested_provider_boundary_id
     OR full_record.authenticated_cell_id IS DISTINCT FROM requested_authenticated_cell_id
     OR full_record.authenticated_tenant_id IS DISTINCT FROM requested_authenticated_tenant_id
     OR full_record.source_authority_blake3 IS DISTINCT FROM expected_source_authority_blake3
     OR full_record.ownership_revision IS DISTINCT FROM expected_ownership_revision
     OR requested_compacted_at_unix_ms < full_record.closure_committed_at_unix_ms
     OR schema_state.compact_sequence_high_water IS DISTINCT FROM
        expected_compact_sequence_high_water
     OR schema_state.compact_sequence_revision IS DISTINCT FROM
        expected_compact_sequence_revision THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_COMPARE_AND_SWAP_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF schema_state.compact_sequence_high_water = 18446744073709551615
     OR schema_state.compact_sequence_revision = 18446744073709551615 THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_SEQUENCE_EXHAUSTED' USING ERRCODE = '22003';
  END IF;
  database_now_unix_ms := object_store_retention.clock_unix_ms_v1();
  IF requested_compacted_at_unix_ms > database_now_unix_ms THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_TIME_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT global_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1'
   FOR UPDATE;
  SELECT * INTO STRICT cell_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 2 AND scope_id = requested_authenticated_cell_id
   FOR UPDATE;
  SELECT * INTO STRICT tenant_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 3 AND scope_id = requested_authenticated_tenant_id
   FOR UPDATE;
  IF global_counter.counter_revision IS DISTINCT FROM expected_global_counter_revision
     OR cell_counter.counter_revision IS DISTINCT FROM expected_cell_counter_revision
     OR tenant_counter.counter_revision IS DISTINCT FROM expected_tenant_counter_revision THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_COMPARE_AND_SWAP_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF cell_counter.full_record_rows > global_counter.full_record_rows
     OR cell_counter.full_record_bytes > global_counter.full_record_bytes
     OR cell_counter.compact_rows > global_counter.compact_rows
     OR cell_counter.compact_bytes > global_counter.compact_bytes
     OR tenant_counter.full_record_rows > global_counter.full_record_rows
     OR tenant_counter.full_record_bytes > global_counter.full_record_bytes
     OR tenant_counter.compact_rows > global_counter.compact_rows
     OR tenant_counter.compact_bytes > global_counter.compact_bytes
     OR global_counter.full_record_rows < full_record.full_record_rows
     OR global_counter.full_record_bytes < full_record.full_record_bytes
     OR cell_counter.full_record_rows < full_record.full_record_rows
     OR cell_counter.full_record_bytes < full_record.full_record_bytes
     OR tenant_counter.full_record_rows < full_record.full_record_rows
     OR tenant_counter.full_record_bytes < full_record.full_record_bytes
     OR global_counter.compact_rows = 18446744073709551615
     OR cell_counter.compact_rows = 18446744073709551615
     OR tenant_counter.compact_rows = 18446744073709551615
     OR global_counter.compact_bytes > 18446744073709551615 - octet_length(requested_compact_receipt_bytes)
     OR cell_counter.compact_bytes > 18446744073709551615 - octet_length(requested_compact_receipt_bytes)
     OR tenant_counter.compact_bytes > 18446744073709551615 - octet_length(requested_compact_receipt_bytes)
     OR global_counter.counter_revision = 18446744073709551615
     OR cell_counter.counter_revision = 18446744073709551615
     OR tenant_counter.counter_revision = 18446744073709551615 THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_COUNTER_INVALID' USING ERRCODE = '22003';
  END IF;

  UPDATE object_store_retention.object_dispatch_retention_schema_state
     SET compact_sequence_high_water = compact_sequence_high_water + 1,
         compact_sequence_revision = compact_sequence_revision + 1
   WHERE singleton
   RETURNING * INTO STRICT schema_state;
  DELETE FROM object_store_retention.object_dispatch_full_record_ownership
   WHERE logical_request_id = requested_logical_request_id
     AND attempt_id = requested_attempt_id
     AND ownership_revision = expected_ownership_revision
     AND source_authority_blake3 = expected_source_authority_blake3;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_COMPARE_AND_SWAP_CONFLICT' USING ERRCODE = '40001';
  END IF;
  INSERT INTO object_store_retention.object_dispatch_compact_receipts (
    compact_sequence, logical_request_id, attempt_id, provider_boundary_id,
    authenticated_cell_id, authenticated_tenant_id, source_authority_blake3,
    compact_receipt_bytes, compact_blake3, compact_rows, compact_bytes,
    compact_concurrency, compaction_fingerprint, transfer_fingerprint,
    compacted_at_unix_ms, compact_prune_after_unix_ms
  ) VALUES (
    schema_state.compact_sequence_high_water, requested_logical_request_id, requested_attempt_id,
    requested_provider_boundary_id, requested_authenticated_cell_id,
    requested_authenticated_tenant_id, expected_source_authority_blake3,
    requested_compact_receipt_bytes, requested_compact_blake3, 1,
    octet_length(requested_compact_receipt_bytes), 0, requested_compaction_fingerprint,
    requested_transfer_fingerprint, requested_compacted_at_unix_ms,
    requested_compact_prune_after_unix_ms
  ) RETURNING * INTO STRICT compact_record;
  UPDATE object_store_retention.object_dispatch_record_storage_counters
     SET full_record_rows = full_record_rows - full_record.full_record_rows,
         full_record_bytes = full_record_bytes - full_record.full_record_bytes,
         compact_rows = compact_rows + 1,
         compact_bytes = compact_bytes + octet_length(requested_compact_receipt_bytes),
         counter_revision = counter_revision + 1
   WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1'
   RETURNING * INTO STRICT global_counter;
  UPDATE object_store_retention.object_dispatch_record_storage_counters
     SET full_record_rows = full_record_rows - full_record.full_record_rows,
         full_record_bytes = full_record_bytes - full_record.full_record_bytes,
         compact_rows = compact_rows + 1,
         compact_bytes = compact_bytes + octet_length(requested_compact_receipt_bytes),
         counter_revision = counter_revision + 1
   WHERE scope_kind = 2 AND scope_id = requested_authenticated_cell_id
   RETURNING * INTO STRICT cell_counter;
  UPDATE object_store_retention.object_dispatch_record_storage_counters
     SET full_record_rows = full_record_rows - full_record.full_record_rows,
         full_record_bytes = full_record_bytes - full_record.full_record_bytes,
         compact_rows = compact_rows + 1,
         compact_bytes = compact_bytes + octet_length(requested_compact_receipt_bytes),
         counter_revision = counter_revision + 1
   WHERE scope_kind = 3 AND scope_id = requested_authenticated_tenant_id
   RETURNING * INTO STRICT tenant_counter;
  IF cell_counter.full_record_rows > global_counter.full_record_rows
     OR cell_counter.full_record_bytes > global_counter.full_record_bytes
     OR cell_counter.compact_rows > global_counter.compact_rows
     OR cell_counter.compact_bytes > global_counter.compact_bytes
     OR tenant_counter.full_record_rows > global_counter.full_record_rows
     OR tenant_counter.full_record_bytes > global_counter.full_record_bytes
     OR tenant_counter.compact_rows > global_counter.compact_rows
     OR tenant_counter.compact_bytes > global_counter.compact_bytes THEN
    RAISE EXCEPTION 'RETENTION_TRANSFER_COUNTER_INVALID' USING ERRCODE = '22003';
  END IF;
  RETURN ROW(
    'APPLIED', compact_record, schema_state, global_counter, cell_counter, tenant_counter
  )::object_store_retention.retention_transfer_mutation_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(
  api_revision text,
  requested_compact_sequence object_store_retention.uint64,
  expected_compact_blake3 bytea,
  requested_prune_fingerprint bytea,
  expected_watermark_revision object_store_retention.uint64,
  expected_global_counter_revision object_store_retention.uint64,
  expected_cell_counter_revision object_store_retention.uint64,
  expected_tenant_counter_revision object_store_retention.uint64,
  requested_backup_revision text,
  requested_backup_manifest_blake3 bytea,
  durable_covered_through_compact_sequence object_store_retention.uint64,
  restore_verified_through_compact_sequence object_store_retention.uint64,
  backup_observed_at_unix_ms bigint
)
RETURNS object_store_retention.retention_prune_mutation_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE compact_record object_store_retention.object_dispatch_compact_receipts%ROWTYPE;
DECLARE watermark object_store_retention.object_dispatch_compact_prune_watermark%ROWTYPE;
DECLARE global_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE cell_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE tenant_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE database_now_unix_ms bigint;
DECLARE has_compact boolean;
BEGIN
  PERFORM object_store_retention.assert_retention_maintenance_v1();
  PERFORM object_store_retention.assert_mutation_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF requested_compact_sequence IS NULL OR requested_compact_sequence = 0
     OR octet_length(expected_compact_blake3) IS DISTINCT FROM 32
     OR octet_length(requested_prune_fingerprint) IS DISTINCT FROM 32
     THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_INPUT_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton FOR UPDATE;
  SELECT * INTO STRICT watermark
    FROM object_store_retention.object_dispatch_compact_prune_watermark
   WHERE singleton FOR UPDATE;
  IF watermark.pruned_through_compact_sequence > schema_state.compact_sequence_high_water THEN
    RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO compact_record
    FROM object_store_retention.object_dispatch_compact_receipts
   WHERE compact_sequence = requested_compact_sequence
   FOR UPDATE;
  has_compact := FOUND;
  IF NOT has_compact THEN
    IF requested_compact_sequence > watermark.pruned_through_compact_sequence THEN
      RAISE EXCEPTION 'RETENTION_PRUNE_LIFECYCLE_CONFLICT' USING ERRCODE = '40001';
    END IF;
    IF requested_compact_sequence = watermark.pruned_through_compact_sequence
       AND (
         watermark.last_compact_blake3 IS DISTINCT FROM expected_compact_blake3
         OR watermark.last_prune_fingerprint IS DISTINCT FROM requested_prune_fingerprint
       ) THEN
      RAISE EXCEPTION 'RETENTION_PRUNE_REPLAY_CONFLICT' USING ERRCODE = '40001';
    END IF;
    SELECT * INTO STRICT global_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1';
    RETURN ROW(
      'REPLAY', watermark, global_counter, NULL, NULL
    )::object_store_retention.retention_prune_mutation_v1;
  END IF;
  IF expected_watermark_revision IS NULL OR expected_watermark_revision = 0
     OR expected_global_counter_revision IS NULL OR expected_global_counter_revision = 0
     OR expected_cell_counter_revision IS NULL OR expected_cell_counter_revision = 0
     OR expected_tenant_counter_revision IS NULL OR expected_tenant_counter_revision = 0
     OR requested_backup_revision IS NULL OR octet_length(requested_backup_revision) = 0
     OR octet_length(requested_backup_manifest_blake3) IS DISTINCT FROM 32
     OR durable_covered_through_compact_sequence IS NULL
     OR restore_verified_through_compact_sequence IS NULL
     OR restore_verified_through_compact_sequence > durable_covered_through_compact_sequence
     OR backup_observed_at_unix_ms IS NULL OR backup_observed_at_unix_ms < 0 THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_INPUT_INVALID' USING ERRCODE = '22023';
  END IF;
  IF requested_compact_sequence <= watermark.pruned_through_compact_sequence
     OR watermark.pruned_through_compact_sequence = 18446744073709551615
     OR requested_compact_sequence <> watermark.pruned_through_compact_sequence + 1
     OR requested_compact_sequence > schema_state.compact_sequence_high_water
     OR compact_record.compact_blake3 IS DISTINCT FROM expected_compact_blake3
     OR watermark.watermark_revision IS DISTINCT FROM expected_watermark_revision THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_COMPARE_AND_SWAP_CONFLICT' USING ERRCODE = '40001';
  END IF;
  database_now_unix_ms := object_store_retention.clock_unix_ms_v1();
  IF database_now_unix_ms < compact_record.compact_prune_after_unix_ms
     OR (
       watermark.last_pruned_at_unix_ms IS NOT NULL
       AND database_now_unix_ms < watermark.last_pruned_at_unix_ms
     )
     OR backup_observed_at_unix_ms > database_now_unix_ms
     OR backup_observed_at_unix_ms < compact_record.compacted_at_unix_ms
     OR durable_covered_through_compact_sequence < requested_compact_sequence
     OR restore_verified_through_compact_sequence < requested_compact_sequence THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_SAFETY_EVIDENCE_INCOMPLETE' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO STRICT global_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1'
   FOR UPDATE;
  SELECT * INTO STRICT cell_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 2 AND scope_id = compact_record.authenticated_cell_id
   FOR UPDATE;
  SELECT * INTO STRICT tenant_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 3 AND scope_id = compact_record.authenticated_tenant_id
   FOR UPDATE;
  IF global_counter.counter_revision IS DISTINCT FROM expected_global_counter_revision
     OR cell_counter.counter_revision IS DISTINCT FROM expected_cell_counter_revision
     OR tenant_counter.counter_revision IS DISTINCT FROM expected_tenant_counter_revision
     OR cell_counter.full_record_rows > global_counter.full_record_rows
     OR cell_counter.full_record_bytes > global_counter.full_record_bytes
     OR cell_counter.compact_rows > global_counter.compact_rows
     OR cell_counter.compact_bytes > global_counter.compact_bytes
     OR tenant_counter.full_record_rows > global_counter.full_record_rows
     OR tenant_counter.full_record_bytes > global_counter.full_record_bytes
     OR tenant_counter.compact_rows > global_counter.compact_rows
     OR tenant_counter.compact_bytes > global_counter.compact_bytes THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_COMPARE_AND_SWAP_CONFLICT' USING ERRCODE = '40001';
  END IF;
  IF global_counter.compact_rows < compact_record.compact_rows
     OR global_counter.compact_bytes < compact_record.compact_bytes
     OR cell_counter.compact_rows < compact_record.compact_rows
     OR cell_counter.compact_bytes < compact_record.compact_bytes
     OR tenant_counter.compact_rows < compact_record.compact_rows
     OR tenant_counter.compact_bytes < compact_record.compact_bytes
     OR watermark.watermark_revision = 18446744073709551615
     OR global_counter.counter_revision = 18446744073709551615
     OR cell_counter.counter_revision = 18446744073709551615
     OR tenant_counter.counter_revision = 18446744073709551615 THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_COUNTER_INVALID' USING ERRCODE = '22003';
  END IF;

  DELETE FROM object_store_retention.object_dispatch_compact_receipts
   WHERE compact_sequence = requested_compact_sequence
     AND compact_blake3 = expected_compact_blake3;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_COMPARE_AND_SWAP_CONFLICT' USING ERRCODE = '40001';
  END IF;
  UPDATE object_store_retention.object_dispatch_record_storage_counters
     SET compact_rows = compact_rows - compact_record.compact_rows,
         compact_bytes = compact_bytes - compact_record.compact_bytes,
         counter_revision = counter_revision + 1
   WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1'
   RETURNING * INTO STRICT global_counter;
  UPDATE object_store_retention.object_dispatch_record_storage_counters
     SET compact_rows = compact_rows - compact_record.compact_rows,
         compact_bytes = compact_bytes - compact_record.compact_bytes,
         counter_revision = counter_revision + 1
   WHERE scope_kind = 2 AND scope_id = compact_record.authenticated_cell_id
   RETURNING * INTO STRICT cell_counter;
  UPDATE object_store_retention.object_dispatch_record_storage_counters
     SET compact_rows = compact_rows - compact_record.compact_rows,
         compact_bytes = compact_bytes - compact_record.compact_bytes,
         counter_revision = counter_revision + 1
   WHERE scope_kind = 3 AND scope_id = compact_record.authenticated_tenant_id
   RETURNING * INTO STRICT tenant_counter;
  UPDATE object_store_retention.object_dispatch_compact_prune_watermark
     SET pruned_through_compact_sequence = requested_compact_sequence,
         watermark_revision = watermark_revision + 1,
         last_prune_fingerprint = requested_prune_fingerprint,
         last_compact_blake3 = expected_compact_blake3,
         last_pruned_at_unix_ms = database_now_unix_ms,
         last_backup_revision = requested_backup_revision,
         last_backup_manifest_blake3 = requested_backup_manifest_blake3
   WHERE singleton AND watermark_revision = expected_watermark_revision
   RETURNING * INTO STRICT watermark;
  IF cell_counter.full_record_rows > global_counter.full_record_rows
     OR cell_counter.full_record_bytes > global_counter.full_record_bytes
     OR cell_counter.compact_rows > global_counter.compact_rows
     OR cell_counter.compact_bytes > global_counter.compact_bytes
     OR tenant_counter.full_record_rows > global_counter.full_record_rows
     OR tenant_counter.full_record_bytes > global_counter.full_record_bytes
     OR tenant_counter.compact_rows > global_counter.compact_rows
     OR tenant_counter.compact_bytes > global_counter.compact_bytes THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_COUNTER_INVALID' USING ERRCODE = '22003';
  END IF;
  RETURN ROW(
    'APPLIED', watermark, global_counter, cell_counter, tenant_counter
  )::object_store_retention.retention_prune_mutation_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_retention_apply_transfer_v1(
    text, uuid, uuid, text, text, text, bytea,
    object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, object_store_retention.uint64,
    bytea, bytea, bytea, bytea, bigint, bigint
  ),
  object_store_retention.object_store_retention_apply_prune_v1(
    text, object_store_retention.uint64, bytea, bytea,
    object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, object_store_retention.uint64,
    text, bytea, object_store_retention.uint64,
    object_store_retention.uint64, bigint
  )
TO object_dispatch_retention_maintenance;

COMMIT;

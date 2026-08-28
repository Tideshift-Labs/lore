-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark durable prune receipts and replay-safe v2 procedures.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TABLE object_store_retention.object_dispatch_compact_prune_receipts_v2 (
  compact_sequence object_store_retention.uint64 PRIMARY KEY CHECK (compact_sequence > 0),
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  authenticated_cell_id text NOT NULL CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  authenticated_tenant_id text NOT NULL CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  compact_blake3 object_store_retention.blake3_256 NOT NULL,
  compact_rows object_store_retention.uint64 NOT NULL CHECK (compact_rows = 1),
  compact_bytes object_store_retention.uint64 NOT NULL CHECK (compact_bytes > 0),
  compact_concurrency object_store_retention.uint64 NOT NULL CHECK (compact_concurrency = 0),
  prune_fingerprint object_store_retention.blake3_256 NOT NULL UNIQUE,
  backup_revision text NOT NULL CHECK (octet_length(backup_revision) BETWEEN 1 AND 4294967295),
  backup_manifest_blake3 object_store_retention.blake3_256 NOT NULL,
  durable_covered_through_compact_sequence object_store_retention.uint64 NOT NULL,
  restore_verified_through_compact_sequence object_store_retention.uint64 NOT NULL,
  backup_observed_at_unix_ms bigint NOT NULL CHECK (backup_observed_at_unix_ms >= 0),
  pruned_at_unix_ms bigint NOT NULL CHECK (pruned_at_unix_ms >= 0),
  post_watermark object_store_retention.object_dispatch_compact_prune_watermark NOT NULL,
  post_global_counter object_store_retention.object_dispatch_record_storage_counters NOT NULL,
  post_cell_counter object_store_retention.object_dispatch_record_storage_counters NOT NULL,
  post_tenant_counter object_store_retention.object_dispatch_record_storage_counters NOT NULL,
  UNIQUE (logical_request_id, attempt_id),
  CHECK (restore_verified_through_compact_sequence <= durable_covered_through_compact_sequence),
  CHECK (durable_covered_through_compact_sequence >= compact_sequence),
  CHECK (restore_verified_through_compact_sequence >= compact_sequence),
  CHECK ((post_watermark).pruned_through_compact_sequence = compact_sequence),
  CHECK ((post_watermark).last_prune_fingerprint = prune_fingerprint),
  CHECK ((post_watermark).last_compact_blake3 = compact_blake3),
  CHECK ((post_watermark).last_pruned_at_unix_ms = pruned_at_unix_ms),
  CHECK ((post_watermark).last_backup_revision = backup_revision),
  CHECK ((post_watermark).last_backup_manifest_blake3 = backup_manifest_blake3),
  CHECK ((post_global_counter).scope_kind = 1),
  CHECK ((post_global_counter).scope_id = 'object-store-full-to-compact-global-v1'),
  CHECK ((post_cell_counter).scope_kind = 2),
  CHECK ((post_cell_counter).scope_id = authenticated_cell_id),
  CHECK ((post_tenant_counter).scope_kind = 3),
  CHECK ((post_tenant_counter).scope_id = authenticated_tenant_id)
);

CREATE TYPE object_store_retention.retention_prune_read_v2 AS (
  state text,
  compact_record object_store_retention.object_dispatch_compact_receipts,
  prune_receipt object_store_retention.object_dispatch_compact_prune_receipts_v2,
  watermark object_store_retention.object_dispatch_compact_prune_watermark,
  global_counter object_store_retention.object_dispatch_record_storage_counters,
  cell_counter object_store_retention.object_dispatch_record_storage_counters,
  tenant_counter object_store_retention.object_dispatch_record_storage_counters,
  database_now_unix_ms bigint
);

CREATE TYPE object_store_retention.retention_prune_mutation_v2 AS (
  result_code text,
  prune_receipt object_store_retention.object_dispatch_compact_prune_receipts_v2
);

CREATE FUNCTION object_store_retention.assert_prune_receipts_api_revision_v2(api_revision text)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-retention-prune-receipts-v2' THEN
    RAISE EXCEPTION 'UNSUPPORTED_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_read_prune_v2(
  api_revision text,
  requested_compact_sequence object_store_retention.uint64
)
RETURNS object_store_retention.retention_prune_read_v2
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE compact_record object_store_retention.object_dispatch_compact_receipts%ROWTYPE;
DECLARE prune_receipt object_store_retention.object_dispatch_compact_prune_receipts_v2%ROWTYPE;
DECLARE watermark object_store_retention.object_dispatch_compact_prune_watermark%ROWTYPE;
DECLARE global_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE cell_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE tenant_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE result_state text;
DECLARE database_now_unix_ms bigint;
BEGIN
  PERFORM object_store_retention.assert_retention_maintenance_v1();
  PERFORM object_store_retention.assert_prune_receipts_api_revision_v2(api_revision);
  IF requested_compact_sequence IS NULL OR requested_compact_sequence = 0 THEN
    RAISE EXCEPTION 'RETENTION_READ_SEQUENCE_REQUIRED' USING ERRCODE = '22023';
  END IF;
  database_now_unix_ms := object_store_retention.clock_unix_ms_v1();
  SELECT * INTO STRICT watermark
    FROM object_store_retention.object_dispatch_compact_prune_watermark WHERE singleton;
  SELECT * INTO STRICT global_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1';
  SELECT * INTO compact_record
    FROM object_store_retention.object_dispatch_compact_receipts
   WHERE compact_sequence = requested_compact_sequence;
  IF FOUND THEN
    result_state := 'COMPACT_INSTALLED';
    SELECT * INTO STRICT cell_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 2 AND scope_id = compact_record.authenticated_cell_id;
    SELECT * INTO STRICT tenant_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 3 AND scope_id = compact_record.authenticated_tenant_id;
  ELSE
    SELECT * INTO prune_receipt
      FROM object_store_retention.object_dispatch_compact_prune_receipts_v2
     WHERE compact_sequence = requested_compact_sequence;
    IF FOUND THEN
      result_state := 'PRUNED';
      watermark := prune_receipt.post_watermark;
      global_counter := prune_receipt.post_global_counter;
      cell_counter := prune_receipt.post_cell_counter;
      tenant_counter := prune_receipt.post_tenant_counter;
    ELSE
      result_state := 'ABSENT_UNPROVEN';
    END IF;
  END IF;
  RETURN ROW(
    result_state, compact_record, prune_receipt, watermark,
    global_counter, cell_counter, tenant_counter, database_now_unix_ms
  )::object_store_retention.retention_prune_read_v2;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v2(
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
RETURNS object_store_retention.retention_prune_mutation_v2
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE compact_record object_store_retention.object_dispatch_compact_receipts%ROWTYPE;
DECLARE existing_receipt object_store_retention.object_dispatch_compact_prune_receipts_v2%ROWTYPE;
DECLARE mutation_result object_store_retention.retention_prune_mutation_v1;
DECLARE inserted_receipt object_store_retention.object_dispatch_compact_prune_receipts_v2%ROWTYPE;
BEGIN
  PERFORM object_store_retention.assert_retention_maintenance_v1();
  PERFORM object_store_retention.assert_prune_receipts_api_revision_v2(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF requested_compact_sequence IS NULL OR requested_compact_sequence = 0
     OR octet_length(expected_compact_blake3) IS DISTINCT FROM 32
     OR octet_length(requested_prune_fingerprint) IS DISTINCT FROM 32 THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_INPUT_INVALID' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton FOR UPDATE;
  SELECT * INTO existing_receipt
    FROM object_store_retention.object_dispatch_compact_prune_receipts_v2
   WHERE compact_sequence = requested_compact_sequence;
  IF FOUND THEN
    IF existing_receipt.compact_blake3 IS DISTINCT FROM expected_compact_blake3
       OR existing_receipt.prune_fingerprint IS DISTINCT FROM requested_prune_fingerprint
       OR existing_receipt.backup_revision IS DISTINCT FROM requested_backup_revision
       OR existing_receipt.backup_manifest_blake3 IS DISTINCT FROM requested_backup_manifest_blake3
       OR existing_receipt.durable_covered_through_compact_sequence IS DISTINCT FROM
          durable_covered_through_compact_sequence
       OR existing_receipt.restore_verified_through_compact_sequence IS DISTINCT FROM
          restore_verified_through_compact_sequence
       OR existing_receipt.backup_observed_at_unix_ms IS DISTINCT FROM
          backup_observed_at_unix_ms THEN
      RAISE EXCEPTION 'RETENTION_PRUNE_REPLAY_CONFLICT' USING ERRCODE = '40001';
    END IF;
    RETURN ROW('REPLAY', existing_receipt)::object_store_retention.retention_prune_mutation_v2;
  END IF;

  SELECT * INTO compact_record
    FROM object_store_retention.object_dispatch_compact_receipts
   WHERE compact_sequence = requested_compact_sequence
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_RECEIPT_REQUIRED' USING ERRCODE = '55000';
  END IF;

  mutation_result := object_store_retention.object_store_retention_apply_prune_v1(
    'object-store-retention-mutations-v1', requested_compact_sequence, expected_compact_blake3,
    requested_prune_fingerprint, expected_watermark_revision,
    expected_global_counter_revision, expected_cell_counter_revision,
    expected_tenant_counter_revision, requested_backup_revision,
    requested_backup_manifest_blake3, durable_covered_through_compact_sequence,
    restore_verified_through_compact_sequence, backup_observed_at_unix_ms
  );
  IF mutation_result.result_code IS DISTINCT FROM 'APPLIED'
     OR mutation_result.cell_counter IS NULL OR mutation_result.tenant_counter IS NULL THEN
    RAISE EXCEPTION 'RETENTION_PRUNE_RECEIPT_REQUIRED' USING ERRCODE = '55000';
  END IF;
  INSERT INTO object_store_retention.object_dispatch_compact_prune_receipts_v2 (
    compact_sequence, logical_request_id, attempt_id, provider_boundary_id,
    authenticated_cell_id, authenticated_tenant_id, compact_blake3,
    compact_rows, compact_bytes, compact_concurrency, prune_fingerprint,
    backup_revision, backup_manifest_blake3,
    durable_covered_through_compact_sequence,
    restore_verified_through_compact_sequence, backup_observed_at_unix_ms,
    pruned_at_unix_ms, post_watermark, post_global_counter,
    post_cell_counter, post_tenant_counter
  ) VALUES (
    compact_record.compact_sequence, compact_record.logical_request_id, compact_record.attempt_id,
    compact_record.provider_boundary_id, compact_record.authenticated_cell_id,
    compact_record.authenticated_tenant_id, compact_record.compact_blake3,
    compact_record.compact_rows, compact_record.compact_bytes,
    compact_record.compact_concurrency, requested_prune_fingerprint,
    requested_backup_revision, requested_backup_manifest_blake3,
    durable_covered_through_compact_sequence,
    restore_verified_through_compact_sequence, backup_observed_at_unix_ms,
    (mutation_result.watermark).last_pruned_at_unix_ms, mutation_result.watermark,
    mutation_result.global_counter, mutation_result.cell_counter, mutation_result.tenant_counter
  ) RETURNING * INTO STRICT inserted_receipt;
  RETURN ROW('APPLIED', inserted_receipt)::object_store_retention.retention_prune_mutation_v2;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM PUBLIC;
REVOKE ALL ON TABLE object_store_retention.object_dispatch_compact_prune_receipts_v2 FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION object_store_retention.object_store_retention_apply_prune_v1(
  text, object_store_retention.uint64, bytea, bytea,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  text, bytea, object_store_retention.uint64,
  object_store_retention.uint64, bigint
) FROM object_dispatch_retention_maintenance;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_retention_read_prune_v2(
    text, object_store_retention.uint64
  ),
  object_store_retention.object_store_retention_apply_prune_v2(
    text, object_store_retention.uint64, bytea, bytea,
    object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, object_store_retention.uint64,
    text, bytea, object_store_retention.uint64,
    object_store_retention.uint64, bigint
  )
TO object_dispatch_retention_maintenance;

COMMIT;

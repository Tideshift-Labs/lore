-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark coherent retention readback.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TYPE object_store_retention.retention_transfer_read_v1 AS (
  state text,
  full_record object_store_retention.object_dispatch_full_record_ownership,
  compact_record object_store_retention.object_dispatch_compact_receipts,
  compact_sequence_high_water object_store_retention.uint64,
  compact_sequence_revision object_store_retention.uint64,
  global_counter object_store_retention.object_dispatch_record_storage_counters,
  cell_counter object_store_retention.object_dispatch_record_storage_counters,
  tenant_counter object_store_retention.object_dispatch_record_storage_counters
);

CREATE TYPE object_store_retention.retention_prune_read_v1 AS (
  state text,
  compact_record object_store_retention.object_dispatch_compact_receipts,
  watermark object_store_retention.object_dispatch_compact_prune_watermark,
  global_counter object_store_retention.object_dispatch_record_storage_counters,
  cell_counter object_store_retention.object_dispatch_record_storage_counters,
  tenant_counter object_store_retention.object_dispatch_record_storage_counters
);

CREATE FUNCTION object_store_retention.assert_readback_api_revision_v1(api_revision text)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-retention-readback-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_retention_maintenance_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance' THEN
    RAISE EXCEPTION 'RETENTION_MAINTENANCE_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_read_transfer_v1(
  api_revision text,
  requested_logical_request_id uuid,
  requested_attempt_id uuid
)
RETURNS object_store_retention.retention_transfer_read_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE full_record object_store_retention.object_dispatch_full_record_ownership%ROWTYPE;
DECLARE compact_record object_store_retention.object_dispatch_compact_receipts%ROWTYPE;
DECLARE global_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE cell_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE tenant_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE has_full boolean;
DECLARE has_compact boolean;
DECLARE result_state text;
DECLARE cell_id text;
DECLARE tenant_id text;
BEGIN
  PERFORM object_store_retention.assert_retention_maintenance_v1();
  PERFORM object_store_retention.assert_readback_api_revision_v1(api_revision);
  IF requested_logical_request_id IS NULL OR requested_attempt_id IS NULL THEN
    RAISE EXCEPTION 'RETENTION_READ_IDENTITY_REQUIRED' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state WHERE singleton;
  SELECT * INTO full_record
    FROM object_store_retention.object_dispatch_full_record_ownership
   WHERE logical_request_id = requested_logical_request_id AND attempt_id = requested_attempt_id;
  has_full := FOUND;
  SELECT * INTO compact_record
    FROM object_store_retention.object_dispatch_compact_receipts
   WHERE logical_request_id = requested_logical_request_id AND attempt_id = requested_attempt_id;
  has_compact := FOUND;
  SELECT * INTO STRICT global_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1';
  IF has_full AND has_compact THEN
    result_state := 'CONFLICT';
    full_record := NULL;
    compact_record := NULL;
  ELSIF has_full THEN
    result_state := 'FULL_OWNED';
    cell_id := full_record.authenticated_cell_id;
    tenant_id := full_record.authenticated_tenant_id;
  ELSIF has_compact THEN
    result_state := 'COMPACT_INSTALLED';
    cell_id := compact_record.authenticated_cell_id;
    tenant_id := compact_record.authenticated_tenant_id;
  ELSE
    result_state := 'ABSENT';
  END IF;
  IF cell_id IS NOT NULL THEN
    SELECT * INTO STRICT cell_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 2 AND scope_id = cell_id;
    SELECT * INTO STRICT tenant_counter
      FROM object_store_retention.object_dispatch_record_storage_counters
     WHERE scope_kind = 3 AND scope_id = tenant_id;
  END IF;
  RETURN ROW(
    result_state, full_record, compact_record,
    schema_state.compact_sequence_high_water, schema_state.compact_sequence_revision,
    global_counter, cell_counter, tenant_counter
  )::object_store_retention.retention_transfer_read_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_read_prune_v1(
  api_revision text,
  requested_compact_sequence object_store_retention.uint64
)
RETURNS object_store_retention.retention_prune_read_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE compact_record object_store_retention.object_dispatch_compact_receipts%ROWTYPE;
DECLARE watermark object_store_retention.object_dispatch_compact_prune_watermark%ROWTYPE;
DECLARE global_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE cell_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE tenant_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
DECLARE result_state text;
BEGIN
  PERFORM object_store_retention.assert_retention_maintenance_v1();
  PERFORM object_store_retention.assert_readback_api_revision_v1(api_revision);
  IF requested_compact_sequence IS NULL OR requested_compact_sequence = 0 THEN
    RAISE EXCEPTION 'RETENTION_READ_SEQUENCE_REQUIRED' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state WHERE singleton;
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
    result_state := 'COMPACT_ABSENT';
  END IF;
  RETURN ROW(
    result_state, compact_record, watermark, global_counter, cell_counter, tenant_counter
  )::object_store_retention.retention_prune_read_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_retention_read_transfer_v1(text, uuid, uuid),
  object_store_retention.object_store_retention_read_prune_v1(
    text, object_store_retention.uint64
  )
TO object_dispatch_retention_maintenance;

COMMIT;

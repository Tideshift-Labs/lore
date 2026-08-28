-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark atomic non-final PUT-upload progress mutation.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TYPE object_store_retention.dispatch_put_upload_progress_result_v1 AS (
  result_code text,
  spool_object_id uuid,
  logical_request_id uuid,
  attempt_id uuid,
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  committed_prefix_bytes object_store_retention.uint64,
  committed_prefix_chunks object_store_retention.uint64,
  spool_revision object_store_retention.uint64,
  record_blake3 bytea
);

CREATE FUNCTION object_store_retention.assert_dispatch_put_upload_progress_api_revision_v1(
  api_revision text
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-dispatch-put-upload-progress-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_DISPATCH_PUT_UPLOAD_PROGRESS_API_REVISION'
      USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.project_dispatch_put_upload_progress_v1(
  stored object_store_retention.object_dispatch_spool_objects,
  result_code text
)
RETURNS object_store_retention.dispatch_put_upload_progress_result_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF result_code IS NULL OR result_code NOT IN ('APPLIED', 'REPLAY') THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_RESULT_INVALID' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_retention.project_dispatch_reserved_put_v1(stored, 'REPLAY');
  IF stored.partial_temp_bytes = 0 OR stored.partial_temp_chunks = 0
     OR stored.partial_temp_files IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_STORED_STATE_INVALID'
      USING ERRCODE = '55000';
  END IF;
  RETURN ROW(
    result_code, stored.spool_object_id, stored.logical_request_id, stored.attempt_id,
    stored.upload_id, stored.upload_fence, stored.partial_temp_bytes,
    stored.partial_temp_chunks, stored.spool_revision, stored.record_blake3
  )::object_store_retention.dispatch_put_upload_progress_result_v1;
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_put_upload_progress_v1(
  api_revision text,
  protocol_revision text,
  provider_boundary_id text,
  authenticated_cell_id text,
  authenticated_tenant_id text,
  logical_request_id uuid,
  attempt_id uuid,
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  chunk_index object_store_retention.uint64,
  fsynced_prefix_bytes object_store_retention.uint64,
  maximum_identity_bytes integer,
  maximum_boundary_token_bytes integer,
  maximum_record_bytes integer
)
RETURNS object_store_retention.dispatch_put_upload_progress_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE stored object_store_retention.object_dispatch_spool_objects%ROWTYPE;
DECLARE next_record object_store_retention.local_canonical_record_v1;
DECLARE database_now bigint;
DECLARE next_chunks numeric;
DECLARE next_revision numeric;
DECLARE affected_rows integer;
BEGIN
  PERFORM object_store_retention.assert_dispatch_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_put_upload_progress_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();

  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton
   FOR SHARE;
  IF schema_state.schema_revision IS DISTINCT FROM 'object-store-retention-authority-schema-v1'
     OR schema_state.migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd', 'hex')
     OR schema_state.local_authority_schema_revision IS DISTINCT FROM
        'object-store-dispatch-authority-schema-v1'
     OR schema_state.local_authority_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff', 'hex')
     OR schema_state.put_reservation_schema_revision IS DISTINCT FROM
        'object-store-dispatch-put-reservation-schema-v1'
     OR schema_state.put_reservation_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67', 'hex') THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_SCHEMA_UNAVAILABLE'
      USING ERRCODE = '55000';
  END IF;

  SELECT * INTO stored
    FROM object_store_retention.object_dispatch_spool_objects AS spool
   WHERE spool.logical_request_id = object_store_dispatch_put_upload_progress_v1.logical_request_id
     AND spool.attempt_id = object_store_dispatch_put_upload_progress_v1.attempt_id
     AND spool.payload_kind = 1
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'EXPIRED_OR_UNKNOWN' USING ERRCODE = '22023';
  END IF;
  IF stored.protocol_revision IS DISTINCT FROM protocol_revision
     OR stored.provider_boundary_id IS DISTINCT FROM provider_boundary_id
     OR stored.authenticated_cell_id IS DISTINCT FROM authenticated_cell_id
     OR stored.authenticated_tenant_id IS DISTINCT FROM authenticated_tenant_id
     OR stored.logical_request_id IS DISTINCT FROM logical_request_id
     OR stored.attempt_id IS DISTINCT FROM attempt_id
     OR stored.upload_id IS DISTINCT FROM upload_id
     OR stored.upload_fence IS DISTINCT FROM upload_fence THEN
    RAISE EXCEPTION 'UPLOAD_STREAM_IDENTITY_MISMATCH' USING ERRCODE = '22023';
  END IF;

  PERFORM object_store_retention.project_dispatch_reserved_put_v1(stored, 'REPLAY');
  IF chunk_index IS NULL OR fsynced_prefix_bytes IS NULL THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT'
      USING ERRCODE = '22023';
  END IF;

  IF stored.partial_temp_chunks > 0
     AND chunk_index = stored.partial_temp_chunks - 1
     AND fsynced_prefix_bytes = stored.partial_temp_bytes THEN
    RETURN object_store_retention.project_dispatch_put_upload_progress_v1(stored, 'REPLAY');
  END IF;
  IF chunk_index < stored.partial_temp_chunks THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_REPLAY_CONFLICT'
      USING ERRCODE = '23505';
  END IF;
  IF chunk_index > stored.partial_temp_chunks THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_CHUNK_GAP' USING ERRCODE = '22023';
  END IF;
  IF maximum_identity_bytes IS NULL OR maximum_identity_bytes NOT BETWEEN 1 AND 1024
     OR maximum_boundary_token_bytes IS NULL
     OR maximum_boundary_token_bytes NOT BETWEEN 1 AND 4096
     OR maximum_record_bytes IS NULL OR maximum_record_bytes NOT BETWEEN 1 AND 16777216 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT'
      USING ERRCODE = '22023';
  END IF;
  IF stored.partial_temp_chunks = 18446744073709551615
     OR stored.spool_revision = 18446744073709551615 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_COUNTER_OVERFLOW'
      USING ERRCODE = '22003';
  END IF;
  IF fsynced_prefix_bytes <= stored.partial_temp_bytes
     OR fsynced_prefix_bytes >= stored.expected_size
     OR fsynced_prefix_bytes - stored.partial_temp_bytes > stored.max_chunk_bytes THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT'
      USING ERRCODE = '22023';
  END IF;

  database_now := object_store_retention.clock_unix_ms_v1();
  IF database_now < 0 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_TIME_INVALID' USING ERRCODE = '22023';
  END IF;
  IF database_now >= stored.expires_at_unix_ms THEN
    RAISE EXCEPTION 'UPLOAD_CLOSED' USING ERRCODE = '55000';
  END IF;

  next_chunks := stored.partial_temp_chunks + 1;
  next_revision := stored.spool_revision + 1;
  next_record := object_store_retention.local_put_reserved_record_v2(
    stored.protocol_revision, stored.policy_revision, stored.provider_boundary_id,
    stored.authenticated_cell_id, stored.authenticated_tenant_id, stored.spool_object_id,
    stored.logical_request_id, stored.attempt_id, stored.upload_id, stored.upload_fence,
    stored.boundary_blake3, stored.boundary_token, stored.observation_binding_blake3,
    stored.expected_size, stored.expected_blake3, fsynced_prefix_bytes, next_chunks, 1,
    stored.put_reservation_fingerprint, stored.allocation_revision, stored.allocation_fence,
    stored.reservation_deadline_unix_ms, stored.allocation_hard_expiry_unix_ms,
    stored.admission_clock_unix_ms, stored.prepared_ttl_ms, stored.expires_at_unix_ms,
    stored.max_chunk_bytes, stored.quota_bytes, stored.quota_rows,
    stored.quota_concurrency, stored.quota_revision,
    stored.reserve_put_ack_canonical_bytes, stored.reserve_put_ack_blake3,
    next_revision, maximum_identity_bytes, maximum_boundary_token_bytes,
    maximum_record_bytes
  );

  UPDATE object_store_retention.object_dispatch_spool_objects AS spool
     SET partial_temp_bytes = fsynced_prefix_bytes,
         partial_temp_chunks = next_chunks,
         partial_temp_files = 1,
         canonical_record_bytes = next_record.canonical_bytes,
         record_blake3 = next_record.record_blake3,
         spool_revision = next_revision
   WHERE spool.logical_request_id = object_store_dispatch_put_upload_progress_v1.logical_request_id
     AND spool.attempt_id = object_store_dispatch_put_upload_progress_v1.attempt_id
     AND spool.payload_kind = 1
     AND spool.spool_revision = stored.spool_revision
  RETURNING * INTO stored;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_CONFLICT' USING ERRCODE = '40001';
  END IF;
  RETURN object_store_retention.project_dispatch_put_upload_progress_v1(stored, 'APPLIED');
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_PROGRESS_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_put_upload_progress_v1(
  text, text, text, text, text, uuid, uuid, uuid,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, integer, integer, integer
) TO object_dispatch_retention_runtime;

REVOKE ALL ON FUNCTION object_store_retention.assert_dispatch_put_upload_progress_api_revision_v1(
  text
) FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;
REVOKE ALL ON FUNCTION object_store_retention.project_dispatch_put_upload_progress_v1(
  object_store_retention.object_dispatch_spool_objects,
  text
) FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;
REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

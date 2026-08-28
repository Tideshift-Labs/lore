-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark canonical in-flight PUT-upload progress codec.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE FUNCTION object_store_retention.local_put_reserved_record_v2(
  protocol_revision text,
  policy_revision text,
  provider_boundary_id text,
  authenticated_cell_id text,
  authenticated_tenant_id text,
  spool_object_id uuid,
  logical_request_id uuid,
  attempt_id uuid,
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  boundary_blake3 bytea,
  boundary_token text,
  observation_binding_blake3 bytea,
  expected_size object_store_retention.uint64,
  expected_blake3 bytea,
  partial_temp_bytes object_store_retention.uint64,
  partial_temp_chunks object_store_retention.uint64,
  partial_temp_files object_store_retention.uint64,
  put_reservation_fingerprint bytea,
  allocation_revision text,
  allocation_fence object_store_retention.uint64,
  reservation_deadline_unix_ms bigint,
  allocation_hard_expiry_unix_ms bigint,
  admission_clock_unix_ms bigint,
  prepared_ttl_ms bigint,
  expires_at_unix_ms bigint,
  max_chunk_bytes object_store_retention.uint64,
  quota_bytes object_store_retention.uint64,
  quota_rows object_store_retention.uint64,
  quota_concurrency object_store_retention.uint64,
  quota_revision object_store_retention.uint64,
  reserve_put_ack_canonical_bytes bytea,
  reserve_put_ack_blake3 bytea,
  spool_revision object_store_retention.uint64,
  maximum_identity_bytes integer,
  maximum_boundary_token_bytes integer,
  maximum_record_bytes integer
)
RETURNS object_store_retention.local_canonical_record_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE expected_ack object_store_retention.local_canonical_record_v1;
DECLARE quota_child bytea;
DECLARE preimage bytea;
BEGIN
  IF protocol_revision IS NULL OR policy_revision IS NULL
     OR provider_boundary_id IS NULL OR authenticated_cell_id IS NULL
     OR authenticated_tenant_id IS NULL OR spool_object_id IS NULL
     OR logical_request_id IS NULL OR attempt_id IS NULL OR upload_id IS NULL
     OR upload_fence IS NULL OR upload_fence = 0
     OR boundary_blake3 IS NULL OR pg_catalog.octet_length(boundary_blake3) <> 32
     OR boundary_token IS NULL
     OR observation_binding_blake3 IS NULL
     OR pg_catalog.octet_length(observation_binding_blake3) <> 32
     OR expected_size IS NULL
     OR expected_blake3 IS NULL OR pg_catalog.octet_length(expected_blake3) <> 32
     OR partial_temp_bytes IS NULL OR partial_temp_chunks IS NULL
     OR partial_temp_files IS NULL
     OR put_reservation_fingerprint IS NULL
     OR pg_catalog.octet_length(put_reservation_fingerprint) <> 32
     OR allocation_revision IS NULL OR allocation_fence IS NULL OR allocation_fence = 0
     OR reservation_deadline_unix_ms IS NULL
     OR allocation_hard_expiry_unix_ms IS NULL OR admission_clock_unix_ms IS NULL
     OR prepared_ttl_ms IS NULL OR expires_at_unix_ms IS NULL
     OR max_chunk_bytes IS NULL OR max_chunk_bytes = 0
     OR quota_bytes IS NULL OR quota_rows IS NULL OR quota_concurrency IS NULL
     OR quota_revision IS NULL OR quota_revision = 0
     OR reserve_put_ack_canonical_bytes IS NULL OR reserve_put_ack_blake3 IS NULL
     OR pg_catalog.octet_length(reserve_put_ack_blake3) <> 32
     OR spool_revision IS NULL OR spool_revision = 0
     OR maximum_identity_bytes IS NULL
     OR maximum_identity_bytes NOT BETWEEN 1 AND 1024
     OR maximum_boundary_token_bytes IS NULL
     OR maximum_boundary_token_bytes NOT BETWEEN 1 AND 4096
     OR maximum_record_bytes IS NULL
     OR maximum_record_bytes NOT BETWEEN 1 AND 16777216
     OR quota_bytes IS DISTINCT FROM expected_size
     OR quota_rows IS DISTINCT FROM 1 OR quota_concurrency IS DISTINCT FROM 1
     OR admission_clock_unix_ms < 0
     OR reservation_deadline_unix_ms <= admission_clock_unix_ms
     OR allocation_hard_expiry_unix_ms <= admission_clock_unix_ms
     OR prepared_ttl_ms <= 0
     OR admission_clock_unix_ms::numeric + prepared_ttl_ms::numeric > 9223372036854775807
     OR expires_at_unix_ms <= admission_clock_unix_ms
     OR expires_at_unix_ms > reservation_deadline_unix_ms
     OR expires_at_unix_ms > allocation_hard_expiry_unix_ms
     OR expires_at_unix_ms - admission_clock_unix_ms > prepared_ttl_ms
     OR NOT (
       expires_at_unix_ms = reservation_deadline_unix_ms OR
       expires_at_unix_ms = allocation_hard_expiry_unix_ms OR
       expires_at_unix_ms - admission_clock_unix_ms = prepared_ttl_ms
     )
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(spool_object_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(spool_object_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 8) >> 6) <> 2
     OR NOT (
       (
         partial_temp_bytes = 0 AND partial_temp_chunks = 0
         AND partial_temp_files = 0 AND spool_revision = 1
       ) OR (
         expected_size > 0 AND partial_temp_bytes > 0
         AND partial_temp_bytes < expected_size
         AND partial_temp_chunks > 0
         AND partial_temp_chunks < 18446744073709551615
         AND partial_temp_files = 1
         AND partial_temp_chunks <= partial_temp_bytes
         AND partial_temp_bytes <= partial_temp_chunks * max_chunk_bytes
         AND spool_revision = partial_temp_chunks + 1
       )
     ) THEN
    RAISE EXCEPTION 'LOCAL_PUT_RESERVED_RECORD_INVALID' USING ERRCODE = '22023';
  END IF;

  expected_ack := object_store_retention.local_reserve_put_ack_v1(
    protocol_revision, policy_revision, provider_boundary_id, authenticated_cell_id,
    authenticated_tenant_id, logical_request_id, attempt_id, upload_id, upload_fence,
    1::smallint, quota_bytes, quota_rows, quota_concurrency, expires_at_unix_ms,
    max_chunk_bytes, NULL, NULL, NULL, NULL, admission_clock_unix_ms,
    allocation_hard_expiry_unix_ms, maximum_identity_bytes, 1, maximum_record_bytes
  );
  IF expected_ack.canonical_bytes IS DISTINCT FROM reserve_put_ack_canonical_bytes
     OR expected_ack.record_blake3 IS DISTINCT FROM reserve_put_ack_blake3 THEN
    RAISE EXCEPTION 'LOCAL_PUT_RESERVATION_ACK_MISMATCH' USING ERRCODE = '22023';
  END IF;

  quota_child := object_store_retention.local_quota_child_v1(
    quota_bytes, quota_rows, quota_concurrency, maximum_record_bytes
  );
  preimage := pg_catalog.convert_to('object-store-dispatch-put-reservation-row-v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || object_store_retention.local_canonical_text_v1(
         'object-store-dispatch-authority-schema-v1', maximum_identity_bytes
       )
    || object_store_retention.local_canonical_text_v1(protocol_revision, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(policy_revision, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(provider_boundary_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(authenticated_cell_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(authenticated_tenant_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(spool_object_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(logical_request_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(attempt_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(upload_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_u64_v1(upload_fence)
    || object_store_retention.local_canonical_u8_v1(1)
    || object_store_retention.local_canonical_u8_v1(1)
    || object_store_retention.local_canonical_u8_v1(1)
    || object_store_retention.local_canonical_u8_v1(1)
    || boundary_blake3
    || object_store_retention.local_canonical_text_v1(
         boundary_token, maximum_boundary_token_bytes
       )
    || observation_binding_blake3
    || object_store_retention.local_canonical_u64_v1(expected_size)
    || expected_blake3
    || object_store_retention.local_canonical_u64_v1(partial_temp_bytes)
    || object_store_retention.local_canonical_u64_v1(partial_temp_chunks)
    || object_store_retention.local_canonical_u64_v1(partial_temp_files)
    || object_store_retention.local_canonical_bytes_v1(quota_child, maximum_record_bytes)
    || object_store_retention.local_canonical_u64_v1(quota_revision)
    || object_store_retention.local_canonical_u64_v1(
         expires_at_unix_ms::object_store_retention.uint64
       )
    || put_reservation_fingerprint
    || object_store_retention.local_canonical_text_v1(allocation_revision, maximum_identity_bytes)
    || object_store_retention.local_canonical_u64_v1(allocation_fence)
    || object_store_retention.local_canonical_u64_v1(
         reservation_deadline_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         allocation_hard_expiry_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         admission_clock_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         prepared_ttl_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(max_chunk_bytes)
    || object_store_retention.local_canonical_bytes_v1(
         reserve_put_ack_canonical_bytes, maximum_record_bytes
       )
    || reserve_put_ack_blake3
    || object_store_retention.local_canonical_u64_v1(spool_revision)
    || object_store_retention.local_canonical_u64_v1(
         admission_clock_unix_ms::object_store_retention.uint64
       );
  RETURN object_store_retention.local_complete_record_v1(preimage, maximum_record_bytes);
END
$$;

CREATE OR REPLACE FUNCTION object_store_retention.local_put_reservation_record_v1(
  protocol_revision text, policy_revision text, provider_boundary_id text,
  authenticated_cell_id text, authenticated_tenant_id text, spool_object_id uuid,
  logical_request_id uuid, attempt_id uuid, upload_id uuid,
  upload_fence object_store_retention.uint64, boundary_blake3 bytea, boundary_token text,
  observation_binding_blake3 bytea, expected_size object_store_retention.uint64,
  expected_blake3 bytea, put_reservation_fingerprint bytea, allocation_revision text,
  allocation_fence object_store_retention.uint64, reservation_deadline_unix_ms bigint,
  allocation_hard_expiry_unix_ms bigint, admission_clock_unix_ms bigint,
  prepared_ttl_ms bigint, expires_at_unix_ms bigint,
  max_chunk_bytes object_store_retention.uint64, quota_bytes object_store_retention.uint64,
  quota_rows object_store_retention.uint64, quota_concurrency object_store_retention.uint64,
  quota_revision object_store_retention.uint64, reserve_put_ack_canonical_bytes bytea,
  reserve_put_ack_blake3 bytea, spool_revision object_store_retention.uint64,
  maximum_identity_bytes integer, maximum_boundary_token_bytes integer,
  maximum_record_bytes integer
)
RETURNS object_store_retention.local_canonical_record_v1
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT object_store_retention.local_put_reserved_record_v2(
    protocol_revision, policy_revision, provider_boundary_id, authenticated_cell_id,
    authenticated_tenant_id, spool_object_id, logical_request_id, attempt_id, upload_id,
    upload_fence, boundary_blake3, boundary_token, observation_binding_blake3,
    expected_size, expected_blake3, 0, 0, 0, put_reservation_fingerprint,
    allocation_revision, allocation_fence, reservation_deadline_unix_ms,
    allocation_hard_expiry_unix_ms, admission_clock_unix_ms, prepared_ttl_ms,
    expires_at_unix_ms, max_chunk_bytes, quota_bytes, quota_rows, quota_concurrency,
    quota_revision, reserve_put_ack_canonical_bytes, reserve_put_ack_blake3,
    spool_revision, maximum_identity_bytes, maximum_boundary_token_bytes,
    maximum_record_bytes
  )
$$;

CREATE OR REPLACE FUNCTION object_store_retention.project_dispatch_reserved_put_v1(
  stored object_store_retention.object_dispatch_spool_objects,
  result_code text
)
RETURNS object_store_retention.dispatch_reserve_put_result_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE expected_record object_store_retention.local_canonical_record_v1;
BEGIN
  IF stored IS NULL OR result_code IS NULL OR result_code NOT IN ('CREATED', 'REPLAY')
     OR stored.schema_revision IS DISTINCT FROM 'object-store-dispatch-authority-schema-v1'
     OR stored.request_binding_state IS DISTINCT FROM 1
     OR stored.payload_kind IS DISTINCT FROM 1
     OR stored.lifecycle_state IS DISTINCT FROM 1
     OR stored.purge_state IS DISTINCT FROM 1
     OR stored.committed_size IS NOT NULL OR stored.committed_blake3 IS NOT NULL
     OR stored.durable_handle IS NOT NULL OR stored.ready_at_unix_ms IS NOT NULL
     OR stored.bound_request_logical_request_id IS NOT NULL
     OR stored.bound_request_attempt_id IS NOT NULL
     OR stored.terminal_result_id IS NOT NULL
     OR stored.purge_eligible_at_unix_ms IS NOT NULL
     OR stored.release_reason IS NOT NULL
     OR stored.release_receipt_bytes IS NOT NULL
     OR stored.release_receipt_blake3 IS NOT NULL
     OR stored.purged_at_unix_ms IS NOT NULL THEN
    RAISE EXCEPTION 'DISPATCH_RESERVED_PUT_STORED_STATE_INVALID' USING ERRCODE = '55000';
  END IF;

  expected_record := object_store_retention.local_put_reserved_record_v2(
    stored.protocol_revision, stored.policy_revision, stored.provider_boundary_id,
    stored.authenticated_cell_id, stored.authenticated_tenant_id, stored.spool_object_id,
    stored.logical_request_id, stored.attempt_id, stored.upload_id, stored.upload_fence,
    stored.boundary_blake3, stored.boundary_token, stored.observation_binding_blake3,
    stored.expected_size, stored.expected_blake3, stored.partial_temp_bytes,
    stored.partial_temp_chunks, stored.partial_temp_files,
    stored.put_reservation_fingerprint, stored.allocation_revision, stored.allocation_fence,
    stored.reservation_deadline_unix_ms, stored.allocation_hard_expiry_unix_ms,
    stored.admission_clock_unix_ms, stored.prepared_ttl_ms, stored.expires_at_unix_ms,
    stored.max_chunk_bytes, stored.quota_bytes, stored.quota_rows,
    stored.quota_concurrency, stored.quota_revision,
    stored.reserve_put_ack_canonical_bytes, stored.reserve_put_ack_blake3,
    stored.spool_revision, 1024, 4096, 16777216
  );
  IF expected_record.canonical_bytes IS DISTINCT FROM stored.canonical_record_bytes
     OR expected_record.record_blake3 IS DISTINCT FROM stored.record_blake3 THEN
    RAISE EXCEPTION 'DISPATCH_RESERVED_PUT_STORED_RECORD_MISMATCH' USING ERRCODE = '55000';
  END IF;

  RETURN ROW(
    result_code, stored.spool_object_id, stored.logical_request_id, stored.attempt_id,
    stored.upload_id, stored.upload_fence, stored.admission_clock_unix_ms,
    stored.expires_at_unix_ms, stored.reserve_put_ack_canonical_bytes,
    stored.reserve_put_ack_blake3
  )::object_store_retention.dispatch_reserve_put_result_v1;
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
REVOKE ALL ON FUNCTION object_store_retention.local_put_reserved_record_v2(
  text, text, text, text, text, uuid, uuid, uuid, uuid,
  object_store_retention.uint64, bytea, text, bytea, object_store_retention.uint64,
  bytea, object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, bytea, text, object_store_retention.uint64,
  bigint, bigint, bigint, bigint, bigint, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  bytea, bytea, object_store_retention.uint64, integer, integer, integer
) FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

REVOKE ALL ON FUNCTION object_store_retention.local_put_reservation_record_v1(
  text, text, text, text, text, uuid, uuid, uuid, uuid,
  object_store_retention.uint64, bytea, text, bytea, object_store_retention.uint64,
  bytea, bytea, text, object_store_retention.uint64, bigint, bigint, bigint, bigint,
  bigint, object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, bytea, bytea, object_store_retention.uint64,
  integer, integer, integer
) FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

REVOKE ALL ON FUNCTION object_store_retention.project_dispatch_reserved_put_v1(
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

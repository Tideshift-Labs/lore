-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark atomic ReservePut authority mutation.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TYPE object_store_retention.dispatch_reserve_put_result_v1 AS (
  result_code text,
  spool_object_id uuid,
  logical_request_id uuid,
  attempt_id uuid,
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  admission_clock_unix_ms bigint,
  expires_at_unix_ms bigint,
  reserve_put_ack_canonical_bytes bytea,
  reserve_put_ack_blake3 bytea
);

CREATE FUNCTION object_store_retention.assert_dispatch_runtime_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_runtime' THEN
    RAISE EXCEPTION 'DISPATCH_RUNTIME_UNAUTHORIZED' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_dispatch_reserve_put_api_revision_v1(
  api_revision text
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-dispatch-reserve-put-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_DISPATCH_RESERVE_PUT_API_REVISION'
      USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.local_uuid_v7_unix_ms_v1(identifier uuid)
RETURNS bigint
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE encoded bytea;
BEGIN
  encoded := pg_catalog.uuid_send(identifier);
  IF (pg_catalog.get_byte(encoded, 6) >> 4) <> 7
     OR (pg_catalog.get_byte(encoded, 8) >> 6) <> 2 THEN
    RAISE EXCEPTION 'INVALID_UUIDV7' USING ERRCODE = '22023';
  END IF;
  RETURN pg_catalog.get_byte(encoded, 0)::bigint * 1099511627776
    + pg_catalog.get_byte(encoded, 1)::bigint * 4294967296
    + pg_catalog.get_byte(encoded, 2)::bigint * 16777216
    + pg_catalog.get_byte(encoded, 3)::bigint * 65536
    + pg_catalog.get_byte(encoded, 4)::bigint * 256
    + pg_catalog.get_byte(encoded, 5)::bigint;
END
$$;

CREATE FUNCTION object_store_retention.project_dispatch_reserved_put_v1(
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
     OR stored.partial_temp_bytes IS DISTINCT FROM 0
     OR stored.partial_temp_chunks IS DISTINCT FROM 0
     OR stored.partial_temp_files IS DISTINCT FROM 0
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

  expected_record := object_store_retention.local_put_reservation_record_v1(
    stored.protocol_revision,
    stored.policy_revision,
    stored.provider_boundary_id,
    stored.authenticated_cell_id,
    stored.authenticated_tenant_id,
    stored.spool_object_id,
    stored.logical_request_id,
    stored.attempt_id,
    stored.upload_id,
    stored.upload_fence,
    stored.boundary_blake3,
    stored.boundary_token,
    stored.observation_binding_blake3,
    stored.expected_size,
    stored.expected_blake3,
    stored.put_reservation_fingerprint,
    stored.allocation_revision,
    stored.allocation_fence,
    stored.reservation_deadline_unix_ms,
    stored.allocation_hard_expiry_unix_ms,
    stored.admission_clock_unix_ms,
    stored.prepared_ttl_ms,
    stored.expires_at_unix_ms,
    stored.max_chunk_bytes,
    stored.quota_bytes,
    stored.quota_rows,
    stored.quota_concurrency,
    stored.quota_revision,
    stored.reserve_put_ack_canonical_bytes,
    stored.reserve_put_ack_blake3,
    stored.spool_revision,
    1024,
    4096,
    16777216
  );
  IF expected_record.canonical_bytes IS DISTINCT FROM stored.canonical_record_bytes
     OR expected_record.record_blake3 IS DISTINCT FROM stored.record_blake3 THEN
    RAISE EXCEPTION 'DISPATCH_RESERVED_PUT_STORED_RECORD_MISMATCH' USING ERRCODE = '55000';
  END IF;

  RETURN ROW(
    result_code,
    stored.spool_object_id,
    stored.logical_request_id,
    stored.attempt_id,
    stored.upload_id,
    stored.upload_fence,
    stored.admission_clock_unix_ms,
    stored.expires_at_unix_ms,
    stored.reserve_put_ack_canonical_bytes,
    stored.reserve_put_ack_blake3
  )::object_store_retention.dispatch_reserve_put_result_v1;
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(
  api_revision text,
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
  put_reservation_fingerprint bytea,
  allocation_revision text,
  allocation_fence object_store_retention.uint64,
  reservation_deadline_unix_ms bigint,
  allocation_hard_expiry_unix_ms bigint,
  prepared_ttl_ms bigint,
  max_chunk_bytes object_store_retention.uint64,
  quota_revision object_store_retention.uint64,
  global_max_bytes object_store_retention.uint64,
  global_max_rows object_store_retention.uint64,
  global_max_concurrency object_store_retention.uint64,
  global_low_water_bytes object_store_retention.uint64,
  global_low_water_rows object_store_retention.uint64,
  global_low_water_concurrency object_store_retention.uint64,
  cell_max_bytes object_store_retention.uint64,
  cell_max_rows object_store_retention.uint64,
  cell_max_concurrency object_store_retention.uint64,
  cell_low_water_bytes object_store_retention.uint64,
  cell_low_water_rows object_store_retention.uint64,
  cell_low_water_concurrency object_store_retention.uint64,
  tenant_max_bytes object_store_retention.uint64,
  tenant_max_rows object_store_retention.uint64,
  tenant_max_concurrency object_store_retention.uint64,
  tenant_low_water_bytes object_store_retention.uint64,
  tenant_low_water_rows object_store_retention.uint64,
  tenant_low_water_concurrency object_store_retention.uint64,
  maximum_identity_bytes integer,
  maximum_boundary_token_bytes integer,
  maximum_record_bytes integer
)
RETURNS object_store_retention.dispatch_reserve_put_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE stored object_store_retention.object_dispatch_spool_objects%ROWTYPE;
DECLARE projected object_store_retention.dispatch_reserve_put_result_v1;
DECLARE ack_record object_store_retention.local_canonical_record_v1;
DECLARE spool_record object_store_retention.local_canonical_record_v1;
DECLARE admission_clock bigint;
DECLARE prepared_expiry numeric;
DECLARE expires_at bigint;
DECLARE quota_counter object_store_retention.object_dispatch_quota_usage%ROWTYPE;
DECLARE locked_quota_rows integer := 0;
DECLARE affected_quota_rows integer;
DECLARE logical_request_unix_ms bigint;
DECLARE attempt_unix_ms bigint;
DECLARE uuid_lower_unix_ms bigint;
DECLARE uuid_upper_unix_ms bigint;
BEGIN
  PERFORM object_store_retention.assert_dispatch_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_reserve_put_api_revision_v1(api_revision);
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
    RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_SCHEMA_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO stored
    FROM object_store_retention.object_dispatch_spool_objects AS spool
   WHERE spool.logical_request_id = object_store_dispatch_reserve_put_v1.logical_request_id
     AND spool.attempt_id = object_store_dispatch_reserve_put_v1.attempt_id
     AND spool.payload_kind = 1
   FOR UPDATE;
  IF FOUND THEN
    projected := object_store_retention.project_dispatch_reserved_put_v1(stored, 'REPLAY');
    IF stored.protocol_revision IS DISTINCT FROM protocol_revision
       OR stored.spool_object_id IS DISTINCT FROM spool_object_id
       OR stored.provider_boundary_id IS DISTINCT FROM provider_boundary_id
       OR stored.authenticated_cell_id IS DISTINCT FROM authenticated_cell_id
       OR stored.authenticated_tenant_id IS DISTINCT FROM authenticated_tenant_id
       OR stored.upload_id IS DISTINCT FROM upload_id
       OR stored.upload_fence IS DISTINCT FROM upload_fence
       OR stored.boundary_blake3 IS DISTINCT FROM boundary_blake3
       OR stored.boundary_token IS DISTINCT FROM boundary_token
       OR stored.observation_binding_blake3 IS DISTINCT FROM observation_binding_blake3
       OR stored.expected_size IS DISTINCT FROM expected_size
       OR stored.expected_blake3 IS DISTINCT FROM expected_blake3
       OR stored.put_reservation_fingerprint IS DISTINCT FROM put_reservation_fingerprint
       OR stored.reservation_deadline_unix_ms IS DISTINCT FROM reservation_deadline_unix_ms THEN
      RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_REPLAY_CONFLICT' USING ERRCODE = '23505';
    END IF;
    RETURN projected;
  END IF;

  IF provider_boundary_id IS NULL OR authenticated_cell_id IS NULL
     OR authenticated_tenant_id IS NULL OR authenticated_cell_id = provider_boundary_id
     OR authenticated_tenant_id = provider_boundary_id
     OR protocol_revision IS NULL OR policy_revision IS NULL
     OR allocation_revision IS NULL
     OR spool_object_id IS NULL OR logical_request_id IS NULL OR attempt_id IS NULL
     OR upload_id IS NULL OR upload_fence IS NULL OR upload_fence = 0
     OR boundary_blake3 IS NULL OR pg_catalog.octet_length(boundary_blake3) <> 32
     OR boundary_token IS NULL
     OR observation_binding_blake3 IS NULL
     OR pg_catalog.octet_length(observation_binding_blake3) <> 32
     OR expected_size IS NULL
     OR expected_blake3 IS NULL OR pg_catalog.octet_length(expected_blake3) <> 32
     OR put_reservation_fingerprint IS NULL
     OR pg_catalog.octet_length(put_reservation_fingerprint) <> 32
     OR allocation_fence IS NULL OR allocation_fence = 0
     OR reservation_deadline_unix_ms IS NULL OR allocation_hard_expiry_unix_ms IS NULL
     OR prepared_ttl_ms IS NULL OR prepared_ttl_ms <= 0
     OR max_chunk_bytes IS NULL OR max_chunk_bytes = 0
     OR quota_revision IS NULL OR quota_revision = 0
     OR global_max_bytes IS NULL OR global_max_rows IS NULL
     OR global_max_concurrency IS NULL OR global_low_water_bytes IS NULL
     OR global_low_water_rows IS NULL OR global_low_water_concurrency IS NULL
     OR cell_max_bytes IS NULL OR cell_max_rows IS NULL OR cell_max_concurrency IS NULL
     OR cell_low_water_bytes IS NULL OR cell_low_water_rows IS NULL
     OR cell_low_water_concurrency IS NULL
     OR tenant_max_bytes IS NULL OR tenant_max_rows IS NULL
     OR tenant_max_concurrency IS NULL OR tenant_low_water_bytes IS NULL
     OR tenant_low_water_rows IS NULL OR tenant_low_water_concurrency IS NULL
     OR maximum_identity_bytes IS NULL OR maximum_identity_bytes NOT BETWEEN 1 AND 1024
     OR maximum_boundary_token_bytes IS NULL
     OR maximum_boundary_token_bytes NOT BETWEEN 1 AND 4096
     OR maximum_record_bytes IS NULL OR maximum_record_bytes NOT BETWEEN 1 AND 16777216 THEN
    RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_INVALID_ARGUMENT' USING ERRCODE = '22023';
  END IF;

  admission_clock := object_store_retention.clock_unix_ms_v1();
  IF admission_clock < 0
     OR reservation_deadline_unix_ms <= admission_clock
     OR allocation_hard_expiry_unix_ms <= admission_clock THEN
    RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_EXPIRED' USING ERRCODE = '22023';
  END IF;
  prepared_expiry := admission_clock::numeric + prepared_ttl_ms::numeric;
  IF prepared_expiry > 9223372036854775807 THEN
    RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_TIME_OVERFLOW' USING ERRCODE = '22003';
  END IF;
  expires_at := least(
    reservation_deadline_unix_ms,
    allocation_hard_expiry_unix_ms,
    prepared_expiry::bigint
  );

  IF admission_clock > 9223372036854475807 THEN
    RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_TIME_OVERFLOW' USING ERRCODE = '22003';
  END IF;
  uuid_lower_unix_ms := greatest(0, admission_clock - 31536000000);
  uuid_upper_unix_ms := admission_clock + 300000;
  logical_request_unix_ms :=
    object_store_retention.local_uuid_v7_unix_ms_v1(logical_request_id);
  attempt_unix_ms := object_store_retention.local_uuid_v7_unix_ms_v1(attempt_id);
  IF logical_request_unix_ms > uuid_upper_unix_ms
     OR attempt_unix_ms > uuid_upper_unix_ms THEN
    RAISE EXCEPTION 'UUIDV7_TIMESTAMP_TOO_FAR_IN_FUTURE'
      USING ERRCODE = '22023';
  END IF;
  IF logical_request_unix_ms < uuid_lower_unix_ms
     OR attempt_unix_ms < uuid_lower_unix_ms THEN
    RAISE EXCEPTION 'EXPIRED_OR_UNKNOWN' USING ERRCODE = '22023';
  END IF;

  ack_record := object_store_retention.local_reserve_put_ack_v1(
    protocol_revision,
    policy_revision,
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id,
    upload_id,
    upload_fence,
    1::smallint,
    expected_size,
    1,
    1,
    expires_at,
    max_chunk_bytes,
    NULL,
    NULL,
    NULL,
    NULL,
    admission_clock,
    allocation_hard_expiry_unix_ms,
    maximum_identity_bytes,
    1,
    maximum_record_bytes
  );
  spool_record := object_store_retention.local_put_reservation_record_v1(
    protocol_revision,
    policy_revision,
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    spool_object_id,
    logical_request_id,
    attempt_id,
    upload_id,
    upload_fence,
    boundary_blake3,
    boundary_token,
    observation_binding_blake3,
    expected_size,
    expected_blake3,
    put_reservation_fingerprint,
    allocation_revision,
    allocation_fence,
    reservation_deadline_unix_ms,
    allocation_hard_expiry_unix_ms,
    admission_clock,
    prepared_ttl_ms,
    expires_at,
    max_chunk_bytes,
    expected_size,
    1,
    1,
    quota_revision,
    ack_record.canonical_bytes,
    ack_record.record_blake3,
    1,
    maximum_identity_bytes,
    maximum_boundary_token_bytes,
    maximum_record_bytes
  );

  INSERT INTO object_store_retention.object_dispatch_quota_usage (
    schema_revision, provider_boundary_id, scope_kind, scope_id, quota_class,
    used_bytes, used_rows, used_concurrency, counter_revision, updated_at_unix_ms
  ) VALUES
    ('object-store-dispatch-authority-schema-v1', provider_boundary_id, 1,
     provider_boundary_id, 1, 0, 0, 0, 1, admission_clock),
    ('object-store-dispatch-authority-schema-v1', provider_boundary_id, 2,
     authenticated_cell_id, 1, 0, 0, 0, 1, admission_clock),
    ('object-store-dispatch-authority-schema-v1', provider_boundary_id, 3,
     authenticated_tenant_id, 1, 0, 0, 0, 1, admission_clock)
  ON CONFLICT ON CONSTRAINT object_dispatch_quota_usage_pkey DO NOTHING;

  FOR quota_counter IN
    SELECT *
      FROM object_store_retention.object_dispatch_quota_usage AS quota
     WHERE quota.provider_boundary_id = object_store_dispatch_reserve_put_v1.provider_boundary_id
       AND quota.quota_class = 1
       AND (
         (quota.scope_kind = 1 AND quota.scope_id = object_store_dispatch_reserve_put_v1.provider_boundary_id) OR
         (quota.scope_kind = 2 AND quota.scope_id = object_store_dispatch_reserve_put_v1.authenticated_cell_id) OR
         (quota.scope_kind = 3 AND quota.scope_id = object_store_dispatch_reserve_put_v1.authenticated_tenant_id)
       )
     ORDER BY quota.scope_kind
     FOR UPDATE
  LOOP
    locked_quota_rows := locked_quota_rows + 1;
    IF quota_counter.counter_revision = 18446744073709551615 THEN
      RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_COUNTER_OVERFLOW' USING ERRCODE = '22003';
    END IF;
    IF (
      quota_counter.scope_kind = 1 AND (
        quota_counter.used_bytes + expected_size + global_low_water_bytes > global_max_bytes OR
        quota_counter.used_rows + 1 + global_low_water_rows > global_max_rows OR
        quota_counter.used_concurrency + 1 + global_low_water_concurrency > global_max_concurrency
      )
    ) OR (
      quota_counter.scope_kind = 2 AND (
        quota_counter.used_bytes + expected_size + cell_low_water_bytes > cell_max_bytes OR
        quota_counter.used_rows + 1 + cell_low_water_rows > cell_max_rows OR
        quota_counter.used_concurrency + 1 + cell_low_water_concurrency > cell_max_concurrency
      )
    ) OR (
      quota_counter.scope_kind = 3 AND (
        quota_counter.used_bytes + expected_size + tenant_low_water_bytes > tenant_max_bytes OR
        quota_counter.used_rows + 1 + tenant_low_water_rows > tenant_max_rows OR
        quota_counter.used_concurrency + 1 + tenant_low_water_concurrency > tenant_max_concurrency
      )
    ) THEN
      RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED' USING ERRCODE = '53000';
    END IF;
  END LOOP;
  IF locked_quota_rows <> 3 THEN
    RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_QUOTA_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;

  UPDATE object_store_retention.object_dispatch_quota_usage AS quota
     SET used_bytes = quota.used_bytes + expected_size,
         used_rows = quota.used_rows + 1,
         used_concurrency = quota.used_concurrency + 1,
         counter_revision = quota.counter_revision + 1,
         updated_at_unix_ms = admission_clock
   WHERE quota.provider_boundary_id = object_store_dispatch_reserve_put_v1.provider_boundary_id
     AND quota.quota_class = 1
     AND (
       (quota.scope_kind = 1 AND quota.scope_id = object_store_dispatch_reserve_put_v1.provider_boundary_id) OR
       (quota.scope_kind = 2 AND quota.scope_id = object_store_dispatch_reserve_put_v1.authenticated_cell_id) OR
       (quota.scope_kind = 3 AND quota.scope_id = object_store_dispatch_reserve_put_v1.authenticated_tenant_id)
     );
  GET DIAGNOSTICS affected_quota_rows = ROW_COUNT;
  IF affected_quota_rows <> 3 THEN
    RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_QUOTA_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;

  INSERT INTO object_store_retention.object_dispatch_spool_objects (
    schema_revision, spool_object_id, logical_request_id, attempt_id,
    provider_boundary_id, authenticated_cell_id, authenticated_tenant_id,
    request_binding_state, payload_kind, lifecycle_state, upload_id, upload_fence,
    boundary_blake3, boundary_token, observation_binding_blake3,
    expected_size, expected_blake3, partial_temp_bytes, partial_temp_chunks,
    partial_temp_files, quota_bytes, quota_rows, quota_concurrency, quota_revision,
    purge_state, expires_at_unix_ms, canonical_record_bytes, record_blake3,
    spool_revision, created_at_unix_ms, protocol_revision, policy_revision,
    put_reservation_fingerprint, allocation_revision, allocation_fence,
    reservation_deadline_unix_ms, allocation_hard_expiry_unix_ms,
    admission_clock_unix_ms, prepared_ttl_ms, max_chunk_bytes,
    reserve_put_ack_canonical_bytes, reserve_put_ack_blake3
  ) VALUES (
    'object-store-dispatch-authority-schema-v1', spool_object_id, logical_request_id, attempt_id,
    provider_boundary_id, authenticated_cell_id, authenticated_tenant_id,
    1, 1, 1, upload_id, upload_fence,
    boundary_blake3, boundary_token, observation_binding_blake3,
    expected_size, expected_blake3, 0, 0, 0,
    expected_size, 1, 1, quota_revision, 1, expires_at,
    spool_record.canonical_bytes, spool_record.record_blake3, 1, admission_clock,
    protocol_revision, policy_revision, put_reservation_fingerprint,
    allocation_revision, allocation_fence, reservation_deadline_unix_ms,
    allocation_hard_expiry_unix_ms, admission_clock, prepared_ttl_ms, max_chunk_bytes,
    ack_record.canonical_bytes, ack_record.record_blake3
  ) RETURNING * INTO stored;

  RETURN object_store_retention.project_dispatch_reserved_put_v1(stored, 'CREATED');
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_RESERVE_PUT_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(
  text, text, text, text, text, text, uuid, uuid, uuid, uuid,
  object_store_retention.uint64, bytea, text, bytea, object_store_retention.uint64,
  bytea, bytea, text, object_store_retention.uint64, bigint, bigint, bigint,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  object_store_retention.uint64, object_store_retention.uint64,
  integer, integer, integer
) TO object_dispatch_retention_runtime;

REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

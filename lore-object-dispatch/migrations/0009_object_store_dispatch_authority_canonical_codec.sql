-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark local dispatch-authority canonical codec.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TYPE object_store_retention.local_canonical_record_v1 AS (
  canonical_bytes bytea,
  record_blake3 object_store_retention.blake3_256
);

-- Production provisioning must install and attest a reviewed BLAKE3 provider with this signature.
CREATE FUNCTION object_store_retention.local_blake3_v1(payload bytea)
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE answer bytea;
BEGIN
  IF pg_catalog.to_regprocedure('public.blake3(bytea)') IS NULL THEN
    RAISE EXCEPTION 'LOCAL_BLAKE3_PROVIDER_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  EXECUTE 'SELECT public.blake3($1)' INTO STRICT answer USING payload;
  IF answer IS NULL OR pg_catalog.octet_length(answer) <> 32 THEN
    RAISE EXCEPTION 'LOCAL_BLAKE3_PROVIDER_INVALID_RESULT' USING ERRCODE = '55000';
  END IF;
  RETURN answer;
END
$$;

CREATE FUNCTION object_store_retention.local_assert_blake3_v1(payload bytea, expected bytea)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF expected IS NULL OR pg_catalog.octet_length(expected) <> 32
     OR object_store_retention.local_blake3_v1(payload) IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'LOCAL_BLAKE3_MISMATCH' USING ERRCODE = '22000';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.local_canonical_u8_v1(value integer)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE answer bytea := pg_catalog.decode('00', 'hex');
BEGIN
  IF value < 0 OR value > 255 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_U8_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN pg_catalog.set_byte(answer, 0, value);
END
$$;

CREATE FUNCTION object_store_retention.local_canonical_u32_v1(value bigint)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE remaining bigint := value;
DECLARE answer bytea := pg_catalog.decode('00000000', 'hex');
DECLARE index_value integer;
BEGIN
  IF value < 0 OR value > 4294967295 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_U32_INVALID' USING ERRCODE = '22023';
  END IF;
  FOR index_value IN REVERSE 3..0 LOOP
    answer := pg_catalog.set_byte(answer, index_value, (remaining % 256)::integer);
    remaining := remaining / 256;
  END LOOP;
  RETURN answer;
END
$$;

CREATE FUNCTION object_store_retention.local_canonical_u64_v1(
  value object_store_retention.uint64
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE remaining numeric(20, 0) := value;
DECLARE answer bytea := pg_catalog.decode('0000000000000000', 'hex');
DECLARE index_value integer;
BEGIN
  FOR index_value IN REVERSE 7..0 LOOP
    answer := pg_catalog.set_byte(answer, index_value, pg_catalog.mod(remaining, 256)::integer);
    remaining := pg_catalog.trunc(remaining / 256);
  END LOOP;
  RETURN answer;
END
$$;

CREATE FUNCTION object_store_retention.local_canonical_bytes_v1(value bytea, maximum_bytes integer)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF maximum_bytes <= 0 OR pg_catalog.octet_length(value) > maximum_bytes THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_BYTES_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN object_store_retention.local_canonical_u32_v1(pg_catalog.octet_length(value)) || value;
END
$$;

CREATE FUNCTION object_store_retention.local_canonical_text_v1(value text, maximum_bytes integer)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE payload bytea := pg_catalog.convert_to(value, 'UTF8');
BEGIN
  IF maximum_bytes <= 0 OR pg_catalog.octet_length(payload) = 0
     OR pg_catalog.octet_length(payload) > maximum_bytes
     OR value IS DISTINCT FROM pg_catalog.normalize(value, 'NFC') THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_TEXT_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN object_store_retention.local_canonical_u32_v1(pg_catalog.octet_length(payload)) || payload;
END
$$;

CREATE FUNCTION object_store_retention.local_complete_record_v1(
  preimage bytea,
  maximum_record_bytes integer
)
RETURNS object_store_retention.local_canonical_record_v1
LANGUAGE plpgsql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE digest bytea;
BEGIN
  IF maximum_record_bytes <= 32
     OR pg_catalog.octet_length(preimage) > maximum_record_bytes - 32 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_RECORD_TOO_LARGE' USING ERRCODE = '22023';
  END IF;
  digest := object_store_retention.local_blake3_v1(preimage);
  RETURN ROW(preimage || digest, digest)::object_store_retention.local_canonical_record_v1;
END
$$;

CREATE FUNCTION object_store_retention.local_quota_child_v1(
  quota_bytes object_store_retention.uint64,
  quota_rows object_store_retention.uint64,
  quota_concurrency object_store_retention.uint64,
  maximum_record_bytes integer
)
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE preimage bytea;
DECLARE complete object_store_retention.local_canonical_record_v1;
BEGIN
  IF quota_bytes IS NULL OR quota_rows IS NULL OR quota_concurrency IS NULL
     OR maximum_record_bytes IS NULL OR maximum_record_bytes <= 0
     OR (quota_bytes = 0 AND quota_rows = 0 AND quota_concurrency = 0) THEN
    RAISE EXCEPTION 'LOCAL_QUOTA_CHILD_INVALID' USING ERRCODE = '22023';
  END IF;
  preimage := pg_catalog.convert_to('object-store-quota-units-v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || object_store_retention.local_canonical_u64_v1(quota_bytes)
    || object_store_retention.local_canonical_u64_v1(quota_rows)
    || object_store_retention.local_canonical_u64_v1(quota_concurrency);
  complete := object_store_retention.local_complete_record_v1(preimage, maximum_record_bytes);
  RETURN complete.canonical_bytes;
END
$$;

CREATE FUNCTION object_store_retention.local_put_spool_ready_child_v1(
  protocol_revision text,
  provider_boundary_id text,
  authenticated_cell_id text,
  authenticated_tenant_id text,
  logical_request_id uuid,
  attempt_id uuid,
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  durable_body_handle text,
  body_size object_store_retention.uint64,
  body_blake3 bytea,
  ready_at_unix_ms bigint,
  admission_clock_unix_ms bigint,
  expires_at_unix_ms bigint,
  maximum_identity_bytes integer,
  maximum_durable_handle_bytes integer,
  maximum_record_bytes integer
)
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE preimage bytea;
DECLARE complete object_store_retention.local_canonical_record_v1;
BEGIN
  IF protocol_revision IS NULL OR provider_boundary_id IS NULL
     OR authenticated_cell_id IS NULL OR authenticated_tenant_id IS NULL
     OR logical_request_id IS NULL OR attempt_id IS NULL OR upload_id IS NULL
     OR upload_fence IS NULL OR upload_fence = 0
     OR durable_body_handle IS NULL OR body_size IS NULL
     OR body_blake3 IS NULL OR pg_catalog.octet_length(body_blake3) <> 32
     OR ready_at_unix_ms IS NULL OR admission_clock_unix_ms IS NULL
     OR expires_at_unix_ms IS NULL OR admission_clock_unix_ms < 0
     OR maximum_identity_bytes IS NULL OR maximum_identity_bytes <= 0
     OR maximum_durable_handle_bytes IS NULL OR maximum_durable_handle_bytes <= 0
     OR maximum_record_bytes IS NULL OR maximum_record_bytes <= 0
     OR ready_at_unix_ms < admission_clock_unix_ms
     OR ready_at_unix_ms >= expires_at_unix_ms
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 8) >> 6) <> 2 THEN
    RAISE EXCEPTION 'LOCAL_PUT_SPOOL_READY_CHILD_INVALID' USING ERRCODE = '22023';
  END IF;
  preimage := pg_catalog.convert_to('object-store-put-spool-ready-v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || object_store_retention.local_canonical_text_v1(protocol_revision, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(provider_boundary_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(authenticated_cell_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(authenticated_tenant_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(logical_request_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(attempt_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(upload_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_u64_v1(upload_fence)
    || object_store_retention.local_canonical_text_v1(
         durable_body_handle, maximum_durable_handle_bytes
       )
    || object_store_retention.local_canonical_u64_v1(body_size)
    || body_blake3
    || object_store_retention.local_canonical_u64_v1(
         ready_at_unix_ms::object_store_retention.uint64
       );
  complete := object_store_retention.local_complete_record_v1(preimage, maximum_record_bytes);
  RETURN complete.canonical_bytes;
END
$$;

CREATE FUNCTION object_store_retention.local_reserve_put_ack_v1(
  protocol_revision text,
  policy_revision text,
  provider_boundary_id text,
  authenticated_cell_id text,
  authenticated_tenant_id text,
  logical_request_id uuid,
  attempt_id uuid,
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  ack_state smallint,
  quota_bytes object_store_retention.uint64,
  quota_rows object_store_retention.uint64,
  quota_concurrency object_store_retention.uint64,
  expires_at_unix_ms bigint,
  max_chunk_bytes object_store_retention.uint64,
  durable_body_handle text,
  body_size object_store_retention.uint64,
  body_blake3 bytea,
  ready_at_unix_ms bigint,
  admission_clock_unix_ms bigint,
  allocation_hard_expiry_unix_ms bigint,
  maximum_identity_bytes integer,
  maximum_durable_handle_bytes integer,
  maximum_record_bytes integer
)
RETURNS object_store_retention.local_canonical_record_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE quota_child bytea;
DECLARE spool_child bytea;
DECLARE preimage bytea;
BEGIN
  IF protocol_revision IS NULL OR policy_revision IS NULL OR provider_boundary_id IS NULL
     OR authenticated_cell_id IS NULL OR authenticated_tenant_id IS NULL
     OR logical_request_id IS NULL OR attempt_id IS NULL OR upload_id IS NULL
     OR upload_fence IS NULL OR upload_fence = 0
     OR ack_state IS NULL OR ack_state NOT IN (1, 2)
     OR quota_bytes IS NULL OR quota_rows IS NULL OR quota_concurrency IS NULL
     OR (quota_bytes = 0 AND quota_rows = 0 AND quota_concurrency = 0)
     OR expires_at_unix_ms IS NULL OR max_chunk_bytes IS NULL OR max_chunk_bytes = 0
     OR admission_clock_unix_ms IS NULL OR allocation_hard_expiry_unix_ms IS NULL
     OR maximum_identity_bytes IS NULL OR maximum_identity_bytes <= 0
     OR maximum_durable_handle_bytes IS NULL OR maximum_durable_handle_bytes <= 0
     OR maximum_record_bytes IS NULL OR maximum_record_bytes <= 0
     OR admission_clock_unix_ms < 0 OR admission_clock_unix_ms >= expires_at_unix_ms
     OR expires_at_unix_ms > allocation_hard_expiry_unix_ms
     OR (ack_state = 1 AND pg_catalog.num_nonnulls(
          durable_body_handle, body_size, body_blake3, ready_at_unix_ms
        ) <> 0)
     OR (ack_state = 2 AND pg_catalog.num_nonnulls(
          durable_body_handle, body_size, body_blake3, ready_at_unix_ms
        ) <> 4)
     OR (ack_state = 2 AND body_size IS DISTINCT FROM quota_bytes)
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 8) >> 6) <> 2 THEN
    RAISE EXCEPTION 'LOCAL_RESERVE_PUT_ACK_INVALID' USING ERRCODE = '22023';
  END IF;

  quota_child := object_store_retention.local_quota_child_v1(
    quota_bytes, quota_rows, quota_concurrency, maximum_record_bytes
  );
  IF ack_state = 2 THEN
    spool_child := object_store_retention.local_put_spool_ready_child_v1(
      protocol_revision,
      provider_boundary_id,
      authenticated_cell_id,
      authenticated_tenant_id,
      logical_request_id,
      attempt_id,
      upload_id,
      upload_fence,
      durable_body_handle,
      body_size,
      body_blake3,
      ready_at_unix_ms,
      admission_clock_unix_ms,
      expires_at_unix_ms,
      maximum_identity_bytes,
      maximum_durable_handle_bytes,
      maximum_record_bytes
    );
  END IF;

  preimage := pg_catalog.convert_to('object-store-reserve-put-ack-v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || object_store_retention.local_canonical_text_v1(protocol_revision, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(policy_revision, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(provider_boundary_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(authenticated_cell_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(authenticated_tenant_id, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(logical_request_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(attempt_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_text_v1(upload_id::text, maximum_identity_bytes)
    || object_store_retention.local_canonical_u64_v1(upload_fence)
    || object_store_retention.local_canonical_u32_v1(ack_state)
    || object_store_retention.local_canonical_bytes_v1(quota_child, maximum_record_bytes)
    || object_store_retention.local_canonical_u64_v1(
         expires_at_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(max_chunk_bytes)
    || object_store_retention.local_canonical_u8_v1((spool_child IS NOT NULL)::integer)
    || CASE WHEN spool_child IS NULL THEN ''::bytea
            ELSE object_store_retention.local_canonical_bytes_v1(
              spool_child, maximum_record_bytes
            )
       END
    || object_store_retention.local_canonical_u8_v1(0)
    || object_store_retention.local_canonical_u64_v1(
         admission_clock_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         allocation_hard_expiry_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u8_v1(0)
    || object_store_retention.local_canonical_u8_v1(0);
  RETURN object_store_retention.local_complete_record_v1(preimage, maximum_record_bytes);
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
DO $$
DECLARE helper regprocedure;
BEGIN
  FOR helper IN
    SELECT procedure.oid::regprocedure
      FROM pg_catalog.pg_proc AS procedure
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
     WHERE namespace.nspname = 'object_store_retention'
       AND procedure.proname IN (
         'local_blake3_v1',
         'local_assert_blake3_v1',
         'local_canonical_u8_v1',
         'local_canonical_u32_v1',
         'local_canonical_u64_v1',
         'local_canonical_bytes_v1',
         'local_canonical_text_v1',
         'local_complete_record_v1',
         'local_quota_child_v1',
         'local_put_spool_ready_child_v1',
         'local_reserve_put_ack_v1'
       )
  LOOP
    EXECUTE pg_catalog.format(
      'REVOKE ALL ON FUNCTION %s FROM object_dispatch_retention_runtime, object_dispatch_retention_maintenance, object_dispatch_retention_migrator',
      helper
    );
  END LOOP;
END
$$;
REVOKE ALL ON TYPE object_store_retention.local_canonical_record_v1 FROM PUBLIC;
REVOKE ALL ON TYPE object_store_retention.local_canonical_record_v1 FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-115 readiness blocker 6: BLAKE3 hashing leaves PostgreSQL. Rust owns it (upstream parity).
--
-- A FORWARD STEP like 0028-0030: no transaction control. The installer opens one SERIALIZABLE
-- transaction around this body, attests R31 inside it, and only then commits.
--
-- Accepted cut (KV, 2026-10-06): the database no longer computes or verifies any BLAKE3 digest. It
-- still stores the 32-byte digests a caller supplies (boundary, observation binding, body, policy
-- and descriptor digests) and compares them byte for byte, but it never hashes them. A fresh cell
-- needs no plpython3u and no public.blake3: no statement in 0002-0031 calls BLAKE3 at install
-- time, and after this step no procedure calls it at run time either. (0008's and 0011's catalog
-- asserts and this step's participant check use the built-in pg_catalog.sha256.)
--
-- What changes:
--
-- * Every record the database builds is now a PREIMAGE ONLY. A nested child is framed as
--   `u32 length || child preimage`; no record carries a trailing digest; the reservation and
--   ready rows no longer embed the raw ack digest. Each layout changed, so each takes a new
--   DB-local domain tag (`*-v2`). The Rust and TypeScript v1 encoders, which hash, keep the v1
--   tags; the database must never emit bytes under them. Integrity is still bound by byte
--   equality: every project_* function rebuilds the whole preimage from the columns and compares.
-- * The digest columns those records used to fill (`record_blake3`, `reserve_put_ack_blake3`) are
--   kept, because dropping a column changes the row type that %ROWTYPE and the project_*
--   parameters use, but they are now NULL by CHECK. Composite result types keep their digest
--   attributes, which now return NULL.
-- * Existing spool and dispatcher rows are rebuilt with the v2 codecs (backfill below), so a
--   released row waiting for compaction does not block the upgrade.
-- * Dispatcher registration keeps its one check: the enrolled participant commitment is now the
--   built-in SHA-256 of the participant key, not BLAKE3. A BLAKE3 commitment cannot be converted,
--   so a cell with enrolled participants is refused (no real cell has any). The column and
--   parameter keep the name `participant_key_blake3`; it now holds SHA-256 (naming debt, deferred).
-- * The five drain policy/descriptor procedures no longer assert BLAKE3 over the canonical bytes.
--   They keep the canonical byte-equality checks. Rust re-checks the policy digest on read.
-- * The drain release receipt is preimage only, tag `fragment-drain-release-v2`, and
--   `release_digest` is NULL from R31 on.
-- * drain_check_ready's CAS token moves from the database-built record digest to
--   (spool_revision, ready_at_unix_ms): drain_check_ready_v2. v1 is dropped.
-- * local_blake3_v1, local_assert_blake3_v1, local_complete_record_v1 and drain_check_ready_v1 are
--   dropped once no body references them.
SET LOCAL ROLE object_dispatch_retention_owner;

-- Replicas must be stopped, as in 0027's rotation and 0028-0030.
LOCK TABLE object_store_retention.object_dispatch_spool_objects,
 object_store_retention.drain_spool_custody,object_store_retention.object_dispatch_quota_usage,
 object_store_retention.drain_policies,object_store_retention.object_dispatch_dispatchers,
 object_store_retention.object_dispatch_dispatcher_participants IN ACCESS EXCLUSIVE MODE NOWAIT;

-- An enrolled participant holds a BLAKE3 commitment that the new SHA-256 check can never match,
-- and a commitment cannot be converted without the key. The installer's prelude refuses this
-- first, with an operator-facing reason; this is the same refusal for any other caller.
-- Spool rows outside the two states a procedure writes (payload 1, lifecycle 1 or 2) cannot be
-- rebuilt by the backfill below; none can exist, so refuse rather than guess.
DO $refuse$
BEGIN
 IF EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_dispatcher_participants) THEN
  RAISE EXCEPTION 'CR038_UPGRADE_R30_ENROLLED_PARTICIPANTS' USING ERRCODE='55000';
 END IF;
 IF EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_spool_objects s
            WHERE s.payload_kind<>1 OR s.lifecycle_state NOT IN (1,2)) THEN
  RAISE EXCEPTION 'CR038_UPGRADE_R30_SPOOL_STATE' USING ERRCODE='55000';
 END IF;
END $refuse$;

CREATE OR REPLACE FUNCTION object_store_retention.cell_schema_revision_v1() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT 31 $$;

-- ---------------------------------------------------------------------------------------------
-- G1. Record codecs: preimage only, v2 tags. Same signatures and return types; their owner-only
-- ACLs from 0009/0014/0016/0020 persist under CREATE OR REPLACE. The size bound is the one
-- local_complete_record_v1 applied (it reserved 32 bytes for the digest), kept unchanged.
-- ---------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION object_store_retention.local_quota_child_v1(
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
BEGIN
  IF quota_bytes IS NULL OR quota_rows IS NULL OR quota_concurrency IS NULL
     OR maximum_record_bytes IS NULL OR maximum_record_bytes <= 0
     OR (quota_bytes = 0 AND quota_rows = 0 AND quota_concurrency = 0) THEN
    RAISE EXCEPTION 'LOCAL_QUOTA_CHILD_INVALID' USING ERRCODE = '22023';
  END IF;
  preimage := pg_catalog.convert_to('object-store-local-quota-units-v2', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || object_store_retention.local_canonical_u64_v1(quota_bytes)
    || object_store_retention.local_canonical_u64_v1(quota_rows)
    || object_store_retention.local_canonical_u64_v1(quota_concurrency);
  IF maximum_record_bytes <= 32
     OR pg_catalog.octet_length(preimage) > maximum_record_bytes - 32 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_RECORD_TOO_LARGE' USING ERRCODE = '22023';
  END IF;
  RETURN preimage;
END
$$;

CREATE OR REPLACE FUNCTION object_store_retention.local_put_spool_ready_child_v1(
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
  preimage := pg_catalog.convert_to('object-store-local-put-spool-ready-v2', 'UTF8')
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
  IF preimage IS NULL THEN
    RETURN NULL;
  END IF;
  IF maximum_record_bytes <= 32
     OR pg_catalog.octet_length(preimage) > maximum_record_bytes - 32 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_RECORD_TOO_LARGE' USING ERRCODE = '22023';
  END IF;
  RETURN preimage;
END
$$;

CREATE OR REPLACE FUNCTION object_store_retention.local_reserve_put_ack_v1(
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

  preimage := pg_catalog.convert_to('object-store-local-reserve-put-ack-v2', 'UTF8')
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
  IF preimage IS NULL THEN
    RETURN NULL;
  END IF;
  IF maximum_record_bytes <= 32
     OR pg_catalog.octet_length(preimage) > maximum_record_bytes - 32 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_RECORD_TOO_LARGE' USING ERRCODE = '22023';
  END IF;
  RETURN ROW(preimage, NULL)::object_store_retention.local_canonical_record_v1;
END
$$;

CREATE OR REPLACE FUNCTION object_store_retention.local_put_reserved_record_v2(
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
  -- R31: the ack carries no digest, so its digest argument must be NULL.
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
     OR reserve_put_ack_canonical_bytes IS NULL OR reserve_put_ack_blake3 IS NOT NULL
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
  preimage := pg_catalog.convert_to('object-store-dispatch-put-reservation-row-v2', 'UTF8')
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
    || object_store_retention.local_canonical_u64_v1(spool_revision)
    || object_store_retention.local_canonical_u64_v1(
         admission_clock_unix_ms::object_store_retention.uint64
       );
  IF preimage IS NULL THEN
    RETURN NULL;
  END IF;
  IF maximum_record_bytes <= 32
     OR pg_catalog.octet_length(preimage) > maximum_record_bytes - 32 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_RECORD_TOO_LARGE' USING ERRCODE = '22023';
  END IF;
  RETURN ROW(preimage, NULL)::object_store_retention.local_canonical_record_v1;
END
$$;

CREATE OR REPLACE FUNCTION object_store_retention.local_put_spool_ready_record_v1(
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
  committed_size object_store_retention.uint64,
  committed_blake3 bytea,
  durable_handle text,
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
  ready_at_unix_ms bigint,
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
  maximum_durable_handle_bytes integer,
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
  -- R31: the ack carries no digest, so its digest argument must be NULL.
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
     OR committed_size IS NULL OR committed_blake3 IS NULL
     OR pg_catalog.octet_length(committed_blake3) <> 32
     OR durable_handle IS NULL
     OR partial_temp_bytes IS NULL OR partial_temp_chunks IS NULL
     OR partial_temp_files IS NULL
     OR put_reservation_fingerprint IS NULL
     OR pg_catalog.octet_length(put_reservation_fingerprint) <> 32
     OR allocation_revision IS NULL OR allocation_fence IS NULL OR allocation_fence = 0
     OR reservation_deadline_unix_ms IS NULL
     OR allocation_hard_expiry_unix_ms IS NULL OR admission_clock_unix_ms IS NULL
     OR prepared_ttl_ms IS NULL OR expires_at_unix_ms IS NULL
     OR ready_at_unix_ms IS NULL
     OR max_chunk_bytes IS NULL OR max_chunk_bytes = 0
     OR quota_bytes IS NULL OR quota_rows IS NULL OR quota_concurrency IS NULL
     OR quota_revision IS NULL OR quota_revision = 0
     OR reserve_put_ack_canonical_bytes IS NULL OR reserve_put_ack_blake3 IS NOT NULL
     OR spool_revision IS NULL OR spool_revision < 2
     OR maximum_identity_bytes IS NULL
     OR maximum_identity_bytes NOT BETWEEN 1 AND 1024
     OR maximum_boundary_token_bytes IS NULL
     OR maximum_boundary_token_bytes NOT BETWEEN 1 AND 4096
     OR maximum_durable_handle_bytes IS NULL
     OR maximum_durable_handle_bytes NOT BETWEEN 1 AND 4096
     OR maximum_record_bytes IS NULL
     OR maximum_record_bytes NOT BETWEEN 1 AND 16777216
     OR committed_size IS DISTINCT FROM expected_size
     OR committed_blake3 IS DISTINCT FROM expected_blake3
     OR partial_temp_bytes <> 0 OR partial_temp_chunks <> 0 OR partial_temp_files <> 0
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
     OR ready_at_unix_ms < admission_clock_unix_ms
     OR ready_at_unix_ms >= expires_at_unix_ms
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(spool_object_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(spool_object_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(logical_request_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(attempt_id), 8) >> 6) <> 2
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 6) >> 4) <> 7
     OR (pg_catalog.get_byte(pg_catalog.uuid_send(upload_id), 8) >> 6) <> 2 THEN
    RAISE EXCEPTION 'LOCAL_PUT_SPOOL_READY_RECORD_INVALID' USING ERRCODE = '22023';
  END IF;

  expected_ack := object_store_retention.local_reserve_put_ack_v1(
    protocol_revision, policy_revision, provider_boundary_id, authenticated_cell_id,
    authenticated_tenant_id, logical_request_id, attempt_id, upload_id, upload_fence,
    2::smallint, quota_bytes, quota_rows, quota_concurrency, expires_at_unix_ms,
    max_chunk_bytes, durable_handle, committed_size, committed_blake3,
    ready_at_unix_ms, admission_clock_unix_ms, allocation_hard_expiry_unix_ms,
    maximum_identity_bytes, maximum_durable_handle_bytes, maximum_record_bytes
  );
  IF expected_ack.canonical_bytes IS DISTINCT FROM reserve_put_ack_canonical_bytes
     OR expected_ack.record_blake3 IS DISTINCT FROM reserve_put_ack_blake3 THEN
    RAISE EXCEPTION 'LOCAL_PUT_SPOOL_READY_ACK_MISMATCH' USING ERRCODE = '22023';
  END IF;

  quota_child := object_store_retention.local_quota_child_v1(
    quota_bytes, quota_rows, quota_concurrency, maximum_record_bytes
  );
  preimage := pg_catalog.convert_to('object-store-dispatch-put-spool-ready-row-v2', 'UTF8')
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
    || object_store_retention.local_canonical_u8_v1(2)
    || object_store_retention.local_canonical_u8_v1(1)
    || boundary_blake3
    || object_store_retention.local_canonical_text_v1(
         boundary_token, maximum_boundary_token_bytes
       )
    || observation_binding_blake3
    || object_store_retention.local_canonical_u64_v1(expected_size)
    || expected_blake3
    || object_store_retention.local_canonical_u64_v1(committed_size)
    || committed_blake3
    || object_store_retention.local_canonical_text_v1(
         durable_handle, maximum_durable_handle_bytes
       )
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
    || object_store_retention.local_canonical_u64_v1(spool_revision)
    || object_store_retention.local_canonical_u64_v1(
         admission_clock_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         ready_at_unix_ms::object_store_retention.uint64
       );
  IF preimage IS NULL THEN
    RETURN NULL;
  END IF;
  IF maximum_record_bytes <= 32
     OR pg_catalog.octet_length(preimage) > maximum_record_bytes - 32 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_RECORD_TOO_LARGE' USING ERRCODE = '22023';
  END IF;
  RETURN ROW(preimage, NULL)::object_store_retention.local_canonical_record_v1;
END
$$;

CREATE OR REPLACE FUNCTION object_store_retention.local_dispatcher_registration_record_v1(
  dispatcher_id text,
  lease_generation object_store_retention.uint64,
  provider_boundary_id text,
  service_instance_id text,
  dispatcher_fence object_store_retention.uint64,
  authority_revision object_store_retention.uint64,
  allocation_revision text,
  allocation_fence object_store_retention.uint64,
  provider_credential_revision text,
  acquired_at_unix_ms bigint,
  renewed_at_unix_ms bigint,
  expires_at_unix_ms bigint,
  state_changed_at_unix_ms bigint
)
RETURNS object_store_retention.local_canonical_record_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE preimage bytea;
BEGIN
  IF dispatcher_id IS NULL OR lease_generation IS NULL OR lease_generation = 0
     OR provider_boundary_id IS NULL OR service_instance_id IS NULL
     OR dispatcher_fence IS NULL OR dispatcher_fence = 0
     OR authority_revision IS NULL OR authority_revision = 0
     OR allocation_revision IS NULL OR allocation_fence IS NULL OR allocation_fence = 0
     OR provider_credential_revision IS NULL
     OR acquired_at_unix_ms IS NULL OR acquired_at_unix_ms < 0
     OR renewed_at_unix_ms IS NULL OR renewed_at_unix_ms < acquired_at_unix_ms
     OR expires_at_unix_ms IS NULL OR expires_at_unix_ms <= renewed_at_unix_ms
     OR state_changed_at_unix_ms IS NULL OR state_changed_at_unix_ms < acquired_at_unix_ms THEN
    RAISE EXCEPTION 'LOCAL_DISPATCHER_REGISTRATION_RECORD_INVALID' USING ERRCODE = '22023';
  END IF;

  preimage := pg_catalog.convert_to('object-store-dispatch-dispatcher-registration-row-v2', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || object_store_retention.local_canonical_text_v1(
         'object-store-dispatch-authority-schema-v1', 1024
       )
    || object_store_retention.local_canonical_text_v1(dispatcher_id, 1024)
    || object_store_retention.local_canonical_u64_v1(lease_generation)
    || object_store_retention.local_canonical_text_v1(provider_boundary_id, 1024)
    || object_store_retention.local_canonical_text_v1(service_instance_id, 1024)
    || object_store_retention.local_canonical_u64_v1(dispatcher_fence)
    || object_store_retention.local_canonical_u64_v1(authority_revision)
    || object_store_retention.local_canonical_text_v1(allocation_revision, 1024)
    || object_store_retention.local_canonical_u64_v1(allocation_fence)
    || object_store_retention.local_canonical_text_v1(provider_credential_revision, 1024)
    || object_store_retention.local_canonical_u8_v1(1)
    || object_store_retention.local_canonical_u64_v1(
         acquired_at_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         renewed_at_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         expires_at_unix_ms::object_store_retention.uint64
       )
    || object_store_retention.local_canonical_u64_v1(
         state_changed_at_unix_ms::object_store_retention.uint64
       );
  IF preimage IS NULL THEN
    RETURN NULL;
  END IF;
  IF pg_catalog.octet_length(preimage) > 16777216 - 32 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_RECORD_TOO_LARGE' USING ERRCODE = '22023';
  END IF;
  RETURN ROW(preimage, NULL)::object_store_retention.local_canonical_record_v1;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- Table CHECKs. The 0007 tail checks (canonical bytes end with the digest) and the NOT NULL on the
-- digest columns go before the backfill; the new NULL checks come after it. 0007's checks have
-- generated names, so they are found by shape: a CHECK on exactly the two columns
-- {canonical_record_bytes, record_blake3}. Never by constraint text, which PG16 and PG18 render
-- differently.
-- ---------------------------------------------------------------------------------------------
DO $drop_tail_checks$
DECLARE target text; found_name text; found_count integer;
BEGIN
 FOREACH target IN ARRAY ARRAY['object_dispatch_spool_objects','object_dispatch_dispatchers'] LOOP
  SELECT count(*), min(constraint_state.conname::text) INTO found_count, found_name
    FROM pg_catalog.pg_constraint AS constraint_state
    JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_state.conrelid
    JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
   WHERE space.nspname = 'object_store_retention' AND relation.relname = target
     AND constraint_state.contype = 'c'
     AND ARRAY(SELECT key FROM pg_catalog.unnest(constraint_state.conkey) AS key ORDER BY key)
       = ARRAY(SELECT attribute.attnum FROM pg_catalog.pg_attribute AS attribute
                WHERE attribute.attrelid = relation.oid
                  AND attribute.attname IN ('canonical_record_bytes','record_blake3')
                ORDER BY attribute.attnum);
  IF found_count <> 1 THEN
   RAISE EXCEPTION 'CR038_UPGRADE_R30_TAIL_CHECK_SHAPE' USING ERRCODE='55000';
  END IF;
  EXECUTE pg_catalog.format('ALTER TABLE object_store_retention.%I DROP CONSTRAINT %I', target, found_name);
 END LOOP;
END $drop_tail_checks$;

ALTER TABLE object_store_retention.object_dispatch_spool_objects
  DROP CONSTRAINT object_dispatch_spool_objects_put_reservation_presence_ck,
  DROP CONSTRAINT object_dispatch_spool_objects_put_reservation_ack_ck,
  ALTER COLUMN record_blake3 DROP NOT NULL;
ALTER TABLE object_store_retention.object_dispatch_dispatchers
  ALTER COLUMN record_blake3 DROP NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- Backfill. Every live spool row and every dispatcher row is rebuilt with the v2 codecs and its
-- digest columns cleared. The argument mapping is project_dispatch_reserved_put_v1's (0016), and
-- the ack is rebuilt with exactly the maxima the record codec passes to it, so the stored bytes
-- equal what the projection recomputes. The framing does not depend on the maxima, so the
-- project limits (1024 / 4096 / 16777216) reproduce the bytes any caller originally wrote. Each
-- rebuilt spool row is then re-projected, which fails the step on any mismatch.
-- ---------------------------------------------------------------------------------------------
DO $backfill$
DECLARE stored object_store_retention.object_dispatch_spool_objects%ROWTYPE;
DECLARE dispatcher object_store_retention.object_dispatch_dispatchers%ROWTYPE;
DECLARE next_ack object_store_retention.local_canonical_record_v1;
DECLARE next_record object_store_retention.local_canonical_record_v1;
BEGIN
 FOR stored IN SELECT * FROM object_store_retention.object_dispatch_spool_objects
                ORDER BY spool_object_id LOOP
  IF stored.lifecycle_state = 1 THEN
   next_ack := object_store_retention.local_reserve_put_ack_v1(
     stored.protocol_revision, stored.policy_revision, stored.provider_boundary_id,
     stored.authenticated_cell_id, stored.authenticated_tenant_id,
     stored.logical_request_id, stored.attempt_id, stored.upload_id, stored.upload_fence,
     1::smallint, stored.quota_bytes, stored.quota_rows, stored.quota_concurrency,
     stored.expires_at_unix_ms, stored.max_chunk_bytes, NULL, NULL, NULL, NULL,
     stored.admission_clock_unix_ms, stored.allocation_hard_expiry_unix_ms,
     1024, 1, 16777216
   );
   next_record := object_store_retention.local_put_reserved_record_v2(
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
     next_ack.canonical_bytes, NULL,
     stored.spool_revision, 1024, 4096, 16777216
   );
  ELSE
   next_ack := object_store_retention.local_reserve_put_ack_v1(
     stored.protocol_revision, stored.policy_revision, stored.provider_boundary_id,
     stored.authenticated_cell_id, stored.authenticated_tenant_id,
     stored.logical_request_id, stored.attempt_id, stored.upload_id, stored.upload_fence,
     2::smallint, stored.quota_bytes, stored.quota_rows, stored.quota_concurrency,
     stored.expires_at_unix_ms, stored.max_chunk_bytes, stored.durable_handle,
     stored.committed_size, stored.committed_blake3, stored.ready_at_unix_ms,
     stored.admission_clock_unix_ms, stored.allocation_hard_expiry_unix_ms,
     1024, 4096, 16777216
   );
   next_record := object_store_retention.local_put_spool_ready_record_v1(
     stored.protocol_revision, stored.policy_revision, stored.provider_boundary_id,
     stored.authenticated_cell_id, stored.authenticated_tenant_id, stored.spool_object_id,
     stored.logical_request_id, stored.attempt_id, stored.upload_id, stored.upload_fence,
     stored.boundary_blake3, stored.boundary_token, stored.observation_binding_blake3,
     stored.expected_size, stored.expected_blake3, stored.committed_size,
     stored.committed_blake3, stored.durable_handle, stored.partial_temp_bytes,
     stored.partial_temp_chunks, stored.partial_temp_files,
     stored.put_reservation_fingerprint, stored.allocation_revision, stored.allocation_fence,
     stored.reservation_deadline_unix_ms, stored.allocation_hard_expiry_unix_ms,
     stored.admission_clock_unix_ms, stored.prepared_ttl_ms, stored.expires_at_unix_ms,
     stored.ready_at_unix_ms, stored.max_chunk_bytes, stored.quota_bytes,
     stored.quota_rows, stored.quota_concurrency, stored.quota_revision,
     next_ack.canonical_bytes, NULL,
     stored.spool_revision, 1024, 4096, 4096, 16777216
   );
  END IF;
  UPDATE object_store_retention.object_dispatch_spool_objects AS spool
     SET reserve_put_ack_canonical_bytes = next_ack.canonical_bytes,
         reserve_put_ack_blake3 = NULL,
         canonical_record_bytes = next_record.canonical_bytes,
         record_blake3 = NULL
   WHERE spool.spool_object_id = stored.spool_object_id
  RETURNING * INTO STRICT stored;
  PERFORM object_store_retention.project_dispatch_reserved_put_v1(stored, 'REPLAY');
 END LOOP;

 FOR dispatcher IN SELECT * FROM object_store_retention.object_dispatch_dispatchers
                    ORDER BY provider_boundary_id, lease_generation LOOP
  next_record := object_store_retention.local_dispatcher_registration_record_v1(
    dispatcher.dispatcher_id, dispatcher.lease_generation, dispatcher.provider_boundary_id,
    dispatcher.service_instance_id, dispatcher.dispatcher_fence, dispatcher.authority_revision,
    dispatcher.allocation_revision, dispatcher.allocation_fence,
    dispatcher.provider_credential_revision, dispatcher.acquired_at_unix_ms,
    dispatcher.renewed_at_unix_ms, dispatcher.expires_at_unix_ms,
    dispatcher.state_changed_at_unix_ms
  );
  UPDATE object_store_retention.object_dispatch_dispatchers AS row_state
     SET canonical_record_bytes = next_record.canonical_bytes,
         record_blake3 = NULL
   WHERE row_state.provider_boundary_id = dispatcher.provider_boundary_id
     AND row_state.lease_generation = dispatcher.lease_generation;
 END LOOP;
END $backfill$;

ALTER TABLE object_store_retention.object_dispatch_spool_objects
  ADD CONSTRAINT object_dispatch_spool_objects_record_blake3_null_ck
    CHECK (record_blake3 IS NULL),
  -- 0010's presence check without reserve_put_ack_blake3: eleven columns.
  ADD CONSTRAINT object_dispatch_spool_objects_put_reservation_presence_ck CHECK (
    (
      payload_kind = 1 AND
      pg_catalog.num_nonnulls(
        protocol_revision,
        policy_revision,
        put_reservation_fingerprint,
        allocation_revision,
        allocation_fence,
        reservation_deadline_unix_ms,
        allocation_hard_expiry_unix_ms,
        admission_clock_unix_ms,
        prepared_ttl_ms,
        max_chunk_bytes,
        reserve_put_ack_canonical_bytes
      ) = 11 AND
      expires_at_unix_ms IS NOT NULL
    ) OR
    (
      payload_kind = 2 AND
      pg_catalog.num_nonnulls(
        protocol_revision,
        policy_revision,
        put_reservation_fingerprint,
        allocation_revision,
        allocation_fence,
        reservation_deadline_unix_ms,
        allocation_hard_expiry_unix_ms,
        admission_clock_unix_ms,
        prepared_ttl_ms,
        max_chunk_bytes,
        reserve_put_ack_canonical_bytes
      ) = 0
    )
  ),
  -- 0010's ack check, as a length check only.
  ADD CONSTRAINT object_dispatch_spool_objects_put_reservation_ack_ck CHECK (
    payload_kind <> 1 OR
    pg_catalog.octet_length(reserve_put_ack_canonical_bytes) BETWEEN 33 AND 16777216
  ),
  ADD CONSTRAINT object_dispatch_spool_objects_reserve_put_ack_blake3_null_ck
    CHECK (reserve_put_ack_blake3 IS NULL);
ALTER TABLE object_store_retention.object_dispatch_dispatchers
  ADD CONSTRAINT object_dispatch_dispatchers_record_blake3_null_ck
    CHECK (record_blake3 IS NULL);

-- ---------------------------------------------------------------------------------------------
-- G2. Dispatcher registration. 0020's body with one expression changed: the enrolled commitment
-- is the built-in SHA-256 of the participant key. The column and the enrollment parameter keep
-- the name participant_key_blake3 and now hold SHA-256. Runtime EXECUTE persists.
-- ---------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION object_store_retention.object_store_dispatch_register_dispatcher_v1(
  api_revision text,
  participant_key bytea,
  next_generation object_store_retention.uint64,
  service_instance_id text,
  dispatcher_fence object_store_retention.uint64,
  authority_revision object_store_retention.uint64,
  allocation_revision text,
  allocation_fence object_store_retention.uint64,
  provider_credential_revision text,
  acquired_at_unix_ms bigint,
  renewed_at_unix_ms bigint,
  expires_at_unix_ms bigint,
  state_changed_at_unix_ms bigint
)
RETURNS object_store_retention.dispatch_dispatcher_registration_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE participant object_store_retention.object_dispatch_dispatcher_participants%ROWTYPE;
DECLARE stored object_store_retention.object_dispatch_dispatchers%ROWTYPE;
DECLARE maximum_generation object_store_retention.uint64;
DECLARE next_record object_store_retention.local_canonical_record_v1;
BEGIN
  PERFORM object_store_retention.assert_dispatch_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_dispatcher_registration_api_revision_v1(
    api_revision
  );
  PERFORM object_store_retention.assert_serializable_write_v1();
  PERFORM object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(
    'object-store-dispatch-dispatcher-identity-provisioning-v1'
  );
  IF participant_key IS NULL OR pg_catalog.octet_length(participant_key) <> 32 THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_PARTICIPANT_AUTHENTICATION_REQUIRED'
      USING ERRCODE = '42501';
  END IF;

  -- Maintenance owns the stable identity mapping. Runtime proves possession of its enrolled slot
  -- key and never supplies either identity column itself. R31: the commitment is SHA-256.
  SELECT * INTO participant
    FROM object_store_retention.object_dispatch_dispatcher_participants AS enrolled
   WHERE enrolled.participant_key_blake3 =
         pg_catalog.sha256(
           object_store_dispatch_register_dispatcher_v1.participant_key
         )
   FOR UPDATE;
  IF participant.participant_key_blake3 IS NULL THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_PARTICIPANT_AUTHENTICATION_REQUIRED'
      USING ERRCODE = '42501';
  END IF;
  IF participant.schema_revision IS DISTINCT FROM
       'object-store-dispatch-dispatcher-registration-v1' THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_PARTICIPANT_STATE_INVALID' USING ERRCODE = '55000';
  END IF;

  -- Lock the complete participant chain before reading its maximum. The registry row serializes
  -- procedure callers; these row locks also bind the mutation to every retained generation.
  PERFORM 1
    FROM object_store_retention.object_dispatch_dispatchers AS dispatcher
   WHERE dispatcher.provider_boundary_id = participant.provider_boundary_id
     AND dispatcher.dispatcher_id = participant.dispatcher_id
   ORDER BY dispatcher.lease_generation
   FOR UPDATE;

  SELECT * INTO stored
    FROM object_store_retention.object_dispatch_dispatchers AS dispatcher
   WHERE dispatcher.provider_boundary_id = participant.provider_boundary_id
     AND dispatcher.dispatcher_id = participant.dispatcher_id
     AND dispatcher.lease_generation = object_store_dispatch_register_dispatcher_v1.next_generation
   FOR UPDATE;
  IF FOUND AND stored.state = 1 THEN
    IF stored.schema_revision IS DISTINCT FROM 'object-store-dispatch-authority-schema-v1'
       OR stored.service_instance_id IS DISTINCT FROM service_instance_id
       OR stored.dispatcher_fence IS DISTINCT FROM dispatcher_fence
       OR stored.authority_revision IS DISTINCT FROM authority_revision
       OR stored.allocation_revision IS DISTINCT FROM allocation_revision
       OR stored.allocation_fence IS DISTINCT FROM allocation_fence
       OR stored.provider_credential_revision IS DISTINCT FROM provider_credential_revision
       OR stored.state IS DISTINCT FROM 1
       OR stored.acquired_at_unix_ms IS DISTINCT FROM acquired_at_unix_ms
       OR stored.renewed_at_unix_ms IS DISTINCT FROM renewed_at_unix_ms
       OR stored.expires_at_unix_ms IS DISTINCT FROM expires_at_unix_ms
       OR stored.state_changed_at_unix_ms IS DISTINCT FROM state_changed_at_unix_ms
       OR pg_catalog.num_nonnulls(
            stored.revocation_id,
            stored.revocation_requested_at_unix_ms,
            stored.revoked_at_unix_ms,
            stored.revocation_evidence_blake3
          ) <> 0 THEN
      RAISE EXCEPTION 'DISPATCH_DISPATCHER_REGISTRATION_REPLAY_CONFLICT'
        USING ERRCODE = '23505';
    END IF;
    RETURN object_store_retention.project_dispatch_dispatcher_registration_v1(stored, 'REPLAY');
  END IF;

  SELECT pg_catalog.max(dispatcher.lease_generation) INTO maximum_generation
    FROM object_store_retention.object_dispatch_dispatchers AS dispatcher
   WHERE dispatcher.provider_boundary_id = participant.provider_boundary_id
     AND dispatcher.dispatcher_id = participant.dispatcher_id;
  IF next_generation IS NULL
     OR next_generation <= COALESCE(maximum_generation, 0) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_GENERATION_NOT_MONOTONIC' USING ERRCODE = '22023';
  END IF;

  next_record := object_store_retention.local_dispatcher_registration_record_v1(
    participant.dispatcher_id,
    next_generation,
    participant.provider_boundary_id,
    service_instance_id,
    dispatcher_fence,
    authority_revision,
    allocation_revision,
    allocation_fence,
    provider_credential_revision,
    acquired_at_unix_ms,
    renewed_at_unix_ms,
    expires_at_unix_ms,
    state_changed_at_unix_ms
  );

  INSERT INTO object_store_retention.object_dispatch_dispatchers (
    schema_revision,
    dispatcher_id,
    lease_generation,
    provider_boundary_id,
    service_instance_id,
    dispatcher_fence,
    authority_revision,
    allocation_revision,
    allocation_fence,
    provider_credential_revision,
    state,
    acquired_at_unix_ms,
    renewed_at_unix_ms,
    expires_at_unix_ms,
    state_changed_at_unix_ms,
    canonical_record_bytes,
    record_blake3
  ) VALUES (
    'object-store-dispatch-authority-schema-v1',
    participant.dispatcher_id,
    next_generation,
    participant.provider_boundary_id,
    service_instance_id,
    dispatcher_fence,
    authority_revision,
    allocation_revision,
    allocation_fence,
    provider_credential_revision,
    1,
    acquired_at_unix_ms,
    renewed_at_unix_ms,
    expires_at_unix_ms,
    state_changed_at_unix_ms,
    next_record.canonical_bytes,
    next_record.record_blake3
  ) RETURNING * INTO stored;

  RETURN object_store_retention.project_dispatch_dispatcher_registration_v1(stored, 'CREATED');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- G3. Drain policy and descriptor procedures: each latest body without its BLAKE3 assert. The
-- canonical byte-equality checks stay. A digest argument is still checked for shape where the
-- removed assert was its only check.
-- ---------------------------------------------------------------------------------------------

-- 0026's publish.
CREATE OR REPLACE FUNCTION object_store_retention.drain_policy_publish_v1(p jsonb, canonical bytea, digest bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old object_store_retention.drain_policies%ROWTYPE;
BEGIN
 IF session_user<>'object_dispatch_retention_maintenance' THEN RAISE EXCEPTION 'UNAUTHORIZED' USING ERRCODE='42501'; END IF;
 PERFORM object_store_retention.assert_serializable_write_v1();
 IF octet_length(p::text)>16384 OR canonical IS DISTINCT FROM object_store_retention.drain_policy_bytes_v1(p) THEN RAISE EXCEPTION 'DRAIN_POLICY_CANONICAL_MISMATCH'; END IF;
 IF digest IS NULL OR octet_length(digest)<>32 THEN RAISE EXCEPTION 'DRAIN_POLICY_DIGEST_INVALID' USING ERRCODE='22000'; END IF;
 IF (p->>'expires_at_ms')::bigint<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_POLICY_EXPIRED'; END IF;
 INSERT INTO object_store_retention.drain_policies(boundary,cell,revision,digest,policy,canonical)
 VALUES(p->>'boundary',p->>'cell',p->>'revision',digest,p,canonical) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT old FROM object_store_retention.drain_policies x WHERE x.boundary=p->>'boundary' AND x.cell=p->>'cell' FOR UPDATE;
 IF old.policy IS DISTINCT FROM p OR old.digest IS DISTINCT FROM digest OR old.canonical IS DISTINCT FROM canonical THEN RAISE EXCEPTION 'DRAIN_POLICY_IMMUTABLE'; END IF;
END $$;

-- 0026's read. The stored digest is pinned by the caller's revision and digest; Rust re-checks
-- the policy bytes against it.
CREATE OR REPLACE FUNCTION object_store_retention.drain_policy_read_v1(boundary text,cell text,revision text,digest bytea)
RETURNS TABLE(policy jsonb,allocation_revision text,allocation_fence object_store_retention.uint64,allocation_expiry_ms bigint,observed_at_ms bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p object_store_retention.drain_policies%ROWTYPE; h object_store_retention.object_dispatch_current_budget_configuration%ROWTYPE;
DECLARE expiry bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 SELECT * INTO STRICT p FROM object_store_retention.drain_policies x WHERE x.boundary=drain_policy_read_v1.boundary AND x.cell=drain_policy_read_v1.cell;
 IF p.revision IS DISTINCT FROM revision OR p.digest IS DISTINCT FROM digest
 OR (p.policy->>'expires_at_ms')::bigint<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
 SELECT * INTO STRICT h FROM object_store_retention.object_dispatch_current_budget_configuration x WHERE x.provider_boundary_id=boundary;
 PERFORM object_store_retention.assert_dispatch_budget_resolved_v1(boundary,h.allocation_revision,h.allocation_fence);
 SELECT x.hard_expires_at_unix_ms INTO STRICT expiry FROM object_store_retention.object_dispatch_budget_configurations x
 WHERE x.provider_boundary_id=boundary AND x.allocation_revision=h.allocation_revision AND x.allocation_fence=h.allocation_fence;
 IF expiry<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_BUDGET_EXPIRED'; END IF;
 RETURN QUERY SELECT p.policy,h.allocation_revision,h.allocation_fence,expiry,object_store_retention.clock_unix_ms_v1();
END $$;

-- 0026's verify. The stored digest comparison already refuses any digest other than the
-- published one.
CREATE OR REPLACE FUNCTION object_store_retention.drain_policy_verify_v1(p jsonb, canonical bytea, digest bytea)
RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE stored object_store_retention.drain_policies%ROWTYPE;
BEGIN
 IF session_user<>'object_dispatch_retention_maintenance' THEN RAISE EXCEPTION 'UNAUTHORIZED' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT stored FROM object_store_retention.drain_policies x WHERE x.boundary=p->>'boundary' AND x.cell=p->>'cell';
 IF stored.policy IS DISTINCT FROM p OR stored.canonical IS DISTINCT FROM canonical OR stored.digest IS DISTINCT FROM digest
 OR (p->>'expires_at_ms')::bigint<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
 IF canonical IS DISTINCT FROM object_store_retention.drain_policy_bytes_v1(p) THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
END $$;

-- 0029's rotation.
CREATE OR REPLACE FUNCTION object_store_retention.drain_policy_rotate_v1(p jsonb, canonical bytea, digest bytea,
 expected_revision text, expected_digest bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old object_store_retention.drain_policies%ROWTYPE; now_ms bigint;
BEGIN
 IF session_user<>'object_dispatch_retention_maintenance' THEN RAISE EXCEPTION 'UNAUTHORIZED' USING ERRCODE='42501'; END IF;
 PERFORM object_store_retention.assert_serializable_write_v1();
 IF expected_revision IS NULL OR expected_digest IS NULL OR octet_length(expected_digest)<>32
 OR digest IS NULL OR octet_length(digest)<>32
 OR canonical IS DISTINCT FROM object_store_retention.drain_policy_bytes_v1(p) OR octet_length(p::text)>16384 THEN
  RAISE EXCEPTION 'DRAIN_ROTATION_INVALID';
 END IF;
 LOCK TABLE object_store_retention.object_dispatch_spool_objects,
  object_store_retention.drain_spool_custody,object_store_retention.object_dispatch_quota_usage,
  object_store_retention.drain_policies IN ACCESS EXCLUSIVE MODE NOWAIT;
 SELECT * INTO STRICT old FROM object_store_retention.drain_policies x WHERE x.boundary=p->>'boundary' AND x.cell=p->>'cell';
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF old.policy=p AND old.canonical=canonical AND old.digest=digest THEN
  IF old.previous_revision IS DISTINCT FROM expected_revision OR old.previous_digest IS DISTINCT FROM expected_digest THEN
   RAISE EXCEPTION 'DRAIN_ROTATION_REPLAY_CONFLICT';
  END IF;
  PERFORM public.stage_policy_rotate_v1(p,digest,expected_revision,expected_digest);
  RETURN;
 END IF;
 IF old.revision IS DISTINCT FROM expected_revision OR old.digest IS DISTINCT FROM expected_digest
 OR (p->>'revision') COLLATE "C" <= old.revision COLLATE "C"
 OR p->>'service' IS DISTINCT FROM old.policy->>'service'
 OR (p->>'expires_at_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_ROTATION_CONFLICT'; END IF;
 IF EXISTS(SELECT 1 FROM object_store_retention.drain_spool_custody c WHERE c.boundary=old.boundary AND c.cell=old.cell
    AND (c.state IN(1,2) OR c.cleanup_not_before>now_ms))
 OR EXISTS(SELECT 1 FROM object_store_retention.object_dispatch_quota_usage q WHERE q.provider_boundary_id=old.boundary
    AND q.quota_class=1 AND (q.used_bytes<>0 OR q.used_rows<>0 OR q.used_concurrency<>0)) THEN
  RAISE EXCEPTION 'DRAIN_ROTATION_NOT_QUIESCENT';
 END IF;
 IF old.metadata_rows>(p->>'metadata_max_rows')::numeric OR old.metadata_bytes>(p->>'metadata_max_bytes')::numeric THEN
  RAISE EXCEPTION 'DRAIN_ROTATION_CAPACITY';
 END IF;
 PERFORM public.stage_policy_rotate_v1(p,digest,expected_revision,expected_digest);
 UPDATE object_store_retention.drain_policies x SET revision=p->>'revision',policy=p,canonical=drain_policy_rotate_v1.canonical,
  digest=drain_policy_rotate_v1.digest,previous_revision=old.revision,previous_digest=old.digest
 WHERE x.boundary=old.boundary AND x.cell=old.cell;
 UPDATE object_store_retention.drain_spool_custody x SET superseded=true,
  marker_fence_ms=greatest(x.marker_fence_ms,now_ms),lease_until_ms=0
 WHERE x.boundary=old.boundary AND x.cell=old.cell;
END $$;

-- 0030's reservation. The descriptor digest is stored as the custody digest and the reservation
-- fingerprint; a replay must carry the same one, byte for byte.
CREATE OR REPLACE FUNCTION object_store_retention.drain_reserve_v1(d jsonb, canonical bytea, digest bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p object_store_retention.drain_policies%ROWTYPE; s object_store_retention.object_dispatch_spool_objects%ROWTYPE;
DECLARE c object_store_retention.drain_spool_custody%ROWTYPE; r object_store_retention.dispatch_reserve_put_result_v1;
DECLARE snapshot record; q jsonb; now_ms bigint; charge bigint:=16384;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 IF octet_length(d::text)+octet_length(canonical)>10000 OR canonical IS DISTINCT FROM object_store_retention.drain_descriptor_bytes_v1(d) THEN RAISE EXCEPTION 'DRAIN_DESCRIPTOR_CANONICAL_MISMATCH'; END IF;
 IF digest IS NULL OR octet_length(digest)<>32 THEN RAISE EXCEPTION 'DRAIN_DESCRIPTOR_DIGEST_INVALID' USING ERRCODE='22000'; END IF;
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF (d->>'send_not_after_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_EXPIRED'; END IF;
 -- Stable spool identity is always locked before custody, and before scope 1/2/3.
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x
 WHERE x.logical_request_id=(d->>'logical_request_id')::uuid AND x.attempt_id=(d->>'attempt_id')::uuid AND x.payload_kind=1 FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.logical_id=(d->>'logical_request_id')::uuid AND x.attempt_id=(d->>'attempt_id')::uuid FOR UPDATE;
 IF FOUND THEN
  IF c.state<>1 OR c.canonical IS DISTINCT FROM canonical OR c.descriptor IS DISTINCT FROM d
   OR c.digest IS DISTINCT FROM digest
   OR s.spool_object_id IS NULL OR s.expires_at_unix_ms<=now_ms THEN RAISE EXCEPTION 'DRAIN_REPLAY_REFUSED'; END IF;
  -- Policy pins and expiry apply to replay too; allocation renewal does not rewrite d.
  SELECT * INTO STRICT p FROM object_store_retention.drain_policies x WHERE x.boundary=c.boundary AND x.cell=c.cell;
  IF p.revision IS DISTINCT FROM d->>'policy_revision' OR encode(p.digest,'hex') IS DISTINCT FROM d->>'policy_digest'
   OR (p.policy->>'expires_at_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
  RETURN;
 END IF;
 IF s.spool_object_id IS NOT NULL THEN RAISE EXCEPTION 'DRAIN_UNOWNED_RESERVATION'; END IF;
 SELECT * INTO STRICT snapshot FROM object_store_retention.drain_policy_read_v1(d->>'boundary',d->>'cell',d->>'policy_revision',decode(d->>'policy_digest','hex'));
 IF snapshot.allocation_revision IS DISTINCT FROM d->>'allocation_revision' OR snapshot.allocation_fence IS DISTINCT FROM (d->>'allocation_fence')::numeric
 OR snapshot.allocation_expiry_ms IS DISTINCT FROM (d->>'allocation_expiry_ms')::bigint
 OR snapshot.policy->>'service' IS DISTINCT FROM d->>'service'
 OR (d->>'prepared_ttl_ms')::numeric IS DISTINCT FROM (snapshot.policy->>'maximum_ttl_ms')::numeric THEN RAISE EXCEPTION 'DRAIN_SNAPSHOT_MISMATCH'; END IF;
 q:=snapshot.policy->'quotas';
 -- The retained reservation algebra owns row/byte/concurrency admission.
 r:=object_store_retention.object_store_dispatch_reserve_put_v1(
 'object-store-dispatch-reserve-put-v1','object-dispatch-v1',d->>'policy_revision',d->>'boundary',d->>'cell',d->>'service',
 (d->>'spool_object_id')::uuid,(d->>'logical_request_id')::uuid,(d->>'attempt_id')::uuid,(d->>'upload_id')::uuid,(d->>'upload_fence')::object_store_retention.uint64,
 decode(d->>'boundary_digest','hex'),d->>'boundary_token',decode(d->>'observation_digest','hex'),
 (d->>'body_size')::object_store_retention.uint64,decode(d->>'body_digest','hex'),digest,
 d->>'allocation_revision',(d->>'allocation_fence')::object_store_retention.uint64,(d->>'send_not_after_ms')::bigint,(d->>'allocation_expiry_ms')::bigint,
 (d->>'prepared_ttl_ms')::bigint,262144::object_store_retention.uint64,(snapshot.policy->>'quota_revision')::object_store_retention.uint64,
 (q->0->>0)::object_store_retention.uint64,(q->0->>1)::object_store_retention.uint64,(q->0->>2)::object_store_retention.uint64,(q->0->>3)::object_store_retention.uint64,(q->0->>4)::object_store_retention.uint64,(q->0->>5)::object_store_retention.uint64,
 (q->1->>0)::object_store_retention.uint64,(q->1->>1)::object_store_retention.uint64,(q->1->>2)::object_store_retention.uint64,(q->1->>3)::object_store_retention.uint64,(q->1->>4)::object_store_retention.uint64,(q->1->>5)::object_store_retention.uint64,
 (q->2->>0)::object_store_retention.uint64,(q->2->>1)::object_store_retention.uint64,(q->2->>2)::object_store_retention.uint64,(q->2->>3)::object_store_retention.uint64,(q->2->>4)::object_store_retention.uint64,(q->2->>5)::object_store_retention.uint64,256,256,16384);
 INSERT INTO object_store_retention.drain_spool_custody(spool_id,boundary,cell,service,logical_id,attempt_id,descriptor,canonical,digest,cleanup_not_before,metadata_bytes)
 VALUES(r.spool_object_id,d->>'boundary',d->>'cell',d->>'service',r.logical_request_id,r.attempt_id,d,canonical,digest,greatest(r.expires_at_unix_ms,(d->>'hard_not_after_ms')::bigint),charge);
 -- The reservation charged the ledger the body size and one row; the counters take the same.
 UPDATE object_store_retention.drain_policies x SET metadata_rows=x.metadata_rows+1,metadata_bytes=x.metadata_bytes+charge,
  charged_bytes=x.charged_bytes+(d->>'body_size')::numeric,charged_files=x.charged_files+1
 WHERE x.boundary=d->>'boundary' AND x.cell=d->>'cell'
 AND x.metadata_rows+1<=(x.policy->>'metadata_max_rows')::numeric AND x.metadata_bytes+charge<=(x.policy->>'metadata_max_bytes')::numeric;
 IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_CAPACITY' USING ERRCODE='53000'; END IF;
END $$;

-- ---------------------------------------------------------------------------------------------
-- G4. Release receipt: 0029's release with a preimage-only receipt under the v2 tag (same
-- 25-byte length as v1) and no digest. Rows released before R31 keep their v1 bytes; nothing
-- reads them except the metadata charge, which uses octet_length only.
-- ---------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION object_store_retention.drain_cleanup_release_v1(spool uuid,fence bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE q object_store_retention.object_dispatch_quota_usage%ROWTYPE; n integer:=0; receipt bytea;
DECLARE retained bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 IF c.cleanup_fence IS DISTINCT FROM fence OR c.state=1 THEN RAISE EXCEPTION 'DRAIN_CLEANUP_FENCED'; END IF;
 IF c.state IN(3,4) THEN RETURN; END IF;
 IF s.spool_object_id IS NULL THEN RAISE EXCEPTION 'DRAIN_CLEANUP_MISSING_ACCOUNTING'; END IF;
 FOR q IN SELECT * FROM object_store_retention.object_dispatch_quota_usage x
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service))
 ORDER BY x.scope_kind FOR UPDATE LOOP
  IF q.used_bytes<s.quota_bytes OR q.used_rows<s.quota_rows OR q.used_concurrency<s.quota_concurrency THEN RAISE EXCEPTION 'DRAIN_COUNTER_UNDERFLOW'; END IF;
  n:=n+1;
 END LOOP;
 IF n<>3 THEN RAISE EXCEPTION 'DRAIN_COUNTER_MISSING'; END IF;
 UPDATE object_store_retention.object_dispatch_quota_usage x SET used_bytes=x.used_bytes-s.quota_bytes,
 used_rows=x.used_rows-s.quota_rows,used_concurrency=x.used_concurrency-s.quota_concurrency,counter_revision=x.counter_revision+1,
 updated_at_unix_ms=object_store_retention.clock_unix_ms_v1()
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service));
 receipt:=convert_to('fragment-drain-release-v2','UTF8')||uuid_send(spool)||c.digest
 ||object_store_retention.local_canonical_u64_v1(fence::object_store_retention.uint64)
 ||object_store_retention.local_canonical_u64_v1(s.quota_bytes)
 ||object_store_retention.local_canonical_u64_v1(s.quota_rows)
 ||object_store_retention.local_canonical_u64_v1(s.quota_concurrency);
 UPDATE object_store_retention.drain_spool_custody x SET state=3,release_receipt=receipt,release_digest=NULL
 WHERE x.spool_id=spool RETURNING * INTO c;
 retained:=object_store_retention.drain_retained_metadata_bytes_v1(c);
 IF retained<c.metadata_bytes THEN
  UPDATE object_store_retention.drain_spool_custody x SET metadata_bytes=retained WHERE x.spool_id=spool;
  UPDATE object_store_retention.drain_policies x
  SET metadata_bytes=(x.metadata_bytes::numeric-(c.metadata_bytes-retained))::object_store_retention.uint64
  WHERE x.boundary=c.boundary AND x.cell=c.cell AND x.metadata_bytes::numeric>=(c.metadata_bytes-retained);
  IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_UNDERFLOW'; END IF;
 END IF;
END $$;

-- ---------------------------------------------------------------------------------------------
-- G5. drain_check_ready_v2: the CAS token is (spool_revision, ready_at_unix_ms) instead of the
-- database-built record digest. Within one row spool_revision only grows, and a ready row is
-- frozen, so the pair names exactly one ready incarnation; ready_at (database clock) closes the
-- re-incarnation case a revision alone would leave open. 0026's body otherwise.
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION object_store_retention.drain_check_ready_v2(spool uuid,attempt uuid,
 spool_revision object_store_retention.uint64,ready_at_unix_ms bigint,object_key text,deadline bigint)
RETURNS TABLE(effective_deadline bigint,remaining_ms bigint) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE; now_ms bigint; policy_expiry bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 SELECT * INTO STRICT s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF c.state<>1 OR s.lifecycle_state<>2 OR s.attempt_id IS DISTINCT FROM attempt
 OR s.spool_revision IS DISTINCT FROM drain_check_ready_v2.spool_revision
 OR s.ready_at_unix_ms IS DISTINCT FROM drain_check_ready_v2.ready_at_unix_ms
 OR s.expires_at_unix_ms<=now_ms OR deadline<=now_ms OR deadline>(c.descriptor->>'send_not_after_ms')::bigint
 OR c.descriptor->>'object_key' IS DISTINCT FROM object_key THEN RAISE EXCEPTION 'DRAIN_READY_REFUSED'; END IF;
 SELECT (p.policy->>'expires_at_ms')::bigint INTO STRICT policy_expiry FROM object_store_retention.drain_policies p WHERE p.boundary=c.boundary AND p.cell=c.cell;
 IF policy_expiry<=now_ms THEN RAISE EXCEPTION 'DRAIN_POLICY_EXPIRED'; END IF;
 RETURN QUERY SELECT least(deadline,s.expires_at_unix_ms,policy_expiry),least(deadline,s.expires_at_unix_ms,policy_expiry)-now_ms;
END $$;

-- A new function is executable by PUBLIC by default; revoke that and every service role, then
-- grant the runtime alone, as 0026 did for v1.
REVOKE ALL ON FUNCTION object_store_retention.drain_check_ready_v2(uuid,uuid,object_store_retention.uint64,bigint,text,bigint)
 FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION object_store_retention.drain_check_ready_v2(uuid,uuid,object_store_retention.uint64,bigint,text,bigint)
 TO object_dispatch_retention_runtime;

-- ---------------------------------------------------------------------------------------------
-- Drops. After the replacements above no function body references these four. plpgsql bodies
-- record no pg_depend edges, so that is checked by source scan of the final install set.
-- ---------------------------------------------------------------------------------------------
DROP FUNCTION object_store_retention.drain_check_ready_v1(uuid,uuid,bytea,text,bigint);
DROP FUNCTION object_store_retention.local_assert_blake3_v1(bytea,bytea);
DROP FUNCTION object_store_retention.local_complete_record_v1(bytea,integer);
DROP FUNCTION object_store_retention.local_blake3_v1(bytea);

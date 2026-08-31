-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-114 CD-3 INV-EM fix round: database-owned dispatcher registration.
--
-- Migrations 0002 through 0019 are frozen. This forward migration closes the two P1 findings from
-- INV-EM without changing their bytes. Maintenance pre-enrolls each durable participant slot with
-- a restart-stable `dispatcher_id` and a BLAKE3 commitment to a random participant key. Runtime
-- registration proves possession of that key, so a restarted process cannot invent a new identity
-- and reset its generation to one. The registration procedure serializes on the enrolled slot,
-- locks the existing chain, and rejects any new generation that is not greater than the chain
-- maximum. `service_instance_id` remains the per-boot identity and is never substituted for the
-- participant key. PostgreSQL also constructs and verifies the canonical dispatcher record; no
-- runtime caller can supply unauthenticated record evidence.
--
-- This migration also replaces two internal 0019 assertions. The public 0019 readback name,
-- signature, result type, and installed-layer projection remain unchanged. Its reader gate becomes
-- runtime-only because no maintenance consumer exists, and its object assertion now pins the
-- attempts foreign key whose removal INV-EM proved was otherwise invisible.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TABLE object_store_retention.object_dispatch_dispatcher_participants (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-dispatcher-registration-v1'),
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  dispatcher_id text NOT NULL CHECK (octet_length(dispatcher_id) BETWEEN 1 AND 1024),
  participant_key_blake3 object_store_retention.blake3_256 NOT NULL UNIQUE,
  PRIMARY KEY (provider_boundary_id, dispatcher_id)
);

CREATE TYPE object_store_retention.dispatch_dispatcher_participant_enrollment_result_v1 AS (
  result_code text,
  provider_boundary_id text,
  dispatcher_id text
);

CREATE TYPE object_store_retention.dispatch_dispatcher_registration_result_v1 AS (
  result_code text,
  dispatcher_id text,
  lease_generation object_store_retention.uint64,
  provider_boundary_id text,
  service_instance_id text,
  dispatcher_fence object_store_retention.uint64,
  state smallint,
  record_blake3 bytea
);

CREATE FUNCTION object_store_retention.assert_dispatch_dispatcher_registration_api_revision_v1(
  api_revision text
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-dispatch-dispatcher-registration-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_DISPATCH_DISPATCHER_REGISTRATION_API_REVISION'
      USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_dispatch_maintenance_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance' THEN
    RAISE EXCEPTION 'DISPATCH_MAINTENANCE_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(
  api_revision text,
  provider_boundary_id text,
  dispatcher_id text,
  participant_key_blake3 bytea
)
RETURNS object_store_retention.dispatch_dispatcher_participant_enrollment_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_retention.object_dispatch_dispatcher_participants%ROWTYPE;
BEGIN
  PERFORM object_store_retention.assert_dispatch_maintenance_v1();
  PERFORM object_store_retention.assert_dispatch_dispatcher_registration_api_revision_v1(
    api_revision
  );
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF participant_key_blake3 IS NULL OR pg_catalog.octet_length(participant_key_blake3) <> 32 THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_PARTICIPANT_KEY_DIGEST_INVALID'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO object_store_retention.object_dispatch_dispatcher_participants (
    schema_revision, provider_boundary_id, dispatcher_id, participant_key_blake3
  ) VALUES (
    'object-store-dispatch-dispatcher-registration-v1',
    provider_boundary_id,
    dispatcher_id,
    participant_key_blake3
  )
  ON CONFLICT ON CONSTRAINT object_dispatch_dispatcher_participants_pkey DO NOTHING
  RETURNING * INTO stored;
  IF FOUND THEN
    RETURN ROW(
      'CREATED', stored.provider_boundary_id, stored.dispatcher_id
    )::object_store_retention.dispatch_dispatcher_participant_enrollment_result_v1;
  END IF;

  SELECT * INTO STRICT stored
    FROM object_store_retention.object_dispatch_dispatcher_participants AS participant
   WHERE participant.provider_boundary_id =
         object_store_dispatch_enroll_dispatcher_participant_v1.provider_boundary_id
     AND participant.dispatcher_id =
         object_store_dispatch_enroll_dispatcher_participant_v1.dispatcher_id
   FOR UPDATE;
  IF stored.schema_revision IS DISTINCT FROM
       'object-store-dispatch-dispatcher-registration-v1'
     OR stored.participant_key_blake3 IS DISTINCT FROM participant_key_blake3 THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_PARTICIPANT_ENROLLMENT_CONFLICT'
      USING ERRCODE = '23505';
  END IF;

  RETURN ROW(
    'REPLAY', stored.provider_boundary_id, stored.dispatcher_id
  )::object_store_retention.dispatch_dispatcher_participant_enrollment_result_v1;
END
$$;

-- Least authority: this is a runtime readiness signal. The migrator has its out-of-band attester,
-- and no maintenance operation consumes the installed-layer projection.
CREATE OR REPLACE FUNCTION object_store_retention.assert_dispatch_dispatcher_identity_reader_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_runtime' THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_READER_AUTHORIZATION_REQUIRED'
      USING ERRCODE = '42501';
  END IF;
END
$$;

-- Keep 0019's four dispatcher-table assertions and add the exact attempts foreign-key carrier.
-- Shape, not name, is authoritative: renaming the constraint is harmless, while changing either
-- ordered column vector, its target relation, validation, or deferrability is drift.
CREATE OR REPLACE FUNCTION object_store_retention.assert_dispatch_dispatcher_identity_objects_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE dispatchers_oid oid;
DECLARE attempts_oid oid;
DECLARE participants_oid oid;
BEGIN
  SELECT relation.oid INTO STRICT dispatchers_oid
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
   WHERE namespace.nspname = 'object_store_retention'
     AND relation.relname = 'object_dispatch_dispatchers'
     AND relation.relkind = 'r';

  SELECT relation.oid INTO STRICT attempts_oid
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
   WHERE namespace.nspname = 'object_store_retention'
     AND relation.relname = 'object_dispatch_attempts'
     AND relation.relkind = 'r';

  SELECT relation.oid INTO STRICT participants_oid
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
   WHERE namespace.nspname = 'object_store_retention'
     AND relation.relname = 'object_dispatch_dispatcher_participants'
     AND relation.relkind = 'r';

  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_index AS idx
      JOIN pg_catalog.pg_class AS idx_relation ON idx_relation.oid = idx.indexrelid
     WHERE idx.indrelid = dispatchers_oid
       AND idx_relation.relname = 'object_dispatch_dispatchers_one_active_participant_idx'
       AND idx.indisunique
       AND idx.indisvalid
       AND idx.indisready
       AND idx.indpred IS NOT NULL
       AND pg_catalog.pg_get_expr(idx.indpred, idx.indrelid) = '(state = 1)'
       AND idx.indnatts = idx.indnkeyatts
       AND ARRAY(
             SELECT attribute.attname::text
               FROM pg_catalog.unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinal)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = idx.indrelid
                AND attribute.attnum = key.attnum
              WHERE key.ordinal <= idx.indnkeyatts
              ORDER BY key.ordinal
           ) = ARRAY['provider_boundary_id', 'dispatcher_id']
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_state
      JOIN pg_catalog.pg_index AS idx ON idx.indexrelid = constraint_state.conindid
     WHERE constraint_state.conrelid = participants_oid
       AND constraint_state.contype = 'p'
       AND constraint_state.convalidated
       AND NOT constraint_state.condeferrable
       AND NOT constraint_state.condeferred
       AND idx.indisunique
       AND idx.indisvalid
       AND idx.indisready
       AND idx.indpred IS NULL
       AND idx.indnatts = idx.indnkeyatts
       AND ARRAY(
             SELECT attribute.attname::text
               FROM pg_catalog.unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinal)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = idx.indrelid
                AND attribute.attnum = key.attnum
              WHERE key.ordinal <= idx.indnkeyatts
              ORDER BY key.ordinal
           ) = ARRAY['provider_boundary_id', 'dispatcher_id']
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_state
      JOIN pg_catalog.pg_index AS idx ON idx.indexrelid = constraint_state.conindid
     WHERE constraint_state.conrelid = participants_oid
       AND constraint_state.contype = 'u'
       AND constraint_state.convalidated
       AND NOT constraint_state.condeferrable
       AND NOT constraint_state.condeferred
       AND idx.indisunique
       AND idx.indisvalid
       AND idx.indisready
       AND idx.indpred IS NULL
       AND idx.indnatts = idx.indnkeyatts
       AND ARRAY(
             SELECT attribute.attname::text
               FROM pg_catalog.unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinal)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = idx.indrelid
                AND attribute.attnum = key.attnum
              WHERE key.ordinal <= idx.indnkeyatts
              ORDER BY key.ordinal
           ) = ARRAY['participant_key_blake3']
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_index AS idx
     WHERE idx.indrelid = dispatchers_oid
       AND idx.indisunique
       AND NOT ('dispatcher_id' = ANY(ARRAY(
             SELECT attribute.attname::text
               FROM pg_catalog.unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinal)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = idx.indrelid
                AND attribute.attnum = key.attnum
              WHERE key.ordinal <= idx.indnkeyatts
              ORDER BY key.ordinal
           )))
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_state
     WHERE constraint_state.conrelid = dispatchers_oid
       AND constraint_state.contype = 'x'
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_state
      JOIN pg_catalog.pg_index AS idx ON idx.indexrelid = constraint_state.conindid
     WHERE constraint_state.conrelid = dispatchers_oid
       AND constraint_state.contype = 'u'
       AND idx.indisunique
       AND idx.indisvalid
       AND idx.indisready
       AND idx.indisreplident
       AND idx.indpred IS NULL
       AND idx.indnatts = idx.indnkeyatts
       AND ARRAY(
             SELECT attribute.attname::text
               FROM pg_catalog.unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinal)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = idx.indrelid
                AND attribute.attnum = key.attnum
              WHERE key.ordinal <= idx.indnkeyatts
              ORDER BY key.ordinal
           ) = ARRAY['provider_boundary_id', 'dispatcher_id', 'lease_generation']
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_state
     WHERE constraint_state.conrelid = attempts_oid
       AND constraint_state.confrelid = dispatchers_oid
       AND constraint_state.contype = 'f'
       AND constraint_state.convalidated
       AND NOT constraint_state.condeferrable
       AND NOT constraint_state.condeferred
       AND ARRAY(
             SELECT attribute.attname::text
               FROM pg_catalog.unnest(constraint_state.conkey)
                    WITH ORDINALITY AS key(attnum, ordinal)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = constraint_state.conrelid
                AND attribute.attnum = key.attnum
              ORDER BY key.ordinal
           ) = ARRAY[
             'provider_boundary_id', 'dispatcher_id', 'dispatcher_lease_generation'
           ]
       AND ARRAY(
             SELECT attribute.attname::text
               FROM pg_catalog.unnest(constraint_state.confkey)
                    WITH ORDINALITY AS key(attnum, ordinal)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid = constraint_state.confrelid
                AND attribute.attnum = key.attnum
              ORDER BY key.ordinal
           ) = ARRAY['provider_boundary_id', 'dispatcher_id', 'lease_generation']
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.local_dispatcher_registration_record_v1(
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

  preimage := pg_catalog.convert_to('object-store-dispatch-dispatcher-registration-row-v1', 'UTF8')
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
  RETURN object_store_retention.local_complete_record_v1(preimage, 16777216);
END
$$;

CREATE FUNCTION object_store_retention.project_dispatch_dispatcher_registration_v1(
  stored object_store_retention.object_dispatch_dispatchers,
  result_code text
)
RETURNS object_store_retention.dispatch_dispatcher_registration_result_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE expected_record object_store_retention.local_canonical_record_v1;
BEGIN
  IF stored IS NULL OR result_code IS NULL OR result_code NOT IN ('CREATED', 'REPLAY')
     OR stored.schema_revision IS DISTINCT FROM 'object-store-dispatch-authority-schema-v1'
     OR stored.state IS DISTINCT FROM 1
     OR pg_catalog.num_nonnulls(
          stored.revocation_id,
          stored.revocation_requested_at_unix_ms,
          stored.revoked_at_unix_ms,
          stored.revocation_evidence_blake3
        ) <> 0 THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_REGISTRATION_STORED_STATE_INVALID'
      USING ERRCODE = '55000';
  END IF;

  expected_record := object_store_retention.local_dispatcher_registration_record_v1(
    stored.dispatcher_id,
    stored.lease_generation,
    stored.provider_boundary_id,
    stored.service_instance_id,
    stored.dispatcher_fence,
    stored.authority_revision,
    stored.allocation_revision,
    stored.allocation_fence,
    stored.provider_credential_revision,
    stored.acquired_at_unix_ms,
    stored.renewed_at_unix_ms,
    stored.expires_at_unix_ms,
    stored.state_changed_at_unix_ms
  );
  IF expected_record.canonical_bytes IS DISTINCT FROM stored.canonical_record_bytes
     OR expected_record.record_blake3 IS DISTINCT FROM stored.record_blake3 THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_REGISTRATION_STORED_RECORD_MISMATCH'
      USING ERRCODE = '55000';
  END IF;

  RETURN ROW(
    result_code,
    stored.dispatcher_id,
    stored.lease_generation,
    stored.provider_boundary_id,
    stored.service_instance_id,
    stored.dispatcher_fence,
    stored.state,
    stored.record_blake3
  )::object_store_retention.dispatch_dispatcher_registration_result_v1;
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_register_dispatcher_v1(
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
  -- key and never supplies either identity column itself.
  SELECT * INTO participant
    FROM object_store_retention.object_dispatch_dispatcher_participants AS enrolled
   WHERE enrolled.participant_key_blake3 =
         object_store_retention.local_blake3_v1(
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

-- CREATE OR REPLACE retains prior ACLs. Revoke explicitly before applying the least-authority
-- grants, and revoke every new helper even though the owner role's default privileges are already
-- expected to deny PUBLIC.
REVOKE ALL ON FUNCTION
  object_store_retention.assert_dispatch_dispatcher_registration_api_revision_v1(text),
  object_store_retention.assert_dispatch_maintenance_v1(),
  object_store_retention.assert_dispatch_dispatcher_identity_reader_v1(),
  object_store_retention.assert_dispatch_dispatcher_identity_objects_v1(),
  object_store_retention.local_dispatcher_registration_record_v1(
    text, object_store_retention.uint64, text, text,
    object_store_retention.uint64, object_store_retention.uint64, text,
    object_store_retention.uint64, text, bigint, bigint, bigint, bigint
  ),
  object_store_retention.project_dispatch_dispatcher_registration_v1(
    object_store_retention.object_dispatch_dispatchers, text
  )
FROM PUBLIC,
     object_dispatch_retention_runtime,
     object_dispatch_retention_maintenance,
     object_dispatch_retention_migrator;
REVOKE ALL ON FUNCTION
  object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(
    text, text, text, bytea
  ),
  object_store_retention.object_store_dispatch_register_dispatcher_v1(
    text, bytea, object_store_retention.uint64, text,
    object_store_retention.uint64, object_store_retention.uint64, text,
    object_store_retention.uint64, text, bigint, bigint, bigint, bigint
  )
FROM PUBLIC,
     object_dispatch_retention_runtime,
     object_dispatch_retention_maintenance,
     object_dispatch_retention_migrator;
REVOKE ALL ON FUNCTION
  object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(text)
FROM object_dispatch_retention_migrator, object_dispatch_retention_maintenance;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(
    text, text, text, bytea
  )
TO object_dispatch_retention_maintenance;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_register_dispatcher_v1(
    text, bytea, object_store_retention.uint64, text,
    object_store_retention.uint64, object_store_retention.uint64, text,
    object_store_retention.uint64, text, bigint, bigint, bigint, bigint
  )
TO object_dispatch_retention_runtime;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(text)
TO object_dispatch_retention_runtime;
REVOKE ALL ON TABLE object_store_retention.object_dispatch_dispatcher_participants
  FROM PUBLIC,
       object_dispatch_retention_runtime,
       object_dispatch_retention_maintenance,
       object_dispatch_retention_migrator;

COMMIT;

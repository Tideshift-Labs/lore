-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark retention provisioning authority.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TYPE object_store_retention.retention_provisioning_state_v1 AS (
  result_code text,
  schema_revision text,
  migration_blake3 bytea,
  install_revision object_store_retention.uint64,
  compact_sequence_high_water object_store_retention.uint64,
  compact_sequence_revision object_store_retention.uint64,
  pruned_through_compact_sequence object_store_retention.uint64,
  watermark_revision object_store_retention.uint64,
  global_counter_revision object_store_retention.uint64,
  installed_at_unix_ms bigint
);

CREATE FUNCTION object_store_retention.clock_unix_ms_v1()
RETURNS bigint
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
$$;

CREATE FUNCTION object_store_retention.assert_provisioning_api_revision_v1(api_revision text)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-retention-provisioning-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_serializable_write_v1()
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

CREATE FUNCTION object_store_retention.assert_retention_migrator_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_migrator' THEN
    RAISE EXCEPTION 'RETENTION_MIGRATOR_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_retention_reader_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_migrator'
     AND session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance' THEN
    RAISE EXCEPTION 'RETENTION_READER_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.project_retention_state_v1(result_code text)
RETURNS object_store_retention.retention_provisioning_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE watermark object_store_retention.object_dispatch_compact_prune_watermark%ROWTYPE;
DECLARE global_counter object_store_retention.object_dispatch_record_storage_counters%ROWTYPE;
BEGIN
  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  SELECT * INTO STRICT watermark
    FROM object_store_retention.object_dispatch_compact_prune_watermark
   WHERE singleton;
  SELECT * INTO STRICT global_counter
    FROM object_store_retention.object_dispatch_record_storage_counters
   WHERE scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1';
  RETURN ROW(
    result_code,
    schema_state.schema_revision,
    schema_state.migration_blake3,
    schema_state.install_revision,
    schema_state.compact_sequence_high_water,
    schema_state.compact_sequence_revision,
    watermark.pruned_through_compact_sequence,
    watermark.watermark_revision,
    global_counter.counter_revision,
    schema_state.installed_at_unix_ms
  )::object_store_retention.retention_provisioning_state_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_install_v1(
  api_revision text,
  expected_schema_revision text,
  expected_migration_blake3 bytea,
  expected_install_revision object_store_retention.uint64
)
RETURNS object_store_retention.retention_provisioning_state_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE installed_at bigint;
BEGIN
  PERFORM object_store_retention.assert_provisioning_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  PERFORM object_store_retention.assert_retention_migrator_v1();
  IF expected_schema_revision IS DISTINCT FROM 'object-store-retention-authority-schema-v1'
     OR expected_migration_blake3 IS DISTINCT FROM
        decode('f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd', 'hex')
     OR expected_install_revision IS NULL OR expected_install_revision = 0 THEN
    RAISE EXCEPTION 'RETENTION_INSTALL_CONTRACT_MISMATCH' USING ERRCODE = '22023';
  END IF;

  LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,
    object_store_retention.object_dispatch_full_record_ownership,
    object_store_retention.object_dispatch_record_storage_counters,
    object_store_retention.object_dispatch_compact_receipts,
    object_store_retention.object_dispatch_compact_prune_watermark
    IN EXCLUSIVE MODE;

  SELECT * INTO stored
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF FOUND THEN
    IF stored.schema_revision IS DISTINCT FROM expected_schema_revision
       OR stored.migration_blake3 IS DISTINCT FROM expected_migration_blake3
       OR stored.install_revision IS DISTINCT FROM expected_install_revision
       OR stored.compact_sequence_high_water <> 0
       OR stored.compact_sequence_revision <> 1
       OR (SELECT count(*) FROM object_store_retention.object_dispatch_full_record_ownership) <> 0
       OR (SELECT count(*) FROM object_store_retention.object_dispatch_compact_receipts) <> 0
       OR (SELECT count(*) FROM object_store_retention.object_dispatch_record_storage_counters) <> 1
       OR NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_record_storage_counters
          WHERE scope_kind = 1
            AND scope_id = 'object-store-full-to-compact-global-v1'
            AND full_record_rows = 0 AND full_record_bytes = 0
            AND compact_rows = 0 AND compact_bytes = 0
            AND counter_revision = 1
       )
       OR (SELECT count(*) FROM object_store_retention.object_dispatch_compact_prune_watermark) <> 1
       OR NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_compact_prune_watermark
          WHERE singleton AND pruned_through_compact_sequence = 0 AND watermark_revision = 1
            AND last_prune_fingerprint IS NULL AND last_compact_blake3 IS NULL
            AND last_pruned_at_unix_ms IS NULL AND last_backup_revision IS NULL
            AND last_backup_manifest_blake3 IS NULL
       ) THEN
      RAISE EXCEPTION 'RETENTION_INSTALL_REPLAY_CONFLICT' USING ERRCODE = '40001';
    END IF;
    RETURN object_store_retention.project_retention_state_v1('REPLAY');
  END IF;

  IF EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_full_record_ownership)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_record_storage_counters)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_compact_receipts)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_compact_prune_watermark) THEN
    RAISE EXCEPTION 'RETENTION_INSTALL_DIRTY_STATE' USING ERRCODE = '55000';
  END IF;

  installed_at := object_store_retention.clock_unix_ms_v1();
  INSERT INTO object_store_retention.object_dispatch_retention_schema_state (
    singleton, schema_revision, migration_blake3, install_revision,
    compact_sequence_high_water, compact_sequence_revision, installed_at_unix_ms
  ) VALUES (
    true, expected_schema_revision, expected_migration_blake3, expected_install_revision,
    0, 1, installed_at
  );
  INSERT INTO object_store_retention.object_dispatch_record_storage_counters (
    scope_kind, scope_id, full_record_rows, full_record_bytes,
    compact_rows, compact_bytes, counter_revision
  ) VALUES (1, 'object-store-full-to-compact-global-v1', 0, 0, 0, 0, 1);
  INSERT INTO object_store_retention.object_dispatch_compact_prune_watermark (
    singleton, pruned_through_compact_sequence, watermark_revision
  ) VALUES (true, 0, 1);
  RETURN object_store_retention.project_retention_state_v1('CREATED');
END
$$;

CREATE FUNCTION object_store_retention.object_store_retention_read_state_v1(api_revision text)
RETURNS object_store_retention.retention_provisioning_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM object_store_retention.assert_provisioning_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_retention_reader_v1();
  RETURN object_store_retention.project_retention_state_v1('READ');
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_retention_install_v1(
    text, text, bytea, object_store_retention.uint64
  )
TO object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_retention_read_state_v1(text)
TO object_dispatch_retention_migrator, object_dispatch_retention_maintenance;

COMMIT;

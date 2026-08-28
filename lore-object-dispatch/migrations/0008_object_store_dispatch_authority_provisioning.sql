-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark local dispatch-authority provisioning and readback.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

ALTER TABLE object_store_retention.object_dispatch_retention_schema_state
  ADD COLUMN local_authority_schema_revision text,
  ADD COLUMN local_authority_migration_blake3 object_store_retention.blake3_256,
  ADD COLUMN local_authority_install_revision object_store_retention.uint64,
  ADD COLUMN local_authority_installed_at_unix_ms bigint,
  ADD CONSTRAINT object_dispatch_retention_schema_state_local_authority_check CHECK (
    num_nonnulls(
      local_authority_schema_revision,
      local_authority_migration_blake3,
      local_authority_install_revision,
      local_authority_installed_at_unix_ms
    ) IN (0, 4) AND
    (
      local_authority_schema_revision IS NULL OR
      local_authority_schema_revision = 'object-store-dispatch-authority-schema-v1'
    ) AND
    (
      local_authority_install_revision IS NULL OR
      local_authority_install_revision > 0
    ) AND
    (
      local_authority_installed_at_unix_ms IS NULL OR
      local_authority_installed_at_unix_ms >= 0
    )
  );

CREATE TYPE object_store_retention.dispatch_authority_provisioning_state_v1 AS (
  result_code text,
  retention_schema_revision text,
  retention_migration_blake3 bytea,
  retention_install_revision object_store_retention.uint64,
  local_authority_schema_revision text,
  local_authority_migration_blake3 bytea,
  local_authority_install_revision object_store_retention.uint64,
  local_authority_installed_at_unix_ms bigint,
  request_rows object_store_retention.uint64,
  attempt_rows object_store_retention.uint64,
  spool_object_rows object_store_retention.uint64,
  quota_usage_rows object_store_retention.uint64,
  dispatcher_rows object_store_retention.uint64,
  payload_purge_rows object_store_retention.uint64,
  fetch_lease_rows object_store_retention.uint64
);

CREATE FUNCTION object_store_retention.assert_dispatch_authority_provisioning_api_revision_v1(
  api_revision text
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-dispatch-authority-provisioning-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_DISPATCH_AUTHORITY_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_dispatch_authority_catalog_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE catalog_manifest text;
DECLARE catalog_manifest_sha256 bytea;
DECLARE authority_owner_oid oid;
BEGIN
  SELECT role.oid INTO STRICT authority_owner_oid
    FROM pg_catalog.pg_roles AS role
   WHERE role.rolname = 'object_dispatch_retention_owner';

  SELECT pg_catalog.concat_ws(
    E'\n',
    'relations=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        namespace.nspname,
        relation.relname,
        relation.relkind,
        pg_catalog.pg_get_userbyid(relation.relowner),
        relation.relpersistence,
        relation.relreplident,
        relation.relrowsecurity,
        relation.relforcerowsecurity
      ) ORDER BY relation.relname)::text
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = 'object_store_retention'
         AND relation.relname IN (
           'object_dispatch_retention_schema_state',
           'object_dispatch_requests',
           'object_dispatch_attempts',
           'object_dispatch_spool_objects',
           'object_dispatch_quota_usage',
           'object_dispatch_dispatchers',
           'object_dispatch_payload_purges',
           'object_dispatch_fetch_leases'
         )
    ), '[]'),
    'columns=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        relation.relname,
        attribute.attnum,
        attribute.attname,
        pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
        attribute.attnotnull,
        attribute.attidentity,
        attribute.attgenerated,
        CASE WHEN attribute.attcollation = 0 THEN NULL
             ELSE pg_catalog.format('%I.%I', collation_namespace.nspname, collation_state.collname)
        END,
        pg_catalog.pg_get_expr(attribute_default.adbin, attribute_default.adrelid, false)
      ) ORDER BY relation.relname, attribute.attnum)::text
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
        LEFT JOIN pg_catalog.pg_attrdef AS attribute_default
          ON attribute_default.adrelid = relation.oid
         AND attribute_default.adnum = attribute.attnum
        LEFT JOIN pg_catalog.pg_collation AS collation_state
          ON collation_state.oid = attribute.attcollation
        LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
          ON collation_namespace.oid = collation_state.collnamespace
       WHERE namespace.nspname = 'object_store_retention'
         AND relation.relname IN (
           'object_dispatch_retention_schema_state',
           'object_dispatch_requests',
           'object_dispatch_attempts',
           'object_dispatch_spool_objects',
           'object_dispatch_quota_usage',
           'object_dispatch_dispatchers',
           'object_dispatch_payload_purges',
           'object_dispatch_fetch_leases'
         )
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped
    ), '[]'),
    'constraints=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        relation.relname,
        constraint_state.conname,
        constraint_state.contype,
        constraint_state.condeferrable,
        constraint_state.condeferred,
        constraint_state.convalidated,
        pg_catalog.pg_get_constraintdef(constraint_state.oid, false)
      ) ORDER BY relation.relname, constraint_state.conname)::text
        FROM pg_catalog.pg_constraint AS constraint_state
        JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_state.conrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = 'object_store_retention'
         AND relation.relname IN (
           'object_dispatch_retention_schema_state',
           'object_dispatch_requests',
           'object_dispatch_attempts',
           'object_dispatch_spool_objects',
           'object_dispatch_quota_usage',
           'object_dispatch_dispatchers',
           'object_dispatch_payload_purges',
           'object_dispatch_fetch_leases'
         )
    ), '[]'),
    'indexes=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        relation.relname,
        index_relation.relname,
        index_state.indisprimary,
        index_state.indisunique,
        index_state.indisexclusion,
        index_state.indimmediate,
        index_state.indisclustered,
        index_state.indisvalid,
        index_state.indisready,
        index_state.indislive,
        index_state.indcheckxmin,
        index_state.indisreplident,
        pg_catalog.pg_get_indexdef(index_state.indexrelid, 0, false)
      ) ORDER BY relation.relname, index_relation.relname)::text
        FROM pg_catalog.pg_index AS index_state
        JOIN pg_catalog.pg_class AS relation ON relation.oid = index_state.indrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_class AS index_relation ON index_relation.oid = index_state.indexrelid
       WHERE namespace.nspname = 'object_store_retention'
         AND relation.relname IN (
           'object_dispatch_retention_schema_state',
           'object_dispatch_requests',
           'object_dispatch_attempts',
           'object_dispatch_spool_objects',
           'object_dispatch_quota_usage',
           'object_dispatch_dispatchers',
           'object_dispatch_payload_purges',
           'object_dispatch_fetch_leases'
         )
    ), '[]'),
    'triggers=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        relation.relname,
        trigger.tgname,
        trigger.tgenabled,
        pg_catalog.pg_get_triggerdef(trigger.oid, false)
      ) ORDER BY relation.relname, trigger.tgname)::text
        FROM pg_catalog.pg_trigger AS trigger
        JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger.tgrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = 'object_store_retention'
         AND relation.relname IN (
           'object_dispatch_retention_schema_state',
           'object_dispatch_requests',
           'object_dispatch_attempts',
           'object_dispatch_spool_objects',
           'object_dispatch_quota_usage',
           'object_dispatch_dispatchers',
           'object_dispatch_payload_purges',
           'object_dispatch_fetch_leases'
         )
         AND NOT trigger.tgisinternal
    ), '[]'),
    'policies=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        relation.relname,
        policy.polname,
        policy.polcmd,
        policy.polpermissive,
        policy.polroles::text,
        pg_catalog.pg_get_expr(policy.polqual, policy.polrelid, false),
        pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid, false)
      ) ORDER BY relation.relname, policy.polname)::text
        FROM pg_catalog.pg_policy AS policy
        JOIN pg_catalog.pg_class AS relation ON relation.oid = policy.polrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = 'object_store_retention'
         AND relation.relname IN (
           'object_dispatch_retention_schema_state',
           'object_dispatch_requests',
           'object_dispatch_attempts',
           'object_dispatch_spool_objects',
           'object_dispatch_quota_usage',
           'object_dispatch_dispatchers',
           'object_dispatch_payload_purges',
           'object_dispatch_fetch_leases'
         )
    ), '[]'),
    'functions=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        procedure.proname,
        pg_catalog.pg_get_function_identity_arguments(procedure.oid),
        pg_catalog.pg_get_function_result(procedure.oid),
        procedure.prokind,
        procedure.provolatile,
        procedure.prosecdef,
        procedure.proleakproof,
        procedure.proisstrict,
        procedure.proparallel,
        procedure.proconfig,
        pg_catalog.pg_get_userbyid(procedure.proowner),
        CASE
          WHEN procedure.proname = 'assert_dispatch_authority_catalog_v1' THEN
            pg_catalog.regexp_replace(
              pg_catalog.pg_get_functiondef(procedure.oid),
              $catalog$pg_catalog\.decode\('[0-9a-f]{64}', 'hex'\)$catalog$,
              $catalog$pg_catalog.decode('<CATALOG_MANIFEST_SHA256>', 'hex')$catalog$,
              'g'
            )
          ELSE pg_catalog.pg_get_functiondef(procedure.oid)
        END
      ) ORDER BY procedure.proname, pg_catalog.pg_get_function_identity_arguments(procedure.oid))::text
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
       WHERE namespace.nspname = 'object_store_retention'
         AND procedure.proname IN (
           'assert_dispatch_authority_provisioning_api_revision_v1',
           'assert_dispatch_authority_catalog_v1',
           'project_dispatch_authority_state_v1',
           'object_store_dispatch_authority_install_v1',
           'object_store_dispatch_authority_read_state_v1'
         )
    ), '[]'),
    'function_acls=' || COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
        procedure.proname,
        pg_catalog.pg_get_function_identity_arguments(procedure.oid),
        CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'
             ELSE pg_catalog.pg_get_userbyid(privilege.grantee)
        END,
        privilege.privilege_type,
        privilege.is_grantable
      ) ORDER BY procedure.proname, pg_catalog.pg_get_function_identity_arguments(procedure.oid),
                 privilege.grantee, privilege.privilege_type)::text
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
        ) AS privilege
       WHERE namespace.nspname = 'object_store_retention'
         AND procedure.proname IN (
           'assert_dispatch_authority_provisioning_api_revision_v1',
           'assert_dispatch_authority_catalog_v1',
           'project_dispatch_authority_state_v1',
           'object_store_dispatch_authority_install_v1',
           'object_store_dispatch_authority_read_state_v1'
         )
    ), '[]')
  ) INTO catalog_manifest;
  catalog_manifest_sha256 := pg_catalog.sha256(pg_catalog.convert_to(catalog_manifest, 'UTF8'));
  IF catalog_manifest_sha256 IS DISTINCT FROM
     pg_catalog.decode('317145373c7f1929f9d85077d05660a6373e7407da3dd1ce88b64936ce7972c8', 'hex') THEN
    RAISE EXCEPTION 'DISPATCH_AUTHORITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'object_store_retention'
       AND relation.relname IN (
         'object_dispatch_retention_schema_state',
         'object_dispatch_requests',
         'object_dispatch_attempts',
         'object_dispatch_spool_objects',
         'object_dispatch_quota_usage',
         'object_dispatch_dispatchers',
         'object_dispatch_payload_purges',
         'object_dispatch_fetch_leases'
       )
       AND (relation.relrowsecurity OR relation.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'DISPATCH_AUTHORITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
      ) AS privilege
     WHERE namespace.nspname = 'object_store_retention'
       AND relation.relname IN (
         'object_dispatch_retention_schema_state',
         'object_dispatch_requests',
         'object_dispatch_attempts',
         'object_dispatch_spool_objects',
         'object_dispatch_quota_usage',
         'object_dispatch_dispatchers',
         'object_dispatch_payload_purges',
         'object_dispatch_fetch_leases'
       )
       AND privilege.grantee <> authority_owner_oid
  ) OR EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
      JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
      CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege
     WHERE namespace.nspname = 'object_store_retention'
       AND relation.relname IN (
         'object_dispatch_retention_schema_state',
         'object_dispatch_requests',
         'object_dispatch_attempts',
         'object_dispatch_spool_objects',
         'object_dispatch_quota_usage',
         'object_dispatch_dispatchers',
         'object_dispatch_payload_purges',
         'object_dispatch_fetch_leases'
       )
       AND attribute.attnum > 0
       AND NOT attribute.attisdropped
       AND privilege.grantee <> authority_owner_oid
  ) OR EXISTS (
    SELECT 1
      FROM (VALUES
        ('object_dispatch_retention_runtime'),
        ('object_dispatch_retention_maintenance'),
        ('object_dispatch_retention_migrator')
      ) AS denied_role(role_name)
      CROSS JOIN (VALUES
        ('object_dispatch_requests'),
        ('object_dispatch_attempts'),
        ('object_dispatch_spool_objects'),
        ('object_dispatch_quota_usage'),
        ('object_dispatch_dispatchers'),
        ('object_dispatch_payload_purges'),
        ('object_dispatch_fetch_leases')
      ) AS authority_table(table_name)
     WHERE pg_catalog.has_table_privilege(
       denied_role.role_name,
       pg_catalog.format('object_store_retention.%I', authority_table.table_name),
       'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
     )
  ) THEN
    RAISE EXCEPTION 'DISPATCH_AUTHORITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.project_dispatch_authority_state_v1(result_code text)
RETURNS object_store_retention.dispatch_authority_provisioning_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
BEGIN
  PERFORM object_store_retention.assert_dispatch_authority_catalog_v1();
  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF num_nonnulls(
       schema_state.local_authority_schema_revision,
       schema_state.local_authority_migration_blake3,
       schema_state.local_authority_install_revision,
       schema_state.local_authority_installed_at_unix_ms
     ) <> 4 THEN
    RAISE EXCEPTION 'DISPATCH_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  RETURN ROW(
    result_code,
    schema_state.schema_revision,
    schema_state.migration_blake3,
    schema_state.install_revision,
    schema_state.local_authority_schema_revision,
    schema_state.local_authority_migration_blake3,
    schema_state.local_authority_install_revision,
    schema_state.local_authority_installed_at_unix_ms,
    (SELECT count(*) FROM object_store_retention.object_dispatch_requests),
    (SELECT count(*) FROM object_store_retention.object_dispatch_attempts),
    (SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects),
    (SELECT count(*) FROM object_store_retention.object_dispatch_quota_usage),
    (SELECT count(*) FROM object_store_retention.object_dispatch_dispatchers),
    (SELECT count(*) FROM object_store_retention.object_dispatch_payload_purges),
    (SELECT count(*) FROM object_store_retention.object_dispatch_fetch_leases)
  )::object_store_retention.dispatch_authority_provisioning_state_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_authority_install_v1(
  api_revision text,
  expected_schema_revision text,
  expected_migration_blake3 bytea,
  expected_install_revision object_store_retention.uint64
)
RETURNS object_store_retention.dispatch_authority_provisioning_state_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE installed_at bigint;
BEGIN
  PERFORM object_store_retention.assert_retention_migrator_v1();
  PERFORM object_store_retention.assert_dispatch_authority_provisioning_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF expected_schema_revision IS DISTINCT FROM 'object-store-dispatch-authority-schema-v1'
     OR expected_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff', 'hex')
     OR expected_install_revision IS NULL OR expected_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_AUTHORITY_INSTALL_CONTRACT_MISMATCH' USING ERRCODE = '22023';
  END IF;

  LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,
    object_store_retention.object_dispatch_requests,
    object_store_retention.object_dispatch_dispatchers,
    object_store_retention.object_dispatch_attempts,
    object_store_retention.object_dispatch_spool_objects,
    object_store_retention.object_dispatch_quota_usage,
    object_store_retention.object_dispatch_payload_purges,
    object_store_retention.object_dispatch_fetch_leases
    IN EXCLUSIVE MODE;
  PERFORM object_store_retention.assert_dispatch_authority_catalog_v1();

  SELECT * INTO STRICT stored
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF stored.local_authority_schema_revision IS NOT NULL THEN
    IF stored.local_authority_schema_revision IS DISTINCT FROM expected_schema_revision
       OR stored.local_authority_migration_blake3 IS DISTINCT FROM expected_migration_blake3
       OR stored.local_authority_install_revision IS DISTINCT FROM expected_install_revision
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_requests)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_attempts)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_spool_objects)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_quota_usage)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_dispatchers)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_payload_purges)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_fetch_leases) THEN
      RAISE EXCEPTION 'DISPATCH_AUTHORITY_INSTALL_REPLAY_CONFLICT' USING ERRCODE = '40001';
    END IF;
    RETURN object_store_retention.project_dispatch_authority_state_v1('REPLAY');
  END IF;

  IF num_nonnulls(
       stored.local_authority_migration_blake3,
       stored.local_authority_install_revision,
       stored.local_authority_installed_at_unix_ms
     ) <> 0
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_requests)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_attempts)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_spool_objects)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_quota_usage)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_dispatchers)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_payload_purges)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_fetch_leases) THEN
    RAISE EXCEPTION 'DISPATCH_AUTHORITY_INSTALL_DIRTY_STATE' USING ERRCODE = '55000';
  END IF;

  installed_at := object_store_retention.clock_unix_ms_v1();
  UPDATE object_store_retention.object_dispatch_retention_schema_state
     SET local_authority_schema_revision = expected_schema_revision,
         local_authority_migration_blake3 = expected_migration_blake3,
         local_authority_install_revision = expected_install_revision,
         local_authority_installed_at_unix_ms = installed_at
   WHERE singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DISPATCH_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  RETURN object_store_retention.project_dispatch_authority_state_v1('CREATED');
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_authority_read_state_v1(
  api_revision text
)
RETURNS object_store_retention.dispatch_authority_provisioning_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM object_store_retention.assert_retention_reader_v1();
  PERFORM object_store_retention.assert_dispatch_authority_provisioning_api_revision_v1(api_revision);
  RETURN object_store_retention.project_dispatch_authority_state_v1('READ');
END
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM
  object_dispatch_retention_runtime;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_authority_install_v1(
    text, text, bytea, object_store_retention.uint64
  )
TO object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_authority_read_state_v1(text)
TO object_dispatch_retention_migrator, object_dispatch_retention_maintenance;

REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

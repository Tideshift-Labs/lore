-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-114 CD-3 per-participant dispatcher identity (CR-033 D8): provisioning and readback for the
-- 0018 schema edge, following the established 0010-edge-then-0011-provisioning pattern.
-- Runtime code never installs this artifact.
--
-- This migration also settles review caveat N2, which CD-1 handed to CD-3 on 2026-08-30 after
-- proving live that on a fully installed cell neither dispatch-layer readback works: 0011 revokes
-- the 0008 pair outright (42501), and 0011's own catalog manifest covers every function in the
-- schema with no name filter, so 0012 through 0017 make the put-reservation readback and install
-- entrypoint fail closed (55000).
--
-- The decision, and the shape of the readback below, is that a whole-schema catalog manifest
-- **cannot** live inside the schema it measures. Such a manifest necessarily covers the next
-- migration's objects, so every successor invalidates it -- including the successor that exists to
-- replace it, which then needs its own successor. 0011 already had to mask its own digest literal
-- out of its own manifest with a regexp_replace to close the first-order case of that recursion.
-- Adding a fourth whole-schema manifest here would reproduce the defect N2 names, one migration
-- later, and would also buy nothing: the manifest it would "repair" (0011's index-shape coverage,
-- which 0018 changes) is already unreachable at full chain depth, so nothing is calling it to fail.
--
-- The whole-schema manifest is therefore the out-of-band Rust attester's job
-- (`cell_schema_install.rs`), which runs outside the schema, is re-pinned deliberately when the
-- schema grows, and is the only place an *added* object -- a planted SECURITY DEFINER function, say
-- -- can be detected at all. A name-filtered in-database manifest could never detect that, so
-- narrowing 0011's manifest rather than retiring it would have traded away the property that made
-- it worth having.
--
-- What an in-database readback *can* do, and what this one does, is assert the specific objects it
-- names. `assert_dispatch_dispatcher_identity_objects_v1` below is growth-tolerant by construction:
-- it names one table and asks three questions about the constraints on it. Migration 0020 may add
-- fifty functions without disturbing it.
--
-- The second half of N2's answer is who may call it. Every readback in the chain so far is gated on
-- `assert_retention_reader_v1`, which admits only the migrator and maintenance roles, so the
-- dispatch runtime -- which authenticates as `object_dispatch_retention_runtime` -- has no readable
-- authority procedure at all, and CD-1's Rust attester is migrator-only by deliberate narrowing.
-- CD-3 needs a runtime-reachable readiness signal and was told it must not be the attester. This is
-- it: `object_store_dispatch_dispatcher_identity_read_state_v1` is granted to the runtime role and
-- reports every installed layer's identity tuple.
--
-- It is honest about what it proves. An installed-migration digest does not attest the live
-- PostgreSQL catalog, so this readback answers "is every layer of the chain installed, at the exact
-- artifact identity this cell expects, and is D8's participant constraint the one in force" -- not
-- "has the catalog drifted". Catalog integrity stays with the out-of-band attester. It also does
-- not count rows: a readiness probe on the request path must not scan the evidence tables, and the
-- row counts 0011's projection returns are for the migrator-facing install report.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

ALTER TABLE object_store_retention.object_dispatch_retention_schema_state
  ADD COLUMN dispatcher_identity_schema_revision text,
  ADD COLUMN dispatcher_identity_migration_blake3 object_store_retention.blake3_256,
  ADD COLUMN dispatcher_identity_install_revision object_store_retention.uint64,
  ADD COLUMN dispatcher_identity_installed_at_unix_ms bigint,
  ADD CONSTRAINT object_dispatch_retention_schema_state_dispatcher_identity_ck CHECK (
    (
      pg_catalog.num_nonnulls(
        dispatcher_identity_schema_revision,
        dispatcher_identity_migration_blake3,
        dispatcher_identity_install_revision,
        dispatcher_identity_installed_at_unix_ms
      ) = 0
    ) OR (
      pg_catalog.num_nonnulls(
        dispatcher_identity_schema_revision,
        dispatcher_identity_migration_blake3,
        dispatcher_identity_install_revision,
        dispatcher_identity_installed_at_unix_ms
      ) = 4 AND
      dispatcher_identity_schema_revision =
        'object-store-dispatch-dispatcher-identity-schema-v1' AND
      dispatcher_identity_install_revision > 0 AND
      dispatcher_identity_installed_at_unix_ms >= 0
    )
  );

CREATE TYPE object_store_retention.dispatch_dispatcher_identity_state_v1 AS (
  result_code text,
  retention_schema_revision text,
  retention_migration_blake3 bytea,
  retention_install_revision object_store_retention.uint64,
  retention_installed_at_unix_ms bigint,
  local_authority_schema_revision text,
  local_authority_migration_blake3 bytea,
  local_authority_install_revision object_store_retention.uint64,
  local_authority_installed_at_unix_ms bigint,
  put_reservation_schema_revision text,
  put_reservation_migration_blake3 bytea,
  put_reservation_install_revision object_store_retention.uint64,
  put_reservation_installed_at_unix_ms bigint,
  dispatcher_identity_schema_revision text,
  dispatcher_identity_migration_blake3 bytea,
  dispatcher_identity_install_revision object_store_retention.uint64,
  dispatcher_identity_installed_at_unix_ms bigint
);

CREATE FUNCTION object_store_retention.assert_dispatch_dispatcher_identity_api_revision_v1(
  api_revision text
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM
       'object-store-dispatch-dispatcher-identity-provisioning-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_DISPATCH_DISPATCHER_IDENTITY_API_REVISION'
      USING ERRCODE = '22023';
  END IF;
END
$$;

-- Who may read the cell's installed-layer identity.
--
-- Deliberately wider than `assert_retention_reader_v1`, which admits the migrator and maintenance
-- roles only. The dispatch runtime is added because it is the role that needs a readiness signal
-- and is the one role every existing readback excludes. This grants no data authority: the
-- projection below reads one singleton row of installed-artifact identity, writes nothing, and
-- touches no request, attempt, spool, quota, dispatcher, purge or lease row.
CREATE FUNCTION object_store_retention.assert_dispatch_dispatcher_identity_reader_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_migrator'
     AND session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance'
     AND session_user IS DISTINCT FROM 'object_dispatch_retention_runtime' THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_READER_AUTHORIZATION_REQUIRED'
      USING ERRCODE = '42501';
  END IF;
END
$$;

-- The growth-tolerant object assertion: four questions about one table, two over `pg_index` and
-- two over `pg_constraint`.
--
-- The first requires D8's per-participant ACTIVE-uniqueness index to be present in exactly its
-- intended shape, INCLUDE columns included in "exactly": D8's index carries none, and an index that
-- grew one is not the index this migration created.
--
-- The second is the load-bearing prohibition, and it is stated as a property rather than as a list
-- of forbidden index names: **every unique index on this table must carry `dispatcher_id` among its
-- key columns.** Uniqueness on this table that does not constrain the participant is uniqueness
-- across participants, which is the single-active-dispatcher model D8 rejected. The property form
-- is what caught 0007's PRIMARY KEY (provider_boundary_id, lease_generation) during 0018's first
-- live run, which D8's own finding had not named -- an enumeration of the one index D8 did name
-- would have passed that database.
--
-- The third covers the one spelling the second cannot see, because an exclusion constraint enforces
-- uniqueness without being `indisunique`.
--
-- The fourth is a *positive* requirement rather than a prohibition, and it exists because the second
-- is satisfied vacuously by a table with no unique index at all. 0018 drops 0007's primary key and
-- hands the table's identity to 0007's retained
-- UNIQUE (provider_boundary_id, dispatcher_id, lease_generation), naming that index as the replica
-- identity. `relreplident` then reads `'i'`, and the attester's manifest pins that letter -- but the
-- letter does not name which index, and PostgreSQL treats `'i'` with the index gone as `NOTHING`.
-- So dropping that one constraint would take the table's identity, the attempts foreign key's
-- target, and its replica identity together, while every digest and every prohibition above stayed
-- satisfied. The fourth check requires it: present, unique, valid, non-partial, no INCLUDE columns,
-- exactly those three key columns in that order, and carrying the replica identity.
--
-- All four are asked by shape, not by name, because a rename is not the drift that matters. Every
-- one of these failures is silent without this assert: writes keep succeeding until the second
-- participant registers.
--
-- One rendering is pinned rather than derived: `pg_get_expr` over the partial-index predicate,
-- measured on PostgreSQL 16. That is the same version dependence the out-of-band attester's
-- twelve-section manifest carries, and it takes the same discipline -- a major-version move is a
-- scheduled re-measure with its own evidence, never a relaxed check.
CREATE FUNCTION object_store_retention.assert_dispatch_dispatcher_identity_objects_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE dispatchers_oid oid;
BEGIN
  SELECT relation.oid INTO STRICT dispatchers_oid
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
   WHERE namespace.nspname = 'object_store_retention'
     AND relation.relname = 'object_dispatch_dispatchers'
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

  -- `indkey` spans key **and** INCLUDE columns; `indnkeyatts` is where the key ends. Without the
  -- ordinal bound below,
  --   CREATE UNIQUE INDEX ... (provider_boundary_id, lease_generation) INCLUDE (dispatcher_id)
  -- satisfies "mentions dispatcher_id" while enforcing exactly the cross-participant uniqueness the
  -- dropped primary key enforced. An INCLUDE column is payload, not part of the uniqueness, so it
  -- must not count. Found by review, not by the first live run: the planted-drift case used the
  -- plain two-column form, which this check caught either way.
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

  -- An exclusion constraint enforces uniqueness without being `indisunique`, so the check above
  -- cannot see one. Migration 0007 declares none on this table and none is expected, so the rule
  -- here is the stricter and simpler one: no exclusion constraint at all. A future layer that wants
  -- one must amend this assert deliberately rather than slip past it.
  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_state
     WHERE constraint_state.conrelid = dispatchers_oid
       AND constraint_state.contype = 'x'
  ) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
  END IF;

  -- The table's identity must exist, and must be the replica identity. Every check above is a
  -- prohibition, and a table with no unique index at all satisfies all of them; `relreplident` would
  -- still read `'i'` in the attester's manifest while resolving to nothing. This is the positive
  -- half, and it is what makes dropping 0007's retained three-column UNIQUE fail closed instead of
  -- silently removing the attempts foreign key's target along with the replica identity.
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
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  -- The `INTO STRICT` above is the only source of these, and it means the dispatchers table is
  -- absent or duplicated. That is catalog drift, and reporting it as such matters: without this
  -- handler it escapes to the projection's own handler and is reported as UNAVAILABLE, which names
  -- an uninstalled layer rather than a broken one.
  RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.project_dispatch_dispatcher_identity_state_v1(
  result_code text
)
RETURNS object_store_retention.dispatch_dispatcher_identity_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
BEGIN
  PERFORM object_store_retention.assert_dispatch_dispatcher_identity_objects_v1();
  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF schema_state.schema_revision IS DISTINCT FROM
       'object-store-retention-authority-schema-v1'
     OR schema_state.migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd', 'hex')
     OR schema_state.install_revision IS NULL OR schema_state.install_revision = 0
     OR schema_state.local_authority_schema_revision IS DISTINCT FROM
        'object-store-dispatch-authority-schema-v1'
     OR schema_state.local_authority_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff', 'hex')
     OR schema_state.local_authority_install_revision IS NULL
     OR schema_state.local_authority_install_revision = 0
     OR schema_state.local_authority_installed_at_unix_ms IS NULL
     OR schema_state.put_reservation_schema_revision IS DISTINCT FROM
        'object-store-dispatch-put-reservation-schema-v1'
     OR schema_state.put_reservation_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67', 'hex')
     OR schema_state.put_reservation_install_revision IS NULL
     OR schema_state.put_reservation_install_revision = 0
     OR schema_state.put_reservation_installed_at_unix_ms IS NULL
     OR schema_state.dispatcher_identity_schema_revision IS DISTINCT FROM
        'object-store-dispatch-dispatcher-identity-schema-v1'
     OR schema_state.dispatcher_identity_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('a7d54d94d0fa5035872eb9b3426cbbe6471bcf9ae34ed41877542f050e1aaad9', 'hex')
     OR schema_state.dispatcher_identity_install_revision IS NULL
     OR schema_state.dispatcher_identity_install_revision = 0
     OR schema_state.dispatcher_identity_installed_at_unix_ms IS NULL THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  RETURN ROW(
    result_code,
    schema_state.schema_revision,
    schema_state.migration_blake3,
    schema_state.install_revision,
    schema_state.installed_at_unix_ms,
    schema_state.local_authority_schema_revision,
    schema_state.local_authority_migration_blake3,
    schema_state.local_authority_install_revision,
    schema_state.local_authority_installed_at_unix_ms,
    schema_state.put_reservation_schema_revision,
    schema_state.put_reservation_migration_blake3,
    schema_state.put_reservation_install_revision,
    schema_state.put_reservation_installed_at_unix_ms,
    schema_state.dispatcher_identity_schema_revision,
    schema_state.dispatcher_identity_migration_blake3,
    schema_state.dispatcher_identity_install_revision,
    schema_state.dispatcher_identity_installed_at_unix_ms
  )::object_store_retention.dispatch_dispatcher_identity_state_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(
  api_revision text,
  expected_schema_revision text,
  expected_migration_blake3 bytea,
  expected_install_revision object_store_retention.uint64
)
RETURNS object_store_retention.dispatch_dispatcher_identity_state_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE installed_at bigint;
BEGIN
  PERFORM object_store_retention.assert_retention_migrator_v1();
  PERFORM object_store_retention.assert_dispatch_dispatcher_identity_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF expected_schema_revision IS DISTINCT FROM
       'object-store-dispatch-dispatcher-identity-schema-v1'
     OR expected_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('a7d54d94d0fa5035872eb9b3426cbbe6471bcf9ae34ed41877542f050e1aaad9', 'hex')
     OR expected_install_revision IS NULL OR expected_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_INSTALL_CONTRACT_MISMATCH'
      USING ERRCODE = '22023';
  END IF;

  LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,
    object_store_retention.object_dispatch_dispatchers,
    object_store_retention.object_dispatch_attempts
    IN EXCLUSIVE MODE;
  PERFORM object_store_retention.assert_dispatch_dispatcher_identity_objects_v1();

  SELECT * INTO STRICT stored
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF stored.put_reservation_schema_revision IS DISTINCT FROM
       'object-store-dispatch-put-reservation-schema-v1'
     OR stored.put_reservation_install_revision IS NULL
     OR stored.put_reservation_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;

  IF stored.dispatcher_identity_schema_revision IS NOT NULL THEN
    IF stored.dispatcher_identity_schema_revision IS DISTINCT FROM expected_schema_revision
       OR stored.dispatcher_identity_migration_blake3 IS DISTINCT FROM expected_migration_blake3
       OR stored.dispatcher_identity_install_revision IS DISTINCT FROM expected_install_revision
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_dispatchers)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_attempts) THEN
      RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_INSTALL_REPLAY_CONFLICT'
        USING ERRCODE = '40001';
    END IF;
    RETURN object_store_retention.project_dispatch_dispatcher_identity_state_v1('REPLAY');
  END IF;

  IF pg_catalog.num_nonnulls(
       stored.dispatcher_identity_migration_blake3,
       stored.dispatcher_identity_install_revision,
       stored.dispatcher_identity_installed_at_unix_ms
     ) <> 0
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_dispatchers)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_attempts) THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_INSTALL_DIRTY_STATE' USING ERRCODE = '55000';
  END IF;

  installed_at := object_store_retention.clock_unix_ms_v1();
  UPDATE object_store_retention.object_dispatch_retention_schema_state
     SET dispatcher_identity_schema_revision = expected_schema_revision,
         dispatcher_identity_migration_blake3 = expected_migration_blake3,
         dispatcher_identity_install_revision = expected_install_revision,
         dispatcher_identity_installed_at_unix_ms = installed_at
   WHERE singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  RETURN object_store_retention.project_dispatch_dispatcher_identity_state_v1('CREATED');
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(
  api_revision text
)
RETURNS object_store_retention.dispatch_dispatcher_identity_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM object_store_retention.assert_dispatch_dispatcher_identity_reader_v1();
  PERFORM object_store_retention.assert_dispatch_dispatcher_identity_api_revision_v1(api_revision);
  RETURN object_store_retention.project_dispatch_dispatcher_identity_state_v1('READ');
END
$$;

-- New functions carry EXECUTE for PUBLIC by default, so revoke that before granting.
--
-- Deliberately NOT `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM
-- object_dispatch_retention_runtime`, which is what 0011 issues. 0011 could, because 0013, 0015 and
-- 0017 grant the runtime mutations afterwards. This migration is after all three, so the same
-- blanket revoke here would strip `object_store_dispatch_reserve_put_v1`,
-- `object_store_dispatch_put_upload_progress_v1` and `object_store_dispatch_put_spool_ready_v1`
-- from the only role permitted to call them, and the cell would fail closed on every mutation.
REVOKE ALL ON FUNCTION
  object_store_retention.assert_dispatch_dispatcher_identity_api_revision_v1(text),
  object_store_retention.assert_dispatch_dispatcher_identity_reader_v1(),
  object_store_retention.assert_dispatch_dispatcher_identity_objects_v1(),
  object_store_retention.project_dispatch_dispatcher_identity_state_v1(text),
  object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(
    text, text, bytea, object_store_retention.uint64
  ),
  object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(
    text, text, bytea, object_store_retention.uint64
  )
TO object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(text)
TO object_dispatch_retention_migrator,
   object_dispatch_retention_maintenance,
   object_dispatch_retention_runtime;
REVOKE ALL ON TABLE object_store_retention.object_dispatch_retention_schema_state
  FROM PUBLIC;
REVOKE ALL ON TABLE object_store_retention.object_dispatch_retention_schema_state FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

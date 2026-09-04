-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-114 CD-8 cell-scale retention: provisioning, the bounded prune, and the backlog probe.
--
-- CR-033 D5 recorded an unpruned evidence table as a fail-closed production activation
-- prerequisite. This migration is the prune path that clears it. The decision it implements --
-- that retention migrations 0004 through 0006 are replaced for a cell rather than installed as-is
-- or resized -- is argued once, in `src/cell_retention.rs`. Read it there; this file states only
-- the contract.
--
-- Three properties are worth stating where the SQL is, because losing any one of them turns a
-- retention pass into data loss.
--
-- **The replay floor is a separate clause from the retention window, and it is the safety one.**
-- A closed request row is the authority for an idempotent replay of that logical request. Deleting
-- it while the same identity could still be admitted would turn a client's retry into a fresh
-- first-seen request and a second provider send. So a candidate must satisfy BOTH
-- `closure_committed_at_unix_ms <= horizon` (the operator's retention window) AND
-- `allocation_hard_expiry_unix_ms <= horizon` (past which admission refuses the identity outright).
-- An operator can shorten the retention window; the operator cannot shorten the replay floor.
--
-- **A request whose payload evidence is not terminal is withheld, and being withheld is reported
-- rather than hidden.** A spool object not in `lifecycle_state = 3` still names a file on the
-- shared spool; a payload purge not in `purge_state = 2` has not completed; a fetch lease in
-- `state = 1` is still open. Deleting the request row under any of those would orphan a file, a
-- purge intent, or a live reader. Past the retention horizon none of the three is transient, which
-- is why `object_store_dispatch_cell_retention_backlog_v1` counts them separately and the caller
-- treats a nonzero blocked count as a stall rather than as a drained table.
--
-- **A provider charge grant is pruned on the budget configuration's clock, never on the request's.**
-- It looks like a child of the request and it is not: `object_dispatch_provider_charge_grants` has
-- no foreign key to `object_dispatch_requests`, and 0022's
-- `object_store_dispatch_charge_provider_attempt_v1` never reads a request row. Its grant row is
-- the sole oracle for `ATTEMPT_ALREADY_CHARGED`, so deleting one on the request's admission clock
-- would let the same `(boundary, request, attempt, ordinal)` charge a second time and debit the
-- budget twice. The one condition under which that is impossible is the configuration's own hard
-- expiry: 0022 refuses on `database_now >= configuration.hard_expires_at_unix_ms` *before* it
-- reaches the grant EXISTS check, so once a configuration is expired no charge under it can succeed
-- and its grants are consulted by nothing. The grant sweep below is therefore independent of the
-- request candidate set and keyed on that, with the operator's retention window applied on top.
--
-- The consequence, stated rather than left to be found: grants under a configuration that has not
-- yet expired are retained however many there are. That is bounded by budget-configuration rotation
-- cadence, which is WP-121's, not by anything this migration can decide.
--
-- **The phase list is literal text, in the candidate query and in 0023's partial index predicate.**
-- The planner uses a partial index only when it can prove the query predicate implies the index
-- predicate, and only literals let it prove that. `phase = ANY($n)` returns the same rows and plans
-- a sequential scan of the largest table in the schema. See the `lore-postgres` skill's "A partial
-- index is unreachable from a bound parameter under a generic plan".
--
-- The bounds below are the OUTER ones. `CellRetentionSettings` in Rust carries a tighter reviewed
-- range and rejects a bad value at configuration parse. These exist so that a caller which somehow
-- bypassed that check still cannot ask for an unbounded delete or a zero-length retention window;
-- they are the floor of last resort, not the reviewed policy.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

ALTER TABLE object_store_retention.object_dispatch_retention_schema_state
  ADD COLUMN cell_retention_schema_revision text,
  ADD COLUMN cell_retention_migration_blake3 object_store_retention.blake3_256,
  ADD COLUMN cell_retention_install_revision object_store_retention.uint64,
  ADD COLUMN cell_retention_installed_at_unix_ms bigint,
  ADD CONSTRAINT object_dispatch_retention_schema_state_cell_retention_ck CHECK (
    pg_catalog.num_nonnulls(
      cell_retention_schema_revision,
      cell_retention_migration_blake3,
      cell_retention_install_revision,
      cell_retention_installed_at_unix_ms
    ) = 0 OR (
      pg_catalog.num_nonnulls(
        cell_retention_schema_revision,
        cell_retention_migration_blake3,
        cell_retention_install_revision,
        cell_retention_installed_at_unix_ms
      ) = 4 AND
      cell_retention_schema_revision = 'object-store-dispatch-cell-retention-schema-v1' AND
      cell_retention_install_revision > 0 AND
      cell_retention_installed_at_unix_ms >= 0
    )
  );

CREATE TYPE object_store_retention.dispatch_cell_retention_state_v1 AS (
  result_code text,
  schema_revision text,
  migration_blake3 bytea,
  install_revision object_store_retention.uint64,
  installed_at_unix_ms bigint
);

CREATE TYPE object_store_retention.dispatch_cell_retention_prune_v1 AS (
  result_code text,
  examined bigint,
  pruned_requests bigint,
  pruned_attempts bigint,
  pruned_spool_objects bigint,
  pruned_payload_purges bigint,
  pruned_fetch_leases bigint,
  pruned_charge_grants bigint,
  horizon_unix_ms bigint,
  database_now_unix_ms bigint
);

CREATE TYPE object_store_retention.dispatch_cell_retention_backlog_v1 AS (
  result_code text,
  prunable_backlog bigint,
  blocked_backlog bigint,
  grant_backlog bigint,
  horizon_unix_ms bigint,
  database_now_unix_ms bigint
);

CREATE FUNCTION object_store_retention.assert_dispatch_cell_retention_api_revision_v1(
  api_revision text
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-dispatch-cell-retention-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_DISPATCH_CELL_RETENTION_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

-- The retention pass runs on the replica's existing dispatch-runtime pool, so it authenticates as
-- the runtime role rather than the maintenance role 0004-0006 used. That is a deliberate widening
-- and it is bounded on purpose: this role gains no ability to delete anything a correct retention
-- pass would not delete anyway, because the horizon, the replay floor, the withhold clauses and the
-- batch ceiling are all computed inside these SECURITY DEFINER procedures from the database's own
-- clock, and the tables themselves remain unwritable by every service role. 0019 set the precedent
-- for a runtime-callable authority procedure.
CREATE FUNCTION object_store_retention.assert_dispatch_cell_retention_runtime_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_runtime' THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
END
$$;

-- Outer hard bounds, shared by the prune's batch and the backlog probe's limit. One minute is short
-- enough for a staging cell to observe a pass working and long enough that no live request's
-- closure is inside it; thirty days is well past any window in which a closed cell request is still
-- interesting. The row ceiling is 1024 rather than the reviewed batch ceiling of 1000 because the
-- probe deliberately counts one past a full batch, so that "exactly a batch remaining" and "more
-- than a batch remaining" are distinguishable. The prune adds its own 1000 check below; this
-- function's only job is that neither number can be unbounded.
CREATE FUNCTION object_store_retention.assert_dispatch_cell_retention_bounds_v1(
  requested_retention_ms bigint,
  requested_rows integer
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF requested_retention_ms IS NULL
     OR requested_retention_ms < 60000
     OR requested_retention_ms > 2592000000 THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_WINDOW_INVALID' USING ERRCODE = '22023';
  END IF;
  IF requested_rows IS NULL OR requested_rows < 1 OR requested_rows > 1024 THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_BATCH_INVALID' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_dispatch_cell_retention_installed_v1()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
BEGIN
  SELECT * INTO STRICT state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF state.cell_retention_schema_revision IS DISTINCT FROM
       'object-store-dispatch-cell-retention-schema-v1'
     OR state.cell_retention_install_revision IS NULL
     OR state.cell_retention_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_NOT_INSTALLED' USING ERRCODE = '55000';
  END IF;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_cell_retention_install_v1(
  api_revision text,
  expected_schema_revision text,
  expected_migration_blake3 bytea,
  expected_install_revision object_store_retention.uint64
)
RETURNS object_store_retention.dispatch_cell_retention_state_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE installed_at bigint;
BEGIN
  PERFORM object_store_retention.assert_retention_migrator_v1();
  PERFORM object_store_retention.assert_dispatch_cell_retention_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF expected_schema_revision IS DISTINCT FROM 'object-store-dispatch-cell-retention-schema-v1'
     OR expected_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('cef47bfe8afd932b66f0c7c6856aa10b27532841e6da90208f8ee753a700542a', 'hex')
     OR expected_install_revision IS NULL OR expected_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_INSTALL_IDENTITY_INVALID' USING ERRCODE = '22023';
  END IF;

  LOCK TABLE object_store_retention.object_dispatch_retention_schema_state IN EXCLUSIVE MODE;
  SELECT * INTO STRICT stored
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  -- The prune reads request, attempt, spool, purge, lease and charge-grant rows, so every layer
  -- that creates one of those must already be installed. The budget limiter is the last of them
  -- and is checked as the chain's tip.
  IF stored.budget_limiter_schema_revision IS DISTINCT FROM
       'object-store-dispatch-budget-limiter-schema-v1'
     OR stored.budget_limiter_install_revision IS NULL
     OR stored.budget_limiter_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  IF stored.cell_retention_schema_revision IS NOT NULL THEN
    IF stored.cell_retention_schema_revision IS DISTINCT FROM expected_schema_revision
       OR stored.cell_retention_migration_blake3 IS DISTINCT FROM expected_migration_blake3
       OR stored.cell_retention_install_revision IS DISTINCT FROM expected_install_revision THEN
      RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_INSTALL_REPLAY_CONFLICT' USING ERRCODE = '40001';
    END IF;
    RETURN ROW('REPLAY', stored.cell_retention_schema_revision,
      stored.cell_retention_migration_blake3, stored.cell_retention_install_revision,
      stored.cell_retention_installed_at_unix_ms)::
      object_store_retention.dispatch_cell_retention_state_v1;
  END IF;
  IF pg_catalog.num_nonnulls(
       stored.cell_retention_migration_blake3,
       stored.cell_retention_install_revision,
       stored.cell_retention_installed_at_unix_ms
     ) <> 0 THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_INSTALL_DIRTY_STATE' USING ERRCODE = '55000';
  END IF;
  installed_at := object_store_retention.clock_unix_ms_v1();
  UPDATE object_store_retention.object_dispatch_retention_schema_state SET
    cell_retention_schema_revision = expected_schema_revision,
    cell_retention_migration_blake3 = expected_migration_blake3,
    cell_retention_install_revision = expected_install_revision,
    cell_retention_installed_at_unix_ms = installed_at
   WHERE singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  RETURN ROW('CREATED', expected_schema_revision, expected_migration_blake3,
    expected_install_revision, installed_at)::
    object_store_retention.dispatch_cell_retention_state_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_cell_retention_read_state_v1(
  api_revision text
)
RETURNS object_store_retention.dispatch_cell_retention_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
BEGIN
  PERFORM object_store_retention.assert_dispatch_cell_retention_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_cell_retention_api_revision_v1(api_revision);
  SELECT * INTO STRICT state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF state.cell_retention_schema_revision IS NULL THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_NOT_INSTALLED' USING ERRCODE = '55000';
  END IF;
  RETURN ROW('READ', state.cell_retention_schema_revision, state.cell_retention_migration_blake3,
    state.cell_retention_install_revision, state.cell_retention_installed_at_unix_ms)::
    object_store_retention.dispatch_cell_retention_state_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

-- One bounded batch. Parent and children are deleted in a single statement: referential-integrity
-- triggers fire after the whole statement, so the request rows and every row referencing them go
-- together and no intermediate state is ever visible to the constraint.
CREATE FUNCTION object_store_retention.object_store_dispatch_cell_retention_prune_v1(
  api_revision text,
  requested_retention_ms bigint,
  requested_batch integer
)
RETURNS object_store_retention.dispatch_cell_retention_prune_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE database_now_unix_ms bigint;
DECLARE horizon bigint;
DECLARE outcome object_store_retention.dispatch_cell_retention_prune_v1;
BEGIN
  PERFORM object_store_retention.assert_dispatch_cell_retention_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_cell_retention_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  PERFORM object_store_retention.assert_dispatch_cell_retention_bounds_v1(
    requested_retention_ms, requested_batch
  );
  IF requested_batch > 1000 THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_BATCH_INVALID' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_retention.assert_dispatch_cell_retention_installed_v1();

  -- No special case for a horizon that lands before the epoch. Every timestamp compared against it
  -- is nonnegative, so a negative horizon selects nothing and the pass reports an honest empty
  -- result with the horizon it actually used. An `IF horizon < 0` branch returning a horizon of 0
  -- was written and removed during review: it invented a number the pass did not use, and it
  -- disagreed with the client's own check that the reported horizon is exactly one window behind
  -- the reported clock.
  database_now_unix_ms := object_store_retention.clock_unix_ms_v1();
  horizon := database_now_unix_ms - requested_retention_ms;

  WITH candidate AS (
    SELECT request.provider_boundary_id,
           request.logical_request_id,
           request.attempt_id
      FROM object_store_retention.object_dispatch_requests AS request
     WHERE request.phase IN (5, 6, 7)
       AND request.closure_committed_at_unix_ms <= horizon
       AND request.allocation_hard_expiry_unix_ms <= horizon
       AND NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_spool_objects AS spool
          WHERE spool.logical_request_id = request.logical_request_id
            AND spool.attempt_id = request.attempt_id
            AND spool.lifecycle_state <> 3
       )
       AND NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_payload_purges AS purge
          WHERE purge.logical_request_id = request.logical_request_id
            AND purge.attempt_id = request.attempt_id
            AND purge.purge_state <> 2
       )
       AND NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_fetch_leases AS lease
          WHERE lease.logical_request_id = request.logical_request_id
            AND lease.attempt_id = request.attempt_id
            AND lease.state = 1
       )
     ORDER BY request.closure_committed_at_unix_ms,
              request.logical_request_id,
              request.attempt_id
     LIMIT requested_batch
     FOR UPDATE OF request SKIP LOCKED
  ),
  deleted_leases AS (
    DELETE FROM object_store_retention.object_dispatch_fetch_leases AS lease
     USING candidate
     WHERE lease.logical_request_id = candidate.logical_request_id
       AND lease.attempt_id = candidate.attempt_id
    RETURNING 1
  ),
  deleted_purges AS (
    DELETE FROM object_store_retention.object_dispatch_payload_purges AS purge
     USING candidate
     WHERE purge.logical_request_id = candidate.logical_request_id
       AND purge.attempt_id = candidate.attempt_id
    RETURNING 1
  ),
  deleted_spool AS (
    DELETE FROM object_store_retention.object_dispatch_spool_objects AS spool
     USING candidate
     WHERE spool.logical_request_id = candidate.logical_request_id
       AND spool.attempt_id = candidate.attempt_id
    RETURNING 1
  ),
  deleted_attempts AS (
    DELETE FROM object_store_retention.object_dispatch_attempts AS attempt
     USING candidate
     WHERE attempt.logical_request_id = candidate.logical_request_id
       AND attempt.attempt_id = candidate.attempt_id
    RETURNING 1
  ),
  -- Independent of `candidate` on purpose: see the header. A grant is safe to delete only once its
  -- budget configuration is past its own hard expiry, because that is the check 0022 makes before
  -- it consults the grant as an idempotency oracle.
  expired_grant AS (
    SELECT grant_row.grant_id
      FROM object_store_retention.object_dispatch_provider_charge_grants AS grant_row
      JOIN object_store_retention.object_dispatch_budget_configurations AS configuration
        ON configuration.provider_boundary_id = grant_row.provider_boundary_id
       AND configuration.allocation_revision = grant_row.allocation_revision
       AND configuration.allocation_fence = grant_row.allocation_fence
     WHERE configuration.hard_expires_at_unix_ms <= horizon
       AND grant_row.grant_committed_at_unix_ms <= horizon
     ORDER BY grant_row.grant_committed_at_unix_ms, grant_row.grant_id
     LIMIT requested_batch
     FOR UPDATE OF grant_row SKIP LOCKED
  ),
  deleted_grants AS (
    DELETE FROM object_store_retention.object_dispatch_provider_charge_grants AS grant_row
     USING expired_grant
     WHERE grant_row.grant_id = expired_grant.grant_id
    RETURNING 1
  ),
  deleted_requests AS (
    DELETE FROM object_store_retention.object_dispatch_requests AS request
     USING candidate
     WHERE request.logical_request_id = candidate.logical_request_id
       AND request.attempt_id = candidate.attempt_id
    RETURNING 1
  )
  SELECT 'APPLIED',
         (SELECT pg_catalog.count(*) FROM candidate),
         (SELECT pg_catalog.count(*) FROM deleted_requests),
         (SELECT pg_catalog.count(*) FROM deleted_attempts),
         (SELECT pg_catalog.count(*) FROM deleted_spool),
         (SELECT pg_catalog.count(*) FROM deleted_purges),
         (SELECT pg_catalog.count(*) FROM deleted_leases),
         (SELECT pg_catalog.count(*) FROM deleted_grants),
         horizon,
         database_now_unix_ms
    INTO STRICT outcome;

  -- Every candidate was locked by this transaction and every delete keyed on exactly that set, so
  -- a request row surviving its own pass is not a lost race. It is the schema disagreeing with this
  -- procedure about what a candidate is, which must not commit.
  IF outcome.pruned_requests IS DISTINCT FROM outcome.examined THEN
    RAISE EXCEPTION 'DISPATCH_CELL_RETENTION_PRUNE_INCOMPLETE' USING ERRCODE = '55000';
  END IF;
  RETURN outcome;
END
$$;

-- Three counts, and the pass report is not one of them. A pass that removed nothing is progress
-- only when there is nothing left to remove, and -- less obviously -- a pass that removed a full
-- batch is not progress when more than a batch is still waiting. A facet keyed on the pass report
-- reports green over exactly the unbounded growth CD-8 exists to stop, in both directions.
--
-- `prunable_backlog` counts what a further pass could take. `blocked_backlog` counts rows past the
-- horizon that the withhold clauses hold back; past the retention horizon an unpurged spool object,
-- an incomplete purge or an open lease is not transient, so each is counted rather than excused.
-- `grant_backlog` counts charge grants whose configuration has expired and which the sweep has not
-- yet taken. All three are capped at `probe_limit`, which the caller sets one above its batch, so
-- "exactly a batch remaining" and "more than a batch remaining" stay distinguishable.
CREATE FUNCTION object_store_retention.object_store_dispatch_cell_retention_backlog_v1(
  api_revision text,
  requested_retention_ms bigint,
  probe_limit integer
)
RETURNS object_store_retention.dispatch_cell_retention_backlog_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE database_now_unix_ms bigint;
DECLARE horizon bigint;
DECLARE prunable bigint;
DECLARE blocked bigint;
DECLARE expired_grants bigint;
BEGIN
  PERFORM object_store_retention.assert_dispatch_cell_retention_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_cell_retention_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_dispatch_cell_retention_bounds_v1(
    requested_retention_ms, probe_limit
  );
  PERFORM object_store_retention.assert_dispatch_cell_retention_installed_v1();

  -- Same reasoning as the prune: no invented horizon for a clock inside one window of the epoch.
  database_now_unix_ms := object_store_retention.clock_unix_ms_v1();
  horizon := database_now_unix_ms - requested_retention_ms;

  SELECT pg_catalog.count(*) INTO STRICT prunable FROM (
    SELECT 1
      FROM object_store_retention.object_dispatch_requests AS request
     WHERE request.phase IN (5, 6, 7)
       AND request.closure_committed_at_unix_ms <= horizon
       AND request.allocation_hard_expiry_unix_ms <= horizon
       AND NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_spool_objects AS spool
          WHERE spool.logical_request_id = request.logical_request_id
            AND spool.attempt_id = request.attempt_id
            AND spool.lifecycle_state <> 3
       )
       AND NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_payload_purges AS purge
          WHERE purge.logical_request_id = request.logical_request_id
            AND purge.attempt_id = request.attempt_id
            AND purge.purge_state <> 2
       )
       AND NOT EXISTS (
         SELECT 1 FROM object_store_retention.object_dispatch_fetch_leases AS lease
          WHERE lease.logical_request_id = request.logical_request_id
            AND lease.attempt_id = request.attempt_id
            AND lease.state = 1
       )
     LIMIT probe_limit
  ) AS bounded_prunable;

  SELECT pg_catalog.count(*) INTO STRICT blocked FROM (
    SELECT 1
      FROM object_store_retention.object_dispatch_requests AS request
     WHERE request.phase IN (5, 6, 7)
       AND request.closure_committed_at_unix_ms <= horizon
       AND request.allocation_hard_expiry_unix_ms <= horizon
       AND (
         EXISTS (
           SELECT 1 FROM object_store_retention.object_dispatch_spool_objects AS spool
            WHERE spool.logical_request_id = request.logical_request_id
              AND spool.attempt_id = request.attempt_id
              AND spool.lifecycle_state <> 3
         )
         OR EXISTS (
           SELECT 1 FROM object_store_retention.object_dispatch_payload_purges AS purge
            WHERE purge.logical_request_id = request.logical_request_id
              AND purge.attempt_id = request.attempt_id
              AND purge.purge_state <> 2
         )
         OR EXISTS (
           SELECT 1 FROM object_store_retention.object_dispatch_fetch_leases AS lease
            WHERE lease.logical_request_id = request.logical_request_id
              AND lease.attempt_id = request.attempt_id
              AND lease.state = 1
         )
       )
     LIMIT probe_limit
  ) AS bounded_blocked;

  SELECT pg_catalog.count(*) INTO STRICT expired_grants FROM (
    SELECT 1
      FROM object_store_retention.object_dispatch_provider_charge_grants AS grant_row
      JOIN object_store_retention.object_dispatch_budget_configurations AS configuration
        ON configuration.provider_boundary_id = grant_row.provider_boundary_id
       AND configuration.allocation_revision = grant_row.allocation_revision
       AND configuration.allocation_fence = grant_row.allocation_fence
     WHERE configuration.hard_expires_at_unix_ms <= horizon
       AND grant_row.grant_committed_at_unix_ms <= horizon
     LIMIT probe_limit
  ) AS bounded_grants;

  RETURN ROW('READ', prunable, blocked, expired_grants, horizon, database_now_unix_ms)::
    object_store_retention.dispatch_cell_retention_backlog_v1;
END
$$;

REVOKE ALL ON FUNCTION object_store_retention.object_store_dispatch_cell_retention_install_v1(
  text, text, bytea, object_store_retention.uint64
) FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_cell_retention_install_v1(
  text, text, bytea, object_store_retention.uint64
) TO object_dispatch_retention_migrator;
REVOKE ALL ON FUNCTION
  object_store_retention.object_store_dispatch_cell_retention_read_state_v1(text)
  FROM PUBLIC, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_cell_retention_read_state_v1(text)
  TO object_dispatch_retention_runtime;
REVOKE ALL ON FUNCTION object_store_retention.object_store_dispatch_cell_retention_prune_v1(
  text, bigint, integer
) FROM PUBLIC, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_cell_retention_prune_v1(
  text, bigint, integer
) TO object_dispatch_retention_runtime;
REVOKE ALL ON FUNCTION object_store_retention.object_store_dispatch_cell_retention_backlog_v1(
  text, bigint, integer
) FROM PUBLIC, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_cell_retention_backlog_v1(
  text, bigint, integer
) TO object_dispatch_retention_runtime;

COMMIT;

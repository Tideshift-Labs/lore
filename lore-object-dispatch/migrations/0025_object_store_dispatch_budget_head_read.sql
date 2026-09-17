-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- CR-034 runtime budget pin re-read: the runtime role's one door onto the published head.
--
-- The charge function refuses a stale pin with `BUDGET_PIN_REJECTED`. Before this migration a
-- writer had no way to learn what the head became, because `object_dispatch_current_budget_configuration`
-- is revoked from every role including the runtime one (0022, the REVOKE ALL block at its tail).
-- Publishing revision N+1 therefore fenced every already-running writer until it was restarted.
-- This function is the narrowest read that closes that gap.
--
-- Three properties are worth stating where the SQL is.
--
-- **It reuses `dispatch_budget_publication_result_v1` rather than declaring a composite of its
-- own.** A new composite type would add `pg_type` and `pg_attribute` rows and move the `types` and
-- `columns` sections of the pinned cell catalog manifest as well. Reusing the existing type keeps
-- the catalog delta to `functions` and `function_acls`, so "which sections moved" stays a two-section
-- check on this migration rather than a four-section one.
--
-- **It is deliberately shallower than the charge.** It calls neither
-- `assert_dispatch_budget_resolved_v1` nor the `hard_expires_at_unix_ms` comparison, so it can hand
-- back a head that is published but not yet resolvable, or one that has already expired. That is not
-- a correctness break: the charge that follows re-checks both and returns `CONFIGURATION_UNRESOLVED`,
-- a typed decisive refusal. The cost is one wasted charge round-trip. The alternative was to widen
-- this function's reads past the head table, which would end the two-column least-privilege argument
-- below, or to duplicate a predicate that already has one authoritative home.
--
-- **It discloses nothing new.** It reads one row of one table and returns two columns,
-- `allocation_revision` and `allocation_fence` -- values the runtime role already puts on the wire
-- on every charge. It does not touch `object_dispatch_budget_configurations`, `_dimensions`,
-- `_caps`, `_bucket_state` or `_provider_charge_grants`, so the other five tables in 0022's revoke
-- block stay unreachable, and in particular `hard_expires_at_unix_ms`, capacity and refill rates
-- stay unreadable. It is STABLE: no write, no LOCK, no FOR UPDATE, no advisory lock.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE FUNCTION object_store_retention.object_store_dispatch_read_current_budget_pin_v1(
  api_revision text,
  provider_boundary_id text
)
RETURNS object_store_retention.dispatch_budget_publication_result_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE current_config object_store_retention.object_dispatch_current_budget_configuration%ROWTYPE;
BEGIN
  PERFORM object_store_retention.assert_dispatch_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_budget_limiter_api_revision_v1(api_revision);
  SELECT * INTO current_config
    FROM object_store_retention.object_dispatch_current_budget_configuration AS candidate
   WHERE candidate.provider_boundary_id =
         object_store_dispatch_read_current_budget_pin_v1.provider_boundary_id;
  IF NOT FOUND THEN
    RETURN ROW('CONFIGURATION_UNRESOLVED', NULL, NULL)::
      object_store_retention.dispatch_budget_publication_result_v1;
  END IF;
  RETURN ROW('HEAD', current_config.allocation_revision, current_config.allocation_fence)::
    object_store_retention.dispatch_budget_publication_result_v1;
END
$$;

-- SECURITY DEFINER without the runtime assert above would be reachable by the maintenance and
-- migrator roles too. The assert is the authority check; this revoke is belt to that braces, and
-- matches how 0022 grants the charge function.
REVOKE ALL ON FUNCTION
  object_store_retention.object_store_dispatch_read_current_budget_pin_v1(text, text)
  FROM PUBLIC, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_read_current_budget_pin_v1(text, text)
  TO object_dispatch_retention_runtime;

COMMIT;

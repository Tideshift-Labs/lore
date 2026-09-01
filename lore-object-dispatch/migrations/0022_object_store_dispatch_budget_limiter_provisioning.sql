-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-114 CD-4 shared cell-local provider limiter: provisioning, publication, and charge CAS.
--
-- The only admission clock below is clock_unix_ms_v1(), which uses PostgreSQL
-- clock_timestamp(). Publication is maintenance-only. Charging is runtime-only. This migration
-- publishes no configuration and keeps the limiter source-dark until a caller supplies a complete,
-- internally consistent, cell-scoped publication.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

ALTER TABLE object_store_retention.object_dispatch_retention_schema_state
  ADD COLUMN budget_limiter_schema_revision text,
  ADD COLUMN budget_limiter_migration_blake3 object_store_retention.blake3_256,
  ADD COLUMN budget_limiter_install_revision object_store_retention.uint64,
  ADD COLUMN budget_limiter_installed_at_unix_ms bigint,
  ADD CONSTRAINT object_dispatch_retention_schema_state_budget_limiter_ck CHECK (
    pg_catalog.num_nonnulls(
      budget_limiter_schema_revision,
      budget_limiter_migration_blake3,
      budget_limiter_install_revision,
      budget_limiter_installed_at_unix_ms
    ) = 0 OR (
      pg_catalog.num_nonnulls(
        budget_limiter_schema_revision,
        budget_limiter_migration_blake3,
        budget_limiter_install_revision,
        budget_limiter_installed_at_unix_ms
      ) = 4 AND
      budget_limiter_schema_revision = 'object-store-dispatch-budget-limiter-schema-v1' AND
      budget_limiter_install_revision > 0 AND
      budget_limiter_installed_at_unix_ms >= 0
    )
  );

CREATE TYPE object_store_retention.dispatch_budget_publication_result_v1 AS (
  result_code text,
  allocation_revision text,
  allocation_fence object_store_retention.uint64
);

CREATE TYPE object_store_retention.dispatch_provider_charge_result_v1 AS (
  result_code text,
  allocation_revision text,
  allocation_fence object_store_retention.uint64,
  grant_id uuid,
  traffic_class smallint,
  attempt_class smallint,
  charged_units object_store_retention.uint64,
  logical_request_id uuid,
  attempt_id uuid,
  attempt_ordinal integer,
  database_now_unix_ms bigint
);

CREATE TYPE object_store_retention.dispatch_budget_limiter_state_v1 AS (
  result_code text,
  schema_revision text,
  migration_blake3 bytea,
  install_revision object_store_retention.uint64,
  installed_at_unix_ms bigint
);

CREATE FUNCTION object_store_retention.assert_dispatch_budget_limiter_api_revision_v1(
  api_revision text
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF api_revision IS DISTINCT FROM 'object-store-dispatch-budget-limiter-v1' THEN
    RAISE EXCEPTION 'UNSUPPORTED_DISPATCH_BUDGET_LIMITER_API_REVISION' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.assert_dispatch_budget_revision_v1(revision text)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE encoded bytea;
DECLARE index integer;
DECLARE value integer;
BEGIN
  IF revision IS NULL THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_REVISION_INVALID' USING ERRCODE = '22023';
  END IF;
  encoded := pg_catalog.convert_to(revision, 'UTF8');
  IF pg_catalog.octet_length(encoded) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_REVISION_INVALID' USING ERRCODE = '22023';
  END IF;
  FOR index IN 0..pg_catalog.octet_length(encoded) - 1 LOOP
    value := pg_catalog.get_byte(encoded, index);
    IF index = 0 THEN
      IF NOT (value BETWEEN 48 AND 57 OR value BETWEEN 65 AND 90 OR value BETWEEN 97 AND 122) THEN
        RAISE EXCEPTION 'DISPATCH_BUDGET_REVISION_INVALID' USING ERRCODE = '22023';
      END IF;
    ELSIF NOT (
      value BETWEEN 48 AND 57 OR value BETWEEN 65 AND 90 OR value BETWEEN 97 AND 122 OR
      value IN (45, 46, 95)
    ) THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_REVISION_INVALID' USING ERRCODE = '22023';
    END IF;
  END LOOP;
END
$$;

CREATE FUNCTION object_store_retention.assert_dispatch_budget_json_v1(
  dimensions jsonb,
  cap_budgets jsonb,
  disposition smallint,
  cache_implementation_package_path text,
  cache_implementation_revision text,
  cache_proof_digest bytea,
  cache_effect_vector_digest bytea
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE dimension jsonb;
DECLARE cap jsonb;
DECLARE shared_capacity numeric;
DECLARE shared_refill numeric;
DECLARE shared_interval numeric;
DECLARE list_capacity numeric;
DECLARE list_refill numeric;
DECLARE list_interval numeric;
BEGIN
  IF pg_catalog.jsonb_typeof(dimensions) IS DISTINCT FROM 'array'
     OR pg_catalog.jsonb_array_length(dimensions) = 0 THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_DIMENSIONS_INVALID' USING ERRCODE = '22023';
  END IF;
  IF pg_catalog.jsonb_typeof(cap_budgets) IS DISTINCT FROM 'array'
     OR pg_catalog.jsonb_array_length(cap_budgets) <> 7 THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_CAPS_INVALID' USING ERRCODE = '22023';
  END IF;

  IF disposition = 1 THEN
    IF pg_catalog.num_nonnulls(
      cache_implementation_package_path,
      cache_implementation_revision,
      cache_proof_digest,
      cache_effect_vector_digest
    ) <> 0 THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_NOT_REQUIRED_CACHE_FIELDS_PRESENT'
        USING ERRCODE = '22023';
    END IF;
  ELSIF disposition = 2 THEN
    IF pg_catalog.num_nonnulls(
      cache_implementation_package_path,
      cache_implementation_revision,
      cache_proof_digest,
      cache_effect_vector_digest
    ) <> 4 THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_REQUIRED_CACHE_FIELDS_INCOMPLETE'
        USING ERRCODE = '22023';
    END IF;
  ELSE
    RAISE EXCEPTION 'DISPATCH_BUDGET_DISPOSITION_INVALID' USING ERRCODE = '22023';
  END IF;

  FOR dimension IN SELECT value FROM pg_catalog.jsonb_array_elements(dimensions) LOOP
    IF pg_catalog.jsonb_typeof(dimension) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(dimension)) NOT IN (7, 8)
       OR NOT dimension ?& ARRAY[
         'dimensionId', 'effectiveBound', 'measuredLoad', 'targetDemand',
         'failureReserve', 'preCacheHeadroom', 'finalBudget'
       ] THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_DIMENSION_SHAPE_INVALID' USING ERRCODE = '22023';
    END IF;
    IF disposition = 1 AND dimension ? 'cacheEffect' THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_NOT_REQUIRED_CACHE_EFFECT_PRESENT'
        USING ERRCODE = '22023';
    END IF;
    IF disposition = 2 AND NOT dimension ? 'cacheEffect' THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_REQUIRED_CACHE_EFFECT_MISSING'
        USING ERRCODE = '22023';
    END IF;
    BEGIN
      IF pg_catalog.octet_length(dimension->>'dimensionId') NOT BETWEEN 1 AND 128
         OR (dimension->>'effectiveBound')::numeric NOT BETWEEN 0 AND 18446744073709551615
         OR (dimension->>'measuredLoad')::numeric NOT BETWEEN 0 AND 18446744073709551615
         OR (dimension->>'targetDemand')::numeric NOT BETWEEN 0 AND 18446744073709551615
         OR (dimension->>'failureReserve')::numeric NOT BETWEEN 0 AND 18446744073709551615
         OR (dimension->>'finalBudget')::numeric NOT BETWEEN 0 AND 18446744073709551615
         OR (dimension->>'preCacheHeadroom')::numeric IS DISTINCT FROM
            (dimension->>'effectiveBound')::numeric -
            (dimension->>'measuredLoad')::numeric -
            (dimension->>'targetDemand')::numeric -
            (dimension->>'failureReserve')::numeric THEN
        RAISE EXCEPTION 'DISPATCH_BUDGET_HEADROOM_IDENTITY_INVALID' USING ERRCODE = '22023';
      END IF;
      IF disposition = 1 AND (
        (dimension->>'preCacheHeadroom')::numeric < 0 OR
        (dimension->>'finalBudget')::numeric IS DISTINCT FROM
          (dimension->>'preCacheHeadroom')::numeric
      ) THEN
        RAISE EXCEPTION 'DISPATCH_BUDGET_NOT_REQUIRED_VECTOR_INVALID' USING ERRCODE = '22023';
      END IF;
      IF disposition = 2 AND (
        (dimension->>'cacheEffect')::numeric NOT BETWEEN 0 AND 18446744073709551615 OR
        (dimension->>'finalBudget')::numeric IS DISTINCT FROM
          (dimension->>'preCacheHeadroom')::numeric + (dimension->>'cacheEffect')::numeric
      ) THEN
        RAISE EXCEPTION 'DISPATCH_BUDGET_REQUIRED_VECTOR_INVALID' USING ERRCODE = '22023';
      END IF;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_DIMENSION_VALUE_INVALID' USING ERRCODE = '22023';
    END;
  END LOOP;
  IF disposition = 2 AND NOT EXISTS (
    SELECT 1 FROM pg_catalog.jsonb_array_elements(dimensions) AS entry
     WHERE (entry->>'preCacheHeadroom')::numeric < 0
  ) THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_REQUIRED_CACHE_UNNECESSARY' USING ERRCODE = '22023';
  END IF;
  IF (SELECT pg_catalog.count(DISTINCT value->>'dimensionId')
        FROM pg_catalog.jsonb_array_elements(dimensions)) <>
     pg_catalog.jsonb_array_length(dimensions) THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_DIMENSION_DUPLICATE' USING ERRCODE = '22023';
  END IF;

  FOR cap IN SELECT value FROM pg_catalog.jsonb_array_elements(cap_budgets) LOOP
    IF pg_catalog.jsonb_typeof(cap) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(cap)) <> 4
       OR NOT cap ?& ARRAY['capClass', 'capacityUnits', 'refillUnits', 'refillIntervalMs'] THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_CAP_SHAPE_INVALID' USING ERRCODE = '22023';
    END IF;
    BEGIN
      IF (cap->>'capClass')::integer NOT BETWEEN 1 AND 7
         OR (cap->>'capacityUnits')::numeric NOT BETWEEN 1 AND 18446744073709551615
         OR (cap->>'refillUnits')::numeric NOT BETWEEN 1 AND 18446744073709551615
         OR (cap->>'refillIntervalMs')::numeric NOT BETWEEN 1 AND 18446744073709551615
         OR (cap->>'capacityUnits')::numeric * (cap->>'refillIntervalMs')::numeric >
            18446744073709551615 THEN
        RAISE EXCEPTION 'DISPATCH_BUDGET_CAP_VALUE_INVALID' USING ERRCODE = '22023';
      END IF;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_CAP_VALUE_INVALID' USING ERRCODE = '22023';
    END;
  END LOOP;
  IF (SELECT pg_catalog.count(DISTINCT (value->>'capClass')::integer)
        FROM pg_catalog.jsonb_array_elements(cap_budgets)) <> 7 THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_CAP_DUPLICATE' USING ERRCODE = '22023';
  END IF;

  SELECT (value->>'capacityUnits')::numeric, (value->>'refillUnits')::numeric,
         (value->>'refillIntervalMs')::numeric
    INTO STRICT shared_capacity, shared_refill, shared_interval
    FROM pg_catalog.jsonb_array_elements(cap_budgets) WHERE (value->>'capClass')::integer = 1;
  SELECT (value->>'capacityUnits')::numeric, (value->>'refillUnits')::numeric,
         (value->>'refillIntervalMs')::numeric
    INTO STRICT list_capacity, list_refill, list_interval
    FROM pg_catalog.jsonb_array_elements(cap_budgets) WHERE (value->>'capClass')::integer = 7;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.jsonb_array_elements(cap_budgets) AS entry
     WHERE (entry->>'capClass')::integer <> 1 AND (
       (entry->>'capacityUnits')::numeric >= shared_capacity OR
       (entry->>'refillUnits')::numeric * shared_interval >=
         shared_refill * (entry->>'refillIntervalMs')::numeric
     )
  ) THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_CLASS_CAP_NOT_SUBORDINATE' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.jsonb_array_elements(cap_budgets) AS entry
     WHERE (entry->>'capClass')::integer BETWEEN 2 AND 6 AND (
       list_capacity >= (entry->>'capacityUnits')::numeric OR
       list_refill * (entry->>'refillIntervalMs')::numeric >=
         (entry->>'refillUnits')::numeric * list_interval
     )
  ) THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_LIST_CAP_NOT_STRICTER' USING ERRCODE = '22023';
  END IF;
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_publish_budget_configuration_v1(
  api_revision text,
  provider_boundary_id text,
  allocation_revision text,
  allocation_fence object_store_retention.uint64,
  hard_expires_at_unix_ms bigint,
  core_schema_revision text,
  disposition_schema_revision text,
  envelope_schema_revision text,
  target_kind smallint,
  target_id text,
  core_target_revision object_store_retention.uint64,
  disposition_target_kind smallint,
  disposition_target_id text,
  disposition_target_revision object_store_retention.uint64,
  envelope_target_kind smallint,
  envelope_target_id text,
  envelope_target_revision object_store_retention.uint64,
  core_cell_id text,
  disposition_cell_id text,
  core_provider_boundary_id text,
  disposition_provider_boundary_id text,
  core_provider_allocation_set_revision object_store_retention.uint64,
  disposition_provider_allocation_set_revision object_store_retention.uint64,
  envelope_provider_allocation_set_revision object_store_retention.uint64,
  core_provider_allocation_set_fence object_store_retention.uint64,
  disposition_provider_allocation_set_fence object_store_retention.uint64,
  envelope_provider_allocation_set_fence object_store_retention.uint64,
  core_record_digest bytea,
  disposition_id uuid,
  disposition_record_digest bytea,
  disposition_core_digest bytea,
  disposition_revision object_store_retention.uint64,
  predecessor_disposition_id uuid,
  predecessor_disposition_digest bytea,
  expected_prior_head_revision object_store_retention.uint64,
  expected_prior_head_digest bytea,
  envelope_record_digest bytea,
  envelope_core_digest bytea,
  envelope_disposition_digest bytea,
  envelope_final_budget_digest bytea,
  envelope_revision object_store_retention.uint64,
  disposition smallint,
  cache_implementation_package_path text,
  cache_implementation_revision text,
  cache_proof_digest bytea,
  cache_effect_vector_digest bytea,
  final_budget_vector_digest bytea,
  dimensions jsonb,
  cap_budgets jsonb
)
RETURNS object_store_retention.dispatch_budget_publication_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE prior object_store_retention.object_dispatch_budget_configurations%ROWTYPE;
DECLARE database_now bigint;
DECLARE dimension jsonb;
DECLARE cap jsonb;
BEGIN
  PERFORM object_store_retention.assert_dispatch_maintenance_v1();
  PERFORM object_store_retention.assert_dispatch_budget_limiter_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  PERFORM object_store_retention.assert_dispatch_budget_revision_v1(allocation_revision);
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(provider_boundary_id, 1144));
  database_now := object_store_retention.clock_unix_ms_v1();
  IF core_schema_revision IS DISTINCT FROM 'object-store-frozen-capacity-budget-core-v1'
     OR disposition_schema_revision IS DISTINCT FROM
        'object-store-exact-target-cache-disposition-v1'
     OR envelope_schema_revision IS DISTINCT FROM 'object-store-budget-frozen-envelope-v1'
     OR core_target_revision = 0
     OR target_kind IS DISTINCT FROM disposition_target_kind
     OR target_kind IS DISTINCT FROM envelope_target_kind
     OR target_id IS DISTINCT FROM disposition_target_id
     OR target_id IS DISTINCT FROM envelope_target_id
     OR core_target_revision IS DISTINCT FROM disposition_target_revision
     OR core_target_revision IS DISTINCT FROM envelope_target_revision
     OR core_cell_id IS DISTINCT FROM disposition_cell_id
     OR core_provider_boundary_id IS DISTINCT FROM provider_boundary_id
     OR disposition_provider_boundary_id IS DISTINCT FROM provider_boundary_id THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_SCHEMA_OR_TARGET_CHAIN_INVALID' USING ERRCODE = '22023';
  END IF;
  IF core_provider_allocation_set_revision IS DISTINCT FROM
       disposition_provider_allocation_set_revision
     OR core_provider_allocation_set_revision IS DISTINCT FROM
        envelope_provider_allocation_set_revision
     OR core_provider_allocation_set_fence IS DISTINCT FROM
        disposition_provider_allocation_set_fence
     OR core_provider_allocation_set_fence IS DISTINCT FROM
        envelope_provider_allocation_set_fence
     OR disposition_core_digest IS DISTINCT FROM core_record_digest
     OR envelope_core_digest IS DISTINCT FROM core_record_digest
     OR envelope_disposition_digest IS DISTINCT FROM disposition_record_digest
     OR envelope_final_budget_digest IS DISTINCT FROM final_budget_vector_digest THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_REVISION_OR_DIGEST_CHAIN_INVALID' USING ERRCODE = '22023';
  END IF;
  PERFORM object_store_retention.assert_dispatch_budget_json_v1(
    dimensions, cap_budgets, disposition, cache_implementation_package_path,
    cache_implementation_revision, cache_proof_digest, cache_effect_vector_digest
  );

  SELECT configuration.* INTO prior
    FROM object_store_retention.object_dispatch_current_budget_configuration AS current_config
    JOIN object_store_retention.object_dispatch_budget_configurations AS configuration
      USING (provider_boundary_id, allocation_revision, allocation_fence)
   WHERE current_config.provider_boundary_id =
         object_store_dispatch_publish_budget_configuration_v1.provider_boundary_id
   FOR UPDATE OF current_config;

  IF FOUND THEN
    IF allocation_revision = prior.allocation_revision AND allocation_fence = prior.allocation_fence THEN
      IF ROW(
        hard_expires_at_unix_ms, core_schema_revision, disposition_schema_revision,
        envelope_schema_revision, target_kind, target_id, core_target_revision,
        disposition_target_kind, disposition_target_id, disposition_target_revision,
        envelope_target_kind, envelope_target_id, envelope_target_revision, core_cell_id,
        core_provider_allocation_set_revision, core_provider_allocation_set_fence,
        core_record_digest, disposition_id, disposition_record_digest, disposition_core_digest,
        disposition_revision, predecessor_disposition_id, predecessor_disposition_digest,
        expected_prior_head_revision, expected_prior_head_digest, envelope_record_digest,
        envelope_core_digest, envelope_disposition_digest, envelope_final_budget_digest,
        envelope_revision, disposition, cache_implementation_package_path,
        cache_implementation_revision, cache_proof_digest, cache_effect_vector_digest,
        final_budget_vector_digest, dimensions, cap_budgets
      ) IS NOT DISTINCT FROM ROW(
        prior.hard_expires_at_unix_ms, prior.core_schema_revision,
        prior.disposition_schema_revision, prior.envelope_schema_revision, prior.target_kind,
        prior.target_id, prior.target_revision, prior.disposition_target_kind,
        prior.disposition_target_id, prior.disposition_target_revision,
        prior.envelope_target_kind, prior.envelope_target_id, prior.envelope_target_revision,
        prior.cell_id,
        prior.provider_allocation_set_revision, prior.provider_allocation_set_fence,
        prior.core_record_digest, prior.disposition_id, prior.disposition_record_digest,
        prior.disposition_core_digest, prior.disposition_revision,
        prior.predecessor_disposition_id, prior.predecessor_disposition_digest,
        prior.expected_prior_head_revision, prior.expected_prior_head_digest,
        prior.envelope_record_digest, prior.envelope_core_digest,
        prior.envelope_disposition_digest, prior.envelope_final_budget_digest,
        prior.envelope_revision, prior.disposition, prior.cache_implementation_package_path,
        prior.cache_implementation_revision, prior.cache_proof_digest,
        prior.cache_effect_vector_digest, prior.final_budget_vector_digest,
        prior.dimensions, prior.cap_budgets
      ) THEN
        RETURN ROW('REPLAY', allocation_revision, allocation_fence)::
          object_store_retention.dispatch_budget_publication_result_v1;
      END IF;
      RAISE EXCEPTION 'DISPATCH_BUDGET_CONFIGURATION_IDENTITY_CONFLICT' USING ERRCODE = '23505';
    END IF;
    IF hard_expires_at_unix_ms <= database_now THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_CONFIGURATION_EXPIRED' USING ERRCODE = '22023';
    END IF;
    IF prior.allocation_fence = 18446744073709551615
       OR allocation_fence IS DISTINCT FROM prior.allocation_fence + 1
       OR allocation_revision = prior.allocation_revision
       OR target_kind IS DISTINCT FROM prior.target_kind
       OR target_id IS DISTINCT FROM prior.target_id
       OR core_cell_id IS DISTINCT FROM prior.cell_id
       OR core_target_revision IS DISTINCT FROM prior.target_revision + 1
       OR disposition_revision IS DISTINCT FROM prior.disposition_revision + 1
       OR envelope_revision IS DISTINCT FROM prior.envelope_revision + 1
       OR predecessor_disposition_id IS DISTINCT FROM prior.disposition_id
       OR predecessor_disposition_digest IS DISTINCT FROM prior.disposition_record_digest
       OR expected_prior_head_revision IS DISTINCT FROM prior.envelope_revision
       OR expected_prior_head_digest IS DISTINCT FROM prior.envelope_record_digest THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_CONFIGURATION_SEQUENCE_INVALID' USING ERRCODE = '22023';
    END IF;
  ELSE
    IF hard_expires_at_unix_ms <= database_now THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_CONFIGURATION_EXPIRED' USING ERRCODE = '22023';
    END IF;
    IF allocation_fence <> 1 OR disposition_revision <> 1 OR envelope_revision <> 1
       OR predecessor_disposition_id IS NOT NULL OR predecessor_disposition_digest IS NOT NULL
       OR expected_prior_head_revision <> 0 OR expected_prior_head_digest IS NOT NULL THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_FIRST_CONFIGURATION_INVALID' USING ERRCODE = '22023';
    END IF;
  END IF;

  INSERT INTO object_store_retention.object_dispatch_budget_configurations VALUES (
    provider_boundary_id, allocation_revision, allocation_fence, hard_expires_at_unix_ms,
    core_schema_revision, disposition_schema_revision, envelope_schema_revision, target_kind,
    target_id, core_target_revision, disposition_target_kind, disposition_target_id,
    disposition_target_revision, envelope_target_kind, envelope_target_id,
    envelope_target_revision, core_cell_id, core_provider_allocation_set_revision,
    core_provider_allocation_set_fence, core_record_digest, disposition_id,
    disposition_record_digest, disposition_core_digest, disposition_revision,
    predecessor_disposition_id, predecessor_disposition_digest, expected_prior_head_revision,
    expected_prior_head_digest, envelope_record_digest, envelope_core_digest,
    envelope_disposition_digest, envelope_final_budget_digest, envelope_revision, disposition,
    cache_implementation_package_path, cache_implementation_revision, cache_proof_digest,
    cache_effect_vector_digest, final_budget_vector_digest, dimensions, cap_budgets, database_now
  );
  FOR dimension IN SELECT value FROM pg_catalog.jsonb_array_elements(dimensions) LOOP
    INSERT INTO object_store_retention.object_dispatch_budget_dimensions VALUES (
      provider_boundary_id, allocation_revision, allocation_fence, dimension->>'dimensionId',
      (dimension->>'effectiveBound')::numeric, (dimension->>'measuredLoad')::numeric,
      (dimension->>'targetDemand')::numeric, (dimension->>'failureReserve')::numeric,
      (dimension->>'preCacheHeadroom')::numeric,
      CASE WHEN dimension ? 'cacheEffect' THEN (dimension->>'cacheEffect')::numeric END,
      (dimension->>'finalBudget')::numeric
    );
  END LOOP;
  FOR cap IN SELECT value FROM pg_catalog.jsonb_array_elements(cap_budgets) LOOP
    INSERT INTO object_store_retention.object_dispatch_budget_caps VALUES (
      provider_boundary_id, allocation_revision, allocation_fence, (cap->>'capClass')::smallint,
      (cap->>'capacityUnits')::numeric, (cap->>'refillUnits')::numeric,
      (cap->>'refillIntervalMs')::numeric
    );
    INSERT INTO object_store_retention.object_dispatch_budget_bucket_state VALUES (
      provider_boundary_id, allocation_revision, allocation_fence, (cap->>'capClass')::smallint,
      (cap->>'capacityUnits')::numeric * (cap->>'refillIntervalMs')::numeric, database_now, 1
    );
  END LOOP;
  INSERT INTO object_store_retention.object_dispatch_current_budget_configuration VALUES (
    provider_boundary_id, allocation_revision, allocation_fence
  ) ON CONFLICT ON CONSTRAINT object_dispatch_current_budget_configuration_pkey DO UPDATE SET
    allocation_revision = EXCLUDED.allocation_revision,
    allocation_fence = EXCLUDED.allocation_fence;
  RETURN ROW('PUBLISHED', allocation_revision, allocation_fence)::
    object_store_retention.dispatch_budget_publication_result_v1;
END
$$;

CREATE FUNCTION object_store_retention.assert_dispatch_budget_resolved_v1(
  provider_boundary_id text,
  allocation_revision text,
  allocation_fence object_store_retention.uint64
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE configuration object_store_retention.object_dispatch_budget_configurations%ROWTYPE;
BEGIN
  SELECT * INTO STRICT configuration
    FROM object_store_retention.object_dispatch_budget_configurations AS candidate
   WHERE candidate.provider_boundary_id = assert_dispatch_budget_resolved_v1.provider_boundary_id
     AND candidate.allocation_revision = assert_dispatch_budget_resolved_v1.allocation_revision
     AND candidate.allocation_fence = assert_dispatch_budget_resolved_v1.allocation_fence;
  IF configuration.core_schema_revision IS DISTINCT FROM
       'object-store-frozen-capacity-budget-core-v1'
     OR configuration.disposition_schema_revision IS DISTINCT FROM
        'object-store-exact-target-cache-disposition-v1'
     OR configuration.envelope_schema_revision IS DISTINCT FROM
        'object-store-budget-frozen-envelope-v1'
     OR configuration.target_revision = 0
     OR configuration.target_kind IS DISTINCT FROM configuration.disposition_target_kind
     OR configuration.target_kind IS DISTINCT FROM configuration.envelope_target_kind
     OR configuration.target_id IS DISTINCT FROM configuration.disposition_target_id
     OR configuration.target_id IS DISTINCT FROM configuration.envelope_target_id
     OR configuration.target_revision IS DISTINCT FROM configuration.disposition_target_revision
     OR configuration.target_revision IS DISTINCT FROM configuration.envelope_target_revision
     OR configuration.disposition_core_digest IS DISTINCT FROM configuration.core_record_digest
     OR configuration.envelope_core_digest IS DISTINCT FROM configuration.core_record_digest
     OR configuration.envelope_disposition_digest IS DISTINCT FROM
        configuration.disposition_record_digest
     OR configuration.envelope_final_budget_digest IS DISTINCT FROM
        configuration.final_budget_vector_digest
     OR configuration.disposition_revision IS DISTINCT FROM configuration.envelope_revision
     OR (
       configuration.disposition_revision = 1 AND (
         configuration.predecessor_disposition_id IS NOT NULL OR
         configuration.predecessor_disposition_digest IS NOT NULL OR
         configuration.expected_prior_head_revision <> 0 OR
         configuration.expected_prior_head_digest IS NOT NULL
       )
     )
     OR (
       configuration.disposition_revision > 1 AND (
         configuration.predecessor_disposition_id IS NULL OR
         configuration.predecessor_disposition_digest IS NULL OR
         configuration.expected_prior_head_digest IS NULL OR
         configuration.expected_prior_head_revision + 1 IS DISTINCT FROM
           configuration.envelope_revision OR
         NOT EXISTS (
           SELECT 1
             FROM object_store_retention.object_dispatch_budget_configurations AS predecessor
            WHERE predecessor.provider_boundary_id = configuration.provider_boundary_id
              AND predecessor.disposition_id = configuration.predecessor_disposition_id
              AND predecessor.disposition_record_digest =
                    configuration.predecessor_disposition_digest
              AND predecessor.disposition_revision + 1 = configuration.disposition_revision
              AND predecessor.envelope_revision = configuration.expected_prior_head_revision
              AND predecessor.envelope_record_digest = configuration.expected_prior_head_digest
              AND predecessor.target_kind = configuration.target_kind
              AND predecessor.target_id = configuration.target_id
              AND predecessor.target_revision + 1 = configuration.target_revision
         )
       )
     )
     OR (SELECT pg_catalog.count(*) FROM object_store_retention.object_dispatch_budget_caps AS cap
          WHERE cap.provider_boundary_id = configuration.provider_boundary_id
            AND cap.allocation_revision = configuration.allocation_revision
            AND cap.allocation_fence = configuration.allocation_fence) <> 7
     OR (SELECT pg_catalog.count(*) FROM object_store_retention.object_dispatch_budget_dimensions AS dimension
          WHERE dimension.provider_boundary_id = configuration.provider_boundary_id
            AND dimension.allocation_revision = configuration.allocation_revision
            AND dimension.allocation_fence = configuration.allocation_fence) = 0
     OR EXISTS (
       SELECT 1 FROM object_store_retention.object_dispatch_budget_caps AS cap
        WHERE cap.provider_boundary_id = configuration.provider_boundary_id
          AND cap.allocation_revision = configuration.allocation_revision
          AND cap.allocation_fence = configuration.allocation_fence
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(configuration.cap_budgets) AS encoded
             WHERE (encoded->>'capClass')::smallint = cap.cap_class
               AND (encoded->>'capacityUnits')::numeric = cap.capacity_units
               AND (encoded->>'refillUnits')::numeric = cap.refill_units
               AND (encoded->>'refillIntervalMs')::numeric = cap.refill_interval_ms
          )
     )
     OR EXISTS (
       SELECT 1 FROM object_store_retention.object_dispatch_budget_dimensions AS dimension
        WHERE dimension.provider_boundary_id = configuration.provider_boundary_id
          AND dimension.allocation_revision = configuration.allocation_revision
          AND dimension.allocation_fence = configuration.allocation_fence
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(configuration.dimensions) AS encoded
             WHERE encoded->>'dimensionId' = dimension.dimension_id
               AND (encoded->>'effectiveBound')::numeric = dimension.effective_bound
               AND (encoded->>'measuredLoad')::numeric = dimension.measured_load
               AND (encoded->>'targetDemand')::numeric = dimension.target_demand
               AND (encoded->>'failureReserve')::numeric = dimension.failure_reserve
               AND (encoded->>'preCacheHeadroom')::numeric = dimension.pre_cache_headroom
               AND (encoded->>'finalBudget')::numeric = dimension.final_budget
               AND CASE WHEN encoded ? 'cacheEffect'
                    THEN (encoded->>'cacheEffect')::numeric IS NOT DISTINCT FROM dimension.cache_effect
                    ELSE dimension.cache_effect IS NULL END
          )
     )
     OR EXISTS (
       SELECT 1 FROM object_store_retention.object_dispatch_budget_dimensions AS dimension
        WHERE dimension.provider_boundary_id = configuration.provider_boundary_id
          AND dimension.allocation_revision = configuration.allocation_revision
          AND dimension.allocation_fence = configuration.allocation_fence
          AND (
            dimension.pre_cache_headroom IS DISTINCT FROM
              dimension.effective_bound - dimension.measured_load -
              dimension.target_demand - dimension.failure_reserve OR
            (configuration.disposition = 1 AND (
              dimension.cache_effect IS NOT NULL OR dimension.pre_cache_headroom < 0 OR
              dimension.final_budget IS DISTINCT FROM dimension.pre_cache_headroom
            )) OR
            (configuration.disposition = 2 AND (
              dimension.cache_effect IS NULL OR dimension.final_budget IS DISTINCT FROM
                dimension.pre_cache_headroom + dimension.cache_effect OR dimension.final_budget < 0
            ))
          )
     ) THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_CONFIGURATION_UNRESOLVED' USING ERRCODE = '55000';
  END IF;
  PERFORM object_store_retention.assert_dispatch_budget_json_v1(
    configuration.dimensions, configuration.cap_budgets, configuration.disposition,
    configuration.cache_implementation_package_path, configuration.cache_implementation_revision,
    configuration.cache_proof_digest, configuration.cache_effect_vector_digest
  );
EXCEPTION WHEN no_data_found OR too_many_rows OR data_exception THEN
  RAISE EXCEPTION 'DISPATCH_BUDGET_CONFIGURATION_UNRESOLVED' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_charge_provider_attempt_v1(
  api_revision text,
  provider_boundary_id text,
  traffic_class smallint,
  attempt_class smallint,
  attempt_units object_store_retention.uint64,
  allocation_revision text,
  allocation_fence object_store_retention.uint64,
  logical_request_id uuid,
  attempt_id uuid,
  attempt_ordinal integer,
  deadline_unix_ms bigint,
  cap_classes smallint[]
)
RETURNS object_store_retention.dispatch_provider_charge_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE current_config object_store_retention.object_dispatch_current_budget_configuration%ROWTYPE;
DECLARE configuration object_store_retention.object_dispatch_budget_configurations%ROWTYPE;
DECLARE bucket record;
DECLARE database_now bigint;
DECLARE elapsed_ms numeric;
DECLARE capacity_scaled numeric;
DECLARE refilled_scaled numeric;
DECLARE charge_scaled numeric;
DECLARE expected_caps smallint[];
DECLARE refusal text;
BEGIN
  PERFORM object_store_retention.assert_dispatch_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_budget_limiter_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(provider_boundary_id, 1144));
  IF traffic_class NOT BETWEEN 1 AND 5 OR attempt_class NOT BETWEEN 1 AND 11
     OR attempt_units <> 1 OR attempt_ordinal <= 0 OR deadline_unix_ms < 0 THEN
    RAISE EXCEPTION 'DISPATCH_PROVIDER_CHARGE_REQUEST_INVALID' USING ERRCODE = '22023';
  END IF;
  expected_caps := ARRAY[1::smallint, (traffic_class + 1)::smallint];
  IF attempt_class IN (9, 10) THEN expected_caps := expected_caps || 7::smallint; END IF;
  IF cap_classes IS DISTINCT FROM expected_caps THEN
    RAISE EXCEPTION 'DISPATCH_PROVIDER_CHARGE_CAP_SET_INVALID' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO current_config
    FROM object_store_retention.object_dispatch_current_budget_configuration AS current_candidate
   WHERE current_candidate.provider_boundary_id =
         object_store_dispatch_charge_provider_attempt_v1.provider_boundary_id;
  IF NOT FOUND THEN
    RETURN ROW('CONFIGURATION_UNRESOLVED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END IF;
  IF current_config.allocation_revision IS DISTINCT FROM allocation_revision
     OR current_config.allocation_fence IS DISTINCT FROM allocation_fence THEN
    RETURN ROW('BUDGET_PIN_REJECTED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END IF;
  BEGIN
    PERFORM object_store_retention.assert_dispatch_budget_resolved_v1(
      provider_boundary_id, allocation_revision, allocation_fence
    );
  EXCEPTION WHEN SQLSTATE '55000' OR SQLSTATE '22023' THEN
    RETURN ROW('CONFIGURATION_UNRESOLVED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END;
  SELECT * INTO STRICT configuration
    FROM object_store_retention.object_dispatch_budget_configurations AS candidate
   WHERE candidate.provider_boundary_id =
         object_store_dispatch_charge_provider_attempt_v1.provider_boundary_id
     AND candidate.allocation_revision =
         object_store_dispatch_charge_provider_attempt_v1.allocation_revision
     AND candidate.allocation_fence = object_store_dispatch_charge_provider_attempt_v1.allocation_fence;
  database_now := object_store_retention.clock_unix_ms_v1();
  IF database_now >= deadline_unix_ms THEN
    RETURN ROW('DEADLINE_EXCEEDED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END IF;
  IF database_now >= configuration.hard_expires_at_unix_ms THEN
    RETURN ROW('CONFIGURATION_UNRESOLVED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END IF;
  IF EXISTS (
    SELECT 1 FROM object_store_retention.object_dispatch_provider_charge_grants AS grant_row
     WHERE grant_row.provider_boundary_id = object_store_dispatch_charge_provider_attempt_v1.provider_boundary_id
       AND grant_row.logical_request_id = object_store_dispatch_charge_provider_attempt_v1.logical_request_id
       AND grant_row.attempt_id = object_store_dispatch_charge_provider_attempt_v1.attempt_id
       AND grant_row.attempt_ordinal = object_store_dispatch_charge_provider_attempt_v1.attempt_ordinal
  ) THEN
    RETURN ROW('ATTEMPT_ALREADY_CHARGED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END IF;

  FOR bucket IN
    SELECT state.cap_class, state.available_scaled, state.updated_at_unix_ms,
           state.state_revision, cap.capacity_units, cap.refill_units, cap.refill_interval_ms
      FROM object_store_retention.object_dispatch_budget_bucket_state AS state
      JOIN object_store_retention.object_dispatch_budget_caps AS cap
        USING (provider_boundary_id, allocation_revision, allocation_fence, cap_class)
     WHERE state.provider_boundary_id = object_store_dispatch_charge_provider_attempt_v1.provider_boundary_id
       AND state.allocation_revision = object_store_dispatch_charge_provider_attempt_v1.allocation_revision
       AND state.allocation_fence = object_store_dispatch_charge_provider_attempt_v1.allocation_fence
       AND state.cap_class = ANY(cap_classes)
     ORDER BY state.cap_class
     FOR UPDATE OF state
  LOOP
    IF database_now < bucket.updated_at_unix_ms THEN
      RETURN ROW('CONFIGURATION_UNRESOLVED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
        object_store_retention.dispatch_provider_charge_result_v1;
    END IF;
    elapsed_ms := database_now - bucket.updated_at_unix_ms;
    capacity_scaled := bucket.capacity_units * bucket.refill_interval_ms;
    IF elapsed_ms * bucket.refill_units > 18446744073709551615
       OR capacity_scaled > 18446744073709551615
       OR bucket.available_scaled + elapsed_ms * bucket.refill_units > 18446744073709551615
       OR attempt_units * bucket.refill_interval_ms > 18446744073709551615
       OR bucket.state_revision = 18446744073709551615 THEN
      RETURN ROW('CONFIGURATION_UNRESOLVED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
        object_store_retention.dispatch_provider_charge_result_v1;
    END IF;
    refilled_scaled := least(
      capacity_scaled,
      bucket.available_scaled + elapsed_ms * bucket.refill_units
    );
    charge_scaled := attempt_units * bucket.refill_interval_ms;
    IF refilled_scaled < charge_scaled THEN
      refusal := CASE WHEN bucket.cap_class = 1 THEN 'BUDGET_EXHAUSTED' ELSE 'CLASS_CAP_EXHAUSTED' END;
      RETURN ROW(refusal, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
        object_store_retention.dispatch_provider_charge_result_v1;
    END IF;
  END LOOP;
  IF (SELECT pg_catalog.count(*) FROM object_store_retention.object_dispatch_budget_bucket_state AS state
       WHERE state.provider_boundary_id = object_store_dispatch_charge_provider_attempt_v1.provider_boundary_id
         AND state.allocation_revision = object_store_dispatch_charge_provider_attempt_v1.allocation_revision
         AND state.allocation_fence = object_store_dispatch_charge_provider_attempt_v1.allocation_fence
         AND state.cap_class = ANY(cap_classes)) <> pg_catalog.array_length(cap_classes, 1) THEN
    RETURN ROW('CONFIGURATION_UNRESOLVED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END IF;

  INSERT INTO object_store_retention.object_dispatch_provider_charge_grants VALUES (
    provider_boundary_id, allocation_revision, allocation_fence, logical_request_id, attempt_id,
    attempt_ordinal, traffic_class, attempt_class, attempt_units, database_now
  ) ON CONFLICT DO NOTHING;
  IF NOT FOUND THEN
    RETURN ROW('ATTEMPT_ALREADY_CHARGED', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)::
      object_store_retention.dispatch_provider_charge_result_v1;
  END IF;
  FOR bucket IN
    SELECT state.cap_class, state.available_scaled, state.updated_at_unix_ms,
           cap.capacity_units, cap.refill_units, cap.refill_interval_ms
      FROM object_store_retention.object_dispatch_budget_bucket_state AS state
      JOIN object_store_retention.object_dispatch_budget_caps AS cap
        USING (provider_boundary_id, allocation_revision, allocation_fence, cap_class)
     WHERE state.provider_boundary_id = object_store_dispatch_charge_provider_attempt_v1.provider_boundary_id
       AND state.allocation_revision = object_store_dispatch_charge_provider_attempt_v1.allocation_revision
       AND state.allocation_fence = object_store_dispatch_charge_provider_attempt_v1.allocation_fence
       AND state.cap_class = ANY(cap_classes)
     ORDER BY state.cap_class
  LOOP
    elapsed_ms := database_now - bucket.updated_at_unix_ms;
    capacity_scaled := bucket.capacity_units * bucket.refill_interval_ms;
    refilled_scaled := least(
      capacity_scaled,
      bucket.available_scaled + elapsed_ms * bucket.refill_units
    );
    charge_scaled := attempt_units * bucket.refill_interval_ms;
    UPDATE object_store_retention.object_dispatch_budget_bucket_state AS state SET
      available_scaled = refilled_scaled - charge_scaled,
      updated_at_unix_ms = database_now,
      state_revision = state.state_revision + 1
     WHERE state.provider_boundary_id = object_store_dispatch_charge_provider_attempt_v1.provider_boundary_id
       AND state.allocation_revision = object_store_dispatch_charge_provider_attempt_v1.allocation_revision
       AND state.allocation_fence = object_store_dispatch_charge_provider_attempt_v1.allocation_fence
       AND state.cap_class = bucket.cap_class;
  END LOOP;
  RETURN ROW(
    'GRANTED', allocation_revision, allocation_fence, attempt_id, traffic_class, attempt_class,
    attempt_units, logical_request_id, attempt_id, attempt_ordinal, database_now
  )::object_store_retention.dispatch_provider_charge_result_v1;
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_budget_limiter_install_v1(
  api_revision text,
  expected_schema_revision text,
  expected_migration_blake3 bytea,
  expected_install_revision object_store_retention.uint64
)
RETURNS object_store_retention.dispatch_budget_limiter_state_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE stored object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE installed_at bigint;
BEGIN
  PERFORM object_store_retention.assert_retention_migrator_v1();
  PERFORM object_store_retention.assert_dispatch_budget_limiter_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  IF expected_schema_revision IS DISTINCT FROM 'object-store-dispatch-budget-limiter-schema-v1'
     OR expected_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('632250487652ee25505ae979c6a8eac9e62ad96b2aeea51864b320bc50953d07', 'hex')
     OR expected_install_revision IS NULL OR expected_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_INSTALL_IDENTITY_INVALID' USING ERRCODE = '22023';
  END IF;

  LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,
    object_store_retention.object_dispatch_budget_configurations,
    object_store_retention.object_dispatch_current_budget_configuration,
    object_store_retention.object_dispatch_budget_dimensions,
    object_store_retention.object_dispatch_budget_caps,
    object_store_retention.object_dispatch_budget_bucket_state,
    object_store_retention.object_dispatch_provider_charge_grants
    IN EXCLUSIVE MODE;
  SELECT * INTO STRICT stored
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton;
  IF stored.dispatcher_identity_schema_revision IS DISTINCT FROM
       'object-store-dispatch-dispatcher-identity-schema-v1'
     OR stored.dispatcher_identity_install_revision IS NULL
     OR stored.dispatcher_identity_install_revision = 0 THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  IF stored.budget_limiter_schema_revision IS NOT NULL THEN
    IF stored.budget_limiter_schema_revision IS DISTINCT FROM expected_schema_revision
       OR stored.budget_limiter_migration_blake3 IS DISTINCT FROM expected_migration_blake3
       OR stored.budget_limiter_install_revision IS DISTINCT FROM expected_install_revision
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_configurations)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_current_budget_configuration)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_dimensions)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_caps)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_bucket_state)
       OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_provider_charge_grants) THEN
      RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_INSTALL_REPLAY_CONFLICT' USING ERRCODE = '40001';
    END IF;
    RETURN ROW('REPLAY', stored.budget_limiter_schema_revision,
      stored.budget_limiter_migration_blake3, stored.budget_limiter_install_revision,
      stored.budget_limiter_installed_at_unix_ms)::
      object_store_retention.dispatch_budget_limiter_state_v1;
  END IF;
  IF pg_catalog.num_nonnulls(
       stored.budget_limiter_migration_blake3,
       stored.budget_limiter_install_revision,
       stored.budget_limiter_installed_at_unix_ms
     ) <> 0
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_configurations)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_current_budget_configuration)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_dimensions)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_caps)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_budget_bucket_state)
     OR EXISTS (SELECT 1 FROM object_store_retention.object_dispatch_provider_charge_grants) THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_INSTALL_DIRTY_STATE' USING ERRCODE = '55000';
  END IF;
  installed_at := object_store_retention.clock_unix_ms_v1();
  UPDATE object_store_retention.object_dispatch_retention_schema_state SET
    budget_limiter_schema_revision = expected_schema_revision,
    budget_limiter_migration_blake3 = expected_migration_blake3,
    budget_limiter_install_revision = expected_install_revision,
    budget_limiter_installed_at_unix_ms = installed_at
   WHERE singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_UNAVAILABLE' USING ERRCODE = '55000';
  END IF;
  RETURN ROW('CREATED', expected_schema_revision, expected_migration_blake3,
    expected_install_revision, installed_at)::object_store_retention.dispatch_budget_limiter_state_v1;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION object_store_retention.object_store_dispatch_budget_limiter_read_state_v1(
  api_revision text
)
RETURNS object_store_retention.dispatch_budget_limiter_state_v1
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
BEGIN
  IF session_user IS DISTINCT FROM 'object_dispatch_retention_runtime' THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_READER_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501';
  END IF;
  PERFORM object_store_retention.assert_dispatch_budget_limiter_api_revision_v1(api_revision);
  SELECT * INTO STRICT state FROM object_store_retention.object_dispatch_retention_schema_state WHERE singleton;
  IF state.budget_limiter_schema_revision IS NULL THEN
    RAISE EXCEPTION 'DISPATCH_BUDGET_LIMITER_NOT_INSTALLED' USING ERRCODE = '55000';
  END IF;
  RETURN ROW('READ', state.budget_limiter_schema_revision, state.budget_limiter_migration_blake3,
    state.budget_limiter_install_revision, state.budget_limiter_installed_at_unix_ms)::
    object_store_retention.dispatch_budget_limiter_state_v1;
END
$$;

REVOKE ALL ON TABLE object_store_retention.object_dispatch_budget_configurations,
  object_store_retention.object_dispatch_current_budget_configuration,
  object_store_retention.object_dispatch_budget_dimensions,
  object_store_retention.object_dispatch_budget_caps,
  object_store_retention.object_dispatch_budget_bucket_state,
  object_store_retention.object_dispatch_provider_charge_grants
  FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance,
       object_dispatch_retention_migrator;
REVOKE ALL ON FUNCTION object_store_retention.assert_dispatch_budget_limiter_api_revision_v1(text),
  object_store_retention.assert_dispatch_budget_revision_v1(text),
  object_store_retention.assert_dispatch_budget_json_v1(jsonb, jsonb, smallint, text, text, bytea, bytea),
  object_store_retention.assert_dispatch_budget_resolved_v1(
    text, text, object_store_retention.uint64
  ) FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance,
         object_dispatch_retention_migrator;
REVOKE ALL ON FUNCTION
  object_store_retention.object_store_dispatch_publish_budget_configuration_v1(
    text, text, text, object_store_retention.uint64, bigint, text, text, text, smallint, text,
    object_store_retention.uint64, smallint, text, object_store_retention.uint64, smallint, text,
    object_store_retention.uint64,
    text, text, text, text, object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, bytea, uuid, bytea, bytea, object_store_retention.uint64, uuid,
    bytea, object_store_retention.uint64, bytea, bytea, bytea, bytea, bytea,
    object_store_retention.uint64, smallint, text, text, bytea, bytea, bytea, jsonb, jsonb
  ) FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION
  object_store_retention.object_store_dispatch_publish_budget_configuration_v1(
    text, text, text, object_store_retention.uint64, bigint, text, text, text, smallint, text,
    object_store_retention.uint64, smallint, text, object_store_retention.uint64, smallint, text,
    object_store_retention.uint64,
    text, text, text, text, object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, object_store_retention.uint64, object_store_retention.uint64,
    object_store_retention.uint64, bytea, uuid, bytea, bytea, object_store_retention.uint64, uuid,
    bytea, object_store_retention.uint64, bytea, bytea, bytea, bytea, bytea,
    object_store_retention.uint64, smallint, text, text, bytea, bytea, bytea, jsonb, jsonb
  ) TO object_dispatch_retention_maintenance;
REVOKE ALL ON FUNCTION object_store_retention.object_store_dispatch_charge_provider_attempt_v1(
  text, text, smallint, smallint, object_store_retention.uint64, text,
  object_store_retention.uint64, uuid, uuid, integer, bigint, smallint[]
) FROM PUBLIC, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_charge_provider_attempt_v1(
  text, text, smallint, smallint, object_store_retention.uint64, text,
  object_store_retention.uint64, uuid, uuid, integer, bigint, smallint[]
) TO object_dispatch_retention_runtime;
REVOKE ALL ON FUNCTION object_store_retention.object_store_dispatch_budget_limiter_install_v1(
  text, text, bytea, object_store_retention.uint64
) FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_budget_limiter_install_v1(
  text, text, bytea, object_store_retention.uint64
) TO object_dispatch_retention_migrator;
REVOKE ALL ON FUNCTION object_store_retention.object_store_dispatch_budget_limiter_read_state_v1(text)
  FROM PUBLIC, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_budget_limiter_read_state_v1(text)
  TO object_dispatch_retention_runtime;

COMMIT;

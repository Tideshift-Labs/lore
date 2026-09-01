-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-114 CD-4 shared cell-local provider limiter: schema edge.
--
-- This artifact is source-dark. It installs no current budget, route, credential, provider
-- endpoint, or activation value. Migration 0022 owns provisioning, publication, resolution, and
-- charging. Migration 0007 remains frozen; its retained allocation_revision/allocation_fence
-- columns carry the same current per-cell budget-configuration pin installed here.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TABLE object_store_retention.object_dispatch_budget_configurations (
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  allocation_revision text COLLATE "C" NOT NULL
    CHECK (octet_length(allocation_revision) BETWEEN 1 AND 128),
  allocation_fence object_store_retention.uint64 NOT NULL CHECK (allocation_fence > 0),
  hard_expires_at_unix_ms bigint NOT NULL CHECK (hard_expires_at_unix_ms >= 0),

  core_schema_revision text NOT NULL,
  disposition_schema_revision text NOT NULL,
  envelope_schema_revision text NOT NULL,
  target_kind smallint NOT NULL CHECK (target_kind BETWEEN 1 AND 3),
  target_id text NOT NULL CHECK (octet_length(target_id) BETWEEN 1 AND 1024),
  target_revision object_store_retention.uint64 NOT NULL CHECK (target_revision > 0),
  disposition_target_kind smallint NOT NULL CHECK (disposition_target_kind BETWEEN 1 AND 3),
  disposition_target_id text NOT NULL
    CHECK (octet_length(disposition_target_id) BETWEEN 1 AND 1024),
  disposition_target_revision object_store_retention.uint64 NOT NULL
    CHECK (disposition_target_revision > 0),
  envelope_target_kind smallint NOT NULL CHECK (envelope_target_kind BETWEEN 1 AND 3),
  envelope_target_id text NOT NULL CHECK (octet_length(envelope_target_id) BETWEEN 1 AND 1024),
  envelope_target_revision object_store_retention.uint64 NOT NULL
    CHECK (envelope_target_revision > 0),
  cell_id text NOT NULL CHECK (octet_length(cell_id) BETWEEN 1 AND 1024),
  provider_allocation_set_revision object_store_retention.uint64 NOT NULL,
  provider_allocation_set_fence object_store_retention.uint64 NOT NULL,

  core_record_digest object_store_retention.blake3_256 NOT NULL,
  disposition_id uuid NOT NULL,
  disposition_record_digest object_store_retention.blake3_256 NOT NULL,
  disposition_core_digest object_store_retention.blake3_256 NOT NULL,
  disposition_revision object_store_retention.uint64 NOT NULL CHECK (disposition_revision > 0),
  predecessor_disposition_id uuid,
  predecessor_disposition_digest object_store_retention.blake3_256,
  expected_prior_head_revision object_store_retention.uint64 NOT NULL,
  expected_prior_head_digest object_store_retention.blake3_256,

  envelope_record_digest object_store_retention.blake3_256 NOT NULL,
  envelope_core_digest object_store_retention.blake3_256 NOT NULL,
  envelope_disposition_digest object_store_retention.blake3_256 NOT NULL,
  envelope_final_budget_digest object_store_retention.blake3_256 NOT NULL,
  envelope_revision object_store_retention.uint64 NOT NULL CHECK (envelope_revision > 0),

  disposition smallint NOT NULL CHECK (disposition IN (1, 2)),
  cache_implementation_package_path text,
  cache_implementation_revision text,
  cache_proof_digest object_store_retention.blake3_256,
  cache_effect_vector_digest object_store_retention.blake3_256,
  final_budget_vector_digest object_store_retention.blake3_256 NOT NULL,
  dimensions jsonb NOT NULL,
  cap_budgets jsonb NOT NULL,
  published_at_unix_ms bigint NOT NULL CHECK (published_at_unix_ms >= 0),

  PRIMARY KEY (provider_boundary_id, allocation_revision, allocation_fence),
  UNIQUE (provider_boundary_id, allocation_fence),
  UNIQUE (provider_boundary_id, disposition_id),
  CHECK (
    pg_catalog.num_nonnulls(
      predecessor_disposition_id,
      predecessor_disposition_digest,
      expected_prior_head_digest
    ) IN (0, 3)
  )
);

CREATE TABLE object_store_retention.object_dispatch_current_budget_configuration (
  provider_boundary_id text PRIMARY KEY,
  allocation_revision text COLLATE "C" NOT NULL,
  allocation_fence object_store_retention.uint64 NOT NULL CHECK (allocation_fence > 0),
  FOREIGN KEY (provider_boundary_id, allocation_revision, allocation_fence)
    REFERENCES object_store_retention.object_dispatch_budget_configurations
      (provider_boundary_id, allocation_revision, allocation_fence)
);

CREATE TABLE object_store_retention.object_dispatch_budget_dimensions (
  provider_boundary_id text NOT NULL,
  allocation_revision text COLLATE "C" NOT NULL,
  allocation_fence object_store_retention.uint64 NOT NULL,
  dimension_id text NOT NULL CHECK (octet_length(dimension_id) BETWEEN 1 AND 128),
  effective_bound object_store_retention.uint64 NOT NULL,
  measured_load object_store_retention.uint64 NOT NULL,
  target_demand object_store_retention.uint64 NOT NULL,
  failure_reserve object_store_retention.uint64 NOT NULL,
  pre_cache_headroom numeric(40, 0) NOT NULL,
  cache_effect object_store_retention.uint64,
  final_budget object_store_retention.uint64 NOT NULL,
  PRIMARY KEY (provider_boundary_id, allocation_revision, allocation_fence, dimension_id),
  FOREIGN KEY (provider_boundary_id, allocation_revision, allocation_fence)
    REFERENCES object_store_retention.object_dispatch_budget_configurations
      (provider_boundary_id, allocation_revision, allocation_fence)
);

CREATE TABLE object_store_retention.object_dispatch_budget_caps (
  provider_boundary_id text NOT NULL,
  allocation_revision text COLLATE "C" NOT NULL,
  allocation_fence object_store_retention.uint64 NOT NULL,
  cap_class smallint NOT NULL CHECK (cap_class BETWEEN 1 AND 7),
  capacity_units object_store_retention.uint64 NOT NULL CHECK (capacity_units > 0),
  refill_units object_store_retention.uint64 NOT NULL CHECK (refill_units > 0),
  refill_interval_ms object_store_retention.uint64 NOT NULL CHECK (refill_interval_ms > 0),
  PRIMARY KEY (provider_boundary_id, allocation_revision, allocation_fence, cap_class),
  FOREIGN KEY (provider_boundary_id, allocation_revision, allocation_fence)
    REFERENCES object_store_retention.object_dispatch_budget_configurations
      (provider_boundary_id, allocation_revision, allocation_fence)
);

CREATE TABLE object_store_retention.object_dispatch_budget_bucket_state (
  provider_boundary_id text NOT NULL,
  allocation_revision text COLLATE "C" NOT NULL,
  allocation_fence object_store_retention.uint64 NOT NULL,
  cap_class smallint NOT NULL,
  available_scaled object_store_retention.uint64 NOT NULL,
  updated_at_unix_ms bigint NOT NULL CHECK (updated_at_unix_ms >= 0),
  state_revision object_store_retention.uint64 NOT NULL CHECK (state_revision > 0),
  PRIMARY KEY (provider_boundary_id, allocation_revision, allocation_fence, cap_class),
  FOREIGN KEY (provider_boundary_id, allocation_revision, allocation_fence, cap_class)
    REFERENCES object_store_retention.object_dispatch_budget_caps
      (provider_boundary_id, allocation_revision, allocation_fence, cap_class)
);

CREATE TABLE object_store_retention.object_dispatch_provider_charge_grants (
  provider_boundary_id text NOT NULL,
  allocation_revision text COLLATE "C" NOT NULL,
  allocation_fence object_store_retention.uint64 NOT NULL,
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  attempt_ordinal integer NOT NULL CHECK (attempt_ordinal > 0),
  traffic_class smallint NOT NULL CHECK (traffic_class BETWEEN 1 AND 5),
  attempt_class smallint NOT NULL CHECK (attempt_class BETWEEN 1 AND 11),
  charged_units object_store_retention.uint64 NOT NULL CHECK (charged_units = 1),
  grant_committed_at_unix_ms bigint NOT NULL CHECK (grant_committed_at_unix_ms >= 0),
  PRIMARY KEY (provider_boundary_id, logical_request_id, attempt_id, attempt_ordinal),
  FOREIGN KEY (provider_boundary_id, allocation_revision, allocation_fence)
    REFERENCES object_store_retention.object_dispatch_budget_configurations
      (provider_boundary_id, allocation_revision, allocation_fence)
);

CREATE INDEX object_dispatch_provider_charge_grants_budget_idx
  ON object_store_retention.object_dispatch_provider_charge_grants
  (provider_boundary_id, allocation_revision, allocation_fence, grant_committed_at_unix_ms);

COMMIT;

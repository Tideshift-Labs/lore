-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark local dispatch-authority table edge.
-- Runtime code never installs this artifact. Later provisioning must install and attest it.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TABLE object_store_retention.object_dispatch_requests (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-authority-schema-v1'),
  protocol_revision text NOT NULL CHECK (octet_length(protocol_revision) BETWEEN 1 AND 1024),
  policy_revision text NOT NULL CHECK (octet_length(policy_revision) BETWEEN 1 AND 1024),
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  authenticated_cell_id text NOT NULL CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  authenticated_tenant_id text NOT NULL CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  logical_request_uuid_unix_ms object_store_retention.uint64 NOT NULL,
  attempt_uuid_unix_ms object_store_retention.uint64 NOT NULL,
  put_reservation_fingerprint object_store_retention.blake3_256,
  canonical_descriptor_bytes bytea NOT NULL
    CHECK (octet_length(canonical_descriptor_bytes) BETWEEN 1 AND 16777216),
  canonical_descriptor_fingerprint object_store_retention.blake3_256 NOT NULL,
  operation_tag smallint NOT NULL CHECK (operation_tag BETWEEN 1 AND 7),
  consumer_context_tag smallint NOT NULL CHECK (consumer_context_tag BETWEEN 1 AND 3),
  phase smallint NOT NULL CHECK (phase BETWEEN 1 AND 7),
  allocation_revision text NOT NULL CHECK (octet_length(allocation_revision) BETWEEN 1 AND 1024),
  allocation_fence object_store_retention.uint64 NOT NULL CHECK (allocation_fence > 0),
  cell_admission_id text CHECK (
    cell_admission_id IS NULL OR octet_length(cell_admission_id) BETWEEN 1 AND 1024
  ),
  cell_admission_fence object_store_retention.uint64,
  admission_clock_unix_ms bigint NOT NULL CHECK (admission_clock_unix_ms >= 0),
  deadline_unix_ms bigint NOT NULL CHECK (deadline_unix_ms >= 0),
  allocation_hard_expiry_unix_ms bigint NOT NULL CHECK (allocation_hard_expiry_unix_ms >= 0),
  request_state_canonical_bytes bytea NOT NULL
    CHECK (octet_length(request_state_canonical_bytes) BETWEEN 33 AND 16777216),
  request_state_blake3 object_store_retention.blake3_256 NOT NULL,
  put_submit_binding_bytes bytea,
  put_submit_binding_blake3 object_store_retention.blake3_256,
  reserve_put_ack_canonical_bytes bytea,
  reserve_put_ack_blake3 object_store_retention.blake3_256,
  terminal_result_id text CHECK (
    terminal_result_id IS NULL OR octet_length(terminal_result_id) BETWEEN 1 AND 1024
  ),
  terminal_result_tag smallint CHECK (terminal_result_tag BETWEEN 1 AND 8),
  terminal_result_canonical_bytes bytea CHECK (
    terminal_result_canonical_bytes IS NULL OR
    octet_length(terminal_result_canonical_bytes) BETWEEN 1 AND 16777216
  ),
  terminal_result_blake3 object_store_retention.blake3_256,
  terminal_result_size object_store_retention.uint64,
  byte_result_handle text CHECK (
    byte_result_handle IS NULL OR octet_length(byte_result_handle) BETWEEN 1 AND 4096
  ),
  payload_size object_store_retention.uint64,
  payload_blake3 object_store_retention.blake3_256,
  terminal_retryability smallint NOT NULL CHECK (terminal_retryability BETWEEN 1 AND 3),
  result_disposition smallint NOT NULL CHECK (result_disposition BETWEEN 1 AND 4),
  put_payload_availability smallint NOT NULL CHECK (put_payload_availability BETWEEN 1 AND 4),
  result_payload_availability smallint NOT NULL CHECK (result_payload_availability BETWEEN 1 AND 4),
  dispatch_attempt_blake3 object_store_retention.blake3_256,
  no_dispatch_reason smallint CHECK (no_dispatch_reason BETWEEN 1 AND 8),
  no_dispatch_proof_canonical_bytes bytea,
  no_dispatch_proof_blake3 object_store_retention.blake3_256,
  closure_committed_at_unix_ms bigint CHECK (closure_committed_at_unix_ms >= 0),
  submit_receipt_canonical_bytes bytea NOT NULL
    CHECK (octet_length(submit_receipt_canonical_bytes) BETWEEN 33 AND 16777216),
  submit_receipt_blake3 object_store_retention.blake3_256 NOT NULL,
  get_outcome_canonical_bytes bytea NOT NULL
    CHECK (octet_length(get_outcome_canonical_bytes) BETWEEN 33 AND 16777216),
  get_outcome_blake3 object_store_retention.blake3_256 NOT NULL,
  quota_revision object_store_retention.uint64 NOT NULL CHECK (quota_revision > 0),
  fetch_head_state smallint CHECK (fetch_head_state BETWEEN 1 AND 5),
  fetch_fence_generation object_store_retention.uint64,
  fetch_open_lease_count object_store_retention.uint64,
  fetch_head_revision object_store_retention.uint64,
  fetch_head_committed_at_unix_ms bigint CHECK (fetch_head_committed_at_unix_ms >= 0),
  fetch_head_canonical_bytes bytea,
  fetch_head_blake3 object_store_retention.blake3_256,
  row_revision object_store_retention.uint64 NOT NULL CHECK (row_revision > 0),
  state_committed_at_unix_ms bigint NOT NULL CHECK (state_committed_at_unix_ms >= 0),
  created_at_unix_ms bigint NOT NULL CHECK (created_at_unix_ms >= 0),
  PRIMARY KEY (logical_request_id, attempt_id),
  UNIQUE (provider_boundary_id, logical_request_id, attempt_id),
  UNIQUE (provider_boundary_id, authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id),
  UNIQUE (logical_request_id, attempt_id, terminal_result_id),
  UNIQUE (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id,
    terminal_result_id
  ),
  CHECK (
    (get_byte(uuid_send(logical_request_id), 6) >> 4) = 7 AND
    (get_byte(uuid_send(logical_request_id), 8) >> 6) = 2
  ),
  CHECK (
    logical_request_uuid_unix_ms =
      get_byte(uuid_send(logical_request_id), 0)::numeric * 1099511627776 +
      get_byte(uuid_send(logical_request_id), 1)::numeric * 4294967296 +
      get_byte(uuid_send(logical_request_id), 2)::numeric * 16777216 +
      get_byte(uuid_send(logical_request_id), 3)::numeric * 65536 +
      get_byte(uuid_send(logical_request_id), 4)::numeric * 256 +
      get_byte(uuid_send(logical_request_id), 5)::numeric
  ),
  CHECK (
    (get_byte(uuid_send(attempt_id), 6) >> 4) = 7 AND
    (get_byte(uuid_send(attempt_id), 8) >> 6) = 2
  ),
  CHECK (
    attempt_uuid_unix_ms =
      get_byte(uuid_send(attempt_id), 0)::numeric * 1099511627776 +
      get_byte(uuid_send(attempt_id), 1)::numeric * 4294967296 +
      get_byte(uuid_send(attempt_id), 2)::numeric * 16777216 +
      get_byte(uuid_send(attempt_id), 3)::numeric * 65536 +
      get_byte(uuid_send(attempt_id), 4)::numeric * 256 +
      get_byte(uuid_send(attempt_id), 5)::numeric
  ),
  UNIQUE (
    logical_request_id,
    attempt_id,
    terminal_result_id,
    terminal_result_size,
    terminal_result_blake3,
    byte_result_handle,
    payload_size,
    payload_blake3
  ),
  CHECK (
    (operation_tag = 5 AND put_reservation_fingerprint IS NOT NULL) OR
    (operation_tag <> 5 AND put_reservation_fingerprint IS NULL)
  ),
  CHECK (num_nonnulls(cell_admission_id, cell_admission_fence) IN (0, 2)),
  CHECK (cell_admission_fence IS NULL OR cell_admission_fence > 0),
  CHECK (admission_clock_unix_ms < deadline_unix_ms),
  CHECK (deadline_unix_ms <= allocation_hard_expiry_unix_ms),
  CHECK (state_committed_at_unix_ms >= admission_clock_unix_ms),
  CHECK (created_at_unix_ms = admission_clock_unix_ms),
  CHECK (
    (phase IN (1, 2) AND dispatch_attempt_blake3 IS NULL AND terminal_result_id IS NULL AND no_dispatch_reason IS NULL AND no_dispatch_proof_canonical_bytes IS NULL AND closure_committed_at_unix_ms IS NULL) OR
    (phase IN (3, 4) AND dispatch_attempt_blake3 IS NOT NULL AND terminal_result_id IS NULL AND no_dispatch_reason IS NULL AND no_dispatch_proof_canonical_bytes IS NULL AND closure_committed_at_unix_ms IS NULL) OR
    (phase = 5 AND dispatch_attempt_blake3 IS NOT NULL AND terminal_result_id IS NOT NULL AND no_dispatch_reason IS NULL AND no_dispatch_proof_canonical_bytes IS NULL AND closure_committed_at_unix_ms IS NOT NULL) OR
    (phase = 6 AND dispatch_attempt_blake3 IS NULL AND terminal_result_id IS NULL AND no_dispatch_reason IS NOT NULL AND no_dispatch_reason <> 4 AND no_dispatch_proof_canonical_bytes IS NOT NULL AND closure_committed_at_unix_ms IS NOT NULL) OR
    (phase = 7 AND dispatch_attempt_blake3 IS NULL AND terminal_result_id IS NULL AND no_dispatch_reason = 4 AND no_dispatch_proof_canonical_bytes IS NOT NULL AND closure_committed_at_unix_ms IS NOT NULL)
  ),
  CHECK (closure_committed_at_unix_ms IS NULL OR closure_committed_at_unix_ms >= admission_clock_unix_ms),
  CHECK (
    num_nonnulls(
      put_submit_binding_bytes,
      put_submit_binding_blake3,
      reserve_put_ack_canonical_bytes,
      reserve_put_ack_blake3
    ) IN (0, 4) AND
    (operation_tag = 5) = (put_submit_binding_bytes IS NOT NULL)
  ),
  CHECK (put_submit_binding_bytes IS NULL OR octet_length(put_submit_binding_bytes) BETWEEN 33 AND 16777216),
  CHECK (
    reserve_put_ack_canonical_bytes IS NULL OR
    octet_length(reserve_put_ack_canonical_bytes) BETWEEN 33 AND 16777216
  ),
  CHECK (
    num_nonnulls(
      terminal_result_id,
      terminal_result_tag,
      terminal_result_canonical_bytes,
      terminal_result_blake3,
      terminal_result_size
    ) IN (0, 5)
  ),
  CHECK (num_nonnulls(byte_result_handle, payload_size, payload_blake3) IN (0, 3)),
  CHECK (terminal_result_canonical_bytes IS NULL OR terminal_result_size = octet_length(terminal_result_canonical_bytes)),
  CHECK ((terminal_result_tag IS NOT DISTINCT FROM 7) = (byte_result_handle IS NOT NULL)),
  CHECK (num_nonnulls(no_dispatch_reason, no_dispatch_proof_canonical_bytes, no_dispatch_proof_blake3) IN (0, 3)),
  CHECK (
    no_dispatch_proof_canonical_bytes IS NULL OR
    octet_length(no_dispatch_proof_canonical_bytes) BETWEEN 33 AND 16777216
  ),
  CHECK (
    num_nonnulls(
      fetch_head_state,
      fetch_fence_generation,
      fetch_open_lease_count,
      fetch_head_revision,
      fetch_head_committed_at_unix_ms,
      fetch_head_canonical_bytes,
      fetch_head_blake3
    ) IN (0, 7)
  ),
  CHECK (fetch_fence_generation IS NULL OR fetch_fence_generation > 0),
  CHECK (fetch_head_revision IS NULL OR fetch_head_revision > 0),
  CHECK (fetch_head_canonical_bytes IS NULL OR octet_length(fetch_head_canonical_bytes) BETWEEN 33 AND 16777216),
  CHECK ((fetch_head_state IS NOT NULL) = (terminal_result_tag IS NOT DISTINCT FROM 7)),
  CHECK (substring(request_state_canonical_bytes FROM octet_length(request_state_canonical_bytes) - 31 FOR 32) = request_state_blake3),
  CHECK (no_dispatch_proof_canonical_bytes IS NULL OR substring(no_dispatch_proof_canonical_bytes FROM octet_length(no_dispatch_proof_canonical_bytes) - 31 FOR 32) = no_dispatch_proof_blake3),
  CHECK (put_submit_binding_bytes IS NULL OR substring(put_submit_binding_bytes FROM octet_length(put_submit_binding_bytes) - 31 FOR 32) = put_submit_binding_blake3),
  CHECK (reserve_put_ack_canonical_bytes IS NULL OR substring(reserve_put_ack_canonical_bytes FROM octet_length(reserve_put_ack_canonical_bytes) - 31 FOR 32) = reserve_put_ack_blake3),
  CHECK (submit_receipt_canonical_bytes IS NULL OR substring(submit_receipt_canonical_bytes FROM octet_length(submit_receipt_canonical_bytes) - 31 FOR 32) = submit_receipt_blake3),
  CHECK (get_outcome_canonical_bytes IS NULL OR substring(get_outcome_canonical_bytes FROM octet_length(get_outcome_canonical_bytes) - 31 FOR 32) = get_outcome_blake3),
  CHECK (fetch_head_canonical_bytes IS NULL OR substring(fetch_head_canonical_bytes FROM octet_length(fetch_head_canonical_bytes) - 31 FOR 32) = fetch_head_blake3)
);

CREATE INDEX object_dispatch_requests_deadline_idx
  ON object_store_retention.object_dispatch_requests (phase, deadline_unix_ms);
CREATE INDEX object_dispatch_requests_closure_idx
  ON object_store_retention.object_dispatch_requests (phase, closure_committed_at_unix_ms);
CREATE INDEX object_dispatch_requests_cell_state_idx
  ON object_store_retention.object_dispatch_requests
  (provider_boundary_id, authenticated_cell_id, phase);
CREATE INDEX object_dispatch_requests_tenant_state_idx
  ON object_store_retention.object_dispatch_requests
  (provider_boundary_id, authenticated_tenant_id, phase);
CREATE INDEX object_dispatch_requests_descriptor_idx
  ON object_store_retention.object_dispatch_requests (canonical_descriptor_fingerprint);
CREATE INDEX object_dispatch_requests_put_reservation_idx
  ON object_store_retention.object_dispatch_requests (put_reservation_fingerprint)
  WHERE put_reservation_fingerprint IS NOT NULL;

CREATE TABLE object_store_retention.object_dispatch_dispatchers (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-authority-schema-v1'),
  dispatcher_id text NOT NULL CHECK (octet_length(dispatcher_id) BETWEEN 1 AND 1024),
  lease_generation object_store_retention.uint64 NOT NULL CHECK (lease_generation > 0),
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  service_instance_id text NOT NULL CHECK (octet_length(service_instance_id) BETWEEN 1 AND 1024),
  dispatcher_fence object_store_retention.uint64 NOT NULL CHECK (dispatcher_fence > 0),
  authority_revision object_store_retention.uint64 NOT NULL CHECK (authority_revision > 0),
  allocation_revision text NOT NULL CHECK (octet_length(allocation_revision) BETWEEN 1 AND 1024),
  allocation_fence object_store_retention.uint64 NOT NULL CHECK (allocation_fence > 0),
  provider_credential_revision text NOT NULL CHECK (octet_length(provider_credential_revision) BETWEEN 1 AND 1024),
  state smallint NOT NULL CHECK (state BETWEEN 1 AND 3),
  acquired_at_unix_ms bigint NOT NULL CHECK (acquired_at_unix_ms >= 0),
  renewed_at_unix_ms bigint NOT NULL CHECK (renewed_at_unix_ms >= 0),
  expires_at_unix_ms bigint NOT NULL CHECK (expires_at_unix_ms >= 0),
  revocation_id text CHECK (
    revocation_id IS NULL OR octet_length(revocation_id) BETWEEN 1 AND 1024
  ),
  revocation_requested_at_unix_ms bigint CHECK (revocation_requested_at_unix_ms >= 0),
  revoked_at_unix_ms bigint CHECK (revoked_at_unix_ms >= 0),
  revocation_evidence_blake3 object_store_retention.blake3_256,
  state_changed_at_unix_ms bigint NOT NULL CHECK (state_changed_at_unix_ms >= 0),
  canonical_record_bytes bytea NOT NULL
    CHECK (octet_length(canonical_record_bytes) BETWEEN 33 AND 16777216),
  record_blake3 object_store_retention.blake3_256 NOT NULL,
  PRIMARY KEY (provider_boundary_id, lease_generation),
  UNIQUE (provider_boundary_id, dispatcher_id, lease_generation),
  CHECK (renewed_at_unix_ms >= acquired_at_unix_ms),
  CHECK (expires_at_unix_ms > renewed_at_unix_ms),
  CHECK (state_changed_at_unix_ms >= acquired_at_unix_ms),
  CHECK (
    (state = 1 AND num_nonnulls(revocation_id, revocation_requested_at_unix_ms, revoked_at_unix_ms, revocation_evidence_blake3) = 0) OR
    (state = 2 AND num_nonnulls(revocation_id, revocation_requested_at_unix_ms) = 2 AND revoked_at_unix_ms IS NULL AND revocation_evidence_blake3 IS NULL) OR
    (state = 3 AND num_nonnulls(revocation_id, revocation_requested_at_unix_ms, revoked_at_unix_ms, revocation_evidence_blake3) = 4)
  ),
  CHECK (revocation_requested_at_unix_ms IS NULL OR revocation_requested_at_unix_ms >= acquired_at_unix_ms),
  CHECK (revoked_at_unix_ms IS NULL OR revoked_at_unix_ms >= revocation_requested_at_unix_ms),
  CHECK (substring(canonical_record_bytes FROM octet_length(canonical_record_bytes) - 31 FOR 32) = record_blake3)
);

CREATE UNIQUE INDEX object_dispatch_dispatchers_one_active_generation_idx
  ON object_store_retention.object_dispatch_dispatchers (provider_boundary_id)
  WHERE state = 1;

CREATE INDEX object_dispatch_dispatchers_expiry_idx
  ON object_store_retention.object_dispatch_dispatchers (state, expires_at_unix_ms);
CREATE INDEX object_dispatch_dispatchers_service_idx
  ON object_store_retention.object_dispatch_dispatchers (service_instance_id, state);

CREATE TABLE object_store_retention.object_dispatch_attempts (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-authority-schema-v1'),
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  provider_grant_id text NOT NULL CHECK (octet_length(provider_grant_id) BETWEEN 1 AND 1024),
  provider_grant_fence object_store_retention.uint64 NOT NULL CHECK (provider_grant_fence > 0),
  grant_canonical_bytes bytea NOT NULL
    CHECK (octet_length(grant_canonical_bytes) BETWEEN 33 AND 16777216),
  grant_blake3 object_store_retention.blake3_256 NOT NULL,
  dispatcher_id text NOT NULL CHECK (octet_length(dispatcher_id) BETWEEN 1 AND 1024),
  dispatcher_lease_generation object_store_retention.uint64 NOT NULL
    CHECK (dispatcher_lease_generation > 0),
  provider_credential_revision text NOT NULL
    CHECK (octet_length(provider_credential_revision) BETWEEN 1 AND 1024),
  attempt_state smallint NOT NULL CHECK (attempt_state BETWEEN 1 AND 5),
  provider_attempt_id text CHECK (
    provider_attempt_id IS NULL OR octet_length(provider_attempt_id) BETWEEN 1 AND 1024
  ),
  dispatch_started_at_unix_ms bigint CHECK (dispatch_started_at_unix_ms >= 0),
  ambiguity_recorded_at_unix_ms bigint CHECK (ambiguity_recorded_at_unix_ms >= 0),
  terminal_recorded_at_unix_ms bigint CHECK (terminal_recorded_at_unix_ms >= 0),
  terminal_result_id text CHECK (
    terminal_result_id IS NULL OR octet_length(terminal_result_id) BETWEEN 1 AND 1024
  ),
  attempt_canonical_bytes bytea,
  attempt_blake3 object_store_retention.blake3_256,
  no_dispatch_proof_blake3 object_store_retention.blake3_256,
  provider_authority_refunded boolean NOT NULL DEFAULT false CHECK (NOT provider_authority_refunded),
  grant_committed_at_unix_ms bigint NOT NULL CHECK (grant_committed_at_unix_ms >= 0),
  attempt_revision object_store_retention.uint64 NOT NULL CHECK (attempt_revision > 0),
  state_changed_at_unix_ms bigint NOT NULL CHECK (state_changed_at_unix_ms >= 0),
  PRIMARY KEY (provider_grant_id),
  UNIQUE (logical_request_id, attempt_id),
  UNIQUE (provider_attempt_id),
  FOREIGN KEY (logical_request_id, attempt_id)
    REFERENCES object_store_retention.object_dispatch_requests (logical_request_id, attempt_id),
  FOREIGN KEY (provider_boundary_id, logical_request_id, attempt_id)
    REFERENCES object_store_retention.object_dispatch_requests
      (provider_boundary_id, logical_request_id, attempt_id),
  FOREIGN KEY (logical_request_id, attempt_id, terminal_result_id)
    REFERENCES object_store_retention.object_dispatch_requests
      (logical_request_id, attempt_id, terminal_result_id),
  FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
    REFERENCES object_store_retention.object_dispatch_dispatchers
      (provider_boundary_id, dispatcher_id, lease_generation),
  CHECK (
    (attempt_state = 1 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, ambiguity_recorded_at_unix_ms, terminal_recorded_at_unix_ms, terminal_result_id, attempt_canonical_bytes, attempt_blake3, no_dispatch_proof_blake3) = 0) OR
    (attempt_state = 2 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, attempt_canonical_bytes, attempt_blake3) = 4 AND num_nonnulls(ambiguity_recorded_at_unix_ms, terminal_recorded_at_unix_ms, terminal_result_id, no_dispatch_proof_blake3) = 0) OR
    (attempt_state = 3 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, ambiguity_recorded_at_unix_ms, attempt_canonical_bytes, attempt_blake3) = 5 AND num_nonnulls(terminal_recorded_at_unix_ms, terminal_result_id, no_dispatch_proof_blake3) = 0) OR
    (attempt_state = 4 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, terminal_recorded_at_unix_ms, terminal_result_id, attempt_canonical_bytes, attempt_blake3) = 6 AND no_dispatch_proof_blake3 IS NULL) OR
    (attempt_state = 5 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, ambiguity_recorded_at_unix_ms, terminal_recorded_at_unix_ms, terminal_result_id, attempt_canonical_bytes, attempt_blake3) = 0 AND no_dispatch_proof_blake3 IS NOT NULL)
  ),
  CHECK (attempt_canonical_bytes IS NULL OR octet_length(attempt_canonical_bytes) BETWEEN 33 AND 16777216),
  CHECK (ambiguity_recorded_at_unix_ms IS NULL OR ambiguity_recorded_at_unix_ms >= dispatch_started_at_unix_ms),
  CHECK (dispatch_started_at_unix_ms IS NULL OR dispatch_started_at_unix_ms >= grant_committed_at_unix_ms),
  CHECK (terminal_recorded_at_unix_ms IS NULL OR terminal_recorded_at_unix_ms >= dispatch_started_at_unix_ms),
  CHECK (state_changed_at_unix_ms >= grant_committed_at_unix_ms),
  CHECK (substring(grant_canonical_bytes FROM octet_length(grant_canonical_bytes) - 31 FOR 32) = grant_blake3),
  CHECK (attempt_canonical_bytes IS NULL OR substring(attempt_canonical_bytes FROM octet_length(attempt_canonical_bytes) - 31 FOR 32) = attempt_blake3)
);

CREATE INDEX object_dispatch_attempts_request_state_idx
  ON object_store_retention.object_dispatch_attempts
  (logical_request_id, attempt_id, attempt_state);
CREATE INDEX object_dispatch_attempts_grant_state_idx
  ON object_store_retention.object_dispatch_attempts (attempt_state, grant_committed_at_unix_ms);
CREATE INDEX object_dispatch_attempts_dispatcher_state_idx
  ON object_store_retention.object_dispatch_attempts
  (provider_boundary_id, dispatcher_lease_generation, attempt_state);

CREATE TABLE object_store_retention.object_dispatch_spool_objects (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-authority-schema-v1'),
  spool_object_id uuid NOT NULL UNIQUE,
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  authenticated_cell_id text NOT NULL CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  authenticated_tenant_id text NOT NULL CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  bound_request_logical_request_id uuid,
  bound_request_attempt_id uuid,
  request_binding_state smallint NOT NULL CHECK (request_binding_state IN (1, 2)),
  payload_kind smallint NOT NULL CHECK (payload_kind IN (1, 2)),
  lifecycle_state smallint NOT NULL CHECK (lifecycle_state BETWEEN 1 AND 3),
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  terminal_result_id text CHECK (
    terminal_result_id IS NULL OR octet_length(terminal_result_id) BETWEEN 1 AND 1024
  ),
  durable_handle text CHECK (
    durable_handle IS NULL OR octet_length(durable_handle) BETWEEN 1 AND 4096
  ),
  boundary_blake3 object_store_retention.blake3_256 NOT NULL,
  boundary_token text NOT NULL CHECK (octet_length(boundary_token) BETWEEN 1 AND 4096),
  observation_binding_blake3 object_store_retention.blake3_256 NOT NULL,
  expected_size object_store_retention.uint64 NOT NULL,
  expected_blake3 object_store_retention.blake3_256 NOT NULL,
  committed_size object_store_retention.uint64,
  committed_blake3 object_store_retention.blake3_256,
  partial_temp_bytes object_store_retention.uint64 NOT NULL DEFAULT 0,
  partial_temp_chunks object_store_retention.uint64 NOT NULL DEFAULT 0,
  partial_temp_files object_store_retention.uint64 NOT NULL DEFAULT 0
    CHECK (partial_temp_files IN (0, 1)),
  quota_bytes object_store_retention.uint64 NOT NULL,
  quota_rows object_store_retention.uint64 NOT NULL,
  quota_concurrency object_store_retention.uint64 NOT NULL,
  quota_revision object_store_retention.uint64 NOT NULL CHECK (quota_revision > 0),
  purge_state smallint NOT NULL CHECK (purge_state BETWEEN 1 AND 4),
  expires_at_unix_ms bigint CHECK (expires_at_unix_ms >= 0),
  purge_eligible_at_unix_ms bigint CHECK (purge_eligible_at_unix_ms >= 0),
  release_reason smallint CHECK (release_reason BETWEEN 1 AND 5),
  release_receipt_bytes bytea,
  release_receipt_blake3 object_store_retention.blake3_256,
  canonical_record_bytes bytea NOT NULL
    CHECK (octet_length(canonical_record_bytes) BETWEEN 33 AND 16777216),
  record_blake3 object_store_retention.blake3_256 NOT NULL,
  spool_revision object_store_retention.uint64 NOT NULL CHECK (spool_revision > 0),
  created_at_unix_ms bigint NOT NULL CHECK (created_at_unix_ms >= 0),
  ready_at_unix_ms bigint CHECK (ready_at_unix_ms >= 0),
  purged_at_unix_ms bigint CHECK (purged_at_unix_ms >= 0),
  PRIMARY KEY (logical_request_id, attempt_id, payload_kind),
  UNIQUE (spool_object_id, logical_request_id, attempt_id, payload_kind),
  UNIQUE (
    spool_object_id,
    logical_request_id,
    attempt_id,
    payload_kind,
    durable_handle,
    expected_size,
    expected_blake3
  ),
  FOREIGN KEY (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    bound_request_logical_request_id,
    bound_request_attempt_id
  ) REFERENCES object_store_retention.object_dispatch_requests (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id
  ),
  FOREIGN KEY (bound_request_logical_request_id, bound_request_attempt_id, terminal_result_id)
    REFERENCES object_store_retention.object_dispatch_requests
      (logical_request_id, attempt_id, terminal_result_id),
  CHECK (num_nonnulls(bound_request_logical_request_id, bound_request_attempt_id) IN (0, 2)),
  CHECK (
    (request_binding_state = 1 AND payload_kind = 1 AND bound_request_logical_request_id IS NULL) OR
    (request_binding_state = 2 AND bound_request_logical_request_id IS NOT NULL)
  ),
  CHECK (bound_request_logical_request_id IS NULL OR bound_request_logical_request_id = logical_request_id),
  CHECK (bound_request_attempt_id IS NULL OR bound_request_attempt_id = attempt_id),
  CHECK (payload_kind = 1 OR bound_request_logical_request_id IS NOT NULL),
  CHECK (
    (payload_kind = 1 AND num_nonnulls(upload_id, upload_fence) = 2 AND terminal_result_id IS NULL) OR
    (payload_kind = 2 AND upload_id IS NULL AND upload_fence IS NULL AND terminal_result_id IS NOT NULL)
  ),
  CHECK (upload_fence IS NULL OR upload_fence > 0),
  CHECK (
    (get_byte(uuid_send(spool_object_id), 6) >> 4) = 7 AND
    (get_byte(uuid_send(spool_object_id), 8) >> 6) = 2
  ),
  CHECK (
    (get_byte(uuid_send(logical_request_id), 6) >> 4) = 7 AND
    (get_byte(uuid_send(logical_request_id), 8) >> 6) = 2 AND
    (get_byte(uuid_send(attempt_id), 6) >> 4) = 7 AND
    (get_byte(uuid_send(attempt_id), 8) >> 6) = 2
  ),
  CHECK (
    upload_id IS NULL OR
    ((get_byte(uuid_send(upload_id), 6) >> 4) = 7 AND (get_byte(uuid_send(upload_id), 8) >> 6) = 2)
  ),
  CHECK (num_nonnulls(committed_size, committed_blake3, durable_handle, ready_at_unix_ms) IN (0, 4)),
  CHECK (
    (lifecycle_state = 1 AND committed_size IS NULL AND partial_temp_files IN (0, 1) AND purged_at_unix_ms IS NULL) OR
    (lifecycle_state = 2 AND committed_size IS NOT NULL AND partial_temp_files = 0 AND purged_at_unix_ms IS NULL) OR
    (lifecycle_state = 3 AND partial_temp_files = 0 AND purged_at_unix_ms IS NOT NULL)
  ),
  CHECK (committed_size IS NULL OR committed_size = expected_size),
  CHECK (committed_blake3 IS NULL OR committed_blake3 = expected_blake3),
  CHECK (partial_temp_bytes <= expected_size),
  CHECK (quota_bytes > 0 OR quota_rows > 0 OR quota_concurrency > 0),
  CHECK (ready_at_unix_ms IS NULL OR ready_at_unix_ms >= created_at_unix_ms),
  CHECK (purged_at_unix_ms IS NULL OR purged_at_unix_ms >= ready_at_unix_ms),
  CHECK (
    (lifecycle_state IN (1, 2) AND num_nonnulls(release_reason, release_receipt_bytes, release_receipt_blake3) = 0) OR
    (lifecycle_state = 3 AND num_nonnulls(release_reason, release_receipt_bytes, release_receipt_blake3) = 3)
  ),
  CHECK (release_receipt_bytes IS NULL OR octet_length(release_receipt_bytes) BETWEEN 33 AND 16777216),
  CHECK (substring(canonical_record_bytes FROM octet_length(canonical_record_bytes) - 31 FOR 32) = record_blake3),
  CHECK (release_receipt_bytes IS NULL OR substring(release_receipt_bytes FROM octet_length(release_receipt_bytes) - 31 FOR 32) = release_receipt_blake3)
);

CREATE UNIQUE INDEX object_dispatch_spool_objects_handle_idx
  ON object_store_retention.object_dispatch_spool_objects (durable_handle)
  WHERE durable_handle IS NOT NULL;

CREATE INDEX object_dispatch_spool_objects_purge_idx
  ON object_store_retention.object_dispatch_spool_objects
  (purge_state, purge_eligible_at_unix_ms, spool_object_id);
CREATE INDEX object_dispatch_spool_objects_expiry_idx
  ON object_store_retention.object_dispatch_spool_objects
  (lifecycle_state, expires_at_unix_ms, spool_object_id);
CREATE INDEX object_dispatch_spool_objects_cell_idx
  ON object_store_retention.object_dispatch_spool_objects
  (provider_boundary_id, authenticated_cell_id, lifecycle_state);
CREATE INDEX object_dispatch_spool_objects_tenant_idx
  ON object_store_retention.object_dispatch_spool_objects
  (provider_boundary_id, authenticated_tenant_id, lifecycle_state);

CREATE TABLE object_store_retention.object_dispatch_quota_usage (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-authority-schema-v1'),
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  scope_kind smallint NOT NULL CHECK (scope_kind IN (1, 2, 3)),
  scope_id text NOT NULL CHECK (octet_length(scope_id) BETWEEN 1 AND 1024),
  quota_class smallint NOT NULL CHECK (quota_class IN (1, 2, 3)),
  used_bytes object_store_retention.uint64 NOT NULL DEFAULT 0,
  used_rows object_store_retention.uint64 NOT NULL DEFAULT 0,
  used_concurrency object_store_retention.uint64 NOT NULL DEFAULT 0,
  counter_revision object_store_retention.uint64 NOT NULL CHECK (counter_revision > 0),
  updated_at_unix_ms bigint NOT NULL CHECK (updated_at_unix_ms >= 0),
  PRIMARY KEY (provider_boundary_id, scope_kind, scope_id, quota_class),
  CHECK (
    (scope_kind = 1 AND scope_id = provider_boundary_id) OR
    (scope_kind IN (2, 3) AND scope_id <> provider_boundary_id)
  ),
  CHECK (used_concurrency <= used_rows),
  CHECK (used_rows <> 0 OR (used_bytes = 0 AND used_concurrency = 0))
);

CREATE INDEX object_dispatch_quota_usage_class_idx
  ON object_store_retention.object_dispatch_quota_usage
  (provider_boundary_id, quota_class);
CREATE INDEX object_dispatch_quota_usage_scope_idx
  ON object_store_retention.object_dispatch_quota_usage (scope_kind, scope_id);

CREATE TABLE object_store_retention.object_dispatch_payload_purges (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-authority-schema-v1'),
  purge_id uuid PRIMARY KEY,
  spool_object_id uuid NOT NULL,
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  authenticated_cell_id text NOT NULL CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  authenticated_tenant_id text NOT NULL CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  payload_kind smallint NOT NULL CHECK (payload_kind IN (1, 2)),
  terminal_result_id text CHECK (
    terminal_result_id IS NULL OR octet_length(terminal_result_id) BETWEEN 1 AND 1024
  ),
  disposition smallint NOT NULL CHECK (disposition IN (1, 3, 4)),
  release_reason smallint NOT NULL CHECK (release_reason BETWEEN 1 AND 5),
  purge_state smallint NOT NULL CHECK (purge_state IN (1, 2)),
  purge_not_before_unix_ms bigint NOT NULL CHECK (purge_not_before_unix_ms >= 0),
  purge_fingerprint object_store_retention.blake3_256 NOT NULL UNIQUE,
  canonical_intent_bytes bytea NOT NULL
    CHECK (octet_length(canonical_intent_bytes) BETWEEN 1 AND 16777216),
  expected_request_state_blake3 object_store_retention.blake3_256 NOT NULL,
  expected_fetch_head_blake3 object_store_retention.blake3_256,
  reserved_fetch_head_blake3 object_store_retention.blake3_256,
  reserved_fetch_fence_generation object_store_retention.uint64,
  reserved_fetch_head_revision object_store_retention.uint64,
  reserved_open_lease_count object_store_retention.uint64,
  reservation_canonical_bytes bytea NOT NULL
    CHECK (octet_length(reservation_canonical_bytes) BETWEEN 33 AND 16777216),
  reservation_blake3 object_store_retention.blake3_256 NOT NULL,
  durable_handle text CHECK (
    durable_handle IS NULL OR octet_length(durable_handle) BETWEEN 1 AND 4096
  ),
  payload_size object_store_retention.uint64 NOT NULL,
  payload_blake3 object_store_retention.blake3_256 NOT NULL,
  released_bytes object_store_retention.uint64,
  released_rows object_store_retention.uint64,
  released_concurrency object_store_retention.uint64,
  provider_authority_refunded boolean NOT NULL DEFAULT false CHECK (NOT provider_authority_refunded),
  deleted_partial_temp_bytes object_store_retention.uint64 NOT NULL DEFAULT 0,
  deleted_partial_temp_files object_store_retention.uint64 NOT NULL DEFAULT 0
    CHECK (deleted_partial_temp_files IN (0, 1)),
  receipt_canonical_bytes bytea,
  receipt_blake3 object_store_retention.blake3_256,
  quota_revision object_store_retention.uint64,
  reserved_at_unix_ms bigint NOT NULL CHECK (reserved_at_unix_ms >= 0),
  purged_at_unix_ms bigint CHECK (purged_at_unix_ms >= 0),
  purge_revision object_store_retention.uint64 NOT NULL CHECK (purge_revision > 0),
  UNIQUE (logical_request_id, attempt_id, payload_kind),
  FOREIGN KEY (spool_object_id, logical_request_id, attempt_id, payload_kind)
    REFERENCES object_store_retention.object_dispatch_spool_objects
      (spool_object_id, logical_request_id, attempt_id, payload_kind),
  FOREIGN KEY (
    spool_object_id,
    logical_request_id,
    attempt_id,
    payload_kind,
    durable_handle,
    payload_size,
    payload_blake3
  ) REFERENCES object_store_retention.object_dispatch_spool_objects (
    spool_object_id,
    logical_request_id,
    attempt_id,
    payload_kind,
    durable_handle,
    expected_size,
    expected_blake3
  ),
  FOREIGN KEY (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id
  ) REFERENCES object_store_retention.object_dispatch_requests (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id
  ),
  FOREIGN KEY (logical_request_id, attempt_id, terminal_result_id)
    REFERENCES object_store_retention.object_dispatch_requests
      (logical_request_id, attempt_id, terminal_result_id),
  CHECK (
    (payload_kind = 1 AND terminal_result_id IS NULL AND disposition = 1 AND release_reason IN (3, 4, 5)) OR
    (terminal_result_id IS NOT NULL AND disposition IN (3, 4) AND release_reason IN (1, 2))
  ),
  CHECK (
    num_nonnulls(
      expected_fetch_head_blake3,
      reserved_fetch_head_blake3,
      reserved_fetch_fence_generation,
      reserved_fetch_head_revision,
      reserved_open_lease_count
    ) IN (0, 5)
  ),
  CHECK ((payload_kind = 2) = (expected_fetch_head_blake3 IS NOT NULL)),
  CHECK (
    (get_byte(uuid_send(purge_id), 6) >> 4) = 7 AND
    (get_byte(uuid_send(purge_id), 8) >> 6) = 2
  ),
  CHECK (payload_kind = 1 OR durable_handle IS NOT NULL),
  CHECK (reserved_fetch_fence_generation IS NULL OR reserved_fetch_fence_generation > 0),
  CHECK (reserved_fetch_head_revision IS NULL OR reserved_fetch_head_revision > 0),
  CHECK (
    (purge_state = 1 AND num_nonnulls(receipt_canonical_bytes, receipt_blake3, released_bytes, released_rows, released_concurrency, quota_revision, purged_at_unix_ms) = 0) OR
    (purge_state = 2 AND num_nonnulls(receipt_canonical_bytes, receipt_blake3, released_bytes, released_rows, released_concurrency, quota_revision, purged_at_unix_ms) = 7)
  ),
  CHECK (receipt_canonical_bytes IS NULL OR octet_length(receipt_canonical_bytes) BETWEEN 33 AND 16777216),
  CHECK (purged_at_unix_ms IS NULL OR purged_at_unix_ms >= purge_not_before_unix_ms),
  CHECK (purged_at_unix_ms IS NULL OR purged_at_unix_ms >= reserved_at_unix_ms),
  CHECK (substring(reservation_canonical_bytes FROM octet_length(reservation_canonical_bytes) - 31 FOR 32) = reservation_blake3),
  CHECK (receipt_canonical_bytes IS NULL OR substring(receipt_canonical_bytes FROM octet_length(receipt_canonical_bytes) - 31 FOR 32) = receipt_blake3)
);

CREATE INDEX object_dispatch_payload_purges_due_idx
  ON object_store_retention.object_dispatch_payload_purges
  (purge_state, purge_not_before_unix_ms, purge_id);
CREATE INDEX object_dispatch_payload_purges_cell_idx
  ON object_store_retention.object_dispatch_payload_purges
  (provider_boundary_id, authenticated_cell_id, purge_state);

CREATE TABLE object_store_retention.object_dispatch_fetch_leases (
  schema_revision text NOT NULL
    CHECK (schema_revision = 'object-store-dispatch-authority-schema-v1'),
  lease_id uuid PRIMARY KEY,
  provider_boundary_id text NOT NULL CHECK (octet_length(provider_boundary_id) BETWEEN 1 AND 1024),
  authenticated_cell_id text NOT NULL CHECK (octet_length(authenticated_cell_id) BETWEEN 1 AND 1024),
  authenticated_tenant_id text NOT NULL CHECK (octet_length(authenticated_tenant_id) BETWEEN 1 AND 1024),
  logical_request_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  terminal_result_id text NOT NULL CHECK (octet_length(terminal_result_id) BETWEEN 1 AND 1024),
  canonical_result_size object_store_retention.uint64 NOT NULL,
  canonical_result_blake3 object_store_retention.blake3_256 NOT NULL,
  byte_result_handle text NOT NULL CHECK (octet_length(byte_result_handle) BETWEEN 1 AND 4096),
  payload_size object_store_retention.uint64 NOT NULL,
  payload_blake3 object_store_retention.blake3_256 NOT NULL,
  owner_service_instance_id text NOT NULL
    CHECK (octet_length(owner_service_instance_id) BETWEEN 1 AND 1024),
  owner_generation object_store_retention.uint64 NOT NULL CHECK (owner_generation > 0),
  owner_authority_revision object_store_retention.uint64 NOT NULL
    CHECK (owner_authority_revision > 0),
  authenticated_principal_id text NOT NULL
    CHECK (octet_length(authenticated_principal_id) BETWEEN 1 AND 1024),
  authenticated_scope text NOT NULL CHECK (octet_length(authenticated_scope) BETWEEN 1 AND 4096),
  canonical_descriptor_fingerprint object_store_retention.blake3_256 NOT NULL,
  caller_fence object_store_retention.uint64 NOT NULL CHECK (caller_fence > 0),
  admitted_generation object_store_retention.uint64 NOT NULL CHECK (admitted_generation > 0),
  open_fingerprint object_store_retention.blake3_256 NOT NULL,
  next_chunk_index object_store_retention.uint64 NOT NULL,
  lease_revision object_store_retention.uint64 NOT NULL CHECK (lease_revision > 0),
  opened_at_unix_ms bigint NOT NULL CHECK (opened_at_unix_ms >= 0),
  state smallint NOT NULL CHECK (state BETWEEN 1 AND 3),
  terminal_reason smallint CHECK (terminal_reason BETWEEN 1 AND 6),
  terminal_at_unix_ms bigint CHECK (terminal_at_unix_ms >= 0),
  terminal_fingerprint object_store_retention.blake3_256,
  owner_revocation_canonical_bytes bytea,
  owner_revocation_blake3 object_store_retention.blake3_256,
  canonical_lease_bytes bytea NOT NULL
    CHECK (octet_length(canonical_lease_bytes) BETWEEN 33 AND 16777216),
  lease_blake3 object_store_retention.blake3_256 NOT NULL,
  UNIQUE (logical_request_id, attempt_id, terminal_result_id, lease_id),
  FOREIGN KEY (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id,
    terminal_result_id
  )
    REFERENCES object_store_retention.object_dispatch_requests
      (
        provider_boundary_id,
        authenticated_cell_id,
        authenticated_tenant_id,
        logical_request_id,
        attempt_id,
        terminal_result_id
      ),
  FOREIGN KEY (
    logical_request_id,
    attempt_id,
    terminal_result_id,
    canonical_result_size,
    canonical_result_blake3,
    byte_result_handle,
    payload_size,
    payload_blake3
  ) REFERENCES object_store_retention.object_dispatch_requests (
    logical_request_id,
    attempt_id,
    terminal_result_id,
    terminal_result_size,
    terminal_result_blake3,
    byte_result_handle,
    payload_size,
    payload_blake3
  ),
  CHECK (
    (state = 1 AND num_nonnulls(terminal_reason, terminal_at_unix_ms, terminal_fingerprint, owner_revocation_canonical_bytes, owner_revocation_blake3) = 0) OR
    (state = 2 AND terminal_reason = 1 AND num_nonnulls(terminal_at_unix_ms, terminal_fingerprint) = 2 AND num_nonnulls(owner_revocation_canonical_bytes, owner_revocation_blake3) = 0) OR
    (state = 3 AND terminal_reason IN (2, 3, 4, 5, 6) AND num_nonnulls(terminal_at_unix_ms, terminal_fingerprint) = 2 AND ((terminal_reason = 5 AND num_nonnulls(owner_revocation_canonical_bytes, owner_revocation_blake3) = 2) OR (terminal_reason <> 5 AND num_nonnulls(owner_revocation_canonical_bytes, owner_revocation_blake3) = 0)))
  ),
  CHECK (terminal_at_unix_ms IS NULL OR terminal_at_unix_ms >= opened_at_unix_ms),
  CHECK (
    (get_byte(uuid_send(lease_id), 6) >> 4) = 7 AND
    (get_byte(uuid_send(lease_id), 8) >> 6) = 2
  ),
  CHECK (num_nonnulls(owner_revocation_canonical_bytes, owner_revocation_blake3) IN (0, 2)),
  CHECK (owner_revocation_canonical_bytes IS NULL OR octet_length(owner_revocation_canonical_bytes) BETWEEN 33 AND 16777216),
  CHECK (substring(canonical_lease_bytes FROM octet_length(canonical_lease_bytes) - 31 FOR 32) = lease_blake3),
  CHECK (owner_revocation_canonical_bytes IS NULL OR substring(owner_revocation_canonical_bytes FROM octet_length(owner_revocation_canonical_bytes) - 31 FOR 32) = owner_revocation_blake3)
);

CREATE INDEX object_dispatch_fetch_leases_open_idx
  ON object_store_retention.object_dispatch_fetch_leases
  (logical_request_id, attempt_id, terminal_result_id, admitted_generation)
  WHERE state = 1;

CREATE INDEX object_dispatch_fetch_leases_owner_idx
  ON object_store_retention.object_dispatch_fetch_leases
  (owner_service_instance_id, owner_generation, state);
CREATE INDEX object_dispatch_fetch_leases_state_time_idx
  ON object_store_retention.object_dispatch_fetch_leases (state, opened_at_unix_ms);

REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

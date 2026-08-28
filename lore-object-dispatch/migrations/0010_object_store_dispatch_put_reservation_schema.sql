-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-121 Phase 2 source-dark pre-Submit PUT-reservation schema edge.
-- Runtime code never installs this artifact. Later provisioning must install and attest it.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

ALTER TABLE object_store_retention.object_dispatch_spool_objects
  ADD COLUMN protocol_revision text,
  ADD COLUMN policy_revision text,
  ADD COLUMN put_reservation_fingerprint object_store_retention.blake3_256,
  ADD COLUMN allocation_revision text,
  ADD COLUMN allocation_fence object_store_retention.uint64,
  ADD COLUMN reservation_deadline_unix_ms bigint,
  ADD COLUMN allocation_hard_expiry_unix_ms bigint,
  ADD COLUMN admission_clock_unix_ms bigint,
  ADD COLUMN prepared_ttl_ms bigint,
  ADD COLUMN max_chunk_bytes object_store_retention.uint64,
  ADD COLUMN reserve_put_ack_canonical_bytes bytea,
  ADD COLUMN reserve_put_ack_blake3 object_store_retention.blake3_256;

ALTER TABLE object_store_retention.object_dispatch_spool_objects
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
        reserve_put_ack_canonical_bytes,
        reserve_put_ack_blake3
      ) = 12 AND
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
        reserve_put_ack_canonical_bytes,
        reserve_put_ack_blake3
      ) = 0
    )
  ),
  ADD CONSTRAINT object_dispatch_spool_objects_put_reservation_identity_ck CHECK (
    payload_kind <> 1 OR (
      pg_catalog.octet_length(protocol_revision) BETWEEN 1 AND 1024 AND
      protocol_revision IS NOT DISTINCT FROM pg_catalog.normalize(protocol_revision, 'NFC') AND
      pg_catalog.octet_length(policy_revision) BETWEEN 1 AND 1024 AND
      policy_revision IS NOT DISTINCT FROM pg_catalog.normalize(policy_revision, 'NFC') AND
      pg_catalog.octet_length(allocation_revision) BETWEEN 1 AND 1024 AND
      allocation_revision IS NOT DISTINCT FROM pg_catalog.normalize(allocation_revision, 'NFC') AND
      allocation_fence > 0 AND
      max_chunk_bytes > 0
    )
  ),
  ADD CONSTRAINT object_dispatch_spool_objects_put_reservation_time_ck CHECK (
    payload_kind <> 1 OR (
      admission_clock_unix_ms >= 0 AND
      reservation_deadline_unix_ms > admission_clock_unix_ms AND
      allocation_hard_expiry_unix_ms > admission_clock_unix_ms AND
      prepared_ttl_ms > 0 AND
      admission_clock_unix_ms::numeric + prepared_ttl_ms::numeric <= 9223372036854775807 AND
      expires_at_unix_ms > admission_clock_unix_ms AND
      expires_at_unix_ms <= reservation_deadline_unix_ms AND
      expires_at_unix_ms <= allocation_hard_expiry_unix_ms AND
      expires_at_unix_ms - admission_clock_unix_ms <= prepared_ttl_ms AND
      (
        expires_at_unix_ms = reservation_deadline_unix_ms OR
        expires_at_unix_ms = allocation_hard_expiry_unix_ms OR
        expires_at_unix_ms - admission_clock_unix_ms = prepared_ttl_ms
      ) AND
      created_at_unix_ms = admission_clock_unix_ms
    )
  ),
  ADD CONSTRAINT object_dispatch_spool_objects_put_reservation_ack_ck CHECK (
    payload_kind <> 1 OR (
      pg_catalog.octet_length(reserve_put_ack_canonical_bytes) BETWEEN 33 AND 16777216 AND
      pg_catalog.substring(
        reserve_put_ack_canonical_bytes,
        pg_catalog.octet_length(reserve_put_ack_canonical_bytes) - 31,
        32
      ) = reserve_put_ack_blake3
    )
  );

CREATE INDEX object_dispatch_spool_objects_put_reservation_lookup_idx
  ON object_store_retention.object_dispatch_spool_objects (
    provider_boundary_id,
    authenticated_cell_id,
    authenticated_tenant_id,
    logical_request_id,
    attempt_id,
    put_reservation_fingerprint
  )
  WHERE payload_kind = 1;

REVOKE ALL ON TABLE object_store_retention.object_dispatch_spool_objects FROM PUBLIC;
REVOKE ALL ON TABLE object_store_retention.object_dispatch_spool_objects FROM
  object_dispatch_retention_runtime,
  object_dispatch_retention_maintenance,
  object_dispatch_retention_migrator;

COMMIT;

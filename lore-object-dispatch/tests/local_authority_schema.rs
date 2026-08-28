// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::local_authority_schema::LOCAL_AUTHORITY_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_schema::LOCAL_AUTHORITY_MIGRATION_V1;
use lore_object_dispatch::local_authority_schema::LOCAL_AUTHORITY_SCHEMA_REVISION_V1;
use lore_object_dispatch::local_authority_schema::validate_embedded_local_authority_migration_v1;

const EXPECTED_MIGRATION_BYTES: usize = 42_294;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_MIGRATION_V1)
        .expect("local authority migration must remain UTF-8 SQL")
}

fn assert_contains_all(sql: &str, expected: &[&str]) {
    for token in expected {
        assert!(sql.contains(token), "missing schema token: {token}");
    }
}

#[test]
fn embedded_migration_has_exact_frozen_identity() {
    assert_eq!(
        LOCAL_AUTHORITY_SCHEMA_REVISION_V1,
        "object-store-dispatch-authority-schema-v1"
    );
    assert_eq!(LOCAL_AUTHORITY_MIGRATION_V1.len(), EXPECTED_MIGRATION_BYTES);
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_MIGRATION_V1).to_hex().as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_migration_v1());
}

#[test]
fn migration_is_lf_normalized_and_one_owner_transaction() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n"));
    assert!(sql.ends_with("\nCOMMIT;\n"));
    assert_eq!(sql.matches("\nBEGIN;\n").count(), 1);
    assert_eq!(sql.matches("\nCOMMIT;\n").count(), 1);
    assert_eq!(
        sql.matches("SET LOCAL ROLE object_dispatch_retention_owner;")
            .count(),
        1
    );
    assert!(!LOCAL_AUTHORITY_MIGRATION_V1.contains(&b'\r'));
    assert!(
        include_str!("../../.gitattributes")
            .lines()
            .any(|line| line == "lore-object-dispatch/migrations/*.sql text eol=lf")
    );
}

#[test]
fn migration_declares_exactly_the_seven_local_authority_tables() {
    let sql = migration();
    let tables = [
        "object_dispatch_requests",
        "object_dispatch_dispatchers",
        "object_dispatch_attempts",
        "object_dispatch_spool_objects",
        "object_dispatch_quota_usage",
        "object_dispatch_payload_purges",
        "object_dispatch_fetch_leases",
    ];
    for table in tables {
        assert_eq!(
            sql.matches(&format!("CREATE TABLE object_store_retention.{table} ("))
                .count(),
            1,
            "table must be declared exactly once: {table}"
        );
    }
    assert_eq!(sql.matches("CREATE TABLE ").count(), tables.len());
    assert_eq!(
        sql.matches("schema_revision = 'object-store-dispatch-authority-schema-v1'")
            .count(),
        tables.len()
    );
}

#[test]
fn migration_reuses_the_existing_retention_namespace_and_domains() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "object_store_retention.uint64",
            "object_store_retention.blake3_256",
            "CREATE TABLE object_store_retention.object_dispatch_requests",
            "SET LOCAL ROLE object_dispatch_retention_owner;",
        ],
    );
    assert!(!sql.contains("CREATE SCHEMA"));
    assert!(!sql.contains("CREATE DOMAIN"));
    assert!(!sql.contains("CREATE TYPE"));
    assert!(!sql.contains("CREATE ROLE"));
}

#[test]
fn request_rows_pin_identity_presence_phase_chronology_and_canonical_evidence() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "PRIMARY KEY (logical_request_id, attempt_id)",
            "UNIQUE (provider_boundary_id, authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id)",
            "CHECK (num_nonnulls(cell_admission_id, cell_admission_fence) IN (0, 2))",
            "CHECK (admission_clock_unix_ms < deadline_unix_ms)",
            "CHECK (deadline_unix_ms <= allocation_hard_expiry_unix_ms)",
            "(get_byte(uuid_send(logical_request_id), 6) >> 4) = 7 AND\n    (get_byte(uuid_send(logical_request_id), 8) >> 6) = 2",
            "logical_request_uuid_unix_ms =\n      get_byte(uuid_send(logical_request_id), 0)::numeric * 1099511627776 +\n      get_byte(uuid_send(logical_request_id), 1)::numeric * 4294967296 +\n      get_byte(uuid_send(logical_request_id), 2)::numeric * 16777216 +\n      get_byte(uuid_send(logical_request_id), 3)::numeric * 65536 +\n      get_byte(uuid_send(logical_request_id), 4)::numeric * 256 +\n      get_byte(uuid_send(logical_request_id), 5)::numeric",
            "(get_byte(uuid_send(attempt_id), 6) >> 4) = 7 AND\n    (get_byte(uuid_send(attempt_id), 8) >> 6) = 2",
            "attempt_uuid_unix_ms =\n      get_byte(uuid_send(attempt_id), 0)::numeric * 1099511627776 +\n      get_byte(uuid_send(attempt_id), 1)::numeric * 4294967296 +\n      get_byte(uuid_send(attempt_id), 2)::numeric * 16777216 +\n      get_byte(uuid_send(attempt_id), 3)::numeric * 65536 +\n      get_byte(uuid_send(attempt_id), 4)::numeric * 256 +\n      get_byte(uuid_send(attempt_id), 5)::numeric",
            "phase IN (1, 2) AND dispatch_attempt_blake3 IS NULL AND terminal_result_id IS NULL AND no_dispatch_reason IS NULL AND no_dispatch_proof_canonical_bytes IS NULL AND closure_committed_at_unix_ms IS NULL",
            "phase IN (3, 4) AND dispatch_attempt_blake3 IS NOT NULL AND terminal_result_id IS NULL AND no_dispatch_reason IS NULL AND no_dispatch_proof_canonical_bytes IS NULL AND closure_committed_at_unix_ms IS NULL",
            "phase = 5 AND dispatch_attempt_blake3 IS NOT NULL AND terminal_result_id IS NOT NULL AND no_dispatch_reason IS NULL AND no_dispatch_proof_canonical_bytes IS NULL AND closure_committed_at_unix_ms IS NOT NULL",
            "phase = 6 AND dispatch_attempt_blake3 IS NULL AND terminal_result_id IS NULL AND no_dispatch_reason IS NOT NULL AND no_dispatch_reason <> 4 AND no_dispatch_proof_canonical_bytes IS NOT NULL AND closure_committed_at_unix_ms IS NOT NULL",
            "phase = 7 AND dispatch_attempt_blake3 IS NULL AND terminal_result_id IS NULL AND no_dispatch_reason = 4 AND no_dispatch_proof_canonical_bytes IS NOT NULL AND closure_committed_at_unix_ms IS NOT NULL",
            "CHECK (num_nonnulls(no_dispatch_reason, no_dispatch_proof_canonical_bytes, no_dispatch_proof_blake3) IN (0, 3))",
            "num_nonnulls(\n      put_submit_binding_bytes,\n      put_submit_binding_blake3,\n      reserve_put_ack_canonical_bytes,\n      reserve_put_ack_blake3\n    ) IN (0, 4)",
            "num_nonnulls(\n      terminal_result_id,\n      terminal_result_tag,\n      terminal_result_canonical_bytes,\n      terminal_result_blake3,\n      terminal_result_size\n    ) IN (0, 5)",
            "CHECK (num_nonnulls(byte_result_handle, payload_size, payload_blake3) IN (0, 3))",
            "num_nonnulls(\n      fetch_head_state,\n      fetch_fence_generation,\n      fetch_open_lease_count,\n      fetch_head_revision,\n      fetch_head_committed_at_unix_ms,\n      fetch_head_canonical_bytes,\n      fetch_head_blake3\n    ) IN (0, 7)",
            "CHECK ((terminal_result_tag IS NOT DISTINCT FROM 7) = (byte_result_handle IS NOT NULL))",
            "CHECK ((fetch_head_state IS NOT NULL) = (terminal_result_tag IS NOT DISTINCT FROM 7))",
            "substring(request_state_canonical_bytes FROM octet_length(request_state_canonical_bytes) - 31 FOR 32) = request_state_blake3",
            "substring(no_dispatch_proof_canonical_bytes FROM octet_length(no_dispatch_proof_canonical_bytes) - 31 FOR 32) = no_dispatch_proof_blake3",
            "substring(put_submit_binding_bytes FROM octet_length(put_submit_binding_bytes) - 31 FOR 32) = put_submit_binding_blake3",
            "substring(reserve_put_ack_canonical_bytes FROM octet_length(reserve_put_ack_canonical_bytes) - 31 FOR 32) = reserve_put_ack_blake3",
            "substring(submit_receipt_canonical_bytes FROM octet_length(submit_receipt_canonical_bytes) - 31 FOR 32) = submit_receipt_blake3",
            "substring(get_outcome_canonical_bytes FROM octet_length(get_outcome_canonical_bytes) - 31 FOR 32) = get_outcome_blake3",
            "substring(fetch_head_canonical_bytes FROM octet_length(fetch_head_canonical_bytes) - 31 FOR 32) = fetch_head_blake3",
        ],
    );
    for preimage_only in [
        "substring(canonical_descriptor_bytes",
        "substring(terminal_result_canonical_bytes",
    ] {
        assert!(
            !sql.contains(preimage_only),
            "preimage/payload bytes must not be modeled as digest-suffixed: {preimage_only}"
        );
    }
}

#[test]
fn dispatcher_rows_pin_single_active_generation_and_closed_revocation_states() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "PRIMARY KEY (provider_boundary_id, lease_generation)",
            "UNIQUE (provider_boundary_id, dispatcher_id, lease_generation)",
            "CHECK (renewed_at_unix_ms >= acquired_at_unix_ms)",
            "CHECK (expires_at_unix_ms > renewed_at_unix_ms)",
            "state = 1 AND num_nonnulls(revocation_id, revocation_requested_at_unix_ms, revoked_at_unix_ms, revocation_evidence_blake3) = 0",
            "state = 2 AND num_nonnulls(revocation_id, revocation_requested_at_unix_ms) = 2 AND revoked_at_unix_ms IS NULL AND revocation_evidence_blake3 IS NULL",
            "state = 3 AND num_nonnulls(revocation_id, revocation_requested_at_unix_ms, revoked_at_unix_ms, revocation_evidence_blake3) = 4",
            "CREATE UNIQUE INDEX object_dispatch_dispatchers_one_active_generation_idx\n  ON object_store_retention.object_dispatch_dispatchers (provider_boundary_id)\n  WHERE state = 1;",
        ],
    );
}

#[test]
fn attempt_rows_pin_grant_before_send_and_closed_dispatch_outcomes() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "provider_authority_refunded boolean NOT NULL DEFAULT false CHECK (NOT provider_authority_refunded)",
            "FOREIGN KEY (logical_request_id, attempt_id)\n    REFERENCES object_store_retention.object_dispatch_requests (logical_request_id, attempt_id)",
            "FOREIGN KEY (provider_boundary_id, logical_request_id, attempt_id)\n    REFERENCES object_store_retention.object_dispatch_requests",
            "FOREIGN KEY (logical_request_id, attempt_id, terminal_result_id)\n    REFERENCES object_store_retention.object_dispatch_requests",
            "FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)\n    REFERENCES object_store_retention.object_dispatch_dispatchers",
            "attempt_state = 1 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, ambiguity_recorded_at_unix_ms, terminal_recorded_at_unix_ms, terminal_result_id, attempt_canonical_bytes, attempt_blake3, no_dispatch_proof_blake3) = 0",
            "attempt_state = 2 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, attempt_canonical_bytes, attempt_blake3) = 4",
            "attempt_state = 3 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, ambiguity_recorded_at_unix_ms, attempt_canonical_bytes, attempt_blake3) = 5",
            "attempt_state = 4 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, terminal_recorded_at_unix_ms, terminal_result_id, attempt_canonical_bytes, attempt_blake3) = 6",
            "attempt_state = 5 AND num_nonnulls(provider_attempt_id, dispatch_started_at_unix_ms, ambiguity_recorded_at_unix_ms, terminal_recorded_at_unix_ms, terminal_result_id, attempt_canonical_bytes, attempt_blake3) = 0 AND no_dispatch_proof_blake3 IS NOT NULL",
            "CHECK (dispatch_started_at_unix_ms IS NULL OR dispatch_started_at_unix_ms >= grant_committed_at_unix_ms)",
            "CHECK (terminal_recorded_at_unix_ms IS NULL OR terminal_recorded_at_unix_ms >= dispatch_started_at_unix_ms)",
        ],
    );
}

#[test]
fn spool_rows_pin_request_binding_lifecycle_quota_and_release_evidence() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "UNIQUE (spool_object_id, logical_request_id, attempt_id, payload_kind)",
            "provider_boundary_id,\n    authenticated_cell_id,\n    authenticated_tenant_id,\n    bound_request_logical_request_id,\n    bound_request_attempt_id\n  ) REFERENCES object_store_retention.object_dispatch_requests",
            "FOREIGN KEY (bound_request_logical_request_id, bound_request_attempt_id, terminal_result_id)\n    REFERENCES object_store_retention.object_dispatch_requests",
            "CHECK (num_nonnulls(bound_request_logical_request_id, bound_request_attempt_id) IN (0, 2))",
            "request_binding_state smallint NOT NULL CHECK (request_binding_state IN (1, 2))",
            "request_binding_state = 1 AND payload_kind = 1 AND bound_request_logical_request_id IS NULL",
            "request_binding_state = 2 AND bound_request_logical_request_id IS NOT NULL",
            "(get_byte(uuid_send(spool_object_id), 6) >> 4) = 7 AND\n    (get_byte(uuid_send(spool_object_id), 8) >> 6) = 2",
            "upload_id IS NULL OR\n    ((get_byte(uuid_send(upload_id), 6) >> 4) = 7 AND (get_byte(uuid_send(upload_id), 8) >> 6) = 2)",
            "payload_kind = 1 AND num_nonnulls(upload_id, upload_fence) = 2 AND terminal_result_id IS NULL",
            "payload_kind = 2 AND upload_id IS NULL AND upload_fence IS NULL AND terminal_result_id IS NOT NULL",
            "CHECK (num_nonnulls(committed_size, committed_blake3, durable_handle, ready_at_unix_ms) IN (0, 4))",
            "lifecycle_state = 2 AND committed_size IS NOT NULL AND partial_temp_files = 0 AND purged_at_unix_ms IS NULL",
            "lifecycle_state = 3 AND partial_temp_files = 0 AND purged_at_unix_ms IS NOT NULL",
            "CHECK (committed_size IS NULL OR committed_size = expected_size)",
            "CHECK (committed_blake3 IS NULL OR committed_blake3 = expected_blake3)",
            "CHECK (quota_bytes > 0 OR quota_rows > 0 OR quota_concurrency > 0)",
            "lifecycle_state = 3 AND num_nonnulls(release_reason, release_receipt_bytes, release_receipt_blake3) = 3",
            "substring(release_receipt_bytes FROM octet_length(release_receipt_bytes) - 31 FOR 32) = release_receipt_blake3",
            "CREATE UNIQUE INDEX object_dispatch_spool_objects_handle_idx",
            "CREATE INDEX object_dispatch_spool_objects_purge_idx",
            "CREATE INDEX object_dispatch_spool_objects_expiry_idx",
            "CREATE INDEX object_dispatch_spool_objects_cell_idx",
            "CREATE INDEX object_dispatch_spool_objects_tenant_idx",
        ],
    );
}

#[test]
fn quota_rows_pin_scope_partition_and_counter_algebra() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "PRIMARY KEY (provider_boundary_id, scope_kind, scope_id, quota_class)",
            "scope_kind smallint NOT NULL CHECK (scope_kind IN (1, 2, 3))",
            "quota_class smallint NOT NULL CHECK (quota_class IN (1, 2, 3))",
            "(scope_kind = 1 AND scope_id = provider_boundary_id) OR\n    (scope_kind IN (2, 3) AND scope_id <> provider_boundary_id)",
            "CHECK (used_concurrency <= used_rows)",
            "CHECK (used_rows <> 0 OR (used_bytes = 0 AND used_concurrency = 0))",
            "CREATE INDEX object_dispatch_quota_usage_class_idx",
            "CREATE INDEX object_dispatch_quota_usage_scope_idx",
        ],
    );
}

#[test]
fn payload_purge_rows_pin_identity_fetch_reservation_terminal_matrix_and_chronology() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "FOREIGN KEY (spool_object_id, logical_request_id, attempt_id, payload_kind)\n    REFERENCES object_store_retention.object_dispatch_spool_objects",
            "spool_object_id,\n    logical_request_id,\n    attempt_id,\n    payload_kind,\n    durable_handle,\n    payload_size,\n    payload_blake3\n  ) REFERENCES object_store_retention.object_dispatch_spool_objects",
            "REFERENCES object_store_retention.object_dispatch_requests (",
            "payload_kind = 1 AND terminal_result_id IS NULL AND disposition = 1 AND release_reason IN (3, 4, 5)",
            "terminal_result_id IS NOT NULL AND disposition IN (3, 4) AND release_reason IN (1, 2)",
            "FOREIGN KEY (logical_request_id, attempt_id, terminal_result_id)\n    REFERENCES object_store_retention.object_dispatch_requests",
            "num_nonnulls(\n      expected_fetch_head_blake3,\n      reserved_fetch_head_blake3,\n      reserved_fetch_fence_generation,\n      reserved_fetch_head_revision,\n      reserved_open_lease_count\n    ) IN (0, 5)",
            "CHECK ((payload_kind = 2) = (expected_fetch_head_blake3 IS NOT NULL))",
            "(get_byte(uuid_send(purge_id), 6) >> 4) = 7 AND\n    (get_byte(uuid_send(purge_id), 8) >> 6) = 2",
            "CHECK (payload_kind = 1 OR durable_handle IS NOT NULL)",
            "purge_state = 1 AND num_nonnulls(receipt_canonical_bytes, receipt_blake3, released_bytes, released_rows, released_concurrency, quota_revision, purged_at_unix_ms) = 0",
            "purge_state = 2 AND num_nonnulls(receipt_canonical_bytes, receipt_blake3, released_bytes, released_rows, released_concurrency, quota_revision, purged_at_unix_ms) = 7",
            "CHECK (purged_at_unix_ms IS NULL OR purged_at_unix_ms >= purge_not_before_unix_ms)",
            "CHECK (purged_at_unix_ms IS NULL OR purged_at_unix_ms >= reserved_at_unix_ms)",
            "substring(reservation_canonical_bytes FROM octet_length(reservation_canonical_bytes) - 31 FOR 32) = reservation_blake3",
            "substring(receipt_canonical_bytes FROM octet_length(receipt_canonical_bytes) - 31 FOR 32) = receipt_blake3",
        ],
    );
    assert!(!sql.contains("substring(canonical_intent_bytes"));
}

#[test]
fn fetch_lease_rows_pin_parent_result_owner_and_terminal_state_matrix() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "UNIQUE (logical_request_id, attempt_id, terminal_result_id, lease_id)",
            "REFERENCES object_store_retention.object_dispatch_requests\n      (\n        provider_boundary_id,\n        authenticated_cell_id,\n        authenticated_tenant_id,\n        logical_request_id,\n        attempt_id,\n        terminal_result_id\n      )",
            "canonical_result_size,\n    canonical_result_blake3,\n    byte_result_handle,\n    payload_size,\n    payload_blake3\n  ) REFERENCES object_store_retention.object_dispatch_requests",
            "state = 1 AND num_nonnulls(terminal_reason, terminal_at_unix_ms, terminal_fingerprint, owner_revocation_canonical_bytes, owner_revocation_blake3) = 0",
            "state = 2 AND terminal_reason = 1 AND num_nonnulls(terminal_at_unix_ms, terminal_fingerprint) = 2",
            "state = 3 AND terminal_reason IN (2, 3, 4, 5, 6)",
            "terminal_reason = 5 AND num_nonnulls(owner_revocation_canonical_bytes, owner_revocation_blake3) = 2",
            "CHECK (terminal_at_unix_ms IS NULL OR terminal_at_unix_ms >= opened_at_unix_ms)",
            "(get_byte(uuid_send(lease_id), 6) >> 4) = 7 AND\n    (get_byte(uuid_send(lease_id), 8) >> 6) = 2",
            "CREATE INDEX object_dispatch_fetch_leases_open_idx\n  ON object_store_retention.object_dispatch_fetch_leases\n  (logical_request_id, attempt_id, terminal_result_id, admitted_generation)\n  WHERE state = 1;",
            "CREATE INDEX object_dispatch_fetch_leases_owner_idx",
            "CREATE INDEX object_dispatch_fetch_leases_state_time_idx",
            "substring(owner_revocation_canonical_bytes FROM octet_length(owner_revocation_canonical_bytes) - 31 FOR 32) = owner_revocation_blake3",
        ],
    );
    assert_eq!(sql.matches("CREATE INDEX ").count(), 22);
    assert_eq!(sql.matches("CREATE UNIQUE INDEX ").count(), 2);
}

#[test]
fn all_authority_tables_deny_direct_public_and_runtime_access() {
    let sql = migration();
    assert_contains_all(
        sql,
        &[
            "REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM PUBLIC;",
            "REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM\n  object_dispatch_retention_runtime,\n  object_dispatch_retention_maintenance,\n  object_dispatch_retention_migrator;",
        ],
    );
    for forbidden in [
        "GRANT SELECT ON",
        "GRANT INSERT ON",
        "GRANT UPDATE ON",
        "GRANT DELETE ON",
        "GRANT ALL ON",
        "GRANT EXECUTE ON",
    ] {
        assert!(!sql.contains(forbidden), "unsafe direct grant: {forbidden}");
    }
}

#[test]
fn artifact_remains_source_dark_and_excludes_later_authority_surfaces() {
    let module = include_str!("../src/local_authority_schema.rs");
    let library = include_str!("../src/lib.rs");
    let sql = migration();
    for forbidden in [
        "tokio_postgres",
        "batch_execute",
        ".execute(",
        "CREATE FUNCTION",
        "CREATE PROCEDURE",
        "SECURITY DEFINER",
        "CREATE SCHEMA",
        "CREATE TYPE",
        "CREATE ROLE",
        "ALTER ROLE",
        "IF NOT EXISTS",
        "object_dispatch_continuity_bindings",
        "object_dispatch_continuity_quarantines",
        "object_dispatch_continuity_adjudications",
        "object_dispatch_continuity_shadow_releases",
        "provider_access_key",
        "provider_secret",
        "bucket_route",
        "endpoint_url",
    ] {
        assert!(
            !module.contains(forbidden) && !sql.contains(forbidden),
            "source-dark artifact contains excluded authority token: {forbidden}"
        );
    }
    assert!(library.contains("pub mod local_authority_schema;"));
    assert!(!library.contains("LOCAL_AUTHORITY_MIGRATION_V1).await"));
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::RETENTION_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::RETENTION_MIGRATION_V1;
use lore_object_dispatch::RETENTION_SCHEMA_REVISION_V1;
use lore_object_dispatch::RETENTION_SCHEMA_V1;
use lore_object_dispatch::validate_embedded_retention_migration_v1;

const EXPECTED_MIGRATION_BYTES: usize = 7_682;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";

fn migration() -> &'static str {
    std::str::from_utf8(RETENTION_MIGRATION_V1).expect("retention migration must remain UTF-8 SQL")
}

#[test]
fn embedded_migration_has_exact_frozen_identity() {
    assert_eq!(RETENTION_SCHEMA_V1, RETENTION_MIGRATION_V1);
    assert_eq!(RETENTION_MIGRATION_V1.len(), EXPECTED_MIGRATION_BYTES);
    assert_eq!(
        blake3::hash(RETENTION_MIGRATION_V1).to_hex().as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        RETENTION_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(RETENTION_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_retention_migration_v1());
}

#[test]
fn migration_is_one_transaction_under_the_owner_role() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n-- SPDX-License-Identifier: MIT\n"));
    assert!(sql.ends_with("\nCOMMIT;\n"));
    assert_eq!(sql.matches("\nBEGIN;\n").count(), 1);
    assert_eq!(sql.matches("\nCOMMIT;\n").count(), 1);
    assert_eq!(
        sql.matches("SET LOCAL ROLE object_dispatch_retention_owner;")
            .count(),
        1
    );
}

#[test]
fn git_attributes_pin_migration_bytes_to_lf() {
    assert!(
        include_str!("../../.gitattributes")
            .lines()
            .any(|line| line == "lore-object-dispatch/migrations/*.sql text eol=lf")
    );
}

#[test]
fn migration_declares_exact_schema_domains_and_five_authority_tables() {
    let sql = migration();
    for required in [
        "CREATE SCHEMA object_store_retention AUTHORIZATION object_dispatch_retention_owner;",
        "CREATE DOMAIN object_store_retention.uint64 AS numeric(20, 0)",
        "CHECK (VALUE >= 0 AND VALUE <= 18446744073709551615);",
        "CREATE DOMAIN object_store_retention.blake3_256 AS bytea",
        "CHECK (octet_length(VALUE) = 32);",
        "CREATE TABLE object_store_retention.object_dispatch_retention_schema_state (",
        "CREATE TABLE object_store_retention.object_dispatch_full_record_ownership (",
        "CREATE TABLE object_store_retention.object_dispatch_record_storage_counters (",
        "CREATE TABLE object_store_retention.object_dispatch_compact_receipts (",
        "CREATE TABLE object_store_retention.object_dispatch_compact_prune_watermark (",
    ] {
        assert!(sql.contains(required), "missing schema token: {required}");
    }
    assert_eq!(
        sql.matches("CREATE TABLE object_store_retention.").count(),
        5
    );
}

#[test]
fn schema_state_pins_revision_digest_and_positive_install_revision() {
    let sql = migration();
    assert_eq!(
        RETENTION_SCHEMA_REVISION_V1,
        "object-store-retention-authority-schema-v1"
    );
    assert_eq!(sql.matches(RETENTION_SCHEMA_REVISION_V1).count(), 1);
    for required in [
        "singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton)",
        "schema_revision text NOT NULL UNIQUE",
        "migration_blake3 object_store_retention.blake3_256 NOT NULL",
        "install_revision object_store_retention.uint64 NOT NULL CHECK (install_revision > 0)",
        "installed_at_unix_ms bigint NOT NULL CHECK (installed_at_unix_ms >= 0)",
        "compact_sequence_high_water object_store_retention.uint64 NOT NULL DEFAULT 0",
        "compact_sequence_revision object_store_retention.uint64 NOT NULL",
        "CHECK (compact_sequence_revision > 0)",
    ] {
        assert!(
            sql.contains(required),
            "missing schema-state invariant: {required}"
        );
    }
}

#[test]
fn full_and_compact_rows_pin_identity_and_exact_charge_algebra() {
    let sql = migration();
    for required in [
        "PRIMARY KEY (logical_request_id, attempt_id)",
        "provider_boundary_id,\n    authenticated_cell_id,\n    authenticated_tenant_id,\n    logical_request_id,\n    attempt_id",
        "source_authority_blake3 object_store_retention.blake3_256 NOT NULL",
        "full_record_rows object_store_retention.uint64 NOT NULL DEFAULT 1 CHECK (full_record_rows = 1)",
        "full_record_bytes object_store_retention.uint64 NOT NULL CHECK (full_record_bytes > 0)",
        "CHECK (full_record_concurrency = 0)",
        "ownership_revision object_store_retention.uint64 NOT NULL CHECK (ownership_revision > 0)",
        "compact_sequence object_store_retention.uint64 PRIMARY KEY CHECK (compact_sequence > 0)",
        "compact_rows object_store_retention.uint64 NOT NULL DEFAULT 1 CHECK (compact_rows = 1)",
        "compact_bytes object_store_retention.uint64 NOT NULL CHECK (compact_bytes > 0)",
        "CHECK (compact_concurrency = 0)",
        "CHECK (compact_bytes = octet_length(compact_receipt_bytes))",
        "transfer_fingerprint object_store_retention.blake3_256 NOT NULL UNIQUE",
        "UNIQUE (logical_request_id, attempt_id)",
    ] {
        assert!(
            sql.contains(required),
            "missing charge or identity invariant: {required}"
        );
    }
}

#[test]
fn counters_pin_closed_scope_kinds_global_identity_and_positive_revision() {
    let sql = migration();
    for required in [
        "scope_kind smallint NOT NULL CHECK (scope_kind IN (1, 2, 3))",
        "PRIMARY KEY (scope_kind, scope_id)",
        "counter_revision object_store_retention.uint64 NOT NULL CHECK (counter_revision > 0)",
        "scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1'",
        "scope_kind IN (2, 3) AND scope_id <> 'object-store-full-to-compact-global-v1'",
    ] {
        assert!(
            sql.contains(required),
            "missing counter invariant: {required}"
        );
    }
}

#[test]
fn watermark_pins_initial_or_complete_advanced_evidence() {
    let sql = migration();
    for required in [
        "pruned_through_compact_sequence object_store_retention.uint64 NOT NULL DEFAULT 0",
        "watermark_revision object_store_retention.uint64 NOT NULL CHECK (watermark_revision > 0)",
        "pruned_through_compact_sequence = 0 AND",
        "pruned_through_compact_sequence > 0 AND",
        "last_prune_fingerprint,\n        last_compact_blake3,\n        last_pruned_at_unix_ms,\n        last_backup_revision,\n        last_backup_manifest_blake3",
        ") = 0",
        ") = 5",
    ] {
        assert!(
            sql.contains(required),
            "missing watermark invariant: {required}"
        );
    }
    assert_eq!(sql.matches("num_nonnulls(").count(), 2);
}

#[test]
fn compact_primary_key_and_indexes_cover_prune_order_floor_cell_and_tenant_queries() {
    let sql = migration();
    for required in [
        "CREATE INDEX object_dispatch_compact_receipts_prune_floor_idx\n  ON object_store_retention.object_dispatch_compact_receipts\n  (compact_prune_after_unix_ms, compact_sequence);",
        "CREATE INDEX object_dispatch_compact_receipts_cell_lookup_idx\n  ON object_store_retention.object_dispatch_compact_receipts\n  (authenticated_cell_id, logical_request_id, attempt_id);",
        "CREATE INDEX object_dispatch_compact_receipts_tenant_lookup_idx\n  ON object_store_retention.object_dispatch_compact_receipts\n  (authenticated_tenant_id, logical_request_id, attempt_id);",
    ] {
        assert!(
            sql.contains(required),
            "missing retention index: {required}"
        );
    }
    assert_eq!(sql.matches("CREATE INDEX ").count(), 3);
}

#[test]
fn public_runtime_maintenance_and_migrator_have_no_direct_table_authority() {
    let sql = migration();
    for required in [
        "REVOKE ALL ON SCHEMA object_store_retention FROM PUBLIC;",
        "IN SCHEMA object_store_retention REVOKE ALL ON TABLES FROM PUBLIC;",
        "IN SCHEMA object_store_retention REVOKE ALL ON SEQUENCES FROM PUBLIC;",
        "IN SCHEMA object_store_retention REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;",
        "REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM PUBLIC;",
        "REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM\n  object_dispatch_retention_runtime,\n  object_dispatch_retention_maintenance,\n  object_dispatch_retention_migrator;",
        "GRANT USAGE ON SCHEMA object_store_retention TO\n  object_dispatch_retention_runtime,\n  object_dispatch_retention_maintenance,\n  object_dispatch_retention_migrator;",
    ] {
        assert!(
            sql.contains(required),
            "missing authority boundary: {required}"
        );
    }
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
fn artifact_is_source_dark_and_has_no_runtime_installer_or_procedure_authority() {
    let module = include_str!("../src/retention_schema.rs");
    let library = include_str!("../src/lib.rs");
    let sql = migration();
    for forbidden in [
        "tokio_postgres",
        "batch_execute",
        ".execute(",
        "CREATE ROLE",
        "ALTER ROLE",
        "CREATE FUNCTION",
        "CREATE PROCEDURE",
        "SECURITY DEFINER",
        "IF NOT EXISTS",
    ] {
        assert!(
            !module.contains(forbidden) && !sql.contains(forbidden),
            "source-dark artifact contains installer or authority token: {forbidden}"
        );
    }
    assert!(library.contains("pub mod retention_schema;"));
    assert!(!library.contains("RETENTION_MIGRATION_V1).await"));
}

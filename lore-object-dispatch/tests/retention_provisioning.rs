// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::RETENTION_PROVISIONING_API_REVISION_V1;
use lore_object_dispatch::RETENTION_PROVISIONING_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::RETENTION_PROVISIONING_MIGRATION_V1;
use lore_object_dispatch::validate_embedded_retention_provisioning_migration_v1;

const EXPECTED_MIGRATION_BYTES: usize = 9_609;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "647ee320d6a615f9a3d91d2919dd4789ffe4073d9f9ea2b97517d4afe974a184";
const RETENTION_SCHEMA_BLAKE3: &str =
    "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";

fn migration() -> &'static str {
    std::str::from_utf8(RETENTION_PROVISIONING_MIGRATION_V1)
        .expect("retention provisioning migration must remain UTF-8 SQL")
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read production source directory") {
        let entry = entry.expect("read production source entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

#[test]
fn embedded_provisioning_migration_has_exact_frozen_identity() {
    assert_eq!(
        RETENTION_PROVISIONING_API_REVISION_V1,
        "object-store-retention-provisioning-v1"
    );
    assert_eq!(
        RETENTION_PROVISIONING_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(RETENTION_PROVISIONING_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        RETENTION_PROVISIONING_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(RETENTION_PROVISIONING_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_retention_provisioning_migration_v1());
}

#[test]
fn migration_is_lf_normalized_and_one_owner_transaction() {
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
    assert!(!RETENTION_PROVISIONING_MIGRATION_V1.contains(&b'\r'));
    assert!(
        include_str!("../../.gitattributes")
            .lines()
            .any(|line| line == "lore-object-dispatch/migrations/*.sql text eol=lf")
    );
}

#[test]
fn every_helper_is_security_definer_with_fixed_catalog_search_path() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 8);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 8);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 8);
    assert!(!sql.contains("SET search_path = public"));
    assert!(!sql.contains("SET search_path = object_store_retention"));
}

#[test]
fn install_and_read_authorize_exact_session_users() {
    let sql = migration();
    for required in [
        "session_user IS DISTINCT FROM 'object_dispatch_retention_migrator'",
        "AND session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance'",
        "RAISE EXCEPTION 'RETENTION_MIGRATOR_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501'",
        "RAISE EXCEPTION 'RETENTION_READER_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501'",
        "TO object_dispatch_retention_migrator;",
        "TO object_dispatch_retention_migrator, object_dispatch_retention_maintenance;",
    ] {
        assert!(
            sql.contains(required),
            "missing session authorization: {required}"
        );
    }
    assert!(!sql.contains("current_user IS DISTINCT FROM"));
    assert!(!sql.contains("object_dispatch_retention_runtime"));
}

#[test]
fn install_requires_serializable_read_write_and_locks_all_authority_tables() {
    let sql = migration();
    for required in [
        "current_setting('transaction_isolation') IS DISTINCT FROM 'serializable'",
        "current_setting('transaction_read_only') IS DISTINCT FROM 'off'",
        "RAISE EXCEPTION 'SERIALIZABLE_READ_WRITE_TRANSACTION_REQUIRED' USING ERRCODE = '25000'",
        "LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,",
        "object_store_retention.object_dispatch_full_record_ownership,",
        "object_store_retention.object_dispatch_record_storage_counters,",
        "object_store_retention.object_dispatch_compact_receipts,",
        "object_store_retention.object_dispatch_compact_prune_watermark\n    IN EXCLUSIVE MODE;",
    ] {
        assert!(
            sql.contains(required),
            "missing transaction invariant: {required}"
        );
    }
    let install_start = sql
        .find("CREATE FUNCTION object_store_retention.object_store_retention_install_v1(")
        .expect("install function");
    let lock = sql.find("LOCK TABLE ").expect("authority lock");
    assert!(lock > install_start);
}

#[test]
fn install_exact_matches_api_schema_digest_and_positive_revision() {
    let sql = migration();
    assert_eq!(
        sql.matches(RETENTION_PROVISIONING_API_REVISION_V1).count(),
        1
    );
    assert_eq!(sql.matches(RETENTION_SCHEMA_BLAKE3).count(), 1);
    for required in [
        "expected_schema_revision IS DISTINCT FROM 'object-store-retention-authority-schema-v1'",
        "expected_migration_blake3 IS DISTINCT FROM",
        "OR expected_install_revision IS NULL OR expected_install_revision = 0",
        "RAISE EXCEPTION 'RETENTION_INSTALL_CONTRACT_MISMATCH' USING ERRCODE = '22023'",
    ] {
        assert!(
            sql.contains(required),
            "missing install identity check: {required}"
        );
    }
}

#[test]
fn first_install_atomically_creates_only_pristine_authority_rows() {
    let sql = migration();
    for required in [
        "INSERT INTO object_store_retention.object_dispatch_retention_schema_state (",
        "compact_sequence_high_water, compact_sequence_revision, installed_at_unix_ms",
        "0, 1, installed_at",
        "INSERT INTO object_store_retention.object_dispatch_record_storage_counters (",
        "VALUES (1, 'object-store-full-to-compact-global-v1', 0, 0, 0, 0, 1);",
        "INSERT INTO object_store_retention.object_dispatch_compact_prune_watermark (",
        "VALUES (true, 0, 1);",
        "project_retention_state_v1('CREATED')",
    ] {
        assert!(
            sql.contains(required),
            "missing pristine install projection: {required}"
        );
    }
    assert_eq!(
        sql.matches("INSERT INTO object_store_retention.").count(),
        3
    );
}

#[test]
fn replay_requires_exact_pristine_schema_counters_and_watermark() {
    let sql = migration();
    for required in [
        "stored.schema_revision IS DISTINCT FROM expected_schema_revision",
        "stored.migration_blake3 IS DISTINCT FROM expected_migration_blake3",
        "stored.install_revision IS DISTINCT FROM expected_install_revision",
        "stored.compact_sequence_high_water <> 0",
        "stored.compact_sequence_revision <> 1",
        "object_dispatch_full_record_ownership) <> 0",
        "object_dispatch_compact_receipts) <> 0",
        "object_dispatch_record_storage_counters) <> 1",
        "full_record_rows = 0 AND full_record_bytes = 0",
        "compact_rows = 0 AND compact_bytes = 0",
        "AND counter_revision = 1",
        "object_dispatch_compact_prune_watermark) <> 1",
        "pruned_through_compact_sequence = 0 AND watermark_revision = 1",
        "last_prune_fingerprint IS NULL AND last_compact_blake3 IS NULL",
        "last_pruned_at_unix_ms IS NULL AND last_backup_revision IS NULL",
        "AND last_backup_manifest_blake3 IS NULL",
        "RAISE EXCEPTION 'RETENTION_INSTALL_REPLAY_CONFLICT' USING ERRCODE = '40001'",
        "project_retention_state_v1('REPLAY')",
    ] {
        assert!(
            sql.contains(required),
            "missing replay invariant: {required}"
        );
    }
}

#[test]
fn dirty_first_install_rejects_every_preexisting_authority_row_kind() {
    let sql = migration();
    for table in [
        "object_dispatch_full_record_ownership",
        "object_dispatch_record_storage_counters",
        "object_dispatch_compact_receipts",
        "object_dispatch_compact_prune_watermark",
    ] {
        assert!(
            sql.contains(&format!(
                "EXISTS (SELECT 1 FROM object_store_retention.{table})"
            )),
            "missing dirty-state guard for {table}"
        );
    }
    assert!(
        sql.contains("RAISE EXCEPTION 'RETENTION_INSTALL_DIRTY_STATE' USING ERRCODE = '55000'")
    );
}

#[test]
fn readback_projects_complete_state_or_typed_unavailable() {
    let sql = migration();
    for field in [
        "result_code text",
        "schema_revision text",
        "migration_blake3 bytea",
        "install_revision object_store_retention.uint64",
        "compact_sequence_high_water object_store_retention.uint64",
        "compact_sequence_revision object_store_retention.uint64",
        "pruned_through_compact_sequence object_store_retention.uint64",
        "watermark_revision object_store_retention.uint64",
        "global_counter_revision object_store_retention.uint64",
        "installed_at_unix_ms bigint",
    ] {
        assert!(sql.contains(field), "missing readback field: {field}");
    }
    assert!(sql.contains("SELECT * INTO STRICT schema_state"));
    assert!(sql.contains("SELECT * INTO STRICT watermark"));
    assert!(sql.contains("SELECT * INTO STRICT global_counter"));
    assert!(sql.contains("EXCEPTION WHEN no_data_found OR too_many_rows THEN"));
    assert!(
        sql.contains("RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000'")
    );
    assert!(sql.contains("project_retention_state_v1('READ')"));
}

#[test]
fn acl_exposes_only_install_and_read_without_direct_table_grants() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;")
    );
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 2);
    for forbidden in [
        "GRANT SELECT ON",
        "GRANT INSERT ON",
        "GRANT UPDATE ON",
        "GRANT DELETE ON",
        "GRANT ALL ON",
        "TO PUBLIC",
    ] {
        assert!(
            !sql.contains(forbidden),
            "unsafe provisioning grant: {forbidden}"
        );
    }
}

#[test]
fn provisioning_artifact_is_embedded_only_and_not_called_by_runtime() {
    let module = include_str!("../src/retention_provisioning.rs");
    let library = include_str!("../src/lib.rs");
    for forbidden in ["tokio_postgres", "batch_execute", ".execute(", ".await"] {
        assert!(
            !module.contains(forbidden),
            "embedded module contains runtime call: {forbidden}"
        );
    }
    assert!(library.contains("pub mod retention_provisioning;"));
    assert!(!library.contains("object_store_retention_install_v1"));
    assert!(!library.contains("object_store_retention_read_state_v1"));
}

#[test]
fn every_production_rust_source_remains_dark_to_provisioning_sql_entrypoints() {
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources.sort();
    assert!(
        !sources.is_empty(),
        "production source inventory must not be empty"
    );

    for source_path in sources {
        let source = std::fs::read_to_string(&source_path).expect("read production Rust source");
        for sql_identifier in [
            "object_store_retention_install_v1",
            "object_store_retention_read_state_v1",
        ] {
            assert!(
                !source.contains(sql_identifier),
                "source-dark SQL identifier {sql_identifier} appeared in {}",
                source_path.display()
            );
        }
    }
}

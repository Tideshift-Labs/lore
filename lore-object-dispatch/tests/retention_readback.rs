// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::RETENTION_READBACK_API_REVISION_V1;
use lore_object_dispatch::RETENTION_READBACK_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::RETENTION_READBACK_MIGRATION_V1;
use lore_object_dispatch::validate_embedded_retention_readback_migration_v1;

const EXPECTED_MIGRATION_BYTES: usize = 8_192;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "0e96da466d8d7d639a510ee1a882a79765d36244c26e941948e189f94df0ed05";

fn migration() -> &'static str {
    std::str::from_utf8(RETENTION_READBACK_MIGRATION_V1)
        .expect("retention readback migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, signature: &str, next_marker: &str) -> &'a str {
    let start = sql.find(signature).expect("readback function signature");
    let rest = &sql[start..];
    let end = rest
        .find(next_marker)
        .expect("next readback artifact marker");
    &rest[..end]
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
fn embedded_readback_migration_has_exact_frozen_identity() {
    assert_eq!(
        RETENTION_READBACK_API_REVISION_V1,
        "object-store-retention-readback-v1"
    );
    assert_eq!(
        RETENTION_READBACK_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(RETENTION_READBACK_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        RETENTION_READBACK_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(RETENTION_READBACK_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_retention_readback_migration_v1());
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
    assert!(!RETENTION_READBACK_MIGRATION_V1.contains(&b'\r'));
    assert!(
        include_str!("../../.gitattributes")
            .lines()
            .any(|line| line == "lore-object-dispatch/migrations/*.sql text eol=lf")
    );
}

#[test]
fn stable_security_definer_functions_hold_one_calling_statement_snapshot() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 4);
    assert_eq!(sql.matches("LANGUAGE plpgsql\nSTABLE").count(), 4);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 4);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 4);
    assert!(!sql.contains("VOLATILE"));
    assert!(!sql.contains("SET search_path = public"));
    assert!(!sql.contains("SET search_path = object_store_retention"));
}

#[test]
fn only_the_exact_maintenance_session_user_receives_readback_authority() {
    let sql = migration();
    assert!(sql.contains("session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance'"));
    assert!(sql.contains(
        "RAISE EXCEPTION 'RETENTION_MAINTENANCE_AUTHORIZATION_REQUIRED' USING ERRCODE = '42501'"
    ));
    assert!(sql.contains("TO object_dispatch_retention_maintenance;"));
    assert!(!sql.contains("object_dispatch_retention_migrator"));
    assert!(!sql.contains("object_dispatch_retention_runtime"));
    assert!(!sql.contains("current_user IS DISTINCT FROM"));
}

#[test]
fn exact_maintenance_authorization_precedes_api_and_request_validation() {
    let sql = migration();
    for (signature, next_marker) in [
        (
            "CREATE FUNCTION object_store_retention.object_store_retention_read_transfer_v1(",
            "CREATE FUNCTION object_store_retention.object_store_retention_read_prune_v1(",
        ),
        (
            "CREATE FUNCTION object_store_retention.object_store_retention_read_prune_v1(",
            "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
        ),
    ] {
        let body = function_body(sql, signature, next_marker);
        let authorization = body
            .find("assert_retention_maintenance_v1()")
            .expect("entrypoint must enforce the exact maintenance session user");
        let api = body
            .find("assert_readback_api_revision_v1(api_revision)")
            .expect("entrypoint must validate the API revision");
        assert!(
            authorization < api,
            "authorization must precede request validation in {signature}"
        );
    }
}

#[test]
fn composite_types_embed_complete_authoritative_rows_and_counter_images() {
    let sql = migration();
    for required in [
        "full_record object_store_retention.object_dispatch_full_record_ownership",
        "compact_record object_store_retention.object_dispatch_compact_receipts",
        "compact_sequence_high_water object_store_retention.uint64",
        "compact_sequence_revision object_store_retention.uint64",
        "watermark object_store_retention.object_dispatch_compact_prune_watermark",
        "global_counter object_store_retention.object_dispatch_record_storage_counters",
        "cell_counter object_store_retention.object_dispatch_record_storage_counters",
        "tenant_counter object_store_retention.object_dispatch_record_storage_counters",
    ] {
        assert!(
            sql.contains(required),
            "missing readback projection: {required}"
        );
    }
    assert_eq!(
        sql.matches(
            "  global_counter object_store_retention.object_dispatch_record_storage_counters"
        )
        .count(),
        2
    );
    assert_eq!(
        sql.matches(
            "  cell_counter object_store_retention.object_dispatch_record_storage_counters"
        )
        .count(),
        2
    );
    assert_eq!(
        sql.matches(
            "  tenant_counter object_store_retention.object_dispatch_record_storage_counters"
        )
        .count(),
        2
    );
}

#[test]
fn transfer_read_closes_identity_state_presence_and_child_counter_binding() {
    let sql = migration();
    let body = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_retention_read_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_read_prune_v1(",
    );
    for required in [
        "requested_logical_request_id uuid,\n  requested_attempt_id uuid",
        "requested_logical_request_id IS NULL OR requested_attempt_id IS NULL",
        "RETENTION_READ_IDENTITY_REQUIRED",
        "SELECT * INTO STRICT schema_state",
        "SELECT * INTO full_record",
        "logical_request_id = requested_logical_request_id AND attempt_id = requested_attempt_id",
        "SELECT * INTO compact_record",
        "SELECT * INTO STRICT global_counter",
        "scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1'",
        "IF has_full AND has_compact THEN\n    result_state := 'CONFLICT';",
        "full_record := NULL;\n    compact_record := NULL;",
        "ELSIF has_full THEN\n    result_state := 'FULL_OWNED';",
        "ELSIF has_compact THEN\n    result_state := 'COMPACT_INSTALLED';",
        "ELSE\n    result_state := 'ABSENT';",
        "IF cell_id IS NOT NULL THEN\n    SELECT * INTO STRICT cell_counter",
        "WHERE scope_kind = 2 AND scope_id = cell_id;",
        "SELECT * INTO STRICT tenant_counter",
        "WHERE scope_kind = 3 AND scope_id = tenant_id;",
        "schema_state.compact_sequence_high_water, schema_state.compact_sequence_revision",
        "global_counter, cell_counter, tenant_counter",
    ] {
        assert!(
            body.contains(required),
            "missing transfer-read invariant: {required}"
        );
    }
    assert_eq!(body.matches("result_state := '").count(), 4);
}

#[test]
fn prune_read_closes_positive_sequence_presence_watermark_and_scope_counters() {
    let sql = migration();
    let body = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_retention_read_prune_v1(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    for required in [
        "requested_compact_sequence object_store_retention.uint64",
        "requested_compact_sequence IS NULL OR requested_compact_sequence = 0",
        "RETENTION_READ_SEQUENCE_REQUIRED",
        "SELECT * INTO STRICT schema_state",
        "SELECT * INTO STRICT watermark",
        "SELECT * INTO STRICT global_counter",
        "SELECT * INTO compact_record",
        "WHERE compact_sequence = requested_compact_sequence;",
        "IF FOUND THEN\n    result_state := 'COMPACT_INSTALLED';",
        "SELECT * INTO STRICT cell_counter",
        "scope_kind = 2 AND scope_id = compact_record.authenticated_cell_id",
        "SELECT * INTO STRICT tenant_counter",
        "scope_kind = 3 AND scope_id = compact_record.authenticated_tenant_id",
        "ELSE\n    result_state := 'COMPACT_ABSENT';",
        "result_state, compact_record, watermark, global_counter, cell_counter, tenant_counter",
    ] {
        assert!(
            body.contains(required),
            "missing prune-read invariant: {required}"
        );
    }
    assert_eq!(body.matches("result_state := '").count(), 2);
}

#[test]
fn both_reads_fail_typed_when_required_singletons_or_counters_are_unavailable() {
    let sql = migration();
    assert_eq!(sql.matches("SELECT * INTO STRICT schema_state").count(), 2);
    assert_eq!(
        sql.matches("SELECT * INTO STRICT global_counter").count(),
        2
    );
    assert_eq!(
        sql.matches("EXCEPTION WHEN no_data_found OR too_many_rows THEN")
            .count(),
        2
    );
    assert_eq!(
        sql.matches("RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000'")
            .count(),
        2
    );
}

#[test]
fn acl_exposes_only_both_read_functions_without_table_or_public_grants() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;")
    );
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 1);
    assert!(sql.contains(
        "object_store_retention.object_store_retention_read_transfer_v1(text, uuid, uuid),"
    ));
    assert!(sql.contains(
        "object_store_retention.object_store_retention_read_prune_v1(\n    text, object_store_retention.uint64\n  )"
    ));
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
            "unsafe readback grant: {forbidden}"
        );
    }
}

#[test]
fn readback_artifact_is_embedded_only_and_not_called_by_runtime() {
    let module = include_str!("../src/retention_readback.rs");
    let library = include_str!("../src/lib.rs");
    for forbidden in ["tokio_postgres", "batch_execute", ".execute(", ".await"] {
        assert!(
            !module.contains(forbidden),
            "embedded module contains runtime call: {forbidden}"
        );
    }
    assert!(library.contains("pub mod retention_readback;"));
}

#[test]
fn every_production_rust_source_remains_dark_to_readback_sql_entrypoints() {
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
            "object_store_retention_read_transfer_v1",
            "object_store_retention_read_prune_v1",
        ] {
            if source_path
                .file_name()
                .is_some_and(|name| name == "retention_client.rs")
            {
                continue;
            }
            if source_path
                == Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("src")
                    .join("cell_schema_install.rs")
            {
                // WP-114 CD-1's attester names the deferred 0004 procedures only to assert they are
                // ABSENT from a cell. Hold it to the stronger rule instead of exempting it: the bare
                // name may appear in its inventory, but a schema-qualified reference -- the only
                // form that can execute one -- may not.
                assert!(
                    !source.contains(&format!("object_store_retention.{sql_identifier}")),
                    "the cell schema installer must never reference {sql_identifier} in callable form"
                );
                continue;
            }
            assert!(
                !source.contains(sql_identifier),
                "retention readback SQL identifier {sql_identifier} escaped the dedicated client into {}",
                source_path.display()
            );
        }
    }
}

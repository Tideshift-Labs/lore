// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::RETENTION_PRUNE_RECEIPTS_API_REVISION_V2;
use lore_object_dispatch::RETENTION_PRUNE_RECEIPTS_MIGRATION_BLAKE3_V2;
use lore_object_dispatch::RETENTION_PRUNE_RECEIPTS_MIGRATION_V2;
use lore_object_dispatch::validate_embedded_retention_prune_receipts_migration_v2;

const EXPECTED_MIGRATION_BYTES: usize = 14_343;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "9687ebf6dcc3771849b1f690eb8be65b010526474a95cbdaabc4aae6f16d218a";

fn migration() -> &'static str {
    std::str::from_utf8(RETENTION_PRUNE_RECEIPTS_MIGRATION_V2)
        .expect("retention prune-receipt migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, signature: &str, next_marker: &str) -> &'a str {
    let start = sql.find(signature).expect("prune v2 function signature");
    let rest = &sql[start..];
    let end = rest
        .find(next_marker)
        .expect("next prune v2 artifact marker");
    &rest[..end]
}

fn position(haystack: &str, needle: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("missing ordering token: {needle}"))
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
fn embedded_v2_artifact_has_a_self_consistent_frozen_identity() {
    assert_eq!(
        RETENTION_PRUNE_RECEIPTS_API_REVISION_V2,
        "object-store-retention-prune-receipts-v2"
    );
    assert_eq!(
        RETENTION_PRUNE_RECEIPTS_MIGRATION_V2.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(RETENTION_PRUNE_RECEIPTS_MIGRATION_V2)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        RETENTION_PRUNE_RECEIPTS_MIGRATION_BLAKE3_V2.as_slice(),
        blake3::hash(RETENTION_PRUNE_RECEIPTS_MIGRATION_V2).as_bytes()
    );
    assert!(validate_embedded_retention_prune_receipts_migration_v2());
}

#[test]
fn v2_is_one_owner_transaction_and_preserves_the_frozen_v1_surface() {
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
    assert!(!RETENTION_PRUNE_RECEIPTS_MIGRATION_V2.contains(&b'\r'));
    for forbidden in [
        "DROP FUNCTION",
        "DROP TYPE",
        "DROP TABLE",
        "ALTER FUNCTION object_store_retention.object_store_retention_apply_prune_v1",
        "CREATE OR REPLACE FUNCTION object_store_retention.object_store_retention_apply_prune_v1",
    ] {
        assert!(
            !sql.contains(forbidden),
            "v2 changed frozen v1: {forbidden}"
        );
    }
}

#[test]
fn append_only_receipt_closes_identity_evidence_and_post_commit_projection() {
    let sql = migration();
    for required in [
        "CREATE TABLE object_store_retention.object_dispatch_compact_prune_receipts_v2",
        "compact_sequence object_store_retention.uint64 PRIMARY KEY",
        "logical_request_id uuid NOT NULL",
        "attempt_id uuid NOT NULL",
        "provider_boundary_id text NOT NULL",
        "authenticated_cell_id text NOT NULL",
        "authenticated_tenant_id text NOT NULL",
        "compact_blake3 object_store_retention.blake3_256 NOT NULL",
        "prune_fingerprint object_store_retention.blake3_256 NOT NULL",
        "backup_revision text NOT NULL",
        "backup_manifest_blake3 object_store_retention.blake3_256 NOT NULL",
        "durable_covered_through_compact_sequence object_store_retention.uint64 NOT NULL",
        "restore_verified_through_compact_sequence object_store_retention.uint64 NOT NULL",
        "backup_observed_at_unix_ms bigint NOT NULL",
        "database_now_unix_ms bigint",
        "post_watermark object_store_retention.object_dispatch_compact_prune_watermark NOT NULL",
        "post_global_counter object_store_retention.object_dispatch_record_storage_counters NOT NULL",
        "post_cell_counter object_store_retention.object_dispatch_record_storage_counters NOT NULL",
        "post_tenant_counter object_store_retention.object_dispatch_record_storage_counters NOT NULL",
    ] {
        assert!(
            sql.contains(required),
            "missing append-only receipt field: {required}"
        );
    }
    assert!(!sql.contains("ON CONFLICT (compact_sequence) DO UPDATE"));
    assert!(
        !sql.contains("UPDATE object_store_retention.object_dispatch_compact_prune_receipts_v2")
    );
}

#[test]
fn read_v2_is_auth_first_and_returns_an_exact_absent_sequence_receipt() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_read_prune_v2(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v2(",
    );
    let authorization = position(body, "assert_retention_maintenance_v1()");
    let api = position(body, "assert_prune_receipts_api_revision_v2(api_revision)");
    let validation = position(body, "RETENTION_READ_SEQUENCE_REQUIRED");
    assert!(authorization < api);
    assert!(api < validation);
    for required in [
        "requested_compact_sequence object_store_retention.uint64",
        "object_dispatch_compact_receipts",
        "object_dispatch_compact_prune_receipts_v2",
        "COMPACT_INSTALLED",
        "PRUNED",
        "ABSENT_UNPROVEN",
    ] {
        assert!(
            body.contains(required),
            "missing prune v2 read state: {required}"
        );
    }
}

#[test]
fn apply_v2_inserts_the_receipt_in_the_same_transaction_as_every_prune_effect() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v2(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    let authorization = position(body, "assert_retention_maintenance_v1()");
    let api = position(body, "assert_prune_receipts_api_revision_v2(api_revision)");
    let serializable = position(body, "assert_serializable_write_v1()");
    let v1_atomic_prune = position(
        body,
        "object_store_retention.object_store_retention_apply_prune_v1(",
    );
    let receipt_insert = position(
        body,
        "INSERT INTO object_store_retention.object_dispatch_compact_prune_receipts_v2",
    );
    assert!(authorization < api);
    assert!(api < serializable);
    assert!(serializable < v1_atomic_prune);
    assert!(v1_atomic_prune < receipt_insert);
    assert!(body.contains("RETURN ROW('APPLIED', inserted_receipt)"));
}

#[test]
fn v2_uses_its_own_api_gate_but_invokes_the_frozen_v1_mutation_with_the_v1_revision() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v2(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    assert!(body.contains("assert_prune_receipts_api_revision_v2(api_revision)"));
    assert!(body.contains(
        "object_store_retention.object_store_retention_apply_prune_v1(\n    'object-store-retention-mutations-v1'"
    ));
    assert!(!body.contains(
        "object_store_retention.object_store_retention_apply_prune_v1(\n    api_revision"
    ));
}

#[test]
fn apply_v2_replays_only_the_exact_immutable_receipt() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v2(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    let receipt_lookup = position(
        body,
        "FROM object_store_retention.object_dispatch_compact_prune_receipts_v2",
    );
    let live_compact_lock = position(
        body,
        "FROM object_store_retention.object_dispatch_compact_receipts",
    );
    assert!(
        receipt_lookup < live_compact_lock,
        "exact receipt replay must precede mutable first-seen authority"
    );
    for required in [
        "compact_blake3 IS DISTINCT FROM expected_compact_blake3",
        "prune_fingerprint IS DISTINCT FROM requested_prune_fingerprint",
        "backup_revision IS DISTINCT FROM requested_backup_revision",
        "backup_manifest_blake3 IS DISTINCT FROM requested_backup_manifest_blake3",
        "durable_covered_through_compact_sequence IS DISTINCT FROM",
        "restore_verified_through_compact_sequence IS DISTINCT FROM",
        "backup_observed_at_unix_ms IS DISTINCT FROM",
        "RETENTION_PRUNE_REPLAY_CONFLICT",
        "RETURN ROW('REPLAY', existing_receipt)",
    ] {
        assert!(
            body.contains(required),
            "incomplete exact replay binding: {required}"
        );
    }
}

#[test]
fn maintenance_receives_only_v2_execute_without_table_or_public_authority() {
    let sql = migration();
    assert!(sql.contains("REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM PUBLIC;"));
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;")
    );
    assert!(sql.contains("object_store_retention.object_store_retention_read_prune_v2("));
    assert!(sql.contains("object_store_retention.object_store_retention_apply_prune_v2("));
    assert!(sql.contains("TO object_dispatch_retention_maintenance;"));
    for forbidden in [
        "GRANT SELECT ON",
        "GRANT INSERT ON",
        "GRANT UPDATE ON",
        "GRANT DELETE ON",
        "GRANT ALL ON",
        "TO PUBLIC",
    ] {
        assert!(!sql.contains(forbidden), "unsafe v2 grant: {forbidden}");
    }
}

#[test]
fn prune_v2_entrypoints_remain_confined_to_the_maintenance_client() {
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources.sort();
    assert!(!sources.is_empty());
    for source_path in sources {
        if source_path.file_name().is_some_and(|name| {
            name == "retention_client.rs" || name == "retention_prune_receipts.rs"
        }) {
            continue;
        }
        let source = std::fs::read_to_string(&source_path).expect("read production Rust source");
        let is_cell_installer = source_path
            == Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("cell_schema_install.rs");
        for identifier in [
            "object_store_retention_read_prune_v2",
            "object_store_retention_apply_prune_v2",
        ] {
            if is_cell_installer {
                // WP-114 CD-1's attester names the deferred 0006 procedures only to assert they are
                // ABSENT from a cell. Hold it to the stronger rule rather than exempting it: the
                // bare name may appear in its inventory, but a schema-qualified reference -- the
                // only form that can execute one -- may not.
                assert!(
                    !source.contains(&format!("object_store_retention.{identifier}")),
                    "the cell schema installer must never reference {identifier} in callable form"
                );
                continue;
            }
            assert!(
                !source.contains(identifier),
                "prune v2 entrypoint {identifier} escaped into {}",
                source_path.display()
            );
        }
    }
}

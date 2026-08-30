// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::RETENTION_MUTATIONS_API_REVISION_V1;
use lore_object_dispatch::RETENTION_MUTATIONS_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::RETENTION_MUTATIONS_MIGRATION_V1;
use lore_object_dispatch::validate_embedded_retention_mutations_migration_v1;

const EXPECTED_MIGRATION_BYTES: usize = 28_203;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "e372c54b965c371dda7177f7a1331bbb8c85ebe66d41e9eacdef336256b81e46";

fn migration() -> &'static str {
    std::str::from_utf8(RETENTION_MUTATIONS_MIGRATION_V1)
        .expect("retention mutations migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, signature: &str, next_marker: &str) -> &'a str {
    let start = sql.find(signature).expect("mutation function signature");
    let rest = &sql[start..];
    let end = rest
        .find(next_marker)
        .expect("next mutation artifact marker");
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
fn embedded_mutations_migration_has_exact_frozen_identity() {
    assert_eq!(
        RETENTION_MUTATIONS_API_REVISION_V1,
        "object-store-retention-mutations-v1"
    );
    assert_eq!(
        RETENTION_MUTATIONS_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(RETENTION_MUTATIONS_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        RETENTION_MUTATIONS_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(RETENTION_MUTATIONS_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_retention_mutations_migration_v1());
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
    assert!(!RETENTION_MUTATIONS_MIGRATION_V1.contains(&b'\r'));
    assert!(
        include_str!("../../.gitattributes")
            .lines()
            .any(|line| line == "lore-object-dispatch/migrations/*.sql text eol=lf")
    );
}

#[test]
fn mutation_functions_are_fixed_definer_and_maintenance_only() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 3);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 3);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 3);
    assert_eq!(sql.matches("LANGUAGE plpgsql\nVOLATILE").count(), 2);
    assert!(sql.contains("TO object_dispatch_retention_maintenance;"));
    assert!(!sql.contains("object_dispatch_retention_runtime"));
    assert!(!sql.contains("object_dispatch_retention_migrator"));
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;")
    );
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 1);
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
            "unsafe mutation grant: {forbidden}"
        );
    }
}

#[test]
fn maintenance_authorization_precedes_api_transaction_and_request_validation() {
    let sql = migration();
    for (signature, next_marker, invalid_input) in [
        (
            "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
            "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
            "RETENTION_TRANSFER_INPUT_INVALID",
        ),
        (
            "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
            "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
            "RETENTION_PRUNE_INPUT_INVALID",
        ),
    ] {
        let body = function_body(sql, signature, next_marker);
        let authorization = position(
            body,
            "PERFORM object_store_retention.assert_retention_maintenance_v1();",
        );
        let api = position(
            body,
            "PERFORM object_store_retention.assert_mutation_api_revision_v1(api_revision);",
        );
        let serializable = position(
            body,
            "PERFORM object_store_retention.assert_serializable_write_v1();",
        );
        let validation = position(body, invalid_input);
        assert!(authorization < api);
        assert!(api < serializable);
        assert!(serializable < validation);
    }
}

#[test]
fn transfer_rejects_every_identity_outside_the_schema_byte_bound() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
    );
    for required in [
        "octet_length(requested_provider_boundary_id) NOT BETWEEN 1 AND 1024",
        "octet_length(requested_authenticated_cell_id) NOT BETWEEN 1 AND 1024",
        "octet_length(requested_authenticated_tenant_id) NOT BETWEEN 1 AND 1024",
    ] {
        assert!(
            body.contains(required),
            "missing identity byte bound: {required}"
        );
    }
    assert_eq!(body.matches("NOT BETWEEN 1 AND 1024").count(), 3);
    assert!(
        body.contains("RAISE EXCEPTION 'RETENTION_TRANSFER_INPUT_INVALID' USING ERRCODE = '22023'")
    );
}

#[test]
fn transfer_locks_schema_first_and_closes_full_compact_lifecycle() {
    let sql = migration();
    let body = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
    );
    let schema_lock = position(
        body,
        "SELECT * INTO STRICT schema_state\n    FROM object_store_retention.object_dispatch_retention_schema_state\n   WHERE singleton FOR UPDATE;",
    );
    let full_lock = position(
        body,
        "SELECT * INTO full_record\n    FROM object_store_retention.object_dispatch_full_record_ownership",
    );
    let compact_lock = position(
        body,
        "SELECT * INTO compact_record\n    FROM object_store_retention.object_dispatch_compact_receipts",
    );
    assert!(schema_lock < full_lock && full_lock < compact_lock);
    assert!(body.contains("IF has_full AND has_compact THEN"));
    assert!(body.contains("IF NOT has_full THEN"));
    assert_eq!(
        body.matches("RETENTION_TRANSFER_LIFECYCLE_CONFLICT")
            .count(),
        2
    );
}

#[test]
fn transfer_replay_exact_binds_stable_evidence_before_mutable_cas() {
    let sql = migration();
    let body = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
    );
    let replay_start = position(body, "IF has_compact THEN");
    let replay_end = position(body, "IF NOT has_full THEN");
    let replay = &body[replay_start..replay_end];
    for required in [
        "provider_boundary_id IS DISTINCT FROM requested_provider_boundary_id",
        "authenticated_cell_id IS DISTINCT FROM requested_authenticated_cell_id",
        "authenticated_tenant_id IS DISTINCT FROM requested_authenticated_tenant_id",
        "source_authority_blake3 IS DISTINCT FROM expected_source_authority_blake3",
        "compact_receipt_bytes IS DISTINCT FROM requested_compact_receipt_bytes",
        "compact_blake3 IS DISTINCT FROM requested_compact_blake3",
        "compaction_fingerprint IS DISTINCT FROM requested_compaction_fingerprint",
        "transfer_fingerprint IS DISTINCT FROM requested_transfer_fingerprint",
        "compacted_at_unix_ms IS DISTINCT FROM requested_compacted_at_unix_ms",
        "compact_prune_after_unix_ms IS DISTINCT FROM\n          requested_compact_prune_after_unix_ms",
        "RETENTION_TRANSFER_REPLAY_CONFLICT",
        "'REPLAY', compact_record, schema_state, global_counter, cell_counter, tenant_counter",
    ] {
        assert!(
            replay.contains(required),
            "missing transfer replay binding: {required}"
        );
    }
    for forbidden in [
        "expected_ownership_revision",
        "counter_revision IS DISTINCT",
        "UPDATE ",
        "DELETE ",
        "INSERT ",
    ] {
        assert!(
            !replay.contains(forbidden),
            "replay depends on mutable evidence: {forbidden}"
        );
    }
    assert!(
        replay_end
            < position(
                body,
                "full_record.ownership_revision IS DISTINCT FROM expected_ownership_revision"
            )
    );
}

#[test]
fn transfer_fingerprint_cross_identity_conflict_is_closed_before_insert() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
    );
    let schema_lock = position(body, "SELECT * INTO STRICT schema_state");
    let fingerprint_conflict = position(
        body,
        "IF EXISTS (\n    SELECT 1 FROM object_store_retention.object_dispatch_compact_receipts\n     WHERE transfer_fingerprint = requested_transfer_fingerprint\n  ) THEN\n    RAISE EXCEPTION 'RETENTION_TRANSFER_REPLAY_CONFLICT' USING ERRCODE = '40001';\n  END IF;",
    );
    let insert = position(
        body,
        "INSERT INTO object_store_retention.object_dispatch_compact_receipts",
    );
    assert!(schema_lock < fingerprint_conflict);
    assert!(fingerprint_conflict < insert);
}

#[test]
fn transfer_first_seen_exact_binds_cas_and_gapless_sequence_allocation() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
    );
    for required in [
        "full_record.provider_boundary_id IS DISTINCT FROM requested_provider_boundary_id",
        "full_record.authenticated_cell_id IS DISTINCT FROM requested_authenticated_cell_id",
        "full_record.authenticated_tenant_id IS DISTINCT FROM requested_authenticated_tenant_id",
        "full_record.source_authority_blake3 IS DISTINCT FROM expected_source_authority_blake3",
        "full_record.ownership_revision IS DISTINCT FROM expected_ownership_revision",
        "expected_compact_sequence_high_water IS NULL",
        "schema_state.compact_sequence_high_water IS DISTINCT FROM\n        expected_compact_sequence_high_water",
        "schema_state.compact_sequence_revision IS DISTINCT FROM\n        expected_compact_sequence_revision",
        "global_counter.counter_revision IS DISTINCT FROM expected_global_counter_revision",
        "cell_counter.counter_revision IS DISTINCT FROM expected_cell_counter_revision",
        "tenant_counter.counter_revision IS DISTINCT FROM expected_tenant_counter_revision",
        "schema_state.compact_sequence_high_water = 18446744073709551615",
        "schema_state.compact_sequence_revision = 18446744073709551615",
        "database_now_unix_ms := object_store_retention.clock_unix_ms_v1()",
        "requested_compacted_at_unix_ms > database_now_unix_ms",
        "RETENTION_TRANSFER_TIME_INVALID",
        "SET compact_sequence_high_water = compact_sequence_high_water + 1,\n         compact_sequence_revision = compact_sequence_revision + 1",
        "schema_state.compact_sequence_high_water, requested_logical_request_id, requested_attempt_id",
    ] {
        assert!(
            body.contains(required),
            "missing transfer CAS invariant: {required}"
        );
    }
}

#[test]
fn transfer_atomically_replaces_full_with_complete_compact_and_updates_three_scopes() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
    );
    assert_eq!(
        body.matches("DELETE FROM object_store_retention.object_dispatch_full_record_ownership")
            .count(),
        1
    );
    assert_eq!(
        body.matches("INSERT INTO object_store_retention.object_dispatch_compact_receipts")
            .count(),
        1
    );
    for field in [
        "compact_sequence, logical_request_id, attempt_id, provider_boundary_id",
        "authenticated_cell_id, authenticated_tenant_id, source_authority_blake3",
        "compact_receipt_bytes, compact_blake3, compact_rows, compact_bytes",
        "compact_concurrency, compaction_fingerprint, transfer_fingerprint",
        "compacted_at_unix_ms, compact_prune_after_unix_ms",
    ] {
        assert!(
            body.contains(field),
            "missing compact insert field: {field}"
        );
    }
    assert_eq!(
        body.matches("SET full_record_rows = full_record_rows - full_record.full_record_rows,")
            .count(),
        3
    );
    assert_eq!(body.matches("compact_rows = compact_rows + 1,").count(), 3);
    assert_eq!(
        body.matches(
            "compact_bytes = compact_bytes + octet_length(requested_compact_receipt_bytes)"
        )
        .count(),
        3
    );
    for scope in [
        "scope_kind = 1 AND scope_id = 'object-store-full-to-compact-global-v1'",
        "scope_kind = 2 AND scope_id = requested_authenticated_cell_id",
        "scope_kind = 3 AND scope_id = requested_authenticated_tenant_id",
    ] {
        assert!(
            body.contains(scope),
            "missing transfer scope mutation: {scope}"
        );
    }
}

#[test]
fn transfer_checked_arithmetic_pins_underflow_overflow_and_child_global_bounds() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_transfer_v1(",
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
    );
    for required in [
        "global_counter.full_record_rows < full_record.full_record_rows",
        "global_counter.full_record_bytes < full_record.full_record_bytes",
        "cell_counter.full_record_rows < full_record.full_record_rows",
        "tenant_counter.full_record_bytes < full_record.full_record_bytes",
        "global_counter.compact_rows = 18446744073709551615",
        "cell_counter.compact_rows = 18446744073709551615",
        "tenant_counter.compact_rows = 18446744073709551615",
        "global_counter.compact_bytes > 18446744073709551615 - octet_length(requested_compact_receipt_bytes)",
        "tenant_counter.compact_bytes > 18446744073709551615 - octet_length(requested_compact_receipt_bytes)",
        "global_counter.counter_revision = 18446744073709551615",
        "tenant_counter.counter_revision = 18446744073709551615",
        "cell_counter.full_record_rows > global_counter.full_record_rows",
        "tenant_counter.compact_bytes > global_counter.compact_bytes",
        "RETENTION_TRANSFER_COUNTER_INVALID",
    ] {
        assert!(
            body.contains(required),
            "missing checked transfer arithmetic: {required}"
        );
    }
}

#[test]
fn prune_locks_schema_watermark_compact_then_replays_before_mutable_evidence() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    let schema = position(body, "SELECT * INTO STRICT schema_state");
    let watermark = position(body, "SELECT * INTO STRICT watermark");
    let compact = position(body, "SELECT * INTO compact_record");
    let replay = position(body, "IF NOT has_compact THEN");
    let first_seen = position(
        body,
        "IF requested_compact_sequence <= watermark.pruned_through_compact_sequence",
    );
    assert!(schema < watermark && watermark < compact && compact < replay && replay < first_seen);
    let replay_block = &body[replay..first_seen];
    for required in [
        "requested_compact_sequence > watermark.pruned_through_compact_sequence",
        "requested_compact_sequence = watermark.pruned_through_compact_sequence",
        "watermark.last_compact_blake3 IS DISTINCT FROM expected_compact_blake3",
        "watermark.last_prune_fingerprint IS DISTINCT FROM requested_prune_fingerprint",
        "RETENTION_PRUNE_REPLAY_CONFLICT",
        "'REPLAY', watermark, global_counter, NULL, NULL",
    ] {
        assert!(
            replay_block.contains(required),
            "missing prune replay invariant: {required}"
        );
    }
    for forbidden in [
        "watermark_revision IS DISTINCT",
        "counter_revision IS DISTINCT",
        "DELETE ",
        "UPDATE ",
    ] {
        assert!(
            !replay_block.contains(forbidden),
            "prune replay uses mutable evidence: {forbidden}"
        );
    }
}

#[test]
fn prune_first_seen_pins_gap_digest_cas_clock_backup_and_restore_safety() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    for required in [
        "requested_compact_sequence <> watermark.pruned_through_compact_sequence + 1",
        "watermark.pruned_through_compact_sequence > schema_state.compact_sequence_high_water",
        "requested_compact_sequence > schema_state.compact_sequence_high_water",
        "compact_record.compact_blake3 IS DISTINCT FROM expected_compact_blake3",
        "watermark.watermark_revision IS DISTINCT FROM expected_watermark_revision",
        "database_now_unix_ms := object_store_retention.clock_unix_ms_v1()",
        "database_now_unix_ms < compact_record.compact_prune_after_unix_ms",
        "watermark.last_pruned_at_unix_ms IS NOT NULL",
        "database_now_unix_ms < watermark.last_pruned_at_unix_ms",
        "backup_observed_at_unix_ms > database_now_unix_ms",
        "backup_observed_at_unix_ms < compact_record.compacted_at_unix_ms",
        "durable_covered_through_compact_sequence < requested_compact_sequence",
        "restore_verified_through_compact_sequence < requested_compact_sequence",
        "restore_verified_through_compact_sequence > durable_covered_through_compact_sequence",
        "RETENTION_PRUNE_SAFETY_EVIDENCE_INCOMPLETE",
        "global_counter.counter_revision IS DISTINCT FROM expected_global_counter_revision",
        "cell_counter.counter_revision IS DISTINCT FROM expected_cell_counter_revision",
        "tenant_counter.counter_revision IS DISTINCT FROM expected_tenant_counter_revision",
    ] {
        assert!(
            body.contains(required),
            "missing prune safety invariant: {required}"
        );
    }
}

#[test]
fn prune_atomically_deletes_one_compact_advances_watermark_and_subtracts_three_scopes() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    assert_eq!(
        body.matches("DELETE FROM object_store_retention.object_dispatch_compact_receipts")
            .count(),
        1
    );
    assert_eq!(
        body.matches("SET compact_rows = compact_rows - compact_record.compact_rows,")
            .count(),
        3
    );
    assert_eq!(
        body.matches("compact_bytes = compact_bytes - compact_record.compact_bytes,")
            .count(),
        3
    );
    for required in [
        "pruned_through_compact_sequence = requested_compact_sequence",
        "watermark_revision = watermark_revision + 1",
        "last_prune_fingerprint = requested_prune_fingerprint",
        "last_compact_blake3 = expected_compact_blake3",
        "last_pruned_at_unix_ms = database_now_unix_ms",
        "last_backup_revision = requested_backup_revision",
        "last_backup_manifest_blake3 = requested_backup_manifest_blake3",
        "WHERE singleton AND watermark_revision = expected_watermark_revision",
        "'APPLIED', watermark, global_counter, cell_counter, tenant_counter",
    ] {
        assert!(
            body.contains(required),
            "missing prune mutation: {required}"
        );
    }
}

#[test]
fn prune_checked_arithmetic_pins_underflow_overflow_and_child_global_bounds() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_retention_apply_prune_v1(",
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;",
    );
    for required in [
        "global_counter.compact_rows < compact_record.compact_rows",
        "global_counter.compact_bytes < compact_record.compact_bytes",
        "cell_counter.compact_rows < compact_record.compact_rows",
        "tenant_counter.compact_bytes < compact_record.compact_bytes",
        "watermark.watermark_revision = 18446744073709551615",
        "global_counter.counter_revision = 18446744073709551615",
        "tenant_counter.counter_revision = 18446744073709551615",
        "cell_counter.full_record_rows > global_counter.full_record_rows",
        "tenant_counter.compact_bytes > global_counter.compact_bytes",
        "RETENTION_PRUNE_COUNTER_INVALID",
    ] {
        assert!(
            body.contains(required),
            "missing checked prune arithmetic: {required}"
        );
    }
}

#[test]
fn mutation_failures_are_closed_and_required_singletons_are_typed_unavailable() {
    let sql = migration();
    assert_eq!(
        sql.matches("EXCEPTION WHEN no_data_found OR too_many_rows THEN")
            .count(),
        2
    );
    assert_eq!(
        sql.matches("RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000'")
            .count(),
        3
    );
    assert!(sql.contains(
        "IF watermark.pruned_through_compact_sequence > schema_state.compact_sequence_high_water THEN\n    RAISE EXCEPTION 'RETENTION_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000';"
    ));
    for required in [
        "RETENTION_TRANSFER_COMPARE_AND_SWAP_CONFLICT",
        "RETENTION_TRANSFER_REPLAY_CONFLICT",
        "RETENTION_TRANSFER_LIFECYCLE_CONFLICT",
        "RETENTION_PRUNE_COMPARE_AND_SWAP_CONFLICT",
        "RETENTION_PRUNE_REPLAY_CONFLICT",
        "RETENTION_PRUNE_LIFECYCLE_CONFLICT",
    ] {
        assert!(
            sql.contains(required),
            "missing typed mutation conflict: {required}"
        );
    }
}

#[test]
fn mutation_artifact_is_embedded_only_and_all_production_rust_remains_dark() {
    let module = include_str!("../src/retention_mutations.rs");
    for forbidden in ["tokio_postgres", "batch_execute", ".execute(", ".await"] {
        assert!(
            !module.contains(forbidden),
            "embedded module contains runtime call: {forbidden}"
        );
    }

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
            "object_store_retention_apply_transfer_v1",
            "object_store_retention_apply_prune_v1",
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
                // WP-114 CD-1's attester names the deferred 0004-0006 procedures to assert they are
                // ABSENT from a cell, which is the opposite of calling one. The stronger, use-based
                // rule for that file lives in
                // `deferred_0004_0006_mutation_names_are_only_listed_by_the_cell_installer` below,
                // which also proves itself against planted calls.
                continue;
            }
            assert!(
                !source.contains(sql_identifier),
                "retention mutation SQL identifier {sql_identifier} escaped the dedicated client into {}",
                source_path.display()
            );
        }
    }
}

/// The cell schema installer may *list* a deferred procedure name; it may not *use* one.
///
/// Spelling is not the invariant, and a guard on spelling is the wrong guard. The installer builds
/// every callable reference by interpolation, `format!("...{CELL_AUTHORITY_SCHEMA}.{}...", name)`,
/// so forbidding only the literal `object_store_retention.<name>` misses the exact form this module
/// emits. The rule here is positional instead: a deferred name may appear only inside the
/// `CELL_DEFERRED_PROCEDURES` array literal, which is an inventory of procedures that must be
/// ABSENT from a cell. Anywhere else in the file is a use.
///
/// Returns `Err` rather than asserting, so the identical rule can be run against a planted negative
/// control and not only against the real source.
fn deferred_name_is_only_listed(source: &str, name: &str) -> Result<(), String> {
    const INVENTORY: &str = "pub const CELL_DEFERRED_PROCEDURES: [&str; 6] = [";
    let start = source
        .find(INVENTORY)
        .ok_or_else(|| "CELL_DEFERRED_PROCEDURES inventory not found".to_owned())?;
    let after = start + INVENTORY.len();
    let end = source[after..]
        .find("];")
        .ok_or_else(|| "unterminated CELL_DEFERRED_PROCEDURES inventory".to_owned())?;
    let mut outside = String::with_capacity(source.len());
    outside.push_str(&source[..start]);
    outside.push_str(&source[after + end..]);
    if outside.contains(name) {
        return Err(format!(
            "{name} appears outside the inventory, which is a use, not a listing"
        ));
    }
    Ok(())
}

/// Prove the rule above rejects the two shapes a real call takes, not just the literal one.
///
/// Without this, the guard could be vacuous and nobody would know.
fn assert_deferred_name_rule_catches_real_call_shapes(source: &str, name: &str) {
    let interpolated =
        format!("{source}\nlet sql = format!(\"SELECT {{CELL_AUTHORITY_SCHEMA}}.{name}()\");\n");
    assert!(
        deferred_name_is_only_listed(&interpolated, name).is_err(),
        "the rule must reject the interpolated call form the installer's own idiom uses"
    );
    let literal = format!(
        "{source}\nclient.batch_execute(\"SELECT object_store_retention.{name}()\").await;\n"
    );
    assert!(
        deferred_name_is_only_listed(&literal, name).is_err(),
        "the rule must reject the schema-qualified literal call form"
    );
}

#[test]
fn deferred_0004_0006_mutation_names_are_only_listed_by_the_cell_installer() {
    let installer = include_str!("../src/cell_schema_install.rs");
    for name in [
        "object_store_retention_apply_transfer_v1",
        "object_store_retention_apply_prune_v1",
    ] {
        if let Err(violation) = deferred_name_is_only_listed(installer, name) {
            panic!("cell_schema_install.rs: {violation}");
        }
        assert_deferred_name_rule_catches_real_call_shapes(installer, name);
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::local_authority_provisioning::LOCAL_AUTHORITY_PROVISIONING_API_REVISION_V1;
use lore_object_dispatch::local_authority_provisioning::LOCAL_AUTHORITY_PROVISIONING_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_provisioning::LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1;
use lore_object_dispatch::local_authority_provisioning::validate_embedded_local_authority_provisioning_migration_v1;

const EXPECTED_MIGRATION_BYTES: usize = 24_837;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "90900a392e8d6ca0b59c12aa735e6acf8da364319025b8fae4cafe88a51ed14d";
const LOCAL_AUTHORITY_SCHEMA_BLAKE3: &str =
    "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";
const AUTHORITY_CATALOG_MANIFEST_SHA256: &str =
    "317145373c7f1929f9d85077d05660a6373e7407da3dd1ce88b64936ce7972c8";
const SCHEMA_STATE_TABLE: &str = "object_dispatch_retention_schema_state";
const AUTHORITY_TABLES: [&str; 7] = [
    "object_dispatch_requests",
    "object_dispatch_dispatchers",
    "object_dispatch_attempts",
    "object_dispatch_spool_objects",
    "object_dispatch_quota_usage",
    "object_dispatch_payload_purges",
    "object_dispatch_fetch_leases",
];

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1)
        .expect("local authority provisioning migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, function_name: &str) -> &'a str {
    let start = sql
        .find(function_name)
        .unwrap_or_else(|| panic!("missing function: {function_name}"));
    let body_start = sql[start..]
        .find("AS $$")
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("missing function body: {function_name}"));
    let body_end = sql[body_start + 5..]
        .find("\n$$;")
        .map(|offset| body_start + 5 + offset)
        .unwrap_or_else(|| panic!("missing function body terminator: {function_name}"));
    &sql[body_start..body_end]
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
        LOCAL_AUTHORITY_PROVISIONING_API_REVISION_V1,
        "object-store-dispatch-authority-provisioning-v1"
    );
    assert_eq!(
        LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_PROVISIONING_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_provisioning_migration_v1());
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
    assert!(!LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1.contains(&b'\r'));
    assert!(
        include_str!("../../.gitattributes")
            .lines()
            .any(|line| line == "lore-object-dispatch/migrations/*.sql text eol=lf")
    );
}

#[test]
fn migration_extends_only_the_existing_schema_state_singleton() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE TABLE ").count(), 0);
    assert_eq!(sql.matches("ALTER TABLE ").count(), 1);
    assert!(
        sql.contains("ALTER TABLE object_store_retention.object_dispatch_retention_schema_state")
    );
    for column in [
        "local_authority_schema_revision text",
        "local_authority_migration_blake3 object_store_retention.blake3_256",
        "local_authority_install_revision object_store_retention.uint64",
        "local_authority_installed_at_unix_ms bigint",
    ] {
        assert!(
            sql.contains(column),
            "missing schema-state column: {column}"
        );
    }
    assert!(sql.contains(
        "num_nonnulls(\n      local_authority_schema_revision,\n      local_authority_migration_blake3,\n      local_authority_install_revision,\n      local_authority_installed_at_unix_ms\n    ) IN (0, 4)"
    ));
    assert!(sql.contains("local_authority_install_revision > 0"));
}

#[test]
fn every_provisioning_surface_is_security_definer_with_fixed_catalog_search_path() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 5);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 5);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 5);
    assert!(!sql.contains("SET search_path = public"));
    assert!(!sql.contains("SET search_path = object_store_retention"));
}

#[test]
fn install_and_readback_authorize_before_api_or_request_validation() {
    let sql = migration();
    let install = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_authority_install_v1(",
    );
    let install_auth = install
        .find("PERFORM object_store_retention.assert_retention_migrator_v1();")
        .expect("install authorization");
    let install_api = install
        .find("assert_dispatch_authority_provisioning_api_revision_v1(api_revision)")
        .expect("install API validation");
    let install_request = install
        .find("expected_schema_revision IS DISTINCT FROM")
        .expect("install request validation");
    assert!(install_auth < install_api && install_api < install_request);

    let read = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_authority_read_state_v1(",
    );
    let read_auth = read
        .find("PERFORM object_store_retention.assert_retention_reader_v1();")
        .expect("read authorization");
    let read_api = read
        .find("assert_dispatch_authority_provisioning_api_revision_v1(api_revision)")
        .expect("read API validation");
    assert!(read_auth < read_api);
}

#[test]
fn provisioning_depends_on_prior_retention_helpers_and_local_schema() {
    let sql = migration();
    let retention_provisioning =
        include_str!("../migrations/0003_object_store_retention_provisioning.sql");
    let local_schema = include_str!("../migrations/0007_object_store_dispatch_authority_core.sql");
    for helper in [
        "assert_retention_migrator_v1",
        "assert_retention_reader_v1",
        "assert_serializable_write_v1",
        "clock_unix_ms_v1",
    ] {
        assert!(sql.contains(helper), "missing dependency call: {helper}");
        assert!(
            retention_provisioning
                .contains(&format!("CREATE FUNCTION object_store_retention.{helper}")),
            "prior migration does not define helper: {helper}"
        );
        assert!(
            !sql.contains(&format!("CREATE FUNCTION object_store_retention.{helper}")),
            "provisioning migration must not redefine helper: {helper}"
        );
    }
    for table in AUTHORITY_TABLES {
        assert!(
            local_schema.contains(&format!("CREATE TABLE object_store_retention.{table} (")),
            "0007 does not define authority table: {table}"
        );
    }
    assert_eq!(sql.matches(LOCAL_AUTHORITY_SCHEMA_BLAKE3).count(), 1);
    assert_eq!(
        sql.matches("object-store-dispatch-authority-schema-v1")
            .count(),
        2
    );
}

#[test]
fn install_requires_serializable_write_and_locks_schema_plus_seven_tables_in_fixed_order() {
    let install = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_authority_install_v1(",
    );
    let transaction_check = install
        .find("PERFORM object_store_retention.assert_serializable_write_v1();")
        .expect("serializable read-write assertion");
    let lock = install
        .find(
            "LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,\n    object_store_retention.object_dispatch_requests,\n    object_store_retention.object_dispatch_dispatchers,\n    object_store_retention.object_dispatch_attempts,\n    object_store_retention.object_dispatch_spool_objects,\n    object_store_retention.object_dispatch_quota_usage,\n    object_store_retention.object_dispatch_payload_purges,\n    object_store_retention.object_dispatch_fetch_leases\n    IN EXCLUSIVE MODE;",
        )
        .expect("fixed authority lock order");
    let catalog_check = install
        .find("PERFORM object_store_retention.assert_dispatch_authority_catalog_v1();")
        .expect("post-lock catalog assertion");
    assert!(transaction_check < lock && lock < catalog_check);
}

#[test]
fn install_exact_matches_local_schema_digest_and_positive_revision() {
    let sql = migration();
    for required in [
        "expected_schema_revision IS DISTINCT FROM 'object-store-dispatch-authority-schema-v1'",
        "expected_migration_blake3 IS DISTINCT FROM",
        "expected_install_revision IS NULL OR expected_install_revision = 0",
        "RAISE EXCEPTION 'DISPATCH_AUTHORITY_INSTALL_CONTRACT_MISMATCH' USING ERRCODE = '22023'",
    ] {
        assert!(
            sql.contains(required),
            "missing install identity check: {required}"
        );
    }
    assert_eq!(sql.matches(LOCAL_AUTHORITY_SCHEMA_BLAKE3).count(), 1);
}

#[test]
fn first_install_requires_pristine_seven_table_authority_and_publishes_all_identity() {
    let install = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_authority_install_v1(",
    );
    for table in AUTHORITY_TABLES {
        assert!(
            install.contains(&format!(
                "EXISTS (SELECT 1 FROM object_store_retention.{table})"
            )),
            "missing dirty-state guard: {table}"
        );
    }
    for assignment in [
        "local_authority_schema_revision = expected_schema_revision",
        "local_authority_migration_blake3 = expected_migration_blake3",
        "local_authority_install_revision = expected_install_revision",
        "local_authority_installed_at_unix_ms = installed_at",
    ] {
        assert!(
            install.contains(assignment),
            "missing install assignment: {assignment}"
        );
    }
    assert!(install.contains(
        "RAISE EXCEPTION 'DISPATCH_AUTHORITY_INSTALL_DIRTY_STATE' USING ERRCODE = '55000'"
    ));
    assert!(install.contains("project_dispatch_authority_state_v1('CREATED')"));
}

#[test]
fn replay_requires_exact_identity_and_pristine_seven_table_authority() {
    let install = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_authority_install_v1(",
    );
    for required in [
        "stored.local_authority_schema_revision IS DISTINCT FROM expected_schema_revision",
        "stored.local_authority_migration_blake3 IS DISTINCT FROM expected_migration_blake3",
        "stored.local_authority_install_revision IS DISTINCT FROM expected_install_revision",
        "RAISE EXCEPTION 'DISPATCH_AUTHORITY_INSTALL_REPLAY_CONFLICT' USING ERRCODE = '40001'",
        "project_dispatch_authority_state_v1('REPLAY')",
    ] {
        assert!(
            install.contains(required),
            "missing replay invariant: {required}"
        );
    }
    for table in AUTHORITY_TABLES {
        assert_eq!(
            install
                .matches(&format!(
                    "EXISTS (SELECT 1 FROM object_store_retention.{table})"
                ))
                .count(),
            2,
            "replay and first install must both reject rows in {table}"
        );
    }
}

#[test]
fn catalog_check_pins_exact_seven_table_inventory_validity_ownership_and_acl() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_authority_catalog_v1()",
    );
    for table in AUTHORITY_TABLES {
        assert!(
            catalog.contains(&format!("'{table}'")),
            "missing catalog table: {table}"
        );
    }
    for required in [
        "pg_catalog.pg_get_userbyid(relation.relowner)",
        "index_state.indisvalid",
        "index_state.indisready",
        "constraint_state.convalidated",
        "('object_dispatch_retention_runtime')",
        "('object_dispatch_retention_maintenance')",
        "('object_dispatch_retention_migrator')",
        "'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'",
        "pg_catalog.aclexplode(",
        "privilege.grantee = 0",
        "RAISE EXCEPTION 'DISPATCH_AUTHORITY_CATALOG_MISMATCH' USING ERRCODE = '55000'",
    ] {
        assert!(
            catalog.contains(required),
            "missing catalog invariant: {required}"
        );
    }
}

#[test]
fn catalog_manifest_covers_schema_state_and_seven_authority_relations() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_authority_catalog_v1()",
    );
    assert!(catalog.contains("DECLARE catalog_manifest text;"));
    assert!(catalog.contains("DECLARE catalog_manifest_sha256 bytea;"));
    assert!(catalog.contains("pg_catalog.concat_ws(\n    E'\\n',"));
    for section in [
        "'relations='",
        "'columns='",
        "'constraints='",
        "'indexes='",
        "'triggers='",
        "'policies='",
        "'functions='",
        "'function_acls='",
    ] {
        assert!(
            catalog.contains(section),
            "missing manifest section: {section}"
        );
    }
    for relation in std::iter::once(SCHEMA_STATE_TABLE).chain(AUTHORITY_TABLES) {
        assert!(
            catalog.matches(&format!("'{relation}'")).count() >= 9,
            "manifest and drift guards do not repeatedly inventory {relation}"
        );
    }
    assert!(catalog.contains(
        "catalog_manifest_sha256 := pg_catalog.sha256(pg_catalog.convert_to(catalog_manifest, 'UTF8'));"
    ));
    assert!(
        catalog.contains(
            "RAISE EXCEPTION 'DISPATCH_AUTHORITY_CATALOG_MISMATCH' USING ERRCODE = '55000'"
        )
    );
}

#[test]
fn catalog_manifest_has_exact_frozen_sha256() {
    assert!(migration().contains(&format!(
        "pg_catalog.decode('{AUTHORITY_CATALOG_MANIFEST_SHA256}', 'hex')"
    )));
}

#[test]
fn catalog_manifest_pins_every_column_constraint_index_trigger_and_policy_shape() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_authority_catalog_v1()",
    );
    for column_metadata in [
        "attribute.attnum",
        "attribute.attname",
        "pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)",
        "attribute.attnotnull",
        "attribute.attidentity",
        "attribute.attgenerated",
        "attribute.attcollation = 0",
        "collation_namespace.nspname, collation_state.collname",
        "pg_catalog.pg_get_expr(attribute_default.adbin, attribute_default.adrelid, false)",
        "attribute.attnum > 0",
        "NOT attribute.attisdropped",
    ] {
        assert!(
            catalog.contains(column_metadata),
            "missing column metadata: {column_metadata}"
        );
    }
    for constraint_metadata in [
        "constraint_state.conname",
        "constraint_state.contype",
        "constraint_state.condeferrable",
        "constraint_state.condeferred",
        "constraint_state.convalidated",
        "pg_catalog.pg_get_constraintdef(constraint_state.oid, false)",
    ] {
        assert!(
            catalog.contains(constraint_metadata),
            "missing constraint metadata: {constraint_metadata}"
        );
    }
    for index_metadata in [
        "index_relation.relname",
        "index_state.indisprimary",
        "index_state.indisunique",
        "index_state.indisexclusion",
        "index_state.indimmediate",
        "index_state.indisclustered",
        "index_state.indisvalid",
        "index_state.indisready",
        "index_state.indislive",
        "index_state.indcheckxmin",
        "index_state.indisreplident",
        "pg_catalog.pg_get_indexdef(index_state.indexrelid, 0, false)",
    ] {
        assert!(
            catalog.contains(index_metadata),
            "missing index metadata: {index_metadata}"
        );
    }
    for trigger_metadata in [
        "trigger.tgname",
        "trigger.tgenabled",
        "pg_catalog.pg_get_triggerdef(trigger.oid, false)",
        "NOT trigger.tgisinternal",
    ] {
        assert!(
            catalog.contains(trigger_metadata),
            "missing trigger metadata: {trigger_metadata}"
        );
    }
    for policy_metadata in [
        "policy.polname",
        "policy.polcmd",
        "policy.polpermissive",
        "policy.polroles::text",
        "pg_catalog.pg_get_expr(policy.polqual, policy.polrelid, false)",
        "pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid, false)",
    ] {
        assert!(
            catalog.contains(policy_metadata),
            "missing policy metadata: {policy_metadata}"
        );
    }
}

#[test]
fn catalog_manifest_pins_five_function_security_signatures_definitions_and_exact_acls() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_authority_catalog_v1()",
    );
    let functions = [
        "assert_dispatch_authority_provisioning_api_revision_v1",
        "assert_dispatch_authority_catalog_v1",
        "project_dispatch_authority_state_v1",
        "object_store_dispatch_authority_install_v1",
        "object_store_dispatch_authority_read_state_v1",
    ];
    for function in functions {
        assert!(
            catalog.matches(&format!("'{function}'")).count() >= 2,
            "function must appear in definition and ACL inventories: {function}"
        );
    }
    assert_eq!(
        catalog
            .matches("'assert_dispatch_authority_catalog_v1'")
            .count(),
        3,
        "catalog function needs two inventory entries plus its self-normalization branch"
    );
    for metadata in [
        "pg_catalog.pg_get_function_identity_arguments(procedure.oid)",
        "pg_catalog.pg_get_function_result(procedure.oid)",
        "procedure.prokind",
        "procedure.provolatile",
        "procedure.prosecdef",
        "procedure.proleakproof",
        "procedure.proisstrict",
        "procedure.proparallel",
        "procedure.proconfig",
        "pg_catalog.pg_get_userbyid(procedure.proowner)",
        "pg_catalog.pg_get_functiondef(procedure.oid)",
        "pg_catalog.regexp_replace(",
        "$catalog$pg_catalog\\.decode\\('[0-9a-f]{64}', 'hex'\\)$catalog$",
        "$catalog$pg_catalog.decode('<CATALOG_MANIFEST_SHA256>', 'hex')$catalog$",
        "CASE WHEN privilege.grantee = 0 THEN 'PUBLIC'",
        "privilege.privilege_type",
        "privilege.is_grantable",
        "COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))",
    ] {
        assert!(
            catalog.contains(metadata),
            "missing function metadata: {metadata}"
        );
    }
}

#[test]
fn catalog_guard_rejects_rls_relation_column_and_effective_role_acl_drift() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_authority_catalog_v1()",
    );
    for required in [
        "relation.relrowsecurity,\n        relation.relforcerowsecurity",
        "relation.relrowsecurity OR relation.relforcerowsecurity",
        "SELECT role.oid INTO STRICT authority_owner_oid",
        "role.rolname = 'object_dispatch_retention_owner'",
        "COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))",
        "privilege.grantee <> authority_owner_oid",
        "CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege",
        "attribute.attnum > 0",
        "NOT attribute.attisdropped",
        "('object_dispatch_retention_runtime')",
        "('object_dispatch_retention_maintenance')",
        "('object_dispatch_retention_migrator')",
        "pg_catalog.has_table_privilege(",
        "'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'",
    ] {
        assert!(
            catalog.contains(required),
            "missing drift rejection: {required}"
        );
    }
    assert!(
        catalog
            .matches("privilege.grantee <> authority_owner_oid")
            .count()
            >= 2,
        "relation and column ACLs must both remain owner-only"
    );
}

#[test]
fn readback_projects_complete_local_identity_and_all_seven_row_counts_or_unavailable() {
    let sql = migration();
    for field in [
        "local_authority_schema_revision text",
        "local_authority_migration_blake3 bytea",
        "local_authority_install_revision object_store_retention.uint64",
        "local_authority_installed_at_unix_ms bigint",
        "request_rows object_store_retention.uint64",
        "attempt_rows object_store_retention.uint64",
        "spool_object_rows object_store_retention.uint64",
        "quota_usage_rows object_store_retention.uint64",
        "dispatcher_rows object_store_retention.uint64",
        "payload_purge_rows object_store_retention.uint64",
        "fetch_lease_rows object_store_retention.uint64",
    ] {
        assert!(sql.contains(field), "missing readback field: {field}");
    }
    let projection = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.project_dispatch_authority_state_v1(result_code text)",
    );
    for table in AUTHORITY_TABLES {
        assert!(
            projection.contains(&format!(
                "(SELECT count(*) FROM object_store_retention.{table})"
            )),
            "missing readback row count: {table}"
        );
    }
    assert!(projection.contains("SELECT * INTO STRICT schema_state"));
    assert!(projection.contains("EXCEPTION WHEN no_data_found OR too_many_rows THEN"));
    assert!(
        projection
            .contains("RAISE EXCEPTION 'DISPATCH_AUTHORITY_UNAVAILABLE' USING ERRCODE = '55000'")
    );
    assert!(sql.contains("project_dispatch_authority_state_v1('READ')"));
}

#[test]
fn acl_exposes_only_install_and_read_without_direct_table_authority() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;")
    );
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 2);
    assert!(
        sql.contains(
            "TO object_dispatch_retention_migrator, object_dispatch_retention_maintenance;"
        )
    );
    assert!(sql.contains("TO object_dispatch_retention_migrator;\nGRANT EXECUTE ON FUNCTION"));
    assert!(sql.contains(
        "REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM\n  object_dispatch_retention_runtime,\n  object_dispatch_retention_maintenance,\n  object_dispatch_retention_migrator;"
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
            "unsafe provisioning grant: {forbidden}"
        );
    }
}

#[test]
fn provisioning_artifact_is_embedded_only_and_source_dark() {
    let module = include_str!("../src/local_authority_provisioning.rs");
    let library = include_str!("../src/lib.rs");
    for forbidden in [
        "tokio_postgres",
        "batch_execute",
        ".execute(",
        ".await",
        "provider_access_key",
        "provider_secret",
        "bucket_route",
        "endpoint_url",
    ] {
        assert!(
            !module.contains(forbidden),
            "embedded module contains runtime or provider token: {forbidden}"
        );
    }
    assert!(library.contains("pub mod local_authority_provisioning;"));
    assert!(!library.contains("LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1).await"));

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
            "object_store_dispatch_authority_install_v1",
            "object_store_dispatch_authority_read_state_v1",
        ] {
            assert!(
                !source.contains(sql_identifier),
                "source-dark SQL identifier {sql_identifier} appeared in {}",
                source_path.display()
            );
        }
    }
}

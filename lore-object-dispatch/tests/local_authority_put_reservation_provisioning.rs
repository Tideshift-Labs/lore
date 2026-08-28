// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract plus an opt-in PostgreSQL 16 probe for PUT-reservation provisioning.
//!
//! The ignored tier requires `LORE_TEST_LOCAL_PUT_RESERVATION_PROVISIONING_PG_URL`, an
//! administrator URL for a fresh disposable database. It installs the complete 0002/0003/0007-
//! 0011 chain itself and intentionally leaves global test roles for the disposable server owner.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::local_authority_put_reservation_provisioning::LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_put_reservation_provisioning::LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1;
use lore_object_dispatch::local_authority_put_reservation_provisioning::validate_embedded_local_authority_put_reservation_provisioning_migration_v1;
use tokio_postgres::error::SqlState;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 31_471;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "afe63db96bf286d1f04e6015eaf797e020b2fcbb2b13012224c66ef462d47248";
const CATALOG_MANIFEST_SHA256: &str =
    "837aa8d2654cea2204e88fcc56d4cd291199c73829aa77c0e55b69544864e32c";
const RETENTION_SCHEMA_BLAKE3: &str =
    "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";
const AUTHORITY_SCHEMA_BLAKE3: &str =
    "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";
const PUT_RESERVATION_SCHEMA_BLAKE3: &str =
    "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67";
const RELATIONS: [&str; 8] = [
    "object_dispatch_retention_schema_state",
    "object_dispatch_requests",
    "object_dispatch_attempts",
    "object_dispatch_spool_objects",
    "object_dispatch_quota_usage",
    "object_dispatch_dispatchers",
    "object_dispatch_payload_purges",
    "object_dispatch_fetch_leases",
];
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
    std::str::from_utf8(LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1)
        .expect("PUT-reservation provisioning migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, signature: &str) -> &'a str {
    let start = sql
        .find(signature)
        .unwrap_or_else(|| panic!("missing function: {signature}"));
    let body_start = sql[start..]
        .find("AS $$")
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("missing body: {signature}"));
    let body_end = sql[body_start + 5..]
        .find("\n$$;")
        .map(|offset| body_start + 5 + offset)
        .unwrap_or_else(|| panic!("missing body terminator: {signature}"));
    &sql[body_start..body_end]
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

#[test]
fn embedded_migration_has_frozen_identity_and_catalog_hash() {
    assert_eq!(
        LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_put_reservation_provisioning_migration_v1());
    assert!(migration().contains(&format!(
        "pg_catalog.decode('{CATALOG_MANIFEST_SHA256}', 'hex')"
    )));
}

#[test]
fn migration_is_one_lf_normalized_owner_transaction() {
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
    assert!(!LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1.contains(&b'\r'));
}

#[test]
fn schema_state_extension_is_all_or_none_and_positive() {
    let sql = migration();
    assert_eq!(sql.matches("ALTER TABLE ").count(), 1);
    assert_eq!(sql.matches("CREATE TABLE ").count(), 0);
    for column in [
        "put_reservation_schema_revision text",
        "put_reservation_migration_blake3 object_store_retention.blake3_256",
        "put_reservation_install_revision object_store_retention.uint64",
        "put_reservation_installed_at_unix_ms bigint",
    ] {
        assert!(
            sql.contains(column),
            "missing schema-state column: {column}"
        );
    }
    assert!(sql.contains(
        "pg_catalog.num_nonnulls(\n        put_reservation_schema_revision,\n        put_reservation_migration_blake3,\n        put_reservation_install_revision,\n        put_reservation_installed_at_unix_ms\n      ) = 4"
    ));
    assert!(sql.contains("put_reservation_install_revision > 0"));
    assert!(sql.contains("put_reservation_installed_at_unix_ms >= 0"));
}

#[test]
fn composite_state_and_five_fixed_security_definer_surfaces_are_exact() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE TYPE ").count(), 1);
    assert!(sql.contains(
        "CREATE TYPE object_store_retention.dispatch_put_reservation_provisioning_state_v1 AS ("
    ));
    for field in [
        "retention_schema_revision text",
        "local_authority_schema_revision text",
        "put_reservation_schema_revision text",
        "put_reservation_migration_blake3 bytea",
        "put_reservation_install_revision object_store_retention.uint64",
        "put_reservation_installed_at_unix_ms bigint",
        "fetch_lease_rows object_store_retention.uint64",
    ] {
        assert!(sql.contains(field), "missing state field: {field}");
    }
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 5);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 5);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 5);
}

#[test]
fn entrypoints_authorize_before_api_and_request_validation() {
    let sql = migration();
    let install = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_reservation_install_v1(",
    );
    let auth = install
        .find("assert_retention_migrator_v1()")
        .expect("install auth");
    let api = install
        .find("assert_dispatch_put_reservation_provisioning_api_revision_v1(")
        .expect("install API check");
    let request = install
        .find("expected_schema_revision IS DISTINCT FROM")
        .expect("install request check");
    assert!(auth < api && api < request);

    let read = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_reservation_read_state_v1(",
    );
    assert!(
        read.find("assert_retention_reader_v1()")
            .expect("read auth")
            < read
                .find("assert_dispatch_put_reservation_provisioning_api_revision_v1(")
                .expect("read API check")
    );
}

#[test]
fn install_pins_api_base_identities_serializable_mode_and_fixed_lock_order() {
    let install = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_reservation_install_v1(",
    );
    for required in [
        "object-store-dispatch-put-reservation-provisioning-v1",
        "PERFORM object_store_retention.assert_serializable_write_v1();",
        RETENTION_SCHEMA_BLAKE3,
        AUTHORITY_SCHEMA_BLAKE3,
        PUT_RESERVATION_SCHEMA_BLAKE3,
        "expected_install_revision IS NULL OR expected_install_revision = 0",
    ] {
        assert!(
            migration().contains(required),
            "missing install contract: {required}"
        );
    }
    let lock = "LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,\n    object_store_retention.object_dispatch_requests,\n    object_store_retention.object_dispatch_dispatchers,\n    object_store_retention.object_dispatch_attempts,\n    object_store_retention.object_dispatch_spool_objects,\n    object_store_retention.object_dispatch_quota_usage,\n    object_store_retention.object_dispatch_payload_purges,\n    object_store_retention.object_dispatch_fetch_leases\n    IN EXCLUSIVE MODE;";
    assert!(install.contains(lock));
    assert!(
        install.find(lock).expect("lock order")
            < install
                .find("assert_dispatch_put_reservation_catalog_v1()")
                .expect("catalog check")
    );
}

#[test]
fn install_and_replay_require_empty_authority_and_exact_extension_identity() {
    let install = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_reservation_install_v1(",
    );
    for table in AUTHORITY_TABLES {
        assert_eq!(
            install
                .matches(&format!(
                    "EXISTS (SELECT 1 FROM object_store_retention.{table})"
                ))
                .count(),
            2,
            "first install and replay must both reject {table} rows"
        );
    }
    for required in [
        "stored.put_reservation_schema_revision IS DISTINCT FROM expected_schema_revision",
        "stored.put_reservation_migration_blake3 IS DISTINCT FROM expected_migration_blake3",
        "stored.put_reservation_install_revision IS DISTINCT FROM expected_install_revision",
        "DISPATCH_PUT_RESERVATION_INSTALL_REPLAY_CONFLICT",
        "DISPATCH_PUT_RESERVATION_INSTALL_DIRTY_STATE",
        "project_dispatch_put_reservation_state_v1('REPLAY')",
        "project_dispatch_put_reservation_state_v1('CREATED')",
    ] {
        assert!(
            install.contains(required),
            "missing install/replay invariant: {required}"
        );
    }
}

#[test]
fn projection_requires_complete_three_layer_identity_and_all_row_counts() {
    let projection = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.project_dispatch_put_reservation_state_v1(",
    );
    for digest in [
        RETENTION_SCHEMA_BLAKE3,
        AUTHORITY_SCHEMA_BLAKE3,
        PUT_RESERVATION_SCHEMA_BLAKE3,
    ] {
        assert!(projection.contains(digest));
    }
    for table in AUTHORITY_TABLES {
        assert!(projection.contains(&format!(
            "(SELECT count(*) FROM object_store_retention.{table})"
        )));
    }
    assert!(projection.contains("DISPATCH_PUT_RESERVATION_UNAVAILABLE"));
    assert!(projection.contains("EXCEPTION WHEN no_data_found OR too_many_rows THEN"));
}

#[test]
fn catalog_manifest_pins_exact_eight_relations_and_every_shape_dimension() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_put_reservation_catalog_v1()",
    );
    for section in [
        "'relations='",
        "'columns='",
        "'types='",
        "'composite_attributes='",
        "'domain_constraints='",
        "'type_acls='",
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
    for relation in RELATIONS {
        assert!(
            catalog.matches(&format!("'{relation}'")).count() >= 9,
            "incomplete inventory for {relation}"
        );
    }
    for metadata in [
        "relation.relrowsecurity",
        "relation.relforcerowsecurity",
        "attribute.attnum",
        "attribute.attname",
        "pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)",
        "attribute.attnotnull",
        "attribute.attidentity",
        "attribute.attgenerated",
        "attribute.attcollation",
        "pg_catalog.pg_get_expr(attribute_default.adbin, attribute_default.adrelid, false)",
        "type_state.typtype",
        "type_state.typcategory",
        "type_state.typbasetype",
        "type_state.typrelid",
        "type_state.typdefaultbin",
        "type_state.typdefault",
        "constraint_state.contypid",
        "COALESCE(type_state.typacl, pg_catalog.acldefault('T', type_state.typowner))",
        "constraint_state.convalidated",
        "pg_catalog.pg_get_constraintdef(constraint_state.oid, false)",
        "index_state.indisvalid",
        "index_state.indisready",
        "index_state.indislive",
        "index_state.indcheckxmin",
        "pg_catalog.pg_get_indexdef(index_state.indexrelid, 0, false)",
        "pg_catalog.pg_get_triggerdef(trigger.oid, false)",
        "pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid, false)",
    ] {
        assert!(
            catalog.contains(metadata),
            "missing catalog metadata: {metadata}"
        );
    }
}

#[test]
fn catalog_manifest_pins_complete_schema_function_definitions_and_acls() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_put_reservation_catalog_v1()",
    );
    assert_eq!(
        catalog
            .matches("WHERE namespace.nspname = 'object_store_retention'")
            .count(),
        15
    );
    assert!(!catalog.contains("AND procedure.proname IN ("));
    for dependency in [
        "assert_retention_migrator_v1()",
        "assert_retention_reader_v1()",
        "assert_serializable_write_v1()",
        "clock_unix_ms_v1()",
    ] {
        assert!(migration().contains(dependency));
    }
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
        "<CATALOG_MANIFEST_SHA256>",
        "pg_catalog.aclexplode(",
        "privilege.privilege_type",
        "privilege.is_grantable",
    ] {
        assert!(
            catalog.contains(metadata),
            "missing function metadata: {metadata}"
        );
    }
}

#[test]
fn catalog_rejects_rls_owner_relation_column_and_effective_service_acl_drift() {
    let catalog = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.assert_dispatch_put_reservation_catalog_v1()",
    );
    for required in [
        "relation.relrowsecurity OR relation.relforcerowsecurity",
        "role.rolname = 'object_dispatch_retention_owner'",
        "COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))",
        "CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS privilege",
        "privilege.grantee <> authority_owner_oid",
        "('object_dispatch_retention_runtime')",
        "('object_dispatch_retention_maintenance')",
        "('object_dispatch_retention_migrator')",
        "pg_catalog.has_table_privilege(",
        "'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'",
    ] {
        assert!(
            catalog.contains(required),
            "missing fail-closed guard: {required}"
        );
    }
}

#[test]
fn acl_retires_old_entrypoints_and_exposes_only_new_install_and_read() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;")
    );
    assert!(sql.contains(
        "object_store_retention.object_store_dispatch_authority_install_v1(\n    text, text, bytea, object_store_retention.uint64\n  )\nFROM object_dispatch_retention_migrator;"
    ));
    assert!(sql.contains(
        "object_store_retention.object_store_dispatch_authority_read_state_v1(text)\nFROM object_dispatch_retention_migrator, object_dispatch_retention_maintenance;"
    ));
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 2);
    assert!(sql.contains(
        "object_store_dispatch_put_reservation_install_v1(\n    text, text, bytea, object_store_retention.uint64\n  )\nTO object_dispatch_retention_migrator;"
    ));
    assert!(sql.contains(
        "object_store_dispatch_put_reservation_read_state_v1(text)\nTO object_dispatch_retention_migrator, object_dispatch_retention_maintenance;"
    ));
    assert!(!sql.contains("GRANT SELECT ON"));
    assert!(!sql.contains("GRANT ALL ON TABLE"));
}

#[test]
fn artifact_is_embedded_and_source_dark_without_runtime_calls() {
    let module = include_str!("../src/local_authority_put_reservation_provisioning.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql\")"
    ));
    assert!(library.contains("pub mod local_authority_put_reservation_provisioning;"));
    for forbidden in [
        "tokio_postgres",
        "batch_execute",
        ".execute(",
        ".await",
        "provider_secret",
    ] {
        assert!(
            !module.contains(forbidden),
            "source-dark module contains {forbidden}"
        );
    }
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read production Rust source");
        for entrypoint in [
            "object_store_dispatch_put_reservation_install_v1",
            "object_store_dispatch_put_reservation_read_state_v1",
        ] {
            assert!(
                !source.contains(entrypoint),
                "runtime source {} calls {entrypoint}",
                path.display()
            );
        }
    }
}

async fn expect_sqlstate(
    client: &tokio_postgres::Client,
    sql: &str,
    expected: &SqlState,
    label: &str,
) {
    let error = match client.batch_execute(sql).await {
        Ok(()) => panic!("{label}: invalid operation was accepted"),
        Err(error) => error,
    };
    let database_error = error
        .as_db_error()
        .unwrap_or_else(|| panic!("{label}: expected typed PostgreSQL error, got {error}"));
    assert_eq!(database_error.code(), expected, "{label}");
}

async fn set_session_user(client: &tokio_postgres::Client, role: &str) {
    client
        .batch_execute(&format!("SET SESSION AUTHORIZATION {role};"))
        .await
        .unwrap_or_else(|error| panic!("set session authorization {role}: {error}"));
}

async fn reset_session_user(client: &tokio_postgres::Client) {
    client
        .batch_execute("RESET SESSION AUTHORIZATION;")
        .await
        .expect("reset administrator session authorization");
}

async fn serializable_call(
    client: &tokio_postgres::Client,
    role: &str,
    sql: &str,
) -> Result<tokio_postgres::Row, tokio_postgres::Error> {
    set_session_user(client, role).await;
    client
        .batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;")
        .await?;
    let result = client.query_one(sql, &[]).await;
    if result.is_ok() {
        client.batch_execute("COMMIT;").await?;
    } else {
        client.batch_execute("ROLLBACK;").await?;
    }
    reset_session_user(client).await;
    result
}

fn install_call() -> String {
    format!(
        "SELECT (object_store_retention.object_store_dispatch_put_reservation_install_v1(
           'object-store-dispatch-put-reservation-provisioning-v1',
           'object-store-dispatch-put-reservation-schema-v1',
           pg_catalog.decode('{PUT_RESERVATION_SCHEMA_BLAKE3}', 'hex'), 1
         )).result_code"
    )
}

async fn expect_catalog_drift(client: &tokio_postgres::Client, drift_sql: &str, label: &str) {
    client
        .batch_execute("BEGIN;")
        .await
        .expect("begin drift probe");
    client
        .batch_execute(drift_sql)
        .await
        .unwrap_or_else(|error| panic!("{label}: install drift: {error}"));
    set_session_user(client, "object_dispatch_retention_maintenance").await;
    let error = client
        .query_one(
            "SELECT (object_store_retention.object_store_dispatch_put_reservation_read_state_v1(
               'object-store-dispatch-put-reservation-provisioning-v1'
             )).result_code",
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(
        error
            .as_db_error()
            .expect("typed catalog drift error")
            .code(),
        &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE,
        "{label}"
    );
    client
        .batch_execute("ROLLBACK;")
        .await
        .expect("rollback drift");
    reset_session_user(client).await;
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_chain_install_replay_read_and_drift_fail_closed() {
    let url = std::env::var("LORE_TEST_LOCAL_PUT_RESERVATION_PROVISIONING_PG_URL").expect(
        "LORE_TEST_LOCAL_PUT_RESERVATION_PROVISIONING_PG_URL must name a fresh disposable database",
    );
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable provisioning database");
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "put-reservation-provisioning-postgres",
        async move {
            let _ = connection.await;
        }
    ));
    client
        .batch_execute(
            "DO $$ BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime NOLOGIN; END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance NOLOGIN; END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator NOLOGIN; END IF;
             END $$;
             GRANT object_dispatch_retention_owner TO CURRENT_USER;
             DO $$ BEGIN EXECUTE pg_catalog.format(
               'GRANT CREATE ON DATABASE %I TO object_dispatch_retention_owner',
               pg_catalog.current_database()
             ); END $$;",
        )
        .await
        .expect("bootstrap disposable roles");
    for migration in [
        include_str!("../migrations/0002_object_store_retention_authority.sql"),
        include_str!("../migrations/0003_object_store_retention_provisioning.sql"),
        include_str!("../migrations/0007_object_store_dispatch_authority_core.sql"),
        include_str!("../migrations/0008_object_store_dispatch_authority_provisioning.sql"),
    ] {
        client
            .batch_execute(migration)
            .await
            .expect("apply base migration");
    }

    let retention_install = format!(
        "SELECT (object_store_retention.object_store_retention_install_v1(
          'object-store-retention-provisioning-v1', 'object-store-retention-authority-schema-v1',
          pg_catalog.decode('{RETENTION_SCHEMA_BLAKE3}', 'hex'), 1)).result_code"
    );
    assert_eq!(
        serializable_call(
            &client,
            "object_dispatch_retention_migrator",
            &retention_install
        )
        .await
        .expect("install base retention")
        .get::<_, String>(0),
        "CREATED"
    );
    let authority_install = format!(
        "SELECT (object_store_retention.object_store_dispatch_authority_install_v1(
          'object-store-dispatch-authority-provisioning-v1',
          'object-store-dispatch-authority-schema-v1',
          pg_catalog.decode('{AUTHORITY_SCHEMA_BLAKE3}', 'hex'), 1)).result_code"
    );
    assert_eq!(
        serializable_call(
            &client,
            "object_dispatch_retention_migrator",
            &authority_install
        )
        .await
        .expect("install base authority")
        .get::<_, String>(0),
        "CREATED"
    );
    for migration in [
        include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql"),
        include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql"),
        include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql"),
    ] {
        client
            .batch_execute(migration)
            .await
            .expect("apply extension migration");
    }

    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM pg_catalog.pg_proc AS procedure
                 JOIN pg_catalog.pg_namespace AS namespace
                   ON namespace.oid = procedure.pronamespace
                 WHERE namespace.nspname = 'object_store_retention'",
                &[],
            )
            .await
            .expect("count complete authority function inventory")
            .get::<_, i64>(0),
        29
    );

    expect_sqlstate(
        &client,
        "UPDATE object_store_retention.object_dispatch_retention_schema_state
         SET put_reservation_schema_revision = 'object-store-dispatch-put-reservation-schema-v1',
             put_reservation_install_revision = 1,
             put_reservation_installed_at_unix_ms = 0;",
        &SqlState::CHECK_VIOLATION,
        "partial extension identity",
    )
    .await;

    set_session_user(&client, "object_dispatch_retention_owner").await;
    expect_sqlstate(
        &client,
        "SELECT object_store_retention.object_store_dispatch_put_reservation_install_v1(
           'bad-api', 'bad-schema', NULL, 0);",
        &SqlState::INSUFFICIENT_PRIVILEGE,
        "authorization before API validation",
    )
    .await;
    reset_session_user(&client).await;

    set_session_user(&client, "object_dispatch_retention_migrator").await;
    expect_sqlstate(
        &client,
        "SELECT object_store_retention.object_store_dispatch_put_reservation_install_v1(
           'bad-api', 'object-store-dispatch-put-reservation-schema-v1',
           decode('56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67', 'hex'), 1);",
        &SqlState::INVALID_PARAMETER_VALUE,
        "bad API revision",
    )
    .await;
    expect_sqlstate(
        &client,
        &install_call(),
        &SqlState::INVALID_TRANSACTION_STATE,
        "nonserializable install",
    )
    .await;
    expect_sqlstate(
        &client,
        &authority_install,
        &SqlState::INSUFFICIENT_PRIVILEGE,
        "retired authority install entrypoint",
    )
    .await;
    reset_session_user(&client).await;

    client
        .batch_execute(
            "INSERT INTO object_store_retention.object_dispatch_quota_usage (
               schema_revision, provider_boundary_id, scope_kind, scope_id, quota_class,
               counter_revision, updated_at_unix_ms
             ) VALUES (
               'object-store-dispatch-authority-schema-v1', 'dirty-boundary', 1,
               'dirty-boundary', 1, 1, 0
             );",
        )
        .await
        .expect("seed dirty authority");
    let dirty_error = serializable_call(
        &client,
        "object_dispatch_retention_migrator",
        &install_call(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        dirty_error.as_db_error().expect("typed dirty error").code(),
        &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE
    );
    client
        .batch_execute("DELETE FROM object_store_retention.object_dispatch_quota_usage;")
        .await
        .expect("remove dirty fixture");

    for expected in ["CREATED", "REPLAY"] {
        assert_eq!(
            serializable_call(
                &client,
                "object_dispatch_retention_migrator",
                &install_call()
            )
            .await
            .unwrap_or_else(|error| panic!("{expected} install: {error}"))
            .get::<_, String>(0),
            expected
        );
    }
    set_session_user(&client, "object_dispatch_retention_maintenance").await;
    let read: String = client
        .query_one(
            "SELECT (object_store_retention.object_store_dispatch_put_reservation_read_state_v1(
               'object-store-dispatch-put-reservation-provisioning-v1'
             )).result_code",
            &[],
        )
        .await
        .expect("maintenance read")
        .get(0);
    assert_eq!(read, "READ");
    expect_sqlstate(
        &client,
        "SELECT object_store_retention.object_store_dispatch_authority_read_state_v1(
           'object-store-dispatch-authority-provisioning-v1');",
        &SqlState::INSUFFICIENT_PRIVILEGE,
        "retired authority read entrypoint",
    )
    .await;
    reset_session_user(&client).await;

    for (label, drift) in [
        (
            "added column",
            "ALTER TABLE object_store_retention.object_dispatch_spool_objects ADD COLUMN drift integer;",
        ),
        (
            "dropped lookup index",
            "DROP INDEX object_store_retention.object_dispatch_spool_objects_put_reservation_lookup_idx;",
        ),
        (
            "replaced codec function",
            "CREATE OR REPLACE FUNCTION object_store_retention.local_canonical_u8_v1(value integer)
             RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
             SET search_path = pg_catalog AS 'SELECT pg_catalog.decode(''00'', ''hex'')';",
        ),
        (
            "replaced trusted clock function",
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1()
             RETURNS bigint LANGUAGE sql VOLATILE SECURITY DEFINER
             SET search_path = pg_catalog AS 'SELECT 0::bigint';",
        ),
        (
            "dropped uint64 domain constraint",
            "ALTER DOMAIN object_store_retention.uint64 DROP CONSTRAINT uint64_check;",
        ),
        (
            "altered provisioning composite",
            "ALTER TYPE object_store_retention.dispatch_put_reservation_provisioning_state_v1
             ADD ATTRIBUTE drift integer;",
        ),
        (
            "extra service-executable function",
            "CREATE FUNCTION object_store_retention.drift_exec_v1()
             RETURNS void LANGUAGE sql AS 'SELECT';
             GRANT EXECUTE ON FUNCTION object_store_retention.drift_exec_v1()
             TO object_dispatch_retention_maintenance;",
        ),
        (
            "column grant",
            "GRANT SELECT (protocol_revision) ON object_store_retention.object_dispatch_spool_objects
             TO object_dispatch_retention_runtime;",
        ),
        (
            "forced RLS",
            "ALTER TABLE object_store_retention.object_dispatch_spool_objects FORCE ROW LEVEL SECURITY;",
        ),
    ] {
        expect_catalog_drift(&client, drift, label).await;
    }
}

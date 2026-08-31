// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract plus an opt-in PostgreSQL 16 probe for per-participant dispatcher-identity
//! provisioning and readback (WP-114 CD-3, CR-033 D8's review caveat N2).
//!
//! The ignored tier requires `LORE_TEST_LOCAL_DISPATCHER_IDENTITY_PROVISIONING_PG_URL`, an
//! administrator URL for a fresh disposable database. It installs the complete cell install set
//! (0002, 0003, 0007-0019) itself and intentionally leaves global test roles for the disposable
//! server owner.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::local_authority_dispatcher_identity_provisioning::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_dispatcher_identity_provisioning::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1;
use lore_object_dispatch::local_authority_dispatcher_identity_provisioning::validate_embedded_local_authority_dispatcher_identity_provisioning_migration_v1;
use tokio_postgres::error::SqlState;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 22_692;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "6413bda96da9263c0d0b631b7c696fd717ff67ff198a2c3304de7d202decfc70";
const RETENTION_SCHEMA_BLAKE3: &str =
    "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";
const AUTHORITY_SCHEMA_BLAKE3: &str =
    "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";
const PUT_RESERVATION_SCHEMA_BLAKE3: &str =
    "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67";
const DISPATCHER_IDENTITY_SCHEMA_BLAKE3: &str =
    "a7d54d94d0fa5035872eb9b3426cbbe6471bcf9ae34ed41877542f050e1aaad9";
const DISPATCHER_IDENTITY_API_REVISION: &str =
    "object-store-dispatch-dispatcher-identity-provisioning-v1";
const DISPATCHER_IDENTITY_SCHEMA_REVISION: &str =
    "object-store-dispatch-dispatcher-identity-schema-v1";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1)
        .expect("dispatcher-identity provisioning migration must remain UTF-8 SQL")
}

fn compact(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
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
fn embedded_migration_has_frozen_identity_and_pins_the_installed_schema_digest() {
    assert_eq!(
        LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_dispatcher_identity_provisioning_migration_v1());
    // 0019 both installs and attests 0018's schema edge; its embedded digest literal must be
    // 0018's frozen BLAKE3, not its own.
    assert!(migration().contains(&format!(
        "pg_catalog.decode('{DISPATCHER_IDENTITY_SCHEMA_BLAKE3}', 'hex')"
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
    assert!(!LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1.contains(&b'\r'));
}

#[test]
fn schema_state_extension_is_all_or_none_and_positive() {
    let sql = migration();
    assert_eq!(sql.matches("ALTER TABLE ").count(), 1);
    assert_eq!(sql.matches("CREATE TABLE ").count(), 0);
    for column in [
        "dispatcher_identity_schema_revision text",
        "dispatcher_identity_migration_blake3 object_store_retention.blake3_256",
        "dispatcher_identity_install_revision object_store_retention.uint64",
        "dispatcher_identity_installed_at_unix_ms bigint",
    ] {
        assert!(
            sql.contains(column),
            "missing schema-state column: {column}"
        );
    }
    assert!(sql.contains(
        "pg_catalog.num_nonnulls(\n        dispatcher_identity_schema_revision,\n        dispatcher_identity_migration_blake3,\n        dispatcher_identity_install_revision,\n        dispatcher_identity_installed_at_unix_ms\n      ) = 0"
    ));
    assert!(sql.contains(
        "pg_catalog.num_nonnulls(\n        dispatcher_identity_schema_revision,\n        dispatcher_identity_migration_blake3,\n        dispatcher_identity_install_revision,\n        dispatcher_identity_installed_at_unix_ms\n      ) = 4"
    ));
    assert!(sql.contains(&format!(
        "dispatcher_identity_schema_revision =\n        '{DISPATCHER_IDENTITY_SCHEMA_REVISION}'"
    )));
    assert!(sql.contains("dispatcher_identity_install_revision > 0"));
    assert!(sql.contains("dispatcher_identity_installed_at_unix_ms >= 0"));
}

#[test]
fn composite_state_and_six_fixed_security_definer_surfaces_are_exact() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE TYPE ").count(), 1);
    assert!(
        sql.contains(
            "CREATE TYPE object_store_retention.dispatch_dispatcher_identity_state_v1 AS ("
        )
    );
    for field in [
        "result_code text",
        "retention_schema_revision text",
        "retention_migration_blake3 bytea",
        "retention_install_revision object_store_retention.uint64",
        "retention_installed_at_unix_ms bigint",
        "local_authority_schema_revision text",
        "local_authority_migration_blake3 bytea",
        "local_authority_install_revision object_store_retention.uint64",
        "local_authority_installed_at_unix_ms bigint",
        "put_reservation_schema_revision text",
        "put_reservation_migration_blake3 bytea",
        "put_reservation_install_revision object_store_retention.uint64",
        "put_reservation_installed_at_unix_ms bigint",
        "dispatcher_identity_schema_revision text",
        "dispatcher_identity_migration_blake3 bytea",
        "dispatcher_identity_install_revision object_store_retention.uint64",
        "dispatcher_identity_installed_at_unix_ms bigint",
    ] {
        assert!(sql.contains(field), "missing state field: {field}");
    }
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 6);
    // 7, not 6: the migration's own header comment names "a planted SECURITY DEFINER function" as
    // the kind of drift the out-of-band attester (not this in-schema readback) exists to catch.
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 7);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 6);
}

#[test]
fn entrypoints_authorize_before_api_then_serializable_write_then_lock_then_objects_assertion() {
    let sql = migration();
    let install = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(",
    );
    let auth = install
        .find("assert_retention_migrator_v1()")
        .expect("install auth");
    let api = install
        .find("assert_dispatch_dispatcher_identity_api_revision_v1(api_revision)")
        .expect("install API check");
    let serializable = install
        .find("assert_serializable_write_v1()")
        .expect("install serializable check");
    let lock = install.find("LOCK TABLE").expect("lock order");
    let objects = install
        .find("assert_dispatch_dispatcher_identity_objects_v1()")
        .expect("objects assertion");
    assert!(auth < api && api < serializable && serializable < lock && lock < objects);

    let read = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(",
    );
    assert!(
        read.find("assert_dispatch_dispatcher_identity_reader_v1()")
            .expect("read auth")
            < read
                .find("assert_dispatch_dispatcher_identity_api_revision_v1(api_revision)")
                .expect("read API check")
    );
}

#[test]
fn install_pins_lock_targets_and_replay_and_dirty_state_require_empty_dispatcher_authority() {
    let sql = migration();
    let install = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(",
    );
    let lock = "LOCK TABLE object_store_retention.object_dispatch_retention_schema_state,\n    object_store_retention.object_dispatch_dispatchers,\n    object_store_retention.object_dispatch_attempts\n    IN EXCLUSIVE MODE;";
    assert!(install.contains(lock));
    for table in ["object_dispatch_dispatchers", "object_dispatch_attempts"] {
        assert_eq!(
            install
                .matches(&format!(
                    "EXISTS (SELECT 1 FROM object_store_retention.{table})"
                ))
                .count(),
            2,
            "both the replay-conflict and dirty-state checks must reject any {table} row"
        );
    }
    for required in [
        DISPATCHER_IDENTITY_SCHEMA_REVISION,
        "DISPATCH_DISPATCHER_IDENTITY_INSTALL_REPLAY_CONFLICT",
        "DISPATCH_DISPATCHER_IDENTITY_INSTALL_DIRTY_STATE",
        "DISPATCH_DISPATCHER_IDENTITY_INSTALL_CONTRACT_MISMATCH",
        "project_dispatch_dispatcher_identity_state_v1('REPLAY')",
        "project_dispatch_dispatcher_identity_state_v1('CREATED')",
    ] {
        assert!(
            install.contains(required),
            "missing install invariant: {required}"
        );
    }
}

#[test]
fn install_requires_the_previously_installed_put_reservation_layer() {
    let sql = migration();
    let install = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(",
    );
    assert!(install.contains(&format!(
        "stored.put_reservation_schema_revision IS DISTINCT FROM\n       '{PUT_RESERVATION_SCHEMA_REVISION}'",
        PUT_RESERVATION_SCHEMA_REVISION = "object-store-dispatch-put-reservation-schema-v1"
    )));
    assert!(install.contains("stored.put_reservation_install_revision IS NULL"));
    assert!(install.contains("DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE"));
}

#[test]
fn projection_requires_complete_four_layer_identity() {
    let sql = migration();
    let projection = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.project_dispatch_dispatcher_identity_state_v1(",
    );
    for digest in [
        RETENTION_SCHEMA_BLAKE3,
        AUTHORITY_SCHEMA_BLAKE3,
        PUT_RESERVATION_SCHEMA_BLAKE3,
        DISPATCHER_IDENTITY_SCHEMA_BLAKE3,
    ] {
        assert!(
            projection.contains(digest),
            "missing projected digest: {digest}"
        );
    }
    assert!(projection.contains("assert_dispatch_dispatcher_identity_objects_v1();"));
    assert!(projection.contains("DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE"));
    assert!(projection.contains("EXCEPTION WHEN no_data_found OR too_many_rows THEN"));
}

#[test]
fn grants_expose_read_state_to_all_three_roles_and_install_to_migrator_only() {
    let compact_sql = compact(migration());
    assert_eq!(compact_sql.matches("GRANT EXECUTE ON FUNCTION").count(), 2);
    assert!(compact_sql.contains(
        "GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_install_v1( text, text, bytea, object_store_retention.uint64 ) TO object_dispatch_retention_migrator;"
    ));
    assert!(compact_sql.contains(
        "GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(text) TO object_dispatch_retention_migrator, object_dispatch_retention_maintenance, object_dispatch_retention_runtime;"
    ));
}

#[test]
fn acl_does_not_reissue_0011s_blanket_runtime_function_revoke() {
    // 0011 issues `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM
    // object_dispatch_retention_runtime`, safe there only because migrations 0013, 0015, and 0017
    // grant the runtime mutation entrypoints (reserve_put_v1, put_upload_progress_v1,
    // put_spool_ready_v1) afterwards. 0019 runs after all three: reissuing the same blanket revoke
    // here would silently strip those grants from the only role permitted to call them and fail
    // the cell closed on every mutation. This is a regression fence, not a positive contract pin.
    assert!(!migration().contains(
        "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM object_dispatch_retention_runtime"
    ));
}

#[test]
fn artifact_is_embedded_and_source_dark_without_runtime_calls() {
    let module = include_str!("../src/local_authority_dispatcher_identity_provisioning.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0019_object_store_dispatch_dispatcher_identity_provisioning.sql\")"
    ));
    assert!(library.contains("pub mod local_authority_dispatcher_identity_provisioning;"));
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
    // WP-114 CD-1's out-of-band installer/attester and its one-shot operator binary are the crate's
    // one deliberate, non-runtime caller of these entrypoints, exempted by exact file path (never by
    // file name alone -- a future `src/spool/cell_schema_install.rs` must not inherit the exemption
    // by sharing a name). `tests/cell_schema_install.rs` proves they are the only two files that
    // reference the installer at all.
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let installer_paths = [
        src_root.join("cell_schema_install.rs"),
        src_root.join("bin").join("cell-schema-install.rs"),
    ];
    for path in sources {
        if installer_paths.contains(&path) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read production Rust source");
        for entrypoint in [
            "object_store_dispatch_dispatcher_identity_install_v1",
            "object_store_dispatch_dispatcher_identity_read_state_v1",
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

async fn expect_serializable_sqlstate(
    client: &tokio_postgres::Client,
    role: &str,
    sql: &str,
    expected: &SqlState,
    label: &str,
) {
    let error = serializable_call(client, role, sql)
        .await
        .expect_err(&format!("{label}: expected rejection"));
    let database_error = error
        .as_db_error()
        .unwrap_or_else(|| panic!("{label}: expected typed PostgreSQL error, got {error}"));
    assert_eq!(database_error.code(), expected, "{label}");
}

fn install_call(
    api_revision: &str,
    schema_revision: &str,
    digest_hex: &str,
    install_revision: &str,
) -> String {
    format!(
        "SELECT (object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(
           '{api_revision}', '{schema_revision}', decode('{digest_hex}', 'hex'), {install_revision}
         )).result_code"
    )
}

fn read_call() -> String {
    format!(
        "SELECT (object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(
           '{DISPATCHER_IDENTITY_API_REVISION}'
         )).result_code"
    )
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_dispatcher_identity_readback_authorizes_by_role_and_fails_closed_on_catalog_drift()
 {
    let url = std::env::var("LORE_TEST_LOCAL_DISPATCHER_IDENTITY_PROVISIONING_PG_URL").expect(
        "LORE_TEST_LOCAL_DISPATCHER_IDENTITY_PROVISIONING_PG_URL must name a fresh disposable database",
    );
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable dispatcher-identity provisioning database");
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "dispatcher-identity-provisioning-postgres",
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
            .expect("apply put-reservation migration");
    }
    let put_reservation_install = format!(
        "SELECT (object_store_retention.object_store_dispatch_put_reservation_install_v1(
          'object-store-dispatch-put-reservation-provisioning-v1',
          'object-store-dispatch-put-reservation-schema-v1',
          pg_catalog.decode('{PUT_RESERVATION_SCHEMA_BLAKE3}', 'hex'), 1)).result_code"
    );
    assert_eq!(
        serializable_call(
            &client,
            "object_dispatch_retention_migrator",
            &put_reservation_install
        )
        .await
        .expect("install put-reservation layer")
        .get::<_, String>(0),
        "CREATED"
    );
    for migration in [
        include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"),
        include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql"),
        include_str!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql"),
        include_str!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql"),
        include_str!("../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql"),
        include_str!("../migrations/0017_object_store_dispatch_put_spool_ready_mutation.sql"),
        include_str!("../migrations/0018_object_store_dispatch_dispatcher_identity_schema.sql"),
        include_str!(
            "../migrations/0019_object_store_dispatch_dispatcher_identity_provisioning.sql"
        ),
    ] {
        client
            .batch_execute(migration)
            .await
            .expect("apply mutation-chain and dispatcher-identity migration");
    }

    // Item 5a: a wrong API revision is rejected before the serializable-write requirement is even
    // reached, so no explicit SERIALIZABLE transaction is needed to observe it.
    set_session_user(&client, "object_dispatch_retention_migrator").await;
    expect_sqlstate(
        &client,
        &install_call(
            "bad-api",
            DISPATCHER_IDENTITY_SCHEMA_REVISION,
            DISPATCHER_IDENTITY_SCHEMA_BLAKE3,
            "1",
        ),
        &SqlState::INVALID_PARAMETER_VALUE,
        "bad API revision",
    )
    .await;
    reset_session_user(&client).await;

    // Item 5b: a wrong expected artifact digest is a contract mismatch, raised only after the
    // serializable-write requirement passes.
    expect_serializable_sqlstate(
        &client,
        "object_dispatch_retention_migrator",
        &install_call(
            DISPATCHER_IDENTITY_API_REVISION,
            DISPATCHER_IDENTITY_SCHEMA_REVISION,
            &"00".repeat(32),
            "1",
        ),
        &SqlState::INVALID_PARAMETER_VALUE,
        "wrong expected artifact digest",
    )
    .await;

    // Item 5c/5d: the first correctly-formed install call creates the layer; a second, identical
    // call replays it rather than mutating anything further.
    let correct_install = install_call(
        DISPATCHER_IDENTITY_API_REVISION,
        DISPATCHER_IDENTITY_SCHEMA_REVISION,
        DISPATCHER_IDENTITY_SCHEMA_BLAKE3,
        "1",
    );
    for expected in ["CREATED", "REPLAY"] {
        assert_eq!(
            serializable_call(
                &client,
                "object_dispatch_retention_migrator",
                &correct_install
            )
            .await
            .unwrap_or_else(|error| panic!("{expected} install: {error}"))
            .get::<_, String>(0),
            expected
        );
    }

    // Item 4: the readback is reachable by all three known roles and refused for everyone else.
    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
    ] {
        set_session_user(&client, role).await;
        let read: String = client
            .query_one(&read_call(), &[])
            .await
            .unwrap_or_else(|error| panic!("{role} read: {error}"))
            .get(0);
        assert_eq!(read, "READ", "{role}");
        reset_session_user(&client).await;
    }
    set_session_user(&client, "object_dispatch_retention_owner").await;
    let owner_error = client.query_one(&read_call(), &[]).await.unwrap_err();
    assert_eq!(
        owner_error
            .as_db_error()
            .expect("typed authorization error")
            .code(),
        &SqlState::INSUFFICIENT_PRIVILEGE
    );
    reset_session_user(&client).await;

    // Item 6: an additional unique index on the dispatchers table whose key omits dispatcher_id
    // makes the readback fail closed, and dropping it restores READ. Run only while the table holds
    // no rows, since a duplicate (provider_boundary_id, lease_generation) pair across participants
    // would otherwise prevent the index from being created at all.
    client
        .batch_execute(
            "CREATE UNIQUE INDEX drift_generation_only_idx
             ON object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, lease_generation);",
        )
        .await
        .expect("create a participant-blind unique index on an empty table");
    set_session_user(&client, "object_dispatch_retention_maintenance").await;
    let drift_error = client.query_one(&read_call(), &[]).await.unwrap_err();
    assert_eq!(
        drift_error
            .as_db_error()
            .expect("typed catalog-mismatch error")
            .code(),
        &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE,
        "participant-blind unique index must fail the readback closed"
    );
    reset_session_user(&client).await;
    client
        .batch_execute("DROP INDEX object_store_retention.drift_generation_only_idx;")
        .await
        .expect("remove the participant-blind unique index");
    set_session_user(&client, "object_dispatch_retention_maintenance").await;
    let restored: String = client
        .query_one(&read_call(), &[])
        .await
        .expect("read after removing the drift index")
        .get(0);
    assert_eq!(restored, "READ");
    reset_session_user(&client).await;

    // Item 7: dropping D8's own participant index likewise fails the readback closed.
    client
        .batch_execute(
            "DROP INDEX object_store_retention.object_dispatch_dispatchers_one_active_participant_idx;",
        )
        .await
        .expect("drop the participant index");
    set_session_user(&client, "object_dispatch_retention_maintenance").await;
    let missing_participant_index_error = client.query_one(&read_call(), &[]).await.unwrap_err();
    assert_eq!(
        missing_participant_index_error
            .as_db_error()
            .expect("typed catalog-mismatch error")
            .code(),
        &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE,
        "dropping the participant index must fail the readback closed"
    );
    reset_session_user(&client).await;
}

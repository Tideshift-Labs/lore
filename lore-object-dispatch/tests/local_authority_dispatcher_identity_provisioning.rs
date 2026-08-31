// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract plus an opt-in PostgreSQL 16 probe for per-participant dispatcher-identity
//! provisioning and readback (WP-114 CD-3, CR-033 D8's review caveat N2).
//!
//! The ignored tier requires `LORE_TEST_LOCAL_DISPATCHER_IDENTITY_PROVISIONING_PG_URL`, an
//! administrator URL for a fresh disposable database. It installs the complete cell install set
//! (0002, 0003, 0007-0020) itself and intentionally leaves global test roles for the disposable
//! server owner.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::local_authority_dispatcher_identity_provisioning::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_dispatcher_identity_provisioning::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1;
use lore_object_dispatch::local_authority_dispatcher_identity_provisioning::validate_embedded_local_authority_dispatcher_identity_provisioning_migration_v1;
use lore_object_dispatch::local_authority_dispatcher_registration::LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_dispatcher_registration::LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1;
use lore_object_dispatch::local_authority_dispatcher_registration::validate_embedded_local_authority_dispatcher_registration_migration_v1;
use tokio_postgres::error::SqlState;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 25_375;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "fd0aa946118010222eed883ab9bc68fa09fd3a3fbb0eb2d1e21e1904bd9c213e";
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
const DISPATCHER_REGISTRATION_API_REVISION: &str =
    "object-store-dispatch-dispatcher-registration-v1";
const EXPECTED_REGISTRATION_MIGRATION_BYTES: usize = 29_189;
const EXPECTED_REGISTRATION_MIGRATION_BLAKE3: &str =
    "aede4135d081a9adbec51cd41141faea81eb3b25860ab9d1968073a230aa78e9";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1)
        .expect("dispatcher-identity provisioning migration must remain UTF-8 SQL")
}

fn registration_migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1)
        .expect("dispatcher registration migration must remain UTF-8 SQL")
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
fn objects_assertion_pins_the_replica_identity_bearing_unique_constraint() {
    // Second review pass, gap 1: `assert_dispatch_dispatcher_identity_objects_v1`'s fourth check
    // (0019:257-285) is the positive half -- a `contype = 'u'` constraint whose backing index is
    // unique, valid, ready, the table's replica identity, non-partial, has no INCLUDE columns
    // (`indnatts = indnkeyatts`), and whose key columns are exactly `provider_boundary_id`,
    // `dispatcher_id`, `lease_generation` in that order. Pin the tokens that state each of those
    // properties, distinct from the first check's similarly-shaped but different assertion (which
    // has no `contype`/`indisreplident` condition and a two-column key array).
    let sql = migration();
    let objects = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.assert_dispatch_dispatcher_identity_objects_v1(",
    );
    for required in [
        "constraint_state.contype = 'u'",
        "idx.indisreplident",
        "idx.indpred IS NULL",
        "idx.indnatts = idx.indnkeyatts",
        "ARRAY['provider_boundary_id', 'dispatcher_id', 'lease_generation']",
    ] {
        assert!(
            objects.contains(required),
            "fourth check must assert: {required}"
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
            "object_store_dispatch_enroll_dispatcher_participant_v1",
            "object_store_dispatch_register_dispatcher_v1",
        ] {
            assert!(
                !source.contains(entrypoint),
                "runtime source {} calls {entrypoint}",
                path.display()
            );
        }
    }
}

#[test]
fn registration_artifact_digest_is_embedded_and_source_dark() {
    let sql = registration_migration();
    assert_eq!(
        LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1.len(),
        EXPECTED_REGISTRATION_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_REGISTRATION_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_dispatcher_registration_migration_v1());
    assert!(!sql.contains('\r'));

    let module = include_str!("../src/local_authority_dispatcher_registration.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0020_object_store_dispatch_dispatcher_registration.sql\")"
    ));
    assert!(library.contains("pub mod local_authority_dispatcher_registration;"));
    for forbidden in ["tokio_postgres", "batch_execute", ".execute(", ".await"] {
        assert!(
            !module.contains(forbidden),
            "source-dark registration module contains {forbidden}"
        );
    }
}

#[test]
fn registration_surface_pins_enrollment_auth_codec_acl_and_generation_fence() {
    let sql = registration_migration();
    let compact_sql = compact(sql);
    let registration = compact(function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_register_dispatcher_v1(",
    ));
    let enrollment = compact(function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(",
    ));
    for required in [
        DISPATCHER_REGISTRATION_API_REVISION,
        "assert_dispatch_maintenance_v1()",
        "assert_serializable_write_v1()",
        "participant_key_blake3",
        "'REPLAY'",
        "'CREATED'",
    ] {
        assert!(
            enrollment.contains(required),
            "participant enrollment missing invariant: {required}"
        );
    }
    for required in [
        DISPATCHER_REGISTRATION_API_REVISION,
        "assert_dispatch_runtime_v1()",
        "assert_serializable_write_v1()",
        "object_dispatch_dispatcher_participants",
        "local_blake3_v1(",
        "FOR UPDATE",
        "pg_catalog.max(dispatcher.lease_generation)",
        "next_generation <=",
        "INSERT INTO object_store_retention.object_dispatch_dispatchers",
        "local_dispatcher_registration_record_v1(",
        "'REPLAY'",
        "'CREATED'",
    ] {
        assert!(
            registration.contains(required),
            "registration procedure missing invariant: {required}"
        );
    }
    assert!(compact_sql.contains(
        "object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1( text, text, text, bytea ), object_store_retention.object_store_dispatch_register_dispatcher_v1( text, bytea, object_store_retention.uint64, text, object_store_retention.uint64, object_store_retention.uint64, text, object_store_retention.uint64, text, bigint, bigint, bigint, bigint ) FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;"
    ));
    assert!(compact_sql.contains(
        "GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1( text, text, text, bytea ) TO object_dispatch_retention_maintenance;"
    ));
    assert!(compact_sql.contains(
        "GRANT EXECUTE ON FUNCTION object_store_retention.object_store_dispatch_register_dispatcher_v1( text, bytea, object_store_retention.uint64, text, object_store_retention.uint64, object_store_retention.uint64, text, object_store_retention.uint64, text, bigint, bigint, bigint, bigint ) TO object_dispatch_retention_runtime;"
    ));
    assert!(!registration.contains("canonical_record_bytes bytea"));
    assert!(!registration.contains("record_blake3 bytea"));
}

#[test]
fn registration_migration_pins_the_exact_attempts_foreign_key_carrier() {
    let objects = compact(function_body(
        registration_migration(),
        "CREATE OR REPLACE FUNCTION object_store_retention.assert_dispatch_dispatcher_identity_objects_v1(",
    ));
    for required in [
        "constraint_state.contype = 'f'",
        "constraint_state.convalidated",
        "NOT constraint_state.condeferrable",
        "NOT constraint_state.condeferred",
        "ARRAY[ 'provider_boundary_id', 'dispatcher_id', 'dispatcher_lease_generation' ]",
        "ARRAY['provider_boundary_id', 'dispatcher_id', 'lease_generation']",
        "object_dispatch_attempts",
        "object_dispatch_dispatchers",
    ] {
        assert!(
            objects.contains(required),
            "attempts foreign-key assertion missing: {required}"
        );
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
    assert_eq!(
        database_error.code(),
        expected,
        "{label}: {}",
        database_error.message()
    );
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
    assert_eq!(
        database_error.code(),
        expected,
        "{label}: {}",
        database_error.message()
    );
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

#[derive(Clone, Copy)]
struct Registration<'a> {
    participant_key_byte: u8,
    generation: u64,
    service_instance_id: &'a str,
}

fn registration_call(input: Registration<'_>) -> String {
    format!(
        "SELECT (object_store_retention.object_store_dispatch_register_dispatcher_v1(
           '{DISPATCHER_REGISTRATION_API_REVISION}',
           pg_catalog.decode(pg_catalog.repeat('{participant_key_byte:02x}', 32), 'hex'),
           {generation}, '{service_instance_id}', {generation}, 1, 'allocation-1', 1,
           'credential-1', 1000, 1100, 2000, 1100
         )).result_code",
        participant_key_byte = input.participant_key_byte,
        generation = input.generation,
        service_instance_id = input.service_instance_id,
    )
}

fn enrollment_call(
    provider_boundary_id: &str,
    dispatcher_id: &str,
    participant_key_byte: u8,
) -> String {
    let digest = blake3::hash(&[participant_key_byte; 32]).to_hex();
    format!(
        "SELECT (object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(
           '{DISPATCHER_REGISTRATION_API_REVISION}', '{provider_boundary_id}', '{dispatcher_id}',
           pg_catalog.decode('{digest}', 'hex')
         )).result_code"
    )
}

fn expected_registration_record(
    dispatcher_id: &str,
    provider_boundary_id: &str,
    input: Registration<'_>,
) -> (Vec<u8>, Vec<u8>) {
    fn push_text(bytes: &mut Vec<u8>, value: &str) {
        let value = value.as_bytes();
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
    }

    let mut preimage = b"object-store-dispatch-dispatcher-registration-row-v1".to_vec();
    preimage.push(0);
    push_text(&mut preimage, "object-store-dispatch-authority-schema-v1");
    push_text(&mut preimage, dispatcher_id);
    preimage.extend_from_slice(&input.generation.to_be_bytes());
    push_text(&mut preimage, provider_boundary_id);
    push_text(&mut preimage, input.service_instance_id);
    preimage.extend_from_slice(&input.generation.to_be_bytes());
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    push_text(&mut preimage, "allocation-1");
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    push_text(&mut preimage, "credential-1");
    preimage.push(1);
    for value in [1000_u64, 1100, 2000, 1100] {
        preimage.extend_from_slice(&value.to_be_bytes());
    }
    let digest = blake3::hash(&preimage).as_bytes().to_vec();
    let mut complete = preimage;
    complete.extend_from_slice(&digest);
    (complete, digest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn blake3_provider_sql() -> String {
    let mut vectors = Vec::new();
    for key_byte in [0xaa, 0xbb, 0xc1, 0xc2, 0xee] {
        let payload = vec![key_byte; 32];
        vectors.push((payload.clone(), blake3::hash(&payload).as_bytes().to_vec()));
    }
    for (dispatcher_id, provider_boundary_id, input) in [
        (
            "dispatcher-a",
            "boundary-a",
            Registration {
                participant_key_byte: 0xaa,
                generation: 1,
                service_instance_id: "instance-a-1",
            },
        ),
        (
            "dispatcher-a",
            "boundary-a",
            Registration {
                participant_key_byte: 0xaa,
                generation: 2,
                service_instance_id: "instance-a-2",
            },
        ),
        (
            "dispatcher-b",
            "boundary-a",
            Registration {
                participant_key_byte: 0xbb,
                generation: 1,
                service_instance_id: "instance-b-1",
            },
        ),
        (
            "dispatcher-race-first",
            "boundary-race-first",
            Registration {
                participant_key_byte: 0xc1,
                generation: 1,
                service_instance_id: "instance-race-first-1",
            },
        ),
        (
            "dispatcher-race-next",
            "boundary-race-next",
            Registration {
                participant_key_byte: 0xc2,
                generation: 1,
                service_instance_id: "instance-race-next-1",
            },
        ),
        (
            "dispatcher-race-next",
            "boundary-race-next",
            Registration {
                participant_key_byte: 0xc2,
                generation: 2,
                service_instance_id: "instance-race-next-2",
            },
        ),
    ] {
        let (complete, digest) =
            expected_registration_record(dispatcher_id, provider_boundary_id, input);
        vectors.push((complete[..complete.len() - 32].to_vec(), digest));
    }
    let cases = vectors
        .iter()
        .map(|(payload, digest)| {
            format!(
                "WHEN '{}' THEN pg_catalog.decode('{}', 'hex')",
                hex(payload),
                hex(digest)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "CREATE FUNCTION public.blake3(payload bytea) RETURNS bytea
         LANGUAGE sql IMMUTABLE STRICT
         AS $$ SELECT CASE pg_catalog.encode(payload, 'hex')
           {cases}
           ELSE NULL::bytea
         END $$;"
    )
}

fn race_outcome(result: Result<tokio_postgres::Row, tokio_postgres::Error>) -> String {
    match result {
        Ok(row) => row.get(0),
        Err(error)
            if error.as_db_error().is_some_and(|database_error| {
                database_error.code() == &SqlState::T_R_SERIALIZATION_FAILURE
            }) =>
        {
            "40001".to_string()
        }
        Err(error) => panic!(
            "registration race returned an unexpected error: {error}; database error: {:?}",
            error.as_db_error()
        ),
    }
}

fn assert_registration_race_outcomes(left: String, right: String, label: &str) {
    let outcomes = [left.as_str(), right.as_str()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == "CREATED")
            .count(),
        1,
        "{label}: exactly one contender must create the generation; outcomes={outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(*outcome, "CREATED" | "REPLAY" | "40001")),
        "{label}: loser may only replay or lose PostgreSQL serialization; outcomes={outcomes:?}"
    );
}

async fn expect_registration_sqlstate(
    client: &tokio_postgres::Client,
    role: &str,
    input: Registration<'_>,
    expected: &SqlState,
    label: &str,
) {
    expect_serializable_sqlstate(client, role, &registration_call(input), expected, label).await;
}

/// Plants one catalog drift on `object_dispatch_dispatchers`, asserts the readback fails closed
/// with `55000`/`OBJECT_NOT_IN_PREREQUISITE_STATE`, removes the drift, then re-asserts the
/// readback returns `READ`. Every drift case in the live test below goes through this helper so
/// the table is restored before the next case runs. There is no unwind guard: a panic between the
/// plant and the restore leaves the drift (and, for the `btree_gist` case, the extension) in
/// place, so this only restores what it planted on the success path, not under every ordering.
async fn assert_drift_fails_closed_then_restores(
    client: &tokio_postgres::Client,
    label: &str,
    plant_sql: &str,
    remove_sql: &str,
) {
    client
        .batch_execute(plant_sql)
        .await
        .unwrap_or_else(|error| panic!("{label}: plant drift: {error}"));
    set_session_user(client, "object_dispatch_retention_runtime").await;
    let drift_error = match client.query_one(&read_call(), &[]).await {
        Ok(_) => panic!("{label}: drifted readback was unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(
        drift_error
            .as_db_error()
            .unwrap_or_else(|| panic!("{label}: expected typed catalog-mismatch error"))
            .code(),
        &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE,
        "{label}: must fail the readback closed"
    );
    reset_session_user(client).await;

    client
        .batch_execute(remove_sql)
        .await
        .unwrap_or_else(|error| panic!("{label}: remove drift: {error}"));
    set_session_user(client, "object_dispatch_retention_runtime").await;
    let restored: String = client
        .query_one(&read_call(), &[])
        .await
        .unwrap_or_else(|error| panic!("{label}: read after removing the drift: {error}"))
        .get(0);
    assert_eq!(
        restored, "READ",
        "{label}: must restore READ once the drift is removed"
    );
    reset_session_user(client).await;
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
        include_str!("../migrations/0020_object_store_dispatch_dispatcher_registration.sql"),
    ] {
        client
            .batch_execute(migration)
            .await
            .expect("apply mutation-chain and dispatcher-identity migration");
    }
    client
        .batch_execute(&blake3_provider_sql())
        .await
        .expect("install exact-vector BLAKE3 provider for dispatcher registration");

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

    // 0020 narrows the growth-tolerant readback to the runtime authority. Maintenance and the
    // owner remain unable to use it even though both can reach stronger out-of-band tooling.
    set_session_user(&client, "object_dispatch_retention_runtime").await;
    let read: String = client
        .query_one(&read_call(), &[])
        .await
        .expect("runtime read")
        .get(0);
    assert_eq!(read, "READ");
    reset_session_user(&client).await;
    for role in [
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_owner",
    ] {
        set_session_user(&client, role).await;
        let error = client.query_one(&read_call(), &[]).await.unwrap_err();
        assert_eq!(
            error
                .as_db_error()
                .expect("typed authorization error")
                .code(),
            &SqlState::INSUFFICIENT_PRIVILEGE,
            "{role} must not read dispatcher identity state"
        );
        reset_session_user(&client).await;
    }

    // Participant enrollment is maintenance-only and SERIALIZABLE-only. Runtime cannot mint its
    // own restart-stable identity, and maintenance cannot bypass the transaction gate.
    expect_serializable_sqlstate(
        &client,
        "object_dispatch_retention_runtime",
        &enrollment_call("boundary-denied", "dispatcher-denied", 0xdd),
        &SqlState::INSUFFICIENT_PRIVILEGE,
        "non-maintenance participant enrollment",
    )
    .await;
    set_session_user(&client, "object_dispatch_retention_maintenance").await;
    expect_sqlstate(
        &client,
        &enrollment_call(
            "boundary-nonserializable",
            "dispatcher-nonserializable",
            0xde,
        ),
        &SqlState::INVALID_TRANSACTION_STATE,
        "non-serializable participant enrollment",
    )
    .await;
    reset_session_user(&client).await;

    for expected in ["CREATED", "REPLAY"] {
        let result: String = serializable_call(
            &client,
            "object_dispatch_retention_maintenance",
            &enrollment_call("boundary-a", "dispatcher-a", 0xaa),
        )
        .await
        .unwrap_or_else(|error| panic!("participant A enrollment {expected}: {error}"))
        .get(0);
        assert_eq!(result, expected);
    }
    expect_serializable_sqlstate(
        &client,
        "object_dispatch_retention_maintenance",
        &enrollment_call("boundary-a", "dispatcher-a", 0xab),
        &SqlState::UNIQUE_VIOLATION,
        "same participant identity with a changed key commitment",
    )
    .await;
    for (boundary, dispatcher, key_byte) in [
        ("boundary-a", "dispatcher-b", 0xbb),
        ("boundary-race-first", "dispatcher-race-first", 0xc1),
        ("boundary-race-next", "dispatcher-race-next", 0xc2),
    ] {
        let result: String = serializable_call(
            &client,
            "object_dispatch_retention_maintenance",
            &enrollment_call(boundary, dispatcher, key_byte),
        )
        .await
        .unwrap_or_else(|error| panic!("enroll {dispatcher}: {error}"))
        .get(0);
        assert_eq!(result, "CREATED", "enroll {dispatcher}");
    }

    // Registration is runtime-only and SERIALIZABLE-only, and an unknown raw key is rejected
    // rather than creating a participant row as the superseded design did.
    expect_registration_sqlstate(
        &client,
        "object_dispatch_retention_maintenance",
        Registration {
            participant_key_byte: 0xaa,
            generation: 1,
            service_instance_id: "instance-denied",
        },
        &SqlState::INSUFFICIENT_PRIVILEGE,
        "non-runtime registration",
    )
    .await;
    set_session_user(&client, "object_dispatch_retention_runtime").await;
    expect_sqlstate(
        &client,
        &registration_call(Registration {
            participant_key_byte: 0xaa,
            generation: 1,
            service_instance_id: "instance-nonserializable",
        }),
        &SqlState::INVALID_TRANSACTION_STATE,
        "non-serializable registration",
    )
    .await;
    reset_session_user(&client).await;
    expect_registration_sqlstate(
        &client,
        "object_dispatch_retention_runtime",
        Registration {
            participant_key_byte: 0xee,
            generation: 1,
            service_instance_id: "instance-unknown",
        },
        &SqlState::INSUFFICIENT_PRIVILEGE,
        "unknown participant key",
    )
    .await;
    let unknown_participant_count: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM object_store_retention.object_dispatch_dispatcher_participants",
            &[],
        )
        .await
        .expect("count pre-enrolled participants after unknown-key rejection")
        .get(0);
    assert_eq!(unknown_participant_count, 4);

    let participant_a_generation_1 = Registration {
        participant_key_byte: 0xaa,
        generation: 1,
        service_instance_id: "instance-a-1",
    };
    for expected in ["CREATED", "REPLAY"] {
        let result: String = serializable_call(
            &client,
            "object_dispatch_retention_runtime",
            &registration_call(participant_a_generation_1),
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "participant A generation 1 {expected}: {error}; database error: {:?}",
                error.as_db_error()
            )
        })
        .get(0);
        assert_eq!(result, expected);
    }
    let participant_a_count: i64 = client
        .query_one(
            "SELECT count(*)::bigint
               FROM object_store_retention.object_dispatch_dispatchers
              WHERE provider_boundary_id = 'boundary-a' AND dispatcher_id = 'dispatcher-a'",
            &[],
        )
        .await
        .expect("count participant A rows after exact replay")
        .get(0);
    assert_eq!(participant_a_count, 1, "exact replay must not insert a row");
    let stored_record = client
        .query_one(
            "SELECT canonical_record_bytes, record_blake3
               FROM object_store_retention.object_dispatch_dispatchers
              WHERE provider_boundary_id = 'boundary-a'
                AND dispatcher_id = 'dispatcher-a'
                AND lease_generation = 1",
            &[],
        )
        .await
        .expect("read PostgreSQL-built canonical participant A generation 1 record");
    let (expected_bytes, expected_digest) =
        expected_registration_record("dispatcher-a", "boundary-a", participant_a_generation_1);
    assert_eq!(stored_record.get::<_, Vec<u8>>(0), expected_bytes);
    assert_eq!(stored_record.get::<_, Vec<u8>>(1), expected_digest);

    expect_registration_sqlstate(
        &client,
        "object_dispatch_retention_runtime",
        Registration {
            service_instance_id: "instance-a-changed",
            ..participant_a_generation_1
        },
        &SqlState::UNIQUE_VIOLATION,
        "same generation with a changed payload",
    )
    .await;

    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_dispatchers
                SET state = 2,
                    revocation_id = 'revoke-a-1',
                    revocation_requested_at_unix_ms = 1200,
                    revoked_at_unix_ms = NULL,
                    revocation_evidence_blake3 = NULL,
                    state_changed_at_unix_ms = 1200
              WHERE provider_boundary_id = 'boundary-a'
                AND dispatcher_id = 'dispatcher-a'
                AND lease_generation = 1",
            &[],
        )
        .await
        .expect("retire participant A generation 1");
    let participant_a_generation_2 = Registration {
        participant_key_byte: 0xaa,
        generation: 2,
        service_instance_id: "instance-a-2",
    };
    let created: String = serializable_call(
        &client,
        "object_dispatch_retention_runtime",
        &registration_call(participant_a_generation_2),
    )
    .await
    .expect("create participant A generation 2")
    .get(0);
    assert_eq!(created, "CREATED");
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_dispatchers
                SET state = 2,
                    revocation_id = 'revoke-a-2',
                    revocation_requested_at_unix_ms = 1300,
                    revoked_at_unix_ms = NULL,
                    revocation_evidence_blake3 = NULL,
                    state_changed_at_unix_ms = 1300
              WHERE provider_boundary_id = 'boundary-a'
                AND dispatcher_id = 'dispatcher-a'
                AND lease_generation = 2",
            &[],
        )
        .await
        .expect("retire participant A generation 2");

    for (label, input) in [
        (
            "backward generation after retiring generation 2",
            participant_a_generation_1,
        ),
        (
            "rewound restart at generation 2",
            participant_a_generation_2,
        ),
    ] {
        expect_registration_sqlstate(
            &client,
            "object_dispatch_retention_runtime",
            input,
            &SqlState::INVALID_PARAMETER_VALUE,
            label,
        )
        .await;
    }

    let independent: String = serializable_call(
        &client,
        "object_dispatch_retention_runtime",
        &registration_call(Registration {
            participant_key_byte: 0xbb,
            generation: 1,
            service_instance_id: "instance-b-1",
        }),
    )
    .await
    .expect("independent participant starts at generation 1")
    .get(0);
    assert_eq!(independent, "CREATED");

    // Two independent sessions prove the participant-row lock closes both empty-chain and
    // next-generation races. PostgreSQL may serialize the loser after the winner commits (REPLAY)
    // or abort its stale SERIALIZABLE snapshot (40001), but exactly one call creates each row.
    let (race_left, race_left_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect left dispatcher registration racer");
    let _race_left_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "dispatcher-registration-race-left",
        async move {
            let _ = race_left_connection.await;
        }
    ));
    let (race_right, race_right_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect right dispatcher registration racer");
    let _race_right_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "dispatcher-registration-race-right",
        async move {
            let _ = race_right_connection.await;
        }
    ));

    let first_race = Registration {
        participant_key_byte: 0xc1,
        generation: 1,
        service_instance_id: "instance-race-first-1",
    };
    let first_race_sql = registration_call(first_race);
    let (left, right) = tokio::join!(
        serializable_call(
            &race_left,
            "object_dispatch_retention_runtime",
            &first_race_sql
        ),
        serializable_call(
            &race_right,
            "object_dispatch_retention_runtime",
            &first_race_sql
        )
    );
    assert_registration_race_outcomes(
        race_outcome(left),
        race_outcome(right),
        "concurrent first registration",
    );
    let first_race_row = client
        .query_one(
            "SELECT count(*) OVER ()::bigint, service_instance_id, dispatcher_fence::text,
                    state, canonical_record_bytes, record_blake3
               FROM object_store_retention.object_dispatch_dispatchers
              WHERE provider_boundary_id = 'boundary-race-first'
                AND dispatcher_id = 'dispatcher-race-first'
                AND lease_generation = 1",
            &[],
        )
        .await
        .expect("read final concurrent first-registration chain");
    assert_eq!(first_race_row.get::<_, i64>(0), 1);
    assert_eq!(first_race_row.get::<_, String>(1), "instance-race-first-1");
    assert_eq!(first_race_row.get::<_, String>(2), "1");
    assert_eq!(first_race_row.get::<_, i16>(3), 1);
    let (first_race_bytes, first_race_digest) =
        expected_registration_record("dispatcher-race-first", "boundary-race-first", first_race);
    assert_eq!(first_race_row.get::<_, Vec<u8>>(4), first_race_bytes);
    assert_eq!(first_race_row.get::<_, Vec<u8>>(5), first_race_digest);

    let next_race_generation_1 = Registration {
        participant_key_byte: 0xc2,
        generation: 1,
        service_instance_id: "instance-race-next-1",
    };
    assert_eq!(
        serializable_call(
            &client,
            "object_dispatch_retention_runtime",
            &registration_call(next_race_generation_1),
        )
        .await
        .expect("seed next-generation race chain")
        .get::<_, String>(0),
        "CREATED"
    );
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_dispatchers
                SET state = 2,
                    revocation_id = 'revoke-race-next-1',
                    revocation_requested_at_unix_ms = 1200,
                    revoked_at_unix_ms = NULL,
                    revocation_evidence_blake3 = NULL,
                    state_changed_at_unix_ms = 1200
              WHERE provider_boundary_id = 'boundary-race-next'
                AND dispatcher_id = 'dispatcher-race-next'
                AND lease_generation = 1",
            &[],
        )
        .await
        .expect("retire seed generation before next-generation race");
    let next_race = Registration {
        participant_key_byte: 0xc2,
        generation: 2,
        service_instance_id: "instance-race-next-2",
    };
    let next_race_sql = registration_call(next_race);
    let (left, right) = tokio::join!(
        serializable_call(
            &race_left,
            "object_dispatch_retention_runtime",
            &next_race_sql
        ),
        serializable_call(
            &race_right,
            "object_dispatch_retention_runtime",
            &next_race_sql
        )
    );
    assert_registration_race_outcomes(
        race_outcome(left),
        race_outcome(right),
        "concurrent next generation",
    );
    let next_race_rows = client
        .query(
            "SELECT lease_generation::text, service_instance_id, dispatcher_fence::text, state,
                    canonical_record_bytes, record_blake3
               FROM object_store_retention.object_dispatch_dispatchers
              WHERE provider_boundary_id = 'boundary-race-next'
                AND dispatcher_id = 'dispatcher-race-next'
              ORDER BY lease_generation",
            &[],
        )
        .await
        .expect("read final concurrent next-generation chain");
    assert_eq!(next_race_rows.len(), 2);
    assert_eq!(next_race_rows[0].get::<_, String>(0), "1");
    assert_eq!(next_race_rows[0].get::<_, i16>(3), 2);
    assert_eq!(next_race_rows[1].get::<_, String>(0), "2");
    assert_eq!(
        next_race_rows[1].get::<_, String>(1),
        "instance-race-next-2"
    );
    assert_eq!(next_race_rows[1].get::<_, String>(2), "2");
    assert_eq!(next_race_rows[1].get::<_, i16>(3), 1);
    let (next_race_bytes, next_race_digest) =
        expected_registration_record("dispatcher-race-next", "boundary-race-next", next_race);
    assert_eq!(next_race_rows[1].get::<_, Vec<u8>>(4), next_race_bytes);
    assert_eq!(next_race_rows[1].get::<_, Vec<u8>>(5), next_race_digest);

    // The catalog-drift probes below deliberately create uniqueness shapes that 0019 must reject.
    // They can only be planted on an empty dispatcher table once two independent participants
    // have both used generation 1, so clear the completed registration fixture first.
    client
        .batch_execute(
            "DELETE FROM object_store_retention.object_dispatch_dispatchers;
             DELETE FROM object_store_retention.object_dispatch_dispatcher_participants;",
        )
        .await
        .expect("clear completed dispatcher-registration fixture before catalog drift probes");

    // Item 6: an additional unique index on the dispatchers table whose key omits dispatcher_id
    // makes the readback fail closed, and dropping it restores READ. Run only while the table holds
    // no rows, since a duplicate (provider_boundary_id, lease_generation) pair across participants
    // would otherwise prevent the index from being created at all. Every drift case from here on
    // runs through `assert_drift_fails_closed_then_restores`, which restores the catalog before
    // returning, so cases can be appended below without any one of them failing for the wrong
    // reason (WP-114 CD-3 review round 63e61d4's Gap 3).
    assert_drift_fails_closed_then_restores(
        &client,
        "unique index whose key omits dispatcher_id entirely",
        "CREATE UNIQUE INDEX drift_generation_only_idx
         ON object_store_retention.object_dispatch_dispatchers
         (provider_boundary_id, lease_generation);",
        "DROP INDEX object_store_retention.drift_generation_only_idx;",
    )
    .await;

    // Gap 1 (63e61d4 review finding 1): `pg_index.indkey` spans key *and* INCLUDE columns, so a
    // naive "does any unique index mention dispatcher_id" check is bypassable by an index that
    // carries dispatcher_id only as an INCLUDE (payload) column while keying uniqueness on
    // (provider_boundary_id, lease_generation) alone -- exactly the cross-participant uniqueness
    // D8 rejected. An INCLUDE column is stored payload, not part of the key: two rows with equal
    // key columns but different INCLUDE values still collide as duplicates. 0019's fix bounds the
    // unnest of `indkey` by `indnkeyatts` (where the key ends) specifically to close this. Prove
    // the INCLUDE form is rejected -- if it were NOT, this assertion would fail here rather than
    // in the SQL, which is exactly the "implementation is wrong, report it" case the task calls
    // out. Built on the empty table (no dispatcher rows), since two participants sharing
    // (provider_boundary_id, lease_generation) would already violate this unique shape and the
    // index could never be created in the first place.
    assert_drift_fails_closed_then_restores(
        &client,
        "unique index carrying dispatcher_id only as an INCLUDE column, not a key column",
        "CREATE UNIQUE INDEX drift_include_only_idx
         ON object_store_retention.object_dispatch_dispatchers
         (provider_boundary_id, lease_generation) INCLUDE (dispatcher_id);",
        "DROP INDEX object_store_retention.drift_include_only_idx;",
    )
    .await;

    // Gap 2 (63e61d4 review finding 2): an exclusion constraint enforces uniqueness without being
    // `indisunique`, so both index-shaped checks above cannot see one; 0019's third check refuses
    // any exclusion constraint on this table outright, regardless of which columns it names. Use
    // the btree_gist-backed spelling that most naturally mirrors the dropped primary key -- the
    // `postgres:16` image this harness runs against bundles `btree_gist`, and the runner connects
    // as a superuser, so there is no disposable-container shape where the extension is unavailable
    // here; a native-GiST fallback would be permanently dead code, not a real branch under test.
    client
        .batch_execute("CREATE EXTENSION IF NOT EXISTS btree_gist;")
        .await
        .expect("btree_gist must be available in the postgres:16 image this harness runs against");
    assert_drift_fails_closed_then_restores(
        &client,
        "btree_gist equality exclusion constraint on (provider_boundary_id, lease_generation)",
        "ALTER TABLE object_store_retention.object_dispatch_dispatchers
           ADD CONSTRAINT drift_excl EXCLUDE USING gist
             (provider_boundary_id WITH =, lease_generation WITH =);",
        "ALTER TABLE object_store_retention.object_dispatch_dispatchers
           DROP CONSTRAINT drift_excl;",
    )
    .await;

    // Item 7: dropping D8's own participant index likewise fails the readback closed. Restoring
    // the exact index 0018 created returns the readback to `READ` -- this is the fix for WP-114
    // CD-3 review round 63e61d4's Gap 3: the old version of this step dropped the index and never
    // restored it, so anything appended after it failed for the wrong reason.
    assert_drift_fails_closed_then_restores(
        &client,
        "D8's own one-active-participant unique index dropped entirely",
        "DROP INDEX object_store_retention.object_dispatch_dispatchers_one_active_participant_idx;",
        "CREATE UNIQUE INDEX object_dispatch_dispatchers_one_active_participant_idx
           ON object_store_retention.object_dispatch_dispatchers (provider_boundary_id, dispatcher_id)
           WHERE state = 1;",
    )
    .await;

    // Item 8 (second review pass, gap 1): 0019's fourth check is the *positive* half -- the table
    // must carry migration 0007's retained three-column UNIQUE, named by PostgreSQL as
    // `object_dispatch_dispatchers_provider_boundary_id_dispatcher_key`, and that index must also
    // be the table's replica identity. Verify the name and `contype` against the live catalog
    // first, rather than trusting the name asserted in the task description.
    let row = client
        .query_one(
            "SELECT conname::text, contype::text
               FROM pg_catalog.pg_constraint
              WHERE conrelid = 'object_store_retention.object_dispatch_dispatchers'::regclass
                AND contype = 'u'",
            &[],
        )
        .await
        .expect("locate migration 0007's retained UNIQUE constraint in the live catalog");
    let dispatcher_unique_constraint: (String, String) = (row.get(0), row.get(1));
    assert_eq!(
        dispatcher_unique_constraint,
        (
            "object_dispatch_dispatchers_provider_boundary_id_dispatcher_key".to_string(),
            "u".to_string()
        ),
        "the live catalog's UNIQUE constraint name/type must match what this test then drives"
    );

    // Item 8a: dropping that UNIQUE constraint is exactly the case the migration's own comment
    // (0019:159-168) says the fourth check exists to catch -- but `object_dispatch_attempts`'
    // foreign key (0007) targets this same constraint's backing index, and PostgreSQL refuses to
    // drop a constraint whose index a live foreign key still depends on. That refusal is itself a
    // stronger guarantee than the SQL assertion: the drop is structurally impossible while the
    // foreign key exists, not merely caught after the fact. Confirmed live (not asserted from
    // documentation): PostgreSQL 16 raises `2BP01`/`dependent_objects_still_exist` naming
    // `object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey` as the dependent object.
    // Assert that refusal explicitly, and do not force it with CASCADE -- doing so would silently
    // drop the attempts table's foreign key along with the constraint under test.
    expect_sqlstate(
        &client,
        "ALTER TABLE object_store_retention.object_dispatch_dispatchers
           DROP CONSTRAINT object_dispatch_dispatchers_provider_boundary_id_dispatcher_key;",
        &SqlState::DEPENDENT_OBJECTS_STILL_EXIST,
        "dropping 0007's retained UNIQUE constraint must be refused by the attempts foreign key",
    )
    .await;

    // Item 8b: the half the fourth check exists for and the constraint-drop case above cannot
    // reach -- the attester's manifest pins `relreplident = 'i'` (CD-1's twelve-section catalog
    // manifest), but that letter names only that *some* index serves as replica identity, not
    // which one, and a live PostgreSQL 16 run confirms it survives `REPLICA IDENTITY NOTHING`
    // unchanged at the letter level even though logical decoding of an UPDATE/DELETE on this table
    // would then fail. Leaving the UNIQUE constraint in place and only retargeting replica
    // identity away from its index is invisible to the out-of-band attester and is exactly the gap
    // 0019's fourth check closes.
    assert_drift_fails_closed_then_restores(
        &client,
        "replica identity retargeted off 0007's retained UNIQUE constraint's index",
        "ALTER TABLE object_store_retention.object_dispatch_dispatchers REPLICA IDENTITY NOTHING;",
        "ALTER TABLE object_store_retention.object_dispatch_dispatchers
           REPLICA IDENTITY USING INDEX
           object_dispatch_dispatchers_provider_boundary_id_dispatcher_key;",
    )
    .await;

    // INV-EM P1-2: the positive unique carrier is not enough. Dropping the attempts foreign key
    // must make the unchanged 0019 public readback fail closed after 0020 replaces its object
    // assertion, and restoring the exact source/target carrier must restore READ.
    assert_drift_fails_closed_then_restores(
        &client,
        "attempts-to-dispatcher-generation foreign key dropped",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE;",
    )
    .await;

    assert_drift_fails_closed_then_restores(
        &client,
        "attempts foreign key replaced by a deferrable carrier",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;
         ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           DEFERRABLE INITIALLY IMMEDIATE;",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;
         ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE;",
    )
    .await;

    assert_drift_fails_closed_then_restores(
        &client,
        "attempts foreign key replaced by an unvalidated carrier",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;
         ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE NOT VALID;",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;
         ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE;",
    )
    .await;

    assert_drift_fails_closed_then_restores(
        &client,
        "exact target columns carried from the wrong source relation",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;
         CREATE TABLE object_store_retention.drift_dispatch_attempt_source (
           provider_boundary_id text NOT NULL,
           dispatcher_id text NOT NULL,
           dispatcher_lease_generation object_store_retention.uint64 NOT NULL
         );
         ALTER TABLE object_store_retention.drift_dispatch_attempt_source
           ADD CONSTRAINT drift_wrong_source_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE;",
        "DROP TABLE object_store_retention.drift_dispatch_attempt_source;
         ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE;",
    )
    .await;

    assert_drift_fails_closed_then_restores(
        &client,
        "exact source columns carried to the wrong target relation",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;
         CREATE TABLE object_store_retention.drift_dispatcher_target (
           provider_boundary_id text NOT NULL,
           dispatcher_id text NOT NULL,
           lease_generation object_store_retention.uint64 NOT NULL,
           UNIQUE (provider_boundary_id, dispatcher_id, lease_generation)
         );
         ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.drift_dispatcher_target
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE;",
        "ALTER TABLE object_store_retention.object_dispatch_attempts
           DROP CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey;
         DROP TABLE object_store_retention.drift_dispatcher_target;
         ALTER TABLE object_store_retention.object_dispatch_attempts
           ADD CONSTRAINT object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey
           FOREIGN KEY (provider_boundary_id, dispatcher_id, dispatcher_lease_generation)
           REFERENCES object_store_retention.object_dispatch_dispatchers
             (provider_boundary_id, dispatcher_id, lease_generation)
           NOT DEFERRABLE;",
    )
    .await;

    let exact_fk = client
        .query_one(
            "SELECT constraint_state.conrelid::regclass::text,
                    constraint_state.confrelid::regclass::text,
                    constraint_state.convalidated,
                    constraint_state.condeferrable,
                    constraint_state.condeferred,
                    (SELECT pg_catalog.string_agg(attribute.attname::text, ',' ORDER BY key.ordinal)
                       FROM pg_catalog.unnest(constraint_state.conkey)
                            WITH ORDINALITY AS key(attnum, ordinal)
                       JOIN pg_catalog.pg_attribute AS attribute
                         ON attribute.attrelid = constraint_state.conrelid
                        AND attribute.attnum = key.attnum),
                    (SELECT pg_catalog.string_agg(attribute.attname::text, ',' ORDER BY key.ordinal)
                       FROM pg_catalog.unnest(constraint_state.confkey)
                            WITH ORDINALITY AS key(attnum, ordinal)
                       JOIN pg_catalog.pg_attribute AS attribute
                         ON attribute.attrelid = constraint_state.confrelid
                        AND attribute.attnum = key.attnum)
               FROM pg_catalog.pg_constraint AS constraint_state
              WHERE constraint_state.conname =
                    'object_dispatch_attempts_provider_boundary_id_dispatcher_i_fkey'",
            &[],
        )
        .await
        .expect("read restored exact attempts foreign-key carrier");
    assert_eq!(
        exact_fk.get::<_, String>(0),
        "object_store_retention.object_dispatch_attempts"
    );
    assert_eq!(
        exact_fk.get::<_, String>(1),
        "object_store_retention.object_dispatch_dispatchers"
    );
    assert!(exact_fk.get::<_, bool>(2));
    assert!(!exact_fk.get::<_, bool>(3));
    assert!(!exact_fk.get::<_, bool>(4));
    assert_eq!(
        exact_fk.get::<_, String>(5),
        "provider_boundary_id,dispatcher_id,dispatcher_lease_generation"
    );
    assert_eq!(
        exact_fk.get::<_, String>(6),
        "provider_boundary_id,dispatcher_id,lease_generation"
    );
}

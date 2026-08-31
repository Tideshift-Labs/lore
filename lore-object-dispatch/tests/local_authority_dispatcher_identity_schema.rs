// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract plus an opt-in PostgreSQL 16 schema probe for the per-participant
//! dispatcher-identity edge (WP-114 CD-3, CR-033 D8).
//!
//! The ignored tier requires `LORE_TEST_LOCAL_DISPATCHER_IDENTITY_SCHEMA_PG_URL`, an administrator
//! URL for a fresh disposable database. It installs migrations 0002, 0007, and 0018 itself. The
//! database is intentionally one-shot because these are committed forward migrations.

use lore_object_dispatch::local_authority_dispatcher_identity_schema::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_dispatcher_identity_schema::LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1;
use lore_object_dispatch::local_authority_dispatcher_identity_schema::validate_embedded_local_authority_dispatcher_identity_schema_migration_v1;
use tokio_postgres::error::SqlState;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 3_772;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "390a1275927fc9273746a8180aab42ab7c446be6283a82f1263026fbee0f755b";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1)
        .expect("local dispatcher-identity schema migration must remain UTF-8 SQL")
}

fn compact(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn embedded_migration_has_frozen_identity() {
    assert_eq!(
        LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        hex(blake3::hash(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1).as_bytes()),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        hex(&LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_BLAKE3_V1),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert!(validate_embedded_local_authority_dispatcher_identity_schema_migration_v1());
}

#[test]
fn migration_is_one_owner_scoped_forward_transaction() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n-- SPDX-License-Identifier: MIT\n"));
    assert_eq!(sql.matches("BEGIN;").count(), 1);
    assert_eq!(sql.matches("COMMIT;").count(), 1);
    assert_eq!(
        sql.matches("SET LOCAL ROLE object_dispatch_retention_owner;")
            .count(),
        1
    );
    assert!(sql.find("BEGIN;") < sql.find("SET LOCAL ROLE"));
    assert!(!sql.contains('\r'));
}

#[test]
fn migration_drops_the_single_active_dispatcher_index_and_primary_key_then_creates_the_participant_index()
 {
    let sql = compact(migration());
    assert_eq!(
        sql.matches(
            "DROP INDEX object_store_retention.object_dispatch_dispatchers_one_active_generation_idx;"
        )
        .count(),
        1,
        "must drop 0007's single-active-dispatcher-per-boundary partial unique index"
    );
    assert_eq!(
        sql.matches(
            "ALTER TABLE object_store_retention.object_dispatch_dispatchers DROP CONSTRAINT object_dispatch_dispatchers_pkey;"
        )
        .count(),
        1,
        "must drop 0007's (provider_boundary_id, lease_generation) primary key, which admits only \
         one dispatcher row per generation across ALL participants"
    );
    assert_eq!(
        sql.matches(
            "CREATE UNIQUE INDEX object_dispatch_dispatchers_one_active_participant_idx ON object_store_retention.object_dispatch_dispatchers (provider_boundary_id, dispatcher_id) WHERE state = 1;"
        )
        .count(),
        1,
        "must create exactly the per-participant ACTIVE-uniqueness index D8 requires"
    );
}

#[test]
fn migration_declares_no_replacement_primary_key() {
    let sql = migration();
    // The deliberate decision: 0007's own UNIQUE (provider_boundary_id, dispatcher_id,
    // lease_generation) -- already the exact target of the attempts foreign key -- becomes the
    // table's identity. A replacement PRIMARY KEY over those columns would build a second,
    // redundant unique index. Checking for the bare substring "PRIMARY KEY" would false-positive on
    // this migration's own header comment, which quotes 0007's dropped primary key by name; the
    // regression this guards is a resurrected `ADD PRIMARY KEY` clause, so check that exact phrase.
    assert!(!sql.contains("ADD PRIMARY KEY"));
}

#[test]
fn artifact_is_embedded_but_source_dark() {
    let module = include_str!("../src/local_authority_dispatcher_identity_schema.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0018_object_store_dispatch_dispatcher_identity_schema.sql\")"
    ));
    assert!(
        module
            .contains("validate_embedded_local_authority_dispatcher_identity_schema_migration_v1")
    );
    assert!(library.contains("pub mod local_authority_dispatcher_identity_schema;"));
    for forbidden in [
        "tokio_postgres",
        "sqlx",
        "batch_execute",
        "query(",
        "execute(",
    ] {
        assert!(
            !module.contains(forbidden),
            "module must remain source-dark: {forbidden}"
        );
    }
}

fn request_fixture_sql(logical: &str, attempt: &str, logical_ms: i64, attempt_ms: i64) -> String {
    let digest = "decode(repeat('11', 32), 'hex')";
    let record = "decode('aa' || repeat('11', 32), 'hex')";
    format!(
        "INSERT INTO object_store_retention.object_dispatch_requests (
           schema_revision, protocol_revision, policy_revision, provider_boundary_id,
           authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id,
           logical_request_uuid_unix_ms, attempt_uuid_unix_ms, put_reservation_fingerprint,
           canonical_descriptor_bytes, canonical_descriptor_fingerprint, operation_tag,
           consumer_context_tag, phase, allocation_revision, allocation_fence,
           admission_clock_unix_ms, deadline_unix_ms, allocation_hard_expiry_unix_ms,
           request_state_canonical_bytes, request_state_blake3, terminal_retryability,
           result_disposition, put_payload_availability, result_payload_availability,
           submit_receipt_canonical_bytes, submit_receipt_blake3, get_outcome_canonical_bytes,
           get_outcome_blake3, quota_revision, row_revision, state_committed_at_unix_ms,
           created_at_unix_ms
         ) VALUES (
           'object-store-dispatch-authority-schema-v1', 'protocol-1', 'policy-1', 'boundary-a',
           'cell-1', 'tenant-1', '{logical}', '{attempt}', {logical_ms}, {attempt_ms}, NULL,
           decode('aa', 'hex'), {digest}, 1, 1, 1, 'allocation-1', 1,
           1000, 2000, 3000, {record}, {digest}, 1, 1, 1, 1,
           {record}, {digest}, {record}, {digest}, 1, 1, 1500, 1000
         );"
    )
}

fn dispatcher_sql(dispatcher_id: &str, generation: u64, instance: &str) -> String {
    format!(
        "INSERT INTO object_store_retention.object_dispatch_dispatchers (
           schema_revision, dispatcher_id, lease_generation, provider_boundary_id,
           service_instance_id, dispatcher_fence, authority_revision, allocation_revision,
           allocation_fence, provider_credential_revision, state, acquired_at_unix_ms,
           renewed_at_unix_ms, expires_at_unix_ms, state_changed_at_unix_ms,
           canonical_record_bytes, record_blake3)
         VALUES ('object-store-dispatch-authority-schema-v1', '{dispatcher_id}', {generation},
           'boundary-a', '{instance}', 1, 1, 'alloc-1', 1, 'cred-1', 1, 1000, 1000, 2000, 1000,
           decode(repeat('11',33),'hex'), decode(repeat('11',32),'hex'));"
    )
}

fn attempt_sql(
    grant_id: &str,
    logical: &str,
    attempt: &str,
    dispatcher_id: &str,
    generation: u64,
) -> String {
    let digest = "decode(repeat('11', 32), 'hex')";
    let record = "decode('aa' || repeat('11', 32), 'hex')";
    format!(
        "INSERT INTO object_store_retention.object_dispatch_attempts (
           schema_revision, logical_request_id, attempt_id, provider_boundary_id,
           provider_grant_id, provider_grant_fence, grant_canonical_bytes, grant_blake3,
           dispatcher_id, dispatcher_lease_generation, provider_credential_revision,
           attempt_state, provider_authority_refunded, grant_committed_at_unix_ms,
           attempt_revision, state_changed_at_unix_ms
         ) VALUES (
           'object-store-dispatch-authority-schema-v1', '{logical}', '{attempt}', 'boundary-a',
           '{grant_id}', 1, {record}, {digest}, '{dispatcher_id}', {generation}, 'cred-1',
           1, false, 1000, 1, 1000
         );"
    )
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_dispatcher_identity_admits_concurrent_participants_and_retains_the_attempts_foreign_key()
 {
    let postgres_url = std::env::var("LORE_TEST_LOCAL_DISPATCHER_IDENTITY_SCHEMA_PG_URL").expect(
        "LORE_TEST_LOCAL_DISPATCHER_IDENTITY_SCHEMA_PG_URL must name a fresh disposable PostgreSQL database",
    );
    let (client, connection) = tokio_postgres::connect(&postgres_url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable dispatcher-identity schema database");
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "local-dispatcher-identity-schema-postgres",
        async move {
            let _ = connection.await;
        }
    ));
    client
        .batch_execute(
            "DO $$
             BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN
                 CREATE ROLE object_dispatch_retention_owner NOLOGIN;
               END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN
                 CREATE ROLE object_dispatch_retention_runtime NOLOGIN;
               END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN
                 CREATE ROLE object_dispatch_retention_maintenance NOLOGIN;
               END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_migrator') THEN
                 CREATE ROLE object_dispatch_retention_migrator NOLOGIN;
               END IF;
             END
             $$;
             GRANT object_dispatch_retention_owner TO CURRENT_USER;
             DO $$
             BEGIN
               EXECUTE pg_catalog.format(
                 'GRANT CREATE ON DATABASE %I TO object_dispatch_retention_owner',
                 pg_catalog.current_database()
               );
             END
             $$;",
        )
        .await
        .expect("bootstrap disposable schema-owner and service roles");
    client
        .batch_execute(include_str!(
            "../migrations/0002_object_store_retention_authority.sql"
        ))
        .await
        .expect("apply migration 0002");
    client
        .batch_execute(include_str!(
            "../migrations/0007_object_store_dispatch_authority_core.sql"
        ))
        .await
        .expect("apply migration 0007");
    client
        .batch_execute(include_str!(
            "../migrations/0018_object_store_dispatch_dispatcher_identity_schema.sql"
        ))
        .await
        .expect("apply migration 0018");

    const LOGICAL_A: &str = "00000000-03e8-7000-8000-000000000001";
    const ATTEMPT_A: &str = "00000000-03e9-7000-8000-000000000002";
    const LOGICAL_B: &str = "00000000-04b0-7000-8000-000000000003";
    const ATTEMPT_B: &str = "00000000-04b1-7000-8000-000000000004";
    client
        .batch_execute(&request_fixture_sql(LOGICAL_A, ATTEMPT_A, 1000, 1001))
        .await
        .expect("valid request fixture A");
    client
        .batch_execute(&request_fixture_sql(LOGICAL_B, ATTEMPT_B, 1200, 1201))
        .await
        .expect("valid request fixture B");

    // D8's headline property: two different participants may both hold the ACTIVE (state = 1) slot
    // for the same provider boundary at lease_generation 1. 0007's dropped primary key
    // (provider_boundary_id, lease_generation) is exactly what prevented this.
    client
        .batch_execute(&dispatcher_sql("dispatcher-a", 1, "instance-a"))
        .await
        .expect("first participant claims generation 1");
    client
        .batch_execute(&dispatcher_sql("dispatcher-b", 1, "instance-b"))
        .await
        .expect("second participant independently claims generation 1 on the same boundary");

    // The same dispatcher_id may not hold a second ACTIVE row: the participant index still
    // enforces one-ACTIVE-per-(boundary, dispatcher_id).
    let second_active_error = client
        .batch_execute(&dispatcher_sql("dispatcher-a", 2, "instance-a-restarted"))
        .await
        .expect_err("a second ACTIVE row for the same dispatcher_id must be rejected");
    let second_active_db_error = second_active_error
        .as_db_error()
        .expect("expected a typed PostgreSQL error");
    assert_eq!(second_active_db_error.code(), &SqlState::UNIQUE_VIOLATION);
    assert_eq!(
        second_active_db_error.constraint(),
        Some("object_dispatch_dispatchers_one_active_participant_idx"),
        "the violation must name the participant index, not any other constraint"
    );

    // The attempts -> dispatchers foreign key over (provider_boundary_id, dispatcher_id,
    // dispatcher_lease_generation) still exists and is still enforced after the primary key drop.
    client
        .batch_execute(&attempt_sql(
            "grant-a",
            LOGICAL_A,
            ATTEMPT_A,
            "dispatcher-a",
            1,
        ))
        .await
        .expect("an attempt referencing an existing dispatcher row must be admitted");
    let fk_error = client
        .batch_execute(&attempt_sql(
            "grant-b",
            LOGICAL_B,
            ATTEMPT_B,
            "dispatcher-a",
            99,
        ))
        .await
        .expect_err("an attempt referencing a nonexistent dispatcher generation must be rejected");
    let fk_db_error = fk_error
        .as_db_error()
        .expect("expected a typed PostgreSQL error");
    assert_eq!(fk_db_error.code(), &SqlState::FOREIGN_KEY_VIOLATION);
}

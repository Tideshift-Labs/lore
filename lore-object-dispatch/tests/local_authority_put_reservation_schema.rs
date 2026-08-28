// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract plus an opt-in PostgreSQL 16 schema probe for the local PUT reservation edge.
//!
//! The ignored tier requires `LORE_TEST_LOCAL_PUT_RESERVATION_SCHEMA_PG_URL`, an administrator URL
//! for a fresh disposable database. It installs migrations 0002, 0007, and 0010 itself. The
//! database is intentionally one-shot because these are committed forward migrations.

use lore_object_dispatch::local_authority_put_reservation_schema::LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_put_reservation_schema::LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1;
use lore_object_dispatch::local_authority_put_reservation_schema::validate_embedded_local_authority_put_reservation_schema_migration_v1;
use tokio_postgres::error::SqlState;
use tokio_util::task::AbortOnDropHandle;

const NEW_COLUMNS: [(&str, &str); 12] = [
    ("protocol_revision", "text"),
    ("policy_revision", "text"),
    (
        "put_reservation_fingerprint",
        "object_store_retention.blake3_256",
    ),
    ("allocation_revision", "text"),
    ("allocation_fence", "object_store_retention.uint64"),
    ("reservation_deadline_unix_ms", "bigint"),
    ("allocation_hard_expiry_unix_ms", "bigint"),
    ("admission_clock_unix_ms", "bigint"),
    ("prepared_ttl_ms", "bigint"),
    ("max_chunk_bytes", "object_store_retention.uint64"),
    ("reserve_put_ack_canonical_bytes", "bytea"),
    (
        "reserve_put_ack_blake3",
        "object_store_retention.blake3_256",
    ),
];
const EXPECTED_MIGRATION_BYTES: usize = 4_690;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1)
        .expect("local PUT reservation schema migration must remain UTF-8 SQL")
}

fn compact(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn constraint_body<'a>(sql: &'a str, name: &str) -> &'a str {
    let start = sql
        .find(name)
        .unwrap_or_else(|| panic!("missing constraint {name}"));
    let end = sql[start..]
        .find("),\n  ADD CONSTRAINT")
        .map(|offset| start + offset + 1)
        .or_else(|| {
            sql[start..]
                .find(");\n\nCREATE INDEX")
                .map(|offset| start + offset + 1)
        })
        .unwrap_or_else(|| panic!("missing end of constraint {name}"));
    &sql[start..end]
}

#[test]
fn embedded_migration_has_frozen_identity() {
    assert_eq!(
        LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        hex(blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1).as_bytes()),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        hex(&LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_BLAKE3_V1),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert!(validate_embedded_local_authority_put_reservation_schema_migration_v1());
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
    assert!(sql.rfind("COMMIT;") > sql.rfind("REVOKE "));
    assert!(!sql.contains('\r'));
}

#[test]
fn migration_is_strictly_additive_to_the_existing_spool_table() {
    let sql = migration();
    assert_eq!(
        sql.matches("ALTER TABLE object_store_retention.object_dispatch_spool_objects")
            .count(),
        2
    );
    assert_eq!(sql.matches("ADD COLUMN ").count(), NEW_COLUMNS.len());
    for (column, data_type) in NEW_COLUMNS {
        assert!(
            sql.contains(&format!("ADD COLUMN {column} {data_type}")),
            "missing exact additive column {column} {data_type}"
        );
    }
    for forbidden in [
        "CREATE TABLE",
        "CREATE TYPE",
        "CREATE FUNCTION",
        "CREATE PROCEDURE",
        "DROP ",
        "RENAME ",
        "ALTER COLUMN",
        "SET DEFAULT",
        "SET NOT NULL",
    ] {
        assert!(
            !sql.contains(forbidden),
            "forbidden schema effect: {forbidden}"
        );
    }
}

#[test]
fn presence_constraint_is_all_or_none_and_payload_kind_specific() {
    let body = constraint_body(
        migration(),
        "object_dispatch_spool_objects_put_reservation_presence_ck",
    );
    for (column, _) in NEW_COLUMNS {
        assert_eq!(
            body.matches(column).count(),
            2,
            "{column} must occur in both all-present and all-absent projections"
        );
    }
    assert!(body.contains("payload_kind = 1"));
    assert!(body.contains("payload_kind = 2"));
    assert!(body.contains("= 12"));
    assert!(body.contains("= 0"));
    assert!(body.contains("expires_at_unix_ms IS NOT NULL"));
}

#[test]
fn immutable_identity_fields_are_bounded_nfc_and_positive() {
    let body = compact(constraint_body(
        migration(),
        "object_dispatch_spool_objects_put_reservation_identity_ck",
    ));
    for revision in [
        "protocol_revision",
        "policy_revision",
        "allocation_revision",
    ] {
        assert!(body.contains(&format!(
            "pg_catalog.octet_length({revision}) BETWEEN 1 AND 1024"
        )));
        assert!(body.contains(&format!(
            "{revision} IS NOT DISTINCT FROM pg_catalog.normalize({revision}, 'NFC')"
        )));
    }
    assert!(body.contains("allocation_fence > 0"));
    assert!(body.contains("max_chunk_bytes > 0"));
}

#[test]
fn time_constraint_pins_chronology_checked_add_and_exact_minimum() {
    let body = compact(constraint_body(
        migration(),
        "object_dispatch_spool_objects_put_reservation_time_ck",
    ));
    for predicate in [
        "admission_clock_unix_ms >= 0",
        "reservation_deadline_unix_ms > admission_clock_unix_ms",
        "allocation_hard_expiry_unix_ms > admission_clock_unix_ms",
        "prepared_ttl_ms > 0",
        "admission_clock_unix_ms::numeric + prepared_ttl_ms::numeric <= 9223372036854775807",
        "expires_at_unix_ms > admission_clock_unix_ms",
        "expires_at_unix_ms <= reservation_deadline_unix_ms",
        "expires_at_unix_ms <= allocation_hard_expiry_unix_ms",
        "expires_at_unix_ms - admission_clock_unix_ms <= prepared_ttl_ms",
        "created_at_unix_ms = admission_clock_unix_ms",
    ] {
        assert!(
            body.contains(predicate),
            "missing exact time predicate: {predicate}"
        );
    }
    for exact_cap in [
        "expires_at_unix_ms = reservation_deadline_unix_ms",
        "expires_at_unix_ms = allocation_hard_expiry_unix_ms",
        "expires_at_unix_ms - admission_clock_unix_ms = prepared_ttl_ms",
    ] {
        assert!(
            body.contains(exact_cap),
            "missing minimum-cap equality: {exact_cap}"
        );
    }
}

#[test]
fn ack_constraint_pins_bounds_and_complete_record_suffix() {
    let body = compact(constraint_body(
        migration(),
        "object_dispatch_spool_objects_put_reservation_ack_ck",
    ));
    assert!(body.contains(
        "pg_catalog.octet_length(reserve_put_ack_canonical_bytes) BETWEEN 33 AND 16777216"
    ));
    assert!(body.contains(
        "pg_catalog.substring( reserve_put_ack_canonical_bytes, pg_catalog.octet_length(reserve_put_ack_canonical_bytes) - 31, 32 ) = reserve_put_ack_blake3"
    ));
}

#[test]
fn lookup_index_has_exact_authenticated_identity_and_put_predicate() {
    let sql = compact(migration());
    assert!(sql.contains(
        "CREATE INDEX object_dispatch_spool_objects_put_reservation_lookup_idx ON object_store_retention.object_dispatch_spool_objects ( provider_boundary_id, authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id, put_reservation_fingerprint ) WHERE payload_kind = 1;"
    ));
    assert_eq!(
        migration()
            .matches("object_dispatch_spool_objects_put_reservation_lookup_idx")
            .count(),
        1
    );
}

#[test]
fn acl_is_reclosed_without_any_new_authority() {
    let sql = compact(migration());
    assert!(sql.contains(
        "REVOKE ALL ON TABLE object_store_retention.object_dispatch_spool_objects FROM PUBLIC;"
    ));
    assert!(sql.contains(
        "REVOKE ALL ON TABLE object_store_retention.object_dispatch_spool_objects FROM object_dispatch_retention_runtime, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;"
    ));
    assert!(!sql.contains("GRANT "));
    assert!(!sql.contains("SECURITY DEFINER"));
}

#[test]
fn artifact_is_embedded_but_source_dark() {
    let module = include_str!("../src/local_authority_put_reservation_schema.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0010_object_store_dispatch_put_reservation_schema.sql\")"
    ));
    assert!(
        module.contains("validate_embedded_local_authority_put_reservation_schema_migration_v1")
    );
    assert!(library.contains("pub mod local_authority_put_reservation_schema;"));
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

#[test]
fn migration_has_no_data_mutation_or_runtime_provider_wiring() {
    let sql = migration();
    for forbidden in [
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "MERGE ",
        "CALL ",
        "runtime wiring",
        "object_store_dispatch_authority_install",
    ] {
        assert!(
            !sql.contains(forbidden),
            "forbidden behavior in schema-only slice: {forbidden}"
        );
    }
}

fn request_fixture_sql() -> String {
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
           request_state_canonical_bytes, request_state_blake3, terminal_result_id,
           terminal_result_tag, terminal_result_canonical_bytes, terminal_result_blake3,
           terminal_result_size, terminal_retryability, result_disposition,
           put_payload_availability, result_payload_availability, dispatch_attempt_blake3,
           closure_committed_at_unix_ms, submit_receipt_canonical_bytes, submit_receipt_blake3,
           get_outcome_canonical_bytes, get_outcome_blake3, quota_revision, row_revision,
           state_committed_at_unix_ms, created_at_unix_ms
         ) VALUES (
           'object-store-dispatch-authority-schema-v1', 'protocol-1', 'policy-1', 'boundary-1',
           'cell-1', 'tenant-1', '00000000-03e8-7000-8000-000000000001',
           '00000000-03e9-7000-8000-000000000002', 1000, 1001, NULL,
           decode('aa', 'hex'), {digest}, 1, 1, 5, 'allocation-1', 1,
           1000, 2000, 3000, {record}, {digest}, 'result-1', 1,
           {record}, {digest}, 33, 1, 1, 1, 1, {digest}, 1500,
           {record}, {digest}, {record}, {digest}, 1, 1, 1500, 1000
         );"
    )
}

struct PutFixture<'a> {
    tail: u16,
    protocol: &'a str,
    allocation_fence: u64,
    admission: i64,
    deadline: i64,
    allocation_expiry: i64,
    ttl: i64,
    expires: i64,
    max_chunk_bytes: u64,
    ack_digest_byte: &'a str,
}

fn put_fixture_sql(value: &PutFixture<'_>) -> String {
    let digest = "decode(repeat('11', 32), 'hex')";
    let record = "decode('aa' || repeat('11', 32), 'hex')";
    let ack = "decode('bb' || repeat('22', 32), 'hex')";
    format!(
        "INSERT INTO object_store_retention.object_dispatch_spool_objects (
           schema_revision, spool_object_id, logical_request_id, attempt_id,
           provider_boundary_id, authenticated_cell_id, authenticated_tenant_id,
           request_binding_state, payload_kind, lifecycle_state, upload_id, upload_fence,
           boundary_blake3, boundary_token, observation_binding_blake3, expected_size,
           expected_blake3, quota_bytes, quota_rows, quota_concurrency, quota_revision,
           purge_state, expires_at_unix_ms, canonical_record_bytes, record_blake3,
           spool_revision, created_at_unix_ms, protocol_revision, policy_revision,
           put_reservation_fingerprint, allocation_revision, allocation_fence,
           reservation_deadline_unix_ms, allocation_hard_expiry_unix_ms,
           admission_clock_unix_ms, prepared_ttl_ms, max_chunk_bytes,
           reserve_put_ack_canonical_bytes, reserve_put_ack_blake3
         ) VALUES (
           'object-store-dispatch-authority-schema-v1',
           '00000000-07d0-7000-8000-00000000{tail:04x}',
           '00000000-07d0-7000-8000-00000001{tail:04x}',
           '00000000-07d1-7000-8000-00000002{tail:04x}',
           'boundary-1', 'cell-1', 'tenant-1', 1, 1, 1,
           '00000000-07d2-7000-8000-00000003{tail:04x}', 7,
           {digest}, 'boundary-token', {digest}, 64, {digest}, 64, 1, 1, 1, 1,
           {expires}, {record}, {digest}, 1, {admission}, {protocol}, 'policy-1',
           {digest}, 'allocation-1', {allocation_fence}, {deadline}, {allocation_expiry}, {admission},
           {ttl}, {max_chunk_bytes}, {ack}, decode(repeat('{ack_digest_byte}', 32), 'hex')
         );",
        protocol = value.protocol,
        allocation_fence = value.allocation_fence,
        admission = value.admission,
        deadline = value.deadline,
        allocation_expiry = value.allocation_expiry,
        ttl = value.ttl,
        expires = value.expires,
        max_chunk_bytes = value.max_chunk_bytes,
        ack_digest_byte = value.ack_digest_byte,
        tail = value.tail,
    )
}

fn result_fixture_sql() -> String {
    let digest = "decode(repeat('11', 32), 'hex')";
    let record = "decode('aa' || repeat('11', 32), 'hex')";
    format!(
        "INSERT INTO object_store_retention.object_dispatch_spool_objects (
           schema_revision, spool_object_id, logical_request_id, attempt_id,
           provider_boundary_id, authenticated_cell_id, authenticated_tenant_id,
           bound_request_logical_request_id, bound_request_attempt_id, request_binding_state,
           payload_kind, lifecycle_state, terminal_result_id, boundary_blake3, boundary_token,
           observation_binding_blake3, expected_size, expected_blake3, quota_bytes, quota_rows,
           quota_concurrency, quota_revision, purge_state, canonical_record_bytes, record_blake3,
           spool_revision, created_at_unix_ms
         ) VALUES (
           'object-store-dispatch-authority-schema-v1',
           '00000000-05dc-7000-8000-000000000003',
           '00000000-03e8-7000-8000-000000000001',
           '00000000-03e9-7000-8000-000000000002', 'boundary-1', 'cell-1', 'tenant-1',
           '00000000-03e8-7000-8000-000000000001',
           '00000000-03e9-7000-8000-000000000002', 2, 2, 1, 'result-1',
           {digest}, 'boundary-token', {digest}, 33, {digest}, 33, 1, 1, 1, 1,
           {record}, {digest}, 1, 1500
         );"
    )
}

async fn expect_check_rejection(client: &tokio_postgres::Client, sql: &str, label: &str) {
    let error = match client.batch_execute(sql).await {
        Ok(()) => panic!("{label}: invalid fixture was accepted"),
        Err(error) => error,
    };
    let database_error = error
        .as_db_error()
        .unwrap_or_else(|| panic!("{label}: expected PostgreSQL CHECK error, got {error}"));
    assert_eq!(database_error.code(), &SqlState::CHECK_VIOLATION, "{label}");
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_enforces_put_result_shape_time_ack_and_service_acl() {
    let postgres_url = std::env::var("LORE_TEST_LOCAL_PUT_RESERVATION_SCHEMA_PG_URL").expect(
        "LORE_TEST_LOCAL_PUT_RESERVATION_SCHEMA_PG_URL must name a fresh disposable PostgreSQL database",
    );
    let (client, connection) = tokio_postgres::connect(&postgres_url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable PUT reservation schema database");
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "local-put-reservation-schema-postgres",
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
            "../migrations/0010_object_store_dispatch_put_reservation_schema.sql"
        ))
        .await
        .expect("apply migration 0010");

    client
        .batch_execute(&put_fixture_sql(&PutFixture {
            tail: 1,
            protocol: "'protocol-1'",
            allocation_fence: 5,
            admission: 2_000,
            deadline: 3_000,
            allocation_expiry: 4_000,
            ttl: 1_000,
            expires: 3_000,
            max_chunk_bytes: 16,
            ack_digest_byte: "22",
        }))
        .await
        .expect("valid unbound PUT reservation shape");
    client
        .batch_execute(&request_fixture_sql())
        .await
        .expect("valid terminal request fixture");
    client
        .batch_execute(&result_fixture_sql())
        .await
        .expect("valid bound result shape with every reservation field absent");
    expect_check_rejection(
        &client,
        "UPDATE object_store_retention.object_dispatch_spool_objects
         SET protocol_revision = 'protocol-1'
         WHERE payload_kind = 2;",
        "result payload with one reservation field present",
    )
    .await;

    for (label, fixture) in [
        (
            "partial reservation fields",
            PutFixture {
                tail: 2,
                protocol: "NULL",
                allocation_fence: 5,
                admission: 2_000,
                deadline: 3_000,
                allocation_expiry: 4_000,
                ttl: 1_000,
                expires: 3_000,
                max_chunk_bytes: 16,
                ack_digest_byte: "22",
            },
        ),
        (
            "decomposed NFC protocol revision",
            PutFixture {
                tail: 6,
                protocol: r"U&'e\0301'",
                allocation_fence: 5,
                admission: 2_000,
                deadline: 3_000,
                allocation_expiry: 4_000,
                ttl: 1_000,
                expires: 3_000,
                max_chunk_bytes: 16,
                ack_digest_byte: "22",
            },
        ),
        (
            "zero allocation fence",
            PutFixture {
                tail: 7,
                protocol: "'protocol-1'",
                allocation_fence: 0,
                admission: 2_000,
                deadline: 3_000,
                allocation_expiry: 4_000,
                ttl: 1_000,
                expires: 3_000,
                max_chunk_bytes: 16,
                ack_digest_byte: "22",
            },
        ),
        (
            "zero max chunk bytes",
            PutFixture {
                tail: 8,
                protocol: "'protocol-1'",
                allocation_fence: 5,
                admission: 2_000,
                deadline: 3_000,
                allocation_expiry: 4_000,
                ttl: 1_000,
                expires: 3_000,
                max_chunk_bytes: 0,
                ack_digest_byte: "22",
            },
        ),
        (
            "checked-add overflow",
            PutFixture {
                tail: 3,
                protocol: "'protocol-1'",
                allocation_fence: 5,
                admission: i64::MAX - 1,
                deadline: i64::MAX,
                allocation_expiry: i64::MAX,
                ttl: 2,
                expires: i64::MAX,
                max_chunk_bytes: 16,
                ack_digest_byte: "22",
            },
        ),
        (
            "expiry is not the exact minimum",
            PutFixture {
                tail: 4,
                protocol: "'protocol-1'",
                allocation_fence: 5,
                admission: 2_000,
                deadline: 4_000,
                allocation_expiry: 5_000,
                ttl: 3_000,
                expires: 3_500,
                max_chunk_bytes: 16,
                ack_digest_byte: "22",
            },
        ),
        (
            "ACK digest suffix mismatch",
            PutFixture {
                tail: 5,
                protocol: "'protocol-1'",
                allocation_fence: 5,
                admission: 2_000,
                deadline: 3_000,
                allocation_expiry: 4_000,
                ttl: 1_000,
                expires: 3_000,
                max_chunk_bytes: 16,
                ack_digest_byte: "23",
            },
        ),
    ] {
        expect_check_rejection(&client, &put_fixture_sql(&fixture), label).await;
    }

    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        client
            .batch_execute(&format!("BEGIN; SET LOCAL ROLE {role}; SAVEPOINT denied;"))
            .await
            .unwrap_or_else(|error| panic!("enter {role}: {error}"));
        let error = client
            .query_one(
                "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
                &[],
            )
            .await
            .unwrap_err();
        let database_error = error
            .as_db_error()
            .unwrap_or_else(|| panic!("{role}: expected typed ACL error, got {error}"));
        assert_eq!(
            database_error.code(),
            &SqlState::INSUFFICIENT_PRIVILEGE,
            "{role}"
        );
        client
            .batch_execute("ROLLBACK;")
            .await
            .unwrap_or_else(|error| panic!("recover after {role} ACL rejection: {error}"));
    }
}

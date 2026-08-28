// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract plus an opt-in PostgreSQL/Rust vector for the owner-only reservation-row codec.
//!
//! The ignored tier requires `LORE_TEST_LOCAL_PUT_RESERVATION_RECORD_CODEC_PG_URL`, an administrator
//! URL for a fresh disposable PostgreSQL 16 database. Its exact-preimage lookup returns genuine
//! BLAKE3 digests for this fixture only; it proves codec mechanics, not provider readiness.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::local_authority_put_reservation_record_codec::LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_put_reservation_record_codec::LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1;
use lore_object_dispatch::local_authority_put_reservation_record_codec::validate_embedded_local_authority_put_reservation_record_codec_migration_v1;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 10_874;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "b37116d9d87e49ad5c0051514e721a80d0c39f1c9dcaa51c19f7a77618ee6514";
const ADMISSION: i64 = 2_000;
const EXPIRES: i64 = 3_000;
const ALLOCATION_EXPIRY: i64 = 4_000;
const BODY_BLAKE3: [u8; 32] = [0x31; 32];
const BOUNDARY_BLAKE3: [u8; 32] = [0x41; 32];
const OBSERVATION_BLAKE3: [u8; 32] = [0x51; 32];
const FINGERPRINT: [u8; 32] = [0x61; 32];

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1)
        .expect("reservation-record migration must remain UTF-8 SQL")
}

fn function_body(sql: &str) -> &str {
    let start = sql
        .find("CREATE FUNCTION object_store_retention.local_put_reservation_record_v1(")
        .expect("record codec function");
    let body_start = sql[start..]
        .find("AS $$")
        .map(|offset| start + offset)
        .expect("record codec body");
    let body_end = sql[body_start + 5..]
        .find("\n$$;")
        .map(|offset| body_start + 5 + offset)
        .expect("record codec body terminator");
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
fn embedded_migration_has_exact_frozen_identity() {
    assert_eq!(
        LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_put_reservation_record_codec_migration_v1());
}

#[test]
fn migration_is_one_owner_transaction_and_one_fixed_security_definer() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n"));
    assert!(sql.ends_with("\nCOMMIT;\n"));
    assert_eq!(sql.matches("\nBEGIN;\n").count(), 1);
    assert_eq!(sql.matches("\nCOMMIT;\n").count(), 1);
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 1);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 1);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 1);
    assert!(!sql.contains("CREATE TABLE"));
    assert!(!sql.contains("ALTER TABLE"));
}

#[test]
fn signature_pins_every_persisted_reservation_input_and_bound() {
    let sql = migration();
    for parameter in [
        "protocol_revision text",
        "policy_revision text",
        "provider_boundary_id text",
        "authenticated_cell_id text",
        "authenticated_tenant_id text",
        "spool_object_id uuid",
        "logical_request_id uuid",
        "attempt_id uuid",
        "upload_id uuid",
        "upload_fence object_store_retention.uint64",
        "boundary_blake3 bytea",
        "boundary_token text",
        "observation_binding_blake3 bytea",
        "expected_size object_store_retention.uint64",
        "expected_blake3 bytea",
        "put_reservation_fingerprint bytea",
        "allocation_revision text",
        "allocation_fence object_store_retention.uint64",
        "reservation_deadline_unix_ms bigint",
        "allocation_hard_expiry_unix_ms bigint",
        "admission_clock_unix_ms bigint",
        "prepared_ttl_ms bigint",
        "expires_at_unix_ms bigint",
        "max_chunk_bytes object_store_retention.uint64",
        "quota_bytes object_store_retention.uint64",
        "quota_rows object_store_retention.uint64",
        "quota_concurrency object_store_retention.uint64",
        "quota_revision object_store_retention.uint64",
        "reserve_put_ack_canonical_bytes bytea",
        "reserve_put_ack_blake3 bytea",
        "spool_revision object_store_retention.uint64",
        "maximum_identity_bytes integer",
        "maximum_boundary_token_bytes integer",
        "maximum_record_bytes integer",
    ] {
        assert!(
            sql.contains(parameter),
            "missing codec parameter: {parameter}"
        );
    }
}

#[test]
fn validation_pins_widths_uuidv7_positive_quota_and_bounds() {
    let body = function_body(migration());
    for required in [
        "pg_catalog.octet_length(boundary_blake3) <> 32",
        "pg_catalog.octet_length(observation_binding_blake3) <> 32",
        "pg_catalog.octet_length(expected_blake3) <> 32",
        "pg_catalog.octet_length(put_reservation_fingerprint) <> 32",
        "pg_catalog.octet_length(reserve_put_ack_blake3) <> 32",
        "upload_fence = 0",
        "allocation_fence = 0",
        "max_chunk_bytes = 0",
        "quota_bytes IS DISTINCT FROM expected_size",
        "quota_rows IS DISTINCT FROM 1",
        "quota_concurrency IS DISTINCT FROM 1",
        "quota_revision = 0",
        "spool_revision IS DISTINCT FROM 1",
        "maximum_identity_bytes NOT BETWEEN 1 AND 1024",
        "maximum_boundary_token_bytes NOT BETWEEN 1 AND 4096",
        "maximum_record_bytes NOT BETWEEN 1 AND 16777216",
    ] {
        assert!(body.contains(required), "missing validation: {required}");
    }
    assert_eq!(body.matches("pg_catalog.uuid_send(").count(), 8);
    assert_eq!(body.matches(") >> 4) <> 7").count(), 4);
    assert_eq!(body.matches(") >> 6) <> 2").count(), 4);
}

#[test]
fn expiry_is_checked_add_safe_and_exactly_one_or_more_minimum_caps() {
    let body = function_body(migration());
    for required in [
        "admission_clock_unix_ms::numeric + prepared_ttl_ms::numeric > 9223372036854775807",
        "expires_at_unix_ms > reservation_deadline_unix_ms",
        "expires_at_unix_ms > allocation_hard_expiry_unix_ms",
        "expires_at_unix_ms - admission_clock_unix_ms > prepared_ttl_ms",
        "expires_at_unix_ms = reservation_deadline_unix_ms OR",
        "expires_at_unix_ms = allocation_hard_expiry_unix_ms OR",
        "expires_at_unix_ms - admission_clock_unix_ms = prepared_ttl_ms",
    ] {
        assert!(
            body.contains(required),
            "missing expiry invariant: {required}"
        );
    }
}

#[test]
fn codec_recomputes_reserved_ack_before_constructing_row() {
    let body = function_body(migration());
    let recompute = body
        .find("expected_ack := object_store_retention.local_reserve_put_ack_v1(")
        .expect("ACK recomputation");
    let compare = body
        .find("expected_ack.canonical_bytes IS DISTINCT FROM reserve_put_ack_canonical_bytes")
        .expect("ACK byte comparison");
    let row = body
        .find("object-store-dispatch-put-reservation-row-v1")
        .expect("row preimage");
    assert!(recompute < compare && compare < row);
    assert!(body.contains("upload_fence,\n    1::smallint,\n    quota_bytes"));
    assert!(body.contains("RAISE EXCEPTION 'LOCAL_PUT_RESERVATION_ACK_MISMATCH'"));
    assert!(!body.contains("substring(reserve_put_ack_canonical_bytes"));
}

#[test]
fn row_preimage_order_binds_schema_identity_lifecycle_quota_ack_and_revision() {
    let body = function_body(migration());
    let ordered = [
        "'object-store-dispatch-authority-schema-v1'",
        "local_canonical_text_v1(protocol_revision",
        "local_canonical_text_v1(policy_revision",
        "local_canonical_text_v1(provider_boundary_id",
        "local_canonical_text_v1(spool_object_id::text",
        "local_canonical_u64_v1(upload_fence)",
        "local_canonical_u8_v1(1)",
        "boundary_blake3",
        "boundary_token, maximum_boundary_token_bytes",
        "observation_binding_blake3",
        "local_canonical_u64_v1(expected_size)",
        "expected_blake3",
        "local_canonical_bytes_v1(quota_child",
        "local_canonical_u64_v1(quota_revision)",
        "local_canonical_u64_v1(expires_at_unix_ms",
        "put_reservation_fingerprint",
        "local_canonical_text_v1(allocation_revision",
        "local_canonical_u64_v1(allocation_fence)",
        "reservation_deadline_unix_ms::object_store_retention.uint64",
        "allocation_hard_expiry_unix_ms::object_store_retention.uint64",
        "admission_clock_unix_ms::object_store_retention.uint64",
        "prepared_ttl_ms::object_store_retention.uint64",
        "local_canonical_u64_v1(max_chunk_bytes)",
        "reserve_put_ack_canonical_bytes, maximum_record_bytes",
        "reserve_put_ack_blake3",
        "local_canonical_u64_v1(spool_revision)",
    ];
    let mut cursor = 0;
    for needle in ordered {
        let offset = body[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing/out-of-order row field: {needle}"));
        cursor += offset + needle.len();
    }
    assert!(body[cursor..].contains("admission_clock_unix_ms::object_store_retention.uint64"));
}

#[test]
fn acl_is_owner_only_and_artifact_is_source_dark() {
    let sql = migration();
    assert_eq!(sql.matches("REVOKE ALL ON FUNCTION").count(), 2);
    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        assert!(sql.contains(role));
    }
    assert!(!sql.contains("GRANT "));

    let module = include_str!("../src/local_authority_put_reservation_record_codec.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql\")"
    ));
    assert!(library.contains("pub mod local_authority_put_reservation_record_codec;"));
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read production Rust source");
        assert!(
            !source.contains("local_put_reservation_record_v1("),
            "runtime source {} calls owner-only codec",
            path.display()
        );
    }
}

fn uuid_v7(timestamp: u64, tail: &str) -> String {
    let prefix = format!("{timestamp:012x}");
    format!("{}-{}-7abc-8def-{tail}", &prefix[..8], &prefix[8..])
}

fn push_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .expect("fixture text length")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value.as_bytes());
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .expect("fixture child length")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value);
}

fn complete_record(preimage: &[u8]) -> Vec<u8> {
    let mut record = preimage.to_vec();
    record.extend_from_slice(blake3::hash(preimage).as_bytes());
    record
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn quota_preimage() -> Vec<u8> {
    let mut bytes = b"object-store-quota-units-v1\0".to_vec();
    for value in [0_u64, 1, 1] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn reserved_ack() -> ReservePutAckV1 {
    ReservePutAckV1 {
        protocol_revision: "protocol-1".to_string(),
        policy_revision: "policy-1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: uuid_v7(1_000, "0123456789ab"),
        attempt_id: uuid_v7(1_001, "0223456789ab"),
        upload_id: uuid_v7(1_002, "0323456789ab"),
        upload_fence: 7,
        state: PutReservationStateV1::PutReservationStateReserved as i32,
        reserved_quota: Some(ObjectStoreQuotaUnitsV1 {
            bytes: 0,
            rows: 1,
            concurrency: 1,
        }),
        expires_at_unix_ms: EXPIRES,
        max_chunk_bytes: 16,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: ADMISSION,
        allocation_hard_expiry_unix_ms: ALLOCATION_EXPIRY,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    }
}

fn row_preimage(ack_bytes: &[u8], ack_blake3: &[u8]) -> Vec<u8> {
    let mut bytes = b"object-store-dispatch-put-reservation-row-v1\0".to_vec();
    for text in [
        "object-store-dispatch-authority-schema-v1",
        "protocol-1",
        "policy-1",
        "boundary-1",
        "cell-1",
        "tenant-1",
        &uuid_v7(1_003, "0423456789ab"),
        &uuid_v7(1_000, "0123456789ab"),
        &uuid_v7(1_001, "0223456789ab"),
        &uuid_v7(1_002, "0323456789ab"),
    ] {
        push_text(&mut bytes, text);
    }
    bytes.extend_from_slice(&7_u64.to_be_bytes());
    bytes.extend_from_slice(&[1, 1, 1, 1]);
    bytes.extend_from_slice(&BOUNDARY_BLAKE3);
    push_text(&mut bytes, "boundary-token");
    bytes.extend_from_slice(&OBSERVATION_BLAKE3);
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.extend_from_slice(&BODY_BLAKE3);
    for _ in 0..3 {
        bytes.extend_from_slice(&0_u64.to_be_bytes());
    }
    push_bytes(&mut bytes, &complete_record(&quota_preimage()));
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&(EXPIRES as u64).to_be_bytes());
    bytes.extend_from_slice(&FINGERPRINT);
    push_text(&mut bytes, "allocation-1");
    for value in [5_u64, 3_000, 4_000, 2_000, 1_000, 16] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    push_bytes(&mut bytes, ack_bytes);
    bytes.extend_from_slice(ack_blake3);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&(ADMISSION as u64).to_be_bytes());
    bytes
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit fixture mutation axes keep each SQL rejection case reviewable"
)]
fn sql_call(
    protocol: &str,
    spool_id: &str,
    boundary_digest_hex: &str,
    admission: i64,
    deadline: i64,
    allocation_expiry: i64,
    ttl: i64,
    expires: i64,
    ack_bytes: &[u8],
    ack_digest: &[u8],
    spool_revision: u64,
    maximum_identity_bytes: i32,
    maximum_boundary_token_bytes: i32,
    maximum_record_bytes: i32,
) -> String {
    format!(
        "SELECT (object_store_retention.local_put_reservation_record_v1(
          {protocol}, 'policy-1', 'boundary-1', 'cell-1', 'tenant-1',
          '{spool_id}', '00000000-03e8-7abc-8def-0123456789ab',
          '00000000-03e9-7abc-8def-0223456789ab',
          '00000000-03ea-7abc-8def-0323456789ab', 7,
          pg_catalog.decode('{boundary_digest_hex}', 'hex'), 'boundary-token',
          pg_catalog.decode('{observation}', 'hex'), 0,
          pg_catalog.decode('{body}', 'hex'), pg_catalog.decode('{fingerprint}', 'hex'),
          'allocation-1', 5, {deadline}, {allocation_expiry}, {admission}, {ttl}, {expires},
          16, 0, 1, 1, 1, pg_catalog.decode('{ack_bytes}', 'hex'),
          pg_catalog.decode('{ack_digest}', 'hex'), {spool_revision}, {maximum_identity_bytes},
          {maximum_boundary_token_bytes}, {maximum_record_bytes}
        )).*",
        observation = hex(&OBSERVATION_BLAKE3),
        body = hex(&BODY_BLAKE3),
        fingerprint = hex(&FINGERPRINT),
        ack_bytes = hex(ack_bytes),
        ack_digest = hex(ack_digest),
    )
}

fn lookup_provider(vectors: &[(&[u8], &[u8])]) -> String {
    let cases = vectors
        .iter()
        .map(|(preimage, digest)| {
            format!(
                "WHEN '{}' THEN pg_catalog.decode('{}', 'hex')",
                hex(preimage),
                hex(digest)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "CREATE FUNCTION public.blake3(payload bytea) RETURNS bytea
         LANGUAGE sql IMMUTABLE STRICT AS $$
         SELECT CASE pg_catalog.encode(payload, 'hex') {cases} ELSE NULL::bytea END
         $$;"
    )
}

async fn expect_rejected(
    client: &tokio_postgres::Client,
    sql: &str,
    expected_message: &str,
    label: &str,
) {
    let error = match client.query_one(sql, &[]).await {
        Ok(_) => panic!("{label}: invalid codec input was accepted"),
        Err(error) => error,
    };
    let database_error = error
        .as_db_error()
        .unwrap_or_else(|| panic!("{label}: expected typed PostgreSQL error, got {error}"));
    assert_eq!(database_error.code().code(), "22023", "{label}");
    assert_eq!(database_error.message(), expected_message, "{label}");
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_row_bytes_match_independent_vector_and_invalid_inputs_fail() {
    let url = std::env::var("LORE_TEST_LOCAL_PUT_RESERVATION_RECORD_CODEC_PG_URL").expect(
        "LORE_TEST_LOCAL_PUT_RESERVATION_RECORD_CODEC_PG_URL must name a fresh disposable database",
    );
    let limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 256,
        max_canonical_row_bytes: 16_384,
    };
    let ack = validate_and_encode_object_store_reserve_put_ack(&reserved_ack(), &limits)
        .expect("zero-body RESERVED ACK with rows/concurrency one");
    let mut changed_protocol_ack = reserved_ack();
    changed_protocol_ack.protocol_revision = "protocol-2".to_string();
    let changed_protocol_ack =
        validate_and_encode_object_store_reserve_put_ack(&changed_protocol_ack, &limits)
            .expect("changed-protocol ACK lookup vector");
    let row_preimage = row_preimage(ack.canonical_bytes(), ack.ack_blake3());
    let row_digest = *blake3::hash(&row_preimage).as_bytes();
    let row_bytes = complete_record(&row_preimage);
    let quota_preimage = quota_preimage();
    let quota_digest = *blake3::hash(&quota_preimage).as_bytes();

    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable record-codec database");
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "put-reservation-record-codec-postgres",
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
    client
        .batch_execute(include_str!(
            "../migrations/0002_object_store_retention_authority.sql"
        ))
        .await
        .expect("apply 0002");
    client
        .batch_execute(include_str!(
            "../migrations/0007_object_store_dispatch_authority_core.sql"
        ))
        .await
        .expect("apply 0007");
    client
        .batch_execute(include_str!(
            "../migrations/0009_object_store_dispatch_authority_canonical_codec.sql"
        ))
        .await
        .expect("apply 0009");
    client
        .batch_execute(include_str!(
            "../migrations/0010_object_store_dispatch_put_reservation_schema.sql"
        ))
        .await
        .expect("apply 0010");
    client
        .batch_execute(include_str!(
            "../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"
        ))
        .await
        .expect("apply 0012");
    client
        .batch_execute(&lookup_provider(&[
            (&quota_preimage, &quota_digest),
            (ack.canonical_preimage(), ack.ack_blake3()),
            (
                changed_protocol_ack.canonical_preimage(),
                changed_protocol_ack.ack_blake3(),
            ),
            (&row_preimage, &row_digest),
        ]))
        .await
        .expect("install genuine exact-preimage BLAKE3 lookup");

    let valid = sql_call(
        "'protocol-1'",
        "00000000-03eb-7abc-8def-0423456789ab",
        &hex(&BOUNDARY_BLAKE3),
        ADMISSION,
        3_000,
        ALLOCATION_EXPIRY,
        1_000,
        EXPIRES,
        ack.canonical_bytes(),
        ack.ack_blake3(),
        1,
        256,
        256,
        16_384,
    );
    let row = client
        .query_one(&valid, &[])
        .await
        .expect("valid row vector");
    assert_eq!(row.get::<_, Vec<u8>>(0), row_bytes);
    assert_eq!(row.get::<_, Vec<u8>>(1), row_digest);

    let insert = format!(
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
           '00000000-03eb-7abc-8def-0423456789ab',
           '00000000-03e8-7abc-8def-0123456789ab',
           '00000000-03e9-7abc-8def-0223456789ab',
           'boundary-1', 'cell-1', 'tenant-1', 1, 1, 1,
           '00000000-03ea-7abc-8def-0323456789ab', 7,
           pg_catalog.decode('{boundary}', 'hex'), 'boundary-token',
           pg_catalog.decode('{observation}', 'hex'), 0,
           pg_catalog.decode('{body}', 'hex'), 0, 1, 1, 1, 1, 3000, $1, $2::bytea, 1, 2000,
           'protocol-1', 'policy-1', pg_catalog.decode('{fingerprint}', 'hex'),
           'allocation-1', 5, 3000, 4000, 2000, 1000, 16,
           pg_catalog.decode('{ack_bytes}', 'hex'), pg_catalog.decode('{ack_digest}', 'hex')
         )",
        boundary = hex(&BOUNDARY_BLAKE3),
        observation = hex(&OBSERVATION_BLAKE3),
        body = hex(&BODY_BLAKE3),
        fingerprint = hex(&FINGERPRINT),
        ack_bytes = hex(ack.canonical_bytes()),
        ack_digest = hex(ack.ack_blake3()),
    );
    client
        .execute(&insert, &[&row_bytes, &row_digest.as_slice()])
        .await
        .expect("persist exact returned record in spool authority table");
    let persisted = client
        .query_one(
            "SELECT canonical_record_bytes, record_blake3
               FROM object_store_retention.object_dispatch_spool_objects
              WHERE spool_object_id = '00000000-03eb-7abc-8def-0423456789ab'",
            &[],
        )
        .await
        .expect("read persisted reservation record");
    assert_eq!(persisted.get::<_, Vec<u8>>(0), row_bytes);
    assert_eq!(persisted.get::<_, Vec<u8>>(1), row_digest);

    for (label, expected_message, sql) in [
        (
            "changed protocol cannot reuse ACK",
            "LOCAL_PUT_RESERVATION_ACK_MISMATCH",
            sql_call(
                "'protocol-2'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                256,
                16_384,
            ),
        ),
        (
            "decomposed NFC",
            "LOCAL_CANONICAL_TEXT_INVALID",
            sql_call(
                r"U&'e\0301'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                256,
                16_384,
            ),
        ),
        (
            "wrong expiry minimum",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                4_000,
                5_000,
                3_000,
                3_500,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                256,
                16_384,
            ),
        ),
        (
            "checked-add overflow",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                i64::MAX - 1,
                i64::MAX,
                i64::MAX,
                2,
                i64::MAX,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                256,
                16_384,
            ),
        ),
        (
            "UUID is not v7",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "550e8400-e29b-41d4-a716-446655440000",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                256,
                16_384,
            ),
        ),
        (
            "digest width",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &"41".repeat(31),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                256,
                16_384,
            ),
        ),
        (
            "identity bound",
            "LOCAL_CANONICAL_TEXT_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                3,
                256,
                16_384,
            ),
        ),
        (
            "identity hard maximum",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                1_025,
                256,
                16_384,
            ),
        ),
        (
            "boundary token hard maximum",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                4_097,
                16_384,
            ),
        ),
        (
            "record hard maximum",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                1,
                256,
                256,
                16_777_217,
            ),
        ),
        (
            "spool revision greater than one",
            "LOCAL_PUT_RESERVATION_RECORD_INVALID",
            sql_call(
                "'protocol-1'",
                "00000000-03eb-7abc-8def-0423456789ab",
                &hex(&BOUNDARY_BLAKE3),
                ADMISSION,
                3_000,
                ALLOCATION_EXPIRY,
                1_000,
                EXPIRES,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                2,
                256,
                256,
                16_384,
            ),
        ),
    ] {
        expect_rejected(&client, &sql, expected_message, label).await;
    }

    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        let row = client
            .query_one(
                &format!(
                    "SELECT pg_catalog.has_function_privilege(
                       '{role}', 'object_store_retention.local_put_reservation_record_v1(
                         text,text,text,text,text,uuid,uuid,uuid,uuid,
                         object_store_retention.uint64,bytea,text,bytea,
                         object_store_retention.uint64,bytea,bytea,text,
                         object_store_retention.uint64,bigint,bigint,bigint,bigint,bigint,
                         object_store_retention.uint64,object_store_retention.uint64,
                         object_store_retention.uint64,object_store_retention.uint64,
                         object_store_retention.uint64,bytea,bytea,
                         object_store_retention.uint64,integer,integer,integer)', 'EXECUTE')"
                ),
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("ACL read for {role}: {error}"));
        assert!(
            !row.get::<_, bool>(0),
            "{role} unexpectedly has codec EXECUTE"
        );
    }
}

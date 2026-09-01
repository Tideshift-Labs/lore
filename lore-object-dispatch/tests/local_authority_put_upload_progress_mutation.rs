// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Contract for source-dark atomic PUT progress claims. This proves database snapshot transitions,
//! not filesystem contents, monotonic fsync, or coordination with an uploader.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::local_authority_put_upload_progress_mutation::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_put_upload_progress_mutation::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1;
use lore_object_dispatch::local_authority_put_upload_progress_mutation::validate_embedded_local_authority_put_upload_progress_mutation_migration_v1;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 10_942;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "f9bb0d0ed36689b6c15b9686108adc905cd8fe9839156e051fc443b09941078c";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1)
        .expect("progress mutation migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, signature: &str) -> &'a str {
    let start = sql
        .find(signature)
        .unwrap_or_else(|| panic!("missing {signature}"));
    let body_start = sql[start..]
        .find("AS $$")
        .map(|offset| start + offset)
        .expect("body");
    let body_end = sql[body_start + 5..]
        .find("\n$$;")
        .map(|offset| body_start + 5 + offset)
        .expect("body terminator");
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
        LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_put_upload_progress_mutation_migration_v1());
}

#[test]
fn migration_is_one_owner_transaction_with_runtime_only_main() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n"));
    assert!(sql.ends_with("\nCOMMIT;\n"));
    assert_eq!(sql.matches("CREATE TYPE ").count(), 1);
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 3);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 3);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 3);
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 1);
    assert!(sql.contains("object_store_dispatch_put_upload_progress_v1("));
    assert!(sql.contains(") TO object_dispatch_retention_runtime;"));
    assert!(!sql.contains("CREATE TABLE"));
    assert!(!sql.contains("ALTER TABLE"));
}

#[test]
fn main_orders_auth_api_isolation_schema_and_exact_row_lock() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_upload_progress_v1(",
    );
    let auth = body.find("assert_dispatch_runtime_v1()").expect("auth");
    let api = body
        .find("assert_dispatch_put_upload_progress_api_revision_v1(api_revision)")
        .expect("api");
    let isolation = body
        .find("assert_serializable_write_v1()")
        .expect("isolation");
    let schema = body.find("FOR SHARE;").expect("schema lock");
    let row = body
        .find("AND spool.payload_kind = 1\n   FOR UPDATE;")
        .expect("row lock");
    assert!(auth < api && api < isolation && isolation < schema && schema < row);
    assert!(body.contains(
        "spool.logical_request_id = object_store_dispatch_put_upload_progress_v1.logical_request_id"
    ));
    assert!(
        body.contains("spool.attempt_id = object_store_dispatch_put_upload_progress_v1.attempt_id")
    );
}

#[test]
fn identity_and_current_reserved_record_are_authenticated_before_arguments() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_upload_progress_v1(",
    );
    for field in [
        "protocol_revision",
        "provider_boundary_id",
        "authenticated_cell_id",
        "authenticated_tenant_id",
        "logical_request_id",
        "attempt_id",
        "upload_id",
        "upload_fence",
    ] {
        assert!(
            body.contains(&format!("stored.{field} IS DISTINCT FROM {field}")),
            "missing {field}"
        );
    }
    let identity = body
        .find("UPLOAD_STREAM_IDENTITY_MISMATCH")
        .expect("identity error");
    let record = body
        .find("project_dispatch_reserved_put_v1(stored, 'REPLAY')")
        .expect("record auth");
    let arguments = body.find("IF chunk_index IS NULL").expect("arguments");
    assert!(identity < record && record < arguments);
}

#[test]
fn replay_precedes_clock_and_maxima_while_new_progress_is_bounded() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_upload_progress_v1(",
    );
    let replay = body
        .find("chunk_index = stored.partial_temp_chunks - 1")
        .expect("replay");
    let maxima = body.find("maximum_identity_bytes IS NULL").expect("maxima");
    let overflow = body
        .find("stored.spool_revision = 18446744073709551615")
        .expect("overflow");
    let prefix_bounds = body
        .find("fsynced_prefix_bytes <= stored.partial_temp_bytes")
        .expect("prefix bounds");
    let clock = body.find("database_now :=").expect("clock");
    assert!(
        replay < maxima && maxima < overflow && overflow < prefix_bounds && prefix_bounds < clock
    );
    for required in [
        "chunk_index < stored.partial_temp_chunks",
        "chunk_index > stored.partial_temp_chunks",
        "fsynced_prefix_bytes <= stored.partial_temp_bytes",
        "fsynced_prefix_bytes >= stored.expected_size",
        "fsynced_prefix_bytes - stored.partial_temp_bytes > stored.max_chunk_bytes",
        "database_now >= stored.expires_at_unix_ms",
    ] {
        assert!(body.contains(required), "missing bound: {required}");
    }
}

#[test]
fn update_is_one_revisioned_row_and_does_not_touch_quota() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_upload_progress_v1(",
    );
    for assignment in [
        "partial_temp_bytes = fsynced_prefix_bytes",
        "partial_temp_chunks = next_chunks",
        "partial_temp_files = 1",
        "canonical_record_bytes = next_record.canonical_bytes",
        "record_blake3 = next_record.record_blake3",
        "spool_revision = next_revision",
    ] {
        assert!(
            body.contains(assignment),
            "missing atomic assignment: {assignment}"
        );
    }
    assert!(body.contains("AND spool.spool_revision = stored.spool_revision"));
    assert!(body.contains("affected_rows <> 1"));
    assert!(!body.contains("UPDATE object_store_retention.object_dispatch_quota_usage"));
}

#[test]
fn helpers_and_tables_are_revoked_and_artifact_is_source_dark() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC")
    );
    assert!(sql.contains("assert_dispatch_put_upload_progress_api_revision_v1("));
    assert!(sql.contains("project_dispatch_put_upload_progress_v1("));
    assert!(sql.contains("REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM"));
    let module = include_str!("../src/local_authority_put_upload_progress_mutation.rs");
    assert!(module.contains("include_bytes!(\"../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql\")"));
    assert!(
        include_str!("../src/lib.rs")
            .contains("pub mod local_authority_put_upload_progress_mutation;")
    );
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    // Narrowed by WP-114 CD-3, recorded in WP-114: `src/dispatch_client.rs` is the sanctioned
    // typed caller of this procedure and is the one file allowed to name it. Every other crate
    // source is still held to source-dark.
    let sanctioned = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("dispatch_client.rs");
    let mut sanctioned_seen = false;
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read production source");
        // The exemption is per-check, not per-file: the typed client may name the procedure, and
        // is still held to every other assertion in this loop. Skipping the whole body would have
        // let it embed the frozen migration bytes unnoticed.
        if path == sanctioned {
            sanctioned_seen = source.contains("object_store_dispatch_put_upload_progress_v1(");
        } else {
            assert!(
                !source.contains("object_store_dispatch_put_upload_progress_v1("),
                "runtime source {} calls source-dark mutation",
                path.display()
            );
        }
        if path.file_name().and_then(|name| name.to_str())
            != Some("local_authority_put_upload_progress_mutation.rs")
        {
            assert!(
                !source.contains("LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1"),
                "production source {} references migration bytes",
                path.display()
            );
        }
    }
    assert!(
        sanctioned_seen,
        "the typed client no longer calls this procedure; the exclusion above is now unearned"
    );
}

const RETENTION_DIGEST: &str = "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";
const AUTHORITY_DIGEST: &str = "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";
const PUT_SCHEMA_DIGEST: &str = "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67";
const BODY: [u8; 32] = [0x31; 32];
const BOUNDARY: [u8; 32] = [0x41; 32];
const OBSERVATION: [u8; 32] = [0x51; 32];
const FINGERPRINT: [u8; 32] = [0x61; 32];

fn uuid_v7(timestamp: u64, tail: &str) -> String {
    let prefix = format!("{timestamp:012x}");
    format!("{}-{}-7abc-8def-{tail}", &prefix[..8], &prefix[8..])
}

fn push_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}
fn complete(preimage: &[u8]) -> Vec<u8> {
    let mut value = preimage.to_vec();
    value.extend_from_slice(blake3::hash(preimage).as_bytes());
    value
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn quota_preimage(size: u64) -> Vec<u8> {
    let mut value = b"object-store-quota-units-v1\0".to_vec();
    for item in [size, 1, 1] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    value
}

fn ack_fixture(size: u64, max_chunk: u64) -> ReservePutAckV1 {
    ReservePutAckV1 {
        protocol_revision: "protocol-1".into(),
        policy_revision: "policy-1".into(),
        provider_boundary_id: "boundary-1".into(),
        authenticated_cell_id: "cell-1".into(),
        authenticated_tenant_id: "tenant-1".into(),
        logical_request_id: uuid_v7(1_000, "0123456789ab"),
        attempt_id: uuid_v7(1_001, "0223456789ab"),
        upload_id: uuid_v7(1_002, "0323456789ab"),
        upload_fence: 7,
        state: PutReservationStateV1::PutReservationStateReserved as i32,
        reserved_quota: Some(ObjectStoreQuotaUnitsV1 {
            bytes: size,
            rows: 1,
            concurrency: 1,
        }),
        expires_at_unix_ms: 3_000,
        max_chunk_bytes: max_chunk,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: 2_000,
        allocation_hard_expiry_unix_ms: 4_000,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    }
}

#[derive(Clone, Copy)]
struct Progress {
    size: u64,
    max_chunk: u64,
    bytes: u64,
    chunks: u64,
    files: u64,
    revision: u64,
}

fn row_preimage(ack: &[u8], ack_digest: &[u8], progress: Progress) -> Vec<u8> {
    let mut value = b"object-store-dispatch-put-reservation-row-v1\0".to_vec();
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
        push_text(&mut value, text);
    }
    value.extend_from_slice(&7_u64.to_be_bytes());
    value.extend_from_slice(&[1, 1, 1, 1]);
    value.extend_from_slice(&BOUNDARY);
    push_text(&mut value, "boundary-token");
    value.extend_from_slice(&OBSERVATION);
    value.extend_from_slice(&progress.size.to_be_bytes());
    value.extend_from_slice(&BODY);
    for item in [progress.bytes, progress.chunks, progress.files] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    push_bytes(&mut value, &complete(&quota_preimage(progress.size)));
    value.extend_from_slice(&1_u64.to_be_bytes());
    value.extend_from_slice(&3_000_u64.to_be_bytes());
    value.extend_from_slice(&FINGERPRINT);
    push_text(&mut value, "allocation-1");
    for item in [5_u64, 3_000, 4_000, 2_000, 1_000, progress.max_chunk] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    push_bytes(&mut value, ack);
    value.extend_from_slice(ack_digest);
    value.extend_from_slice(&progress.revision.to_be_bytes());
    value.extend_from_slice(&2_000_u64.to_be_bytes());
    value
}

fn provider(vectors: &[(&[u8], &[u8])]) -> String {
    let cases = vectors
        .iter()
        .map(|(preimage, digest)| {
            format!(
                "WHEN '{}' THEN pg_catalog.decode('{}','hex')",
                hex(preimage),
                hex(digest)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "CREATE FUNCTION public.blake3(payload bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT
             AS $$ SELECT CASE pg_catalog.encode(payload,'hex') {cases} ELSE NULL::bytea END $$;"
    )
}

fn reserve_sql(size: u64, max_chunk: u64) -> String {
    format!("SELECT (object_store_retention.object_store_dispatch_reserve_put_v1(
      'object-store-dispatch-reserve-put-v1','protocol-1','policy-1','boundary-1','cell-1','tenant-1',
      '{}','{}','{}','{}',7,decode('{}','hex'),'boundary-token',decode('{}','hex'),{size},
      decode('{}','hex'),decode('{}','hex'),'allocation-1',5,3000,4000,1000,{max_chunk},1,
      18446744073709551615,10,10,0,0,0,18446744073709551615,10,10,0,0,0,
      18446744073709551615,10,10,0,0,0,256,256,16777216)).*",
      uuid_v7(1_003,"0423456789ab"), uuid_v7(1_000,"0123456789ab"),
      uuid_v7(1_001,"0223456789ab"), uuid_v7(1_002,"0323456789ab"),
      hex(&BOUNDARY), hex(&OBSERVATION), hex(&BODY), hex(&FINGERPRINT))
}

fn progress_sql(
    protocol: &str,
    logical: &str,
    attempt: &str,
    chunk: u64,
    prefix: u64,
    caps: (i32, i32, i32),
    api: &str,
) -> String {
    format!(
        "SELECT (object_store_retention.object_store_dispatch_put_upload_progress_v1(
      '{api}','{protocol}','boundary-1','cell-1','tenant-1','{logical}','{attempt}','{}',7,
      {chunk},{prefix},{},{},{})).*",
        uuid_v7(1_002, "0323456789ab"),
        caps.0,
        caps.1,
        caps.2
    )
}

async fn set_user(client: &tokio_postgres::Client, role: &str) {
    client
        .batch_execute(&format!("SET SESSION AUTHORIZATION {role};"))
        .await
        .unwrap_or_else(|error| panic!("set {role}: {error}"));
}
async fn reset_user(client: &tokio_postgres::Client) {
    client
        .batch_execute("RESET SESSION AUTHORIZATION;")
        .await
        .expect("reset user");
}
async fn serial_call(
    client: &tokio_postgres::Client,
    sql: &str,
) -> Result<tokio_postgres::Row, tokio_postgres::Error> {
    client
        .batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;")
        .await?;
    let result = client.query_one(sql, &[]).await;
    client
        .batch_execute(if result.is_ok() {
            "COMMIT;"
        } else {
            "ROLLBACK;"
        })
        .await?;
    result
}
async fn install_as_migrator(client: &tokio_postgres::Client, sql: &str) -> String {
    set_user(client, "object_dispatch_retention_migrator").await;
    let value = serial_call(client, sql).await.expect("install").get(0);
    reset_user(client).await;
    value
}

fn db_message(error: &tokio_postgres::Error) -> &str {
    error
        .as_db_error()
        .map(|db| db.message())
        .unwrap_or("untyped")
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_progress_mutation_is_atomic_and_replay_safe() {
    let url = std::env::var("LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_MUTATION_PG_URL")
        .expect("LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_MUTATION_PG_URL must name a fresh database");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect progress mutation database");
    let _connection = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "put-upload-progress-mutation-postgres",
        async move {
            let _ = connection.await;
        }
    ));
    client.batch_execute("DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime NOLOGIN; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance NOLOGIN; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator NOLOGIN; END IF;
      END $$; GRANT object_dispatch_retention_owner TO CURRENT_USER;
      DO $$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO object_dispatch_retention_owner',current_database()); END $$;")
        .await.expect("bootstrap roles");
    for sql in [
        include_str!("../migrations/0002_object_store_retention_authority.sql"),
        include_str!("../migrations/0003_object_store_retention_provisioning.sql"),
        include_str!("../migrations/0007_object_store_dispatch_authority_core.sql"),
        include_str!("../migrations/0008_object_store_dispatch_authority_provisioning.sql"),
    ] {
        client
            .batch_execute(sql)
            .await
            .expect("apply base migration");
    }
    assert_eq!(install_as_migrator(&client, &format!("SELECT (object_store_retention.object_store_retention_install_v1(
      'object-store-retention-provisioning-v1','object-store-retention-authority-schema-v1',decode('{RETENTION_DIGEST}','hex'),1)).result_code")).await,"CREATED");
    assert_eq!(install_as_migrator(&client, &format!("SELECT (object_store_retention.object_store_dispatch_authority_install_v1(
      'object-store-dispatch-authority-provisioning-v1','object-store-dispatch-authority-schema-v1',decode('{AUTHORITY_DIGEST}','hex'),1)).result_code")).await,"CREATED");
    for sql in [
        include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql"),
        include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql"),
        include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql"),
    ] {
        client
            .batch_execute(sql)
            .await
            .expect("apply PUT schema migration");
    }
    assert_eq!(install_as_migrator(&client, &format!("SELECT (object_store_retention.object_store_dispatch_put_reservation_install_v1(
      'object-store-dispatch-put-reservation-provisioning-v1','object-store-dispatch-put-reservation-schema-v1',decode('{PUT_SCHEMA_DIGEST}','hex'),1)).result_code")).await,"CREATED");
    for sql in [
        include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"),
        include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql"),
        include_str!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql"),
        include_str!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql"),
    ] {
        client
            .batch_execute(sql)
            .await
            .expect("apply mutation chain");
    }
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint';",
        )
        .await
        .expect("freeze clock");

    let limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 1,
        max_canonical_row_bytes: 16_777_216,
    };
    let ack = validate_and_encode_object_store_reserve_put_ack(&ack_fixture(10, 4), &limits)
        .expect("ACK");
    let zero_ack = validate_and_encode_object_store_reserve_put_ack(&ack_fixture(0, 4), &limits)
        .expect("zero ACK");
    let max_ack =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture(u64::MAX, 1), &limits)
            .expect("max ACK");
    let initial = Progress {
        size: 10,
        max_chunk: 4,
        bytes: 0,
        chunks: 0,
        files: 0,
        revision: 1,
    };
    let first = Progress {
        bytes: 4,
        chunks: 1,
        files: 1,
        revision: 2,
        ..initial
    };
    let second = Progress {
        bytes: 8,
        chunks: 2,
        files: 1,
        revision: 3,
        ..initial
    };
    let zero = Progress {
        size: 0,
        max_chunk: 4,
        bytes: 0,
        chunks: 0,
        files: 0,
        revision: 1,
    };
    let initial_preimage = row_preimage(ack.canonical_bytes(), ack.ack_blake3(), initial);
    let first_preimage = row_preimage(ack.canonical_bytes(), ack.ack_blake3(), first);
    let second_preimage = row_preimage(ack.canonical_bytes(), ack.ack_blake3(), second);
    let zero_preimage = row_preimage(zero_ack.canonical_bytes(), zero_ack.ack_blake3(), zero);
    let vectors = [
        quota_preimage(10),
        quota_preimage(0),
        quota_preimage(u64::MAX),
    ];
    let digests = vectors
        .each_ref()
        .map(|value| *blake3::hash(value).as_bytes());
    let rows = [
        &initial_preimage,
        &first_preimage,
        &second_preimage,
        &zero_preimage,
    ];
    let row_digests = rows.map(|value| *blake3::hash(value).as_bytes());
    let provider_sql = provider(&[
        (&vectors[0], &digests[0]),
        (&vectors[1], &digests[1]),
        (&vectors[2], &digests[2]),
        (ack.canonical_preimage(), ack.ack_blake3()),
        (zero_ack.canonical_preimage(), zero_ack.ack_blake3()),
        (max_ack.canonical_preimage(), max_ack.ack_blake3()),
        (&initial_preimage, &row_digests[0]),
        (&first_preimage, &row_digests[1]),
        (&second_preimage, &row_digests[2]),
        (&zero_preimage, &row_digests[3]),
    ]);
    client
        .batch_execute(&provider_sql)
        .await
        .expect("install genuine BLAKE3 lookup");

    set_user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        serial_call(&client, &reserve_sql(10, 4))
            .await
            .expect("reserve")
            .get::<_, String>(0),
        "CREATED"
    );
    reset_user(&client).await;
    let (peer, peer_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("peer");
    let _peer_connection =
        AbortOnDropHandle::new(lore_base::lore_spawn!("progress-peer", async move {
            let _ = peer_connection.await;
        }));
    set_user(&client, "object_dispatch_retention_runtime").await;
    set_user(&peer, "object_dispatch_retention_runtime").await;
    let logical = uuid_v7(1_000, "0123456789ab");
    let attempt = uuid_v7(1_001, "0223456789ab");
    let first_sql = progress_sql(
        "protocol-1",
        &logical,
        &attempt,
        0,
        4,
        (256, 256, 16_777_216),
        "object-store-dispatch-put-upload-progress-v1",
    );
    let (left, right) = tokio::join!(
        serial_call(&client, &first_sql),
        serial_call(&peer, &first_sql)
    );
    let loser = match (left, right) {
        (Ok(applied), Err(loser)) => {
            assert_eq!(applied.get::<_, String>(0), "APPLIED");
            (loser, &peer)
        }
        (Err(loser), Ok(applied)) => {
            assert_eq!(applied.get::<_, String>(0), "APPLIED");
            (loser, &client)
        }
        (left, right) => panic!("race must yield APPLIED/40001, got {left:?}/{right:?}"),
    };
    assert_eq!(
        loser
            .0
            .as_db_error()
            .expect("typed race loser")
            .code()
            .code(),
        "40001"
    );
    assert_eq!(
        serial_call(loser.1, &first_sql)
            .await
            .expect("exact race retry")
            .get::<_, String>(0),
        "REPLAY"
    );
    reset_user(&peer).await;
    reset_user(&client).await;
    let stored_first=client.query_one("SELECT partial_temp_bytes::numeric::text,partial_temp_chunks::numeric::text,
      partial_temp_files::numeric::text,spool_revision::numeric::text,canonical_record_bytes,record_blake3,
      reserve_put_ack_canonical_bytes,reserve_put_ack_blake3 FROM object_store_retention.object_dispatch_spool_objects",&[])
      .await.expect("first row");
    assert_eq!(
        (
            stored_first.get::<_, String>(0),
            stored_first.get::<_, String>(1),
            stored_first.get::<_, String>(2),
            stored_first.get::<_, String>(3)
        ),
        ("4".into(), "1".into(), "1".into(), "2".into())
    );
    assert_eq!(stored_first.get::<_, Vec<u8>>(4), complete(&first_preimage));
    assert_eq!(stored_first.get::<_, Vec<u8>>(5), row_digests[1]);
    assert_eq!(stored_first.get::<_, Vec<u8>>(6), ack.canonical_bytes());

    set_user(&client, "object_dispatch_retention_runtime").await;
    for (label, sql, expected) in [
        (
            "identity",
            progress_sql(
                "protocol-2",
                &logical,
                &attempt,
                1,
                8,
                (256, 256, 16_777_216),
                "object-store-dispatch-put-upload-progress-v1",
            ),
            "UPLOAD_STREAM_IDENTITY_MISMATCH",
        ),
        (
            "missing",
            progress_sql(
                "protocol-1",
                &uuid_v7(1_100, "1123456789ab"),
                &attempt,
                1,
                8,
                (256, 256, 16_777_216),
                "object-store-dispatch-put-upload-progress-v1",
            ),
            "EXPIRED_OR_UNKNOWN",
        ),
        (
            "old changed",
            progress_sql(
                "protocol-1",
                &logical,
                &attempt,
                0,
                3,
                (256, 256, 16_777_216),
                "object-store-dispatch-put-upload-progress-v1",
            ),
            "DISPATCH_PUT_UPLOAD_PROGRESS_REPLAY_CONFLICT",
        ),
        (
            "gap",
            progress_sql(
                "protocol-1",
                &logical,
                &attempt,
                2,
                8,
                (256, 256, 16_777_216),
                "object-store-dispatch-put-upload-progress-v1",
            ),
            "DISPATCH_PUT_UPLOAD_CHUNK_GAP",
        ),
        (
            "nonadvance",
            progress_sql(
                "protocol-1",
                &logical,
                &attempt,
                1,
                4,
                (256, 256, 16_777_216),
                "object-store-dispatch-put-upload-progress-v1",
            ),
            "DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT",
        ),
        (
            "full",
            progress_sql(
                "protocol-1",
                &logical,
                &attempt,
                1,
                10,
                (256, 256, 16_777_216),
                "object-store-dispatch-put-upload-progress-v1",
            ),
            "DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT",
        ),
        (
            "oversize",
            progress_sql(
                "protocol-1",
                &logical,
                &attempt,
                1,
                9,
                (256, 256, 16_777_216),
                "object-store-dispatch-put-upload-progress-v1",
            ),
            "DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT",
        ),
    ] {
        let error = serial_call(&client, &sql).await.unwrap_err();
        assert_eq!(db_message(&error), expected, "{label}");
    }
    let second_result = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            1,
            8,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .expect("second chunk");
    assert_eq!(second_result.get::<_, String>(0), "APPLIED");
    let last_replay = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            1,
            8,
            (1, 1, 1),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .expect("exact replay ignores maxima");
    assert_eq!(last_replay.get::<_, String>(0), "REPLAY");
    reset_user(&client).await;

    let quota_before=client.query_one("SELECT sum(used_bytes)::numeric::text,sum(used_rows)::numeric::text,
      sum(used_concurrency)::numeric::text,sum(counter_revision)::numeric::text FROM object_store_retention.object_dispatch_quota_usage",&[])
      .await.expect("quota before");
    let second_row=client.query_one("SELECT canonical_record_bytes,record_blake3,spool_revision::numeric::text FROM object_store_retention.object_dispatch_spool_objects",&[])
      .await.expect("second row");
    assert_eq!(second_row.get::<_, Vec<u8>>(0), complete(&second_preimage));
    assert_eq!(second_row.get::<_, Vec<u8>>(1), row_digests[2]);
    assert_eq!(second_row.get::<_, String>(2), "3");

    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 3000::bigint';",
        )
        .await
        .expect("clock at expiry");
    set_user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        serial_call(
            &client,
            &progress_sql(
                "protocol-1",
                &logical,
                &attempt,
                1,
                8,
                (1, 1, 1),
                "object-store-dispatch-put-upload-progress-v1"
            )
        )
        .await
        .expect("lost response after expiry")
        .get::<_, String>(0),
        "REPLAY"
    );
    let closed = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            2,
            9,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(db_message(&closed), "UPLOAD_CLOSED");
    reset_user(&client).await;
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint';",
        )
        .await
        .expect("restore clock");

    set_user(&client, "object_dispatch_retention_runtime").await;
    let bad_cap = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            2,
            9,
            (1025, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        db_message(&bad_cap),
        "DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT"
    );
    reset_user(&client).await;
    client
        .batch_execute(&provider_sql.replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
        .await
        .expect("ensure provider restored");
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea
      LANGUAGE sql IMMUTABLE STRICT AS 'SELECT NULL::bytea';",
        )
        .await
        .expect("break provider");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let provider_error = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            2,
            9,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        db_message(&provider_error),
        "LOCAL_BLAKE3_PROVIDER_INVALID_RESULT"
    );
    reset_user(&client).await;
    client
        .batch_execute(&provider_sql.replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
        .await
        .expect("restore provider");
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_retention_schema_state
      SET put_reservation_migration_blake3=decode(repeat('00',32),'hex') WHERE singleton",
            &[],
        )
        .await
        .expect("drift schema");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let schema_error = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            2,
            9,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        db_message(&schema_error),
        "DISPATCH_PUT_UPLOAD_PROGRESS_SCHEMA_UNAVAILABLE"
    );
    reset_user(&client).await;
    client.execute("UPDATE object_store_retention.object_dispatch_retention_schema_state
      SET put_reservation_migration_blake3=decode('56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67','hex') WHERE singleton",&[])
      .await.expect("restore schema");
    let unchanged=client.query_one("SELECT canonical_record_bytes,record_blake3,spool_revision::numeric::text,
      (SELECT sum(used_bytes)::numeric::text FROM object_store_retention.object_dispatch_quota_usage),
      (SELECT sum(used_rows)::numeric::text FROM object_store_retention.object_dispatch_quota_usage),
      (SELECT sum(used_concurrency)::numeric::text FROM object_store_retention.object_dispatch_quota_usage),
      (SELECT sum(counter_revision)::numeric::text FROM object_store_retention.object_dispatch_quota_usage)
      FROM object_store_retention.object_dispatch_spool_objects",&[]).await.expect("rollback state");
    assert_eq!(
        unchanged.get::<_, Vec<u8>>(0),
        second_row.get::<_, Vec<u8>>(0)
    );
    assert_eq!(
        unchanged.get::<_, Vec<u8>>(1),
        second_row.get::<_, Vec<u8>>(1)
    );
    assert_eq!(unchanged.get::<_, String>(2), "3");
    for index in 3..7 {
        assert_eq!(
            unchanged.get::<_, String>(index),
            quota_before.get::<_, String>(index - 3)
        );
    }

    let valid_canonical = unchanged.get::<_, Vec<u8>>(0);
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_spool_objects
                SET canonical_record_bytes=pg_catalog.set_byte(
                  canonical_record_bytes,0,(pg_catalog.get_byte(canonical_record_bytes,0)+1)%256)",
            &[],
        )
        .await
        .expect("install schema-valid canonical tamper");
    let tampered_row_before = client
        .query_one(
            "SELECT pg_catalog.row_to_json(spool)::text
               FROM object_store_retention.object_dispatch_spool_objects AS spool",
            &[],
        )
        .await
        .expect("snapshot tampered row")
        .get::<_, String>(0);
    let tampered_quota_before = client
        .query_one(
            "SELECT pg_catalog.json_agg(quota ORDER BY quota.scope_kind)::text
               FROM object_store_retention.object_dispatch_quota_usage AS quota",
            &[],
        )
        .await
        .expect("snapshot tampered quota")
        .get::<_, String>(0);
    set_user(&client, "object_dispatch_retention_runtime").await;
    let record_tamper_error = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            2,
            9,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        db_message(&record_tamper_error),
        "DISPATCH_RESERVED_PUT_STORED_RECORD_MISMATCH"
    );
    reset_user(&client).await;
    assert_eq!(
        client.query_one("SELECT pg_catalog.row_to_json(spool)::text FROM object_store_retention.object_dispatch_spool_objects AS spool", &[])
          .await.expect("read unchanged tampered row").get::<_,String>(0), tampered_row_before
    );
    assert_eq!(
        client.query_one("SELECT pg_catalog.json_agg(quota ORDER BY quota.scope_kind)::text FROM object_store_retention.object_dispatch_quota_usage AS quota", &[])
          .await.expect("read unchanged tampered quota").get::<_,String>(0), tampered_quota_before
    );
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_spool_objects
                SET canonical_record_bytes=$1::bytea",
            &[&valid_canonical],
        )
        .await
        .expect("restore canonical record");

    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_spool_objects SET
               lifecycle_state=2, committed_size=expected_size,
               committed_blake3=expected_blake3, durable_handle=decode('01','hex'),
               ready_at_unix_ms=created_at_unix_ms, partial_temp_files=0",
            &[],
        )
        .await
        .expect("install schema-valid incompatible lifecycle");
    let lifecycle_row_before = client
        .query_one(
            "SELECT pg_catalog.row_to_json(spool)::text
               FROM object_store_retention.object_dispatch_spool_objects AS spool",
            &[],
        )
        .await
        .expect("snapshot lifecycle row")
        .get::<_, String>(0);
    let lifecycle_quota_before = client
        .query_one(
            "SELECT pg_catalog.json_agg(quota ORDER BY quota.scope_kind)::text
               FROM object_store_retention.object_dispatch_quota_usage AS quota",
            &[],
        )
        .await
        .expect("snapshot lifecycle quota")
        .get::<_, String>(0);
    set_user(&client, "object_dispatch_retention_runtime").await;
    let lifecycle_error = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            2,
            9,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        db_message(&lifecycle_error),
        "DISPATCH_RESERVED_PUT_STORED_STATE_INVALID"
    );
    reset_user(&client).await;
    assert_eq!(
        client.query_one("SELECT pg_catalog.row_to_json(spool)::text FROM object_store_retention.object_dispatch_spool_objects AS spool", &[])
          .await.expect("read unchanged lifecycle row").get::<_,String>(0), lifecycle_row_before
    );
    assert_eq!(
        client.query_one("SELECT pg_catalog.json_agg(quota ORDER BY quota.scope_kind)::text FROM object_store_retention.object_dispatch_quota_usage AS quota", &[])
          .await.expect("read unchanged lifecycle quota").get::<_,String>(0), lifecycle_quota_before
    );
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_spool_objects SET
               lifecycle_state=1, committed_size=NULL, committed_blake3=NULL,
               durable_handle=NULL, ready_at_unix_ms=NULL, partial_temp_files=1",
            &[],
        )
        .await
        .expect("restore RESERVED lifecycle");

    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET
      expected_size=0,quota_bytes=0,max_chunk_bytes=4,partial_temp_bytes=0,partial_temp_chunks=0,
      partial_temp_files=0,reserve_put_ack_canonical_bytes=$1::bytea,reserve_put_ack_blake3=$2::bytea,
      canonical_record_bytes=$3::bytea,record_blake3=$4::bytea,spool_revision=1",
      &[&zero_ack.canonical_bytes(),&&zero_ack.ack_blake3()[..],&complete(&zero_preimage),&&row_digests[3][..]])
      .await.expect("install valid zero-body reservation");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let zero_error = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            0,
            1,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        db_message(&zero_error),
        "DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT"
    );
    reset_user(&client).await;

    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET
      expected_size=18446744073709551615,quota_bytes=18446744073709551615,max_chunk_bytes=1,
      partial_temp_bytes=18446744073709551614,partial_temp_chunks=18446744073709551614,partial_temp_files=1,
      spool_revision=18446744073709551615",
      &[])
      .await.expect("prepare near-u64 fields");
    client
        .batch_execute(
            &provider_sql
                .replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
                .replacen(
                    "ELSE NULL::bytea",
                    "ELSE pg_catalog.decode(pg_catalog.repeat('00',32),'hex')",
                    1,
                ),
        )
        .await
        .expect("install mechanics-only near-u64 preimage provider");
    set_user(&client, "object_dispatch_retention_owner").await;
    let mechanics_quota = client
        .query_one(
            "SELECT object_store_retention.local_quota_child_v1(
      18446744073709551615,1,1,16777216)",
            &[],
        )
        .await
        .expect("derive mechanics-only near-u64 quota preimage");
    reset_user(&client).await;
    let mechanics_quota_bytes = mechanics_quota.get::<_, Vec<u8>>(0);
    let actual_quota_preimage = &mechanics_quota_bytes[..mechanics_quota_bytes.len() - 32];
    let actual_quota_digest = *blake3::hash(actual_quota_preimage).as_bytes();
    let quota_case = format!(
        "WHEN '{}' THEN pg_catalog.decode('{}','hex') ",
        hex(actual_quota_preimage),
        hex(&actual_quota_digest)
    );
    let mechanics_with_quota = provider_sql
        .replacen(
            "ELSE NULL::bytea",
            &format!("{quota_case}ELSE pg_catalog.decode(pg_catalog.repeat('00',32),'hex')"),
            1,
        )
        .replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1);
    client
        .batch_execute(&mechanics_with_quota)
        .await
        .expect("install genuine near-u64 quota mapping");
    set_user(&client, "object_dispatch_retention_owner").await;
    let mechanics_ack = client
        .query_one(
            "SELECT (object_store_retention.local_reserve_put_ack_v1(
      s.protocol_revision,s.policy_revision,s.provider_boundary_id,s.authenticated_cell_id,
      s.authenticated_tenant_id,s.logical_request_id,s.attempt_id,s.upload_id,s.upload_fence,
      1::smallint,s.quota_bytes,s.quota_rows,s.quota_concurrency,s.expires_at_unix_ms,
      s.max_chunk_bytes,NULL,NULL,NULL,NULL,s.admission_clock_unix_ms,
      s.allocation_hard_expiry_unix_ms,1024,1,16777216)).*
      FROM object_store_retention.object_dispatch_spool_objects s",
            &[],
        )
        .await
        .expect("derive mechanics-only near-u64 ACK preimage");
    reset_user(&client).await;
    let mechanics_ack_bytes = mechanics_ack.get::<_, Vec<u8>>(0);
    let actual_ack_preimage = &mechanics_ack_bytes[..mechanics_ack_bytes.len() - 32];
    let actual_ack_digest = *blake3::hash(actual_ack_preimage).as_bytes();
    let ack_case = format!(
        "WHEN '{}' THEN pg_catalog.decode('{}','hex') ",
        hex(actual_ack_preimage),
        hex(&actual_ack_digest)
    );
    let mechanics_with_ack = provider_sql
        .replacen(
            "ELSE NULL::bytea",
            &format!(
                "{quota_case}{ack_case}ELSE pg_catalog.decode(pg_catalog.repeat('00',32),'hex')"
            ),
            1,
        )
        .replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1);
    client
        .batch_execute(&mechanics_with_ack)
        .await
        .expect("install genuine near-u64 ACK mapping");
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_spool_objects SET
      reserve_put_ack_canonical_bytes=$1::bytea,reserve_put_ack_blake3=$2::bytea",
            &[&complete(actual_ack_preimage), &&actual_ack_digest[..]],
        )
        .await
        .expect("install near-u64 ACK");
    set_user(&client, "object_dispatch_retention_owner").await;
    let mechanics=client.query_one("SELECT (object_store_retention.local_put_reserved_record_v2(
      s.protocol_revision,s.policy_revision,s.provider_boundary_id,s.authenticated_cell_id,
      s.authenticated_tenant_id,s.spool_object_id,s.logical_request_id,s.attempt_id,s.upload_id,
      s.upload_fence,s.boundary_blake3,s.boundary_token,s.observation_binding_blake3,s.expected_size,
      s.expected_blake3,s.partial_temp_bytes,s.partial_temp_chunks,s.partial_temp_files,
      s.put_reservation_fingerprint,s.allocation_revision,s.allocation_fence,
      s.reservation_deadline_unix_ms,s.allocation_hard_expiry_unix_ms,s.admission_clock_unix_ms,
      s.prepared_ttl_ms,s.expires_at_unix_ms,s.max_chunk_bytes,s.quota_bytes,s.quota_rows,
      s.quota_concurrency,s.quota_revision,s.reserve_put_ack_canonical_bytes,
      s.reserve_put_ack_blake3,s.spool_revision,1024,4096,16777216)).*
      FROM object_store_retention.object_dispatch_spool_objects s",&[]).await
      .expect("derive mechanics-only near-u64 preimage");
    reset_user(&client).await;
    let mechanics_bytes = mechanics.get::<_, Vec<u8>>(0);
    let actual_near_preimage = &mechanics_bytes[..mechanics_bytes.len() - 32];
    let actual_near_digest = *blake3::hash(actual_near_preimage).as_bytes();
    let near_case = format!(
        "WHEN '{}' THEN pg_catalog.decode('{}','hex') ",
        hex(actual_near_preimage),
        hex(&actual_near_digest)
    );
    let extended_provider = provider_sql
        .replacen(
            "ELSE NULL::bytea",
            &format!("{quota_case}{ack_case}{near_case}ELSE NULL::bytea"),
            1,
        )
        .replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1);
    client
        .batch_execute(&extended_provider)
        .await
        .expect("install genuine near-u64 digest mapping");
    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_spool_objects SET
      canonical_record_bytes=$1::bytea,record_blake3=$2::bytea",
            &[&complete(actual_near_preimage), &&actual_near_digest[..]],
        )
        .await
        .expect("install valid near-u64 record");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let overflow = serial_call(
        &client,
        &progress_sql(
            "protocol-1",
            &logical,
            &attempt,
            u64::MAX - 1,
            u64::MAX,
            (256, 256, 16_777_216),
            "object-store-dispatch-put-upload-progress-v1",
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        db_message(&overflow),
        "DISPATCH_PUT_UPLOAD_PROGRESS_COUNTER_OVERFLOW"
    );
    reset_user(&client).await;

    let helper_calls = [
        "SELECT object_store_retention.assert_dispatch_put_upload_progress_api_revision_v1('object-store-dispatch-put-upload-progress-v1')",
        "SELECT object_store_retention.project_dispatch_put_upload_progress_v1(NULL::object_store_retention.object_dispatch_spool_objects,'REPLAY')",
    ];
    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        set_user(&client, role).await;
        for sql in [
            helper_calls[0],
            helper_calls[1],
            "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
            "UPDATE object_store_retention.object_dispatch_spool_objects SET spool_revision=spool_revision WHERE false",
        ] {
            let error = client.batch_execute(sql).await.unwrap_err();
            assert_eq!(
                error.as_db_error().expect("typed ACL").code().code(),
                "42501",
                "{role}: {sql}"
            );
        }
        if role != "object_dispatch_retention_runtime" {
            let error = serial_call(
                &client,
                &progress_sql(
                    "protocol-1",
                    &logical,
                    &attempt,
                    u64::MAX - 1,
                    u64::MAX,
                    (256, 256, 16_777_216),
                    "object-store-dispatch-put-upload-progress-v1",
                ),
            )
            .await
            .unwrap_err();
            assert_eq!(
                error.as_db_error().expect("typed main ACL").code().code(),
                "42501"
            );
        }
        reset_user(&client).await;
    }
}

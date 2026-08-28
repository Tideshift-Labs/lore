// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract and opt-in PostgreSQL 16 vectors for the source-dark PUT progress codec.
//! This tier proves canonical snapshot algebra, not transition monotonicity or an actual fsync.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::local_authority_put_upload_progress_codec::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_put_upload_progress_codec::LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1;
use lore_object_dispatch::local_authority_put_upload_progress_codec::validate_embedded_local_authority_put_upload_progress_codec_migration_v1;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 17_444;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "f5361aa66c3e1bdced683040e3a405557a8d2d07f85a182e8e33867e208631a0";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1)
        .expect("upload-progress migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, signature: &str) -> &'a str {
    let start = sql
        .find(signature)
        .unwrap_or_else(|| panic!("missing function: {signature}"));
    let body_start = sql[start..]
        .find("AS $$")
        .map(|offset| start + offset)
        .expect("function body");
    let body_end = sql[body_start + 5..]
        .find("\n$$;")
        .map(|offset| body_start + 5 + offset)
        .expect("function body terminator");
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
        LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_put_upload_progress_codec_migration_v1());
}

#[test]
fn migration_replaces_only_owner_codec_and_projection_surfaces() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n"));
    assert!(sql.ends_with("\nCOMMIT;\n"));
    assert_eq!(sql.matches("\nBEGIN;\n").count(), 1);
    assert_eq!(sql.matches("\nCOMMIT;\n").count(), 1);
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 1);
    assert_eq!(sql.matches("CREATE OR REPLACE FUNCTION ").count(), 2);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 3);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 3);
    for forbidden in [
        "CREATE TABLE",
        "ALTER TABLE",
        "CREATE PROCEDURE",
        "GRANT EXECUTE",
        "GRANT SELECT",
        "GRANT INSERT",
        "GRANT UPDATE",
    ] {
        assert!(!sql.contains(forbidden), "unexpected surface: {forbidden}");
    }
}

#[test]
fn pristine_wrapper_is_exact_0012_shape() {
    let body = function_body(
        migration(),
        "CREATE OR REPLACE FUNCTION object_store_retention.local_put_reservation_record_v1(",
    );
    assert!(body.contains("SELECT object_store_retention.local_put_reserved_record_v2("));
    assert!(body.contains("expected_size, expected_blake3, 0, 0, 0, put_reservation_fingerprint"));
    assert!(body.contains("reserve_put_ack_blake3,\n    spool_revision"));
}

#[test]
fn progress_is_strictly_nonfinal_and_revision_tracks_chunks() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_put_reserved_record_v2(",
    );
    for required in [
        "partial_temp_bytes = 0 AND partial_temp_chunks = 0\n         AND partial_temp_files = 0 AND spool_revision = 1",
        "expected_size > 0 AND partial_temp_bytes > 0",
        "partial_temp_bytes < expected_size",
        "partial_temp_chunks > 0",
        "partial_temp_chunks < 18446744073709551615",
        "partial_temp_files = 1",
        "partial_temp_chunks <= partial_temp_bytes",
        "partial_temp_bytes <= partial_temp_chunks * max_chunk_bytes",
        "spool_revision = partial_temp_chunks + 1",
    ] {
        assert!(
            body.contains(required),
            "missing progress invariant: {required}"
        );
    }
}

#[test]
fn ack_is_recomputed_reserved_and_record_binds_progress() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_put_reserved_record_v2(",
    );
    assert!(body.contains("expected_ack := object_store_retention.local_reserve_put_ack_v1("));
    assert!(body.contains("upload_id, upload_fence,\n    1::smallint"));
    assert!(body.contains("LOCAL_PUT_RESERVATION_ACK_MISMATCH"));
    for field in [
        "local_canonical_u64_v1(partial_temp_bytes)",
        "local_canonical_u64_v1(partial_temp_chunks)",
        "local_canonical_u64_v1(partial_temp_files)",
        "local_canonical_u64_v1(spool_revision)",
    ] {
        assert!(body.contains(field), "record does not bind {field}");
    }
    assert!(body.contains("object-store-dispatch-put-reservation-row-v1"));
}

#[test]
fn replay_projection_accepts_progress_but_returns_stored_ack() {
    let body = function_body(
        migration(),
        "CREATE OR REPLACE FUNCTION object_store_retention.project_dispatch_reserved_put_v1(",
    );
    assert!(body.contains("local_put_reserved_record_v2("));
    assert!(body.contains("stored.partial_temp_bytes"));
    assert!(body.contains("stored.partial_temp_chunks"));
    assert!(body.contains("stored.partial_temp_files"));
    assert!(body.contains("stored.spool_revision"));
    assert!(body.contains("stored.reserve_put_ack_canonical_bytes"));
    assert!(body.contains("stored.reserve_put_ack_blake3"));
}

#[test]
fn helpers_are_owner_only_and_tables_are_re_revoked() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC")
    );
    assert!(
        sql.contains("REVOKE ALL ON FUNCTION object_store_retention.local_put_reserved_record_v2(")
    );
    assert!(sql.contains(
        "REVOKE ALL ON FUNCTION object_store_retention.local_put_reservation_record_v1("
    ));
    assert!(sql.contains(
        "REVOKE ALL ON FUNCTION object_store_retention.project_dispatch_reserved_put_v1("
    ));
    assert!(sql.contains("object_dispatch_retention_runtime,\n  object_dispatch_retention_maintenance,\n  object_dispatch_retention_migrator"));
    assert!(sql.contains("REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM"));
    assert_eq!(sql.matches("GRANT ").count(), 0);
}

#[test]
fn artifact_is_embedded_only_and_runtime_source_dark() {
    let module = include_str!("../src/local_authority_put_upload_progress_codec.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql\")"
    ));
    assert!(library.contains("pub mod local_authority_put_upload_progress_codec;"));
    for forbidden in ["tokio_postgres", "batch_execute", ".execute(", ".await"] {
        assert!(!module.contains(forbidden));
    }
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read production source");
        assert!(
            !source.contains("local_put_reserved_record_v2("),
            "runtime source {} calls source-dark codec",
            path.display()
        );
        if path.file_name().and_then(|name| name.to_str())
            != Some("local_authority_put_upload_progress_codec.rs")
        {
            assert!(
                !source.contains("LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1"),
                "production source {} references source-dark migration bytes",
                path.display()
            );
        }
    }
}

const RETENTION_DIGEST: &str = "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";
const AUTHORITY_DIGEST: &str = "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";
const PUT_SCHEMA_DIGEST: &str = "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67";
const BODY_SIZE: u64 = 10;
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

fn quota_preimage() -> Vec<u8> {
    let mut value = b"object-store-quota-units-v1\0".to_vec();
    for item in [BODY_SIZE, 1, 1] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    value
}

fn ack_fixture() -> ReservePutAckV1 {
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
            bytes: BODY_SIZE,
            rows: 1,
            concurrency: 1,
        }),
        expires_at_unix_ms: 3_000,
        max_chunk_bytes: 4,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: 2_000,
        allocation_hard_expiry_unix_ms: 4_000,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    }
}

fn row_preimage(
    ack: &[u8],
    ack_digest: &[u8],
    bytes: u64,
    chunks: u64,
    files: u64,
    revision: u64,
) -> Vec<u8> {
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
    value.extend_from_slice(&BODY_SIZE.to_be_bytes());
    value.extend_from_slice(&BODY);
    for item in [bytes, chunks, files] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    push_bytes(&mut value, &complete(&quota_preimage()));
    value.extend_from_slice(&1_u64.to_be_bytes());
    value.extend_from_slice(&3_000_u64.to_be_bytes());
    value.extend_from_slice(&FINGERPRINT);
    push_text(&mut value, "allocation-1");
    for item in [5_u64, 3_000, 4_000, 2_000, 1_000, 4] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    push_bytes(&mut value, ack);
    value.extend_from_slice(ack_digest);
    value.extend_from_slice(&revision.to_be_bytes());
    value.extend_from_slice(&2_000_u64.to_be_bytes());
    value
}

fn provider(vectors: &[(&[u8], &[u8])]) -> String {
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
        .join(" ");
    format!(
        "CREATE FUNCTION public.blake3(payload bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT
         AS $$ SELECT CASE pg_catalog.encode(payload, 'hex') {cases} ELSE NULL::bytea END $$;"
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit progress and bound axes keep rejection fixtures reviewable"
)]
fn record_sql(
    function: &str,
    expected_size: u64,
    bytes: u64,
    chunks: u64,
    files: u64,
    revision: u64,
    ack: &[u8],
    ack_digest: &[u8],
    caps: (i32, i32, i32),
) -> String {
    let progress_arguments = if function.ends_with("local_put_reservation_record_v1") {
        String::new()
    } else {
        format!("{bytes},{chunks},{files},")
    };
    format!(
        "SELECT ({function}(
          'protocol-1','policy-1','boundary-1','cell-1','tenant-1',
          '{}','{}','{}','{}',7,decode('{}','hex'),'boundary-token',decode('{}','hex'),
          {expected_size},decode('{}','hex'),{progress_arguments}decode('{}','hex'),
          'allocation-1',5,3000,4000,2000,1000,3000,4,{expected_size},1,1,1,
          decode('{}','hex'),decode('{}','hex'),{revision},{},{},{})).*",
        uuid_v7(1_003, "0423456789ab"),
        uuid_v7(1_000, "0123456789ab"),
        uuid_v7(1_001, "0223456789ab"),
        uuid_v7(1_002, "0323456789ab"),
        hex(&BOUNDARY),
        hex(&OBSERVATION),
        hex(&BODY),
        hex(&FINGERPRINT),
        hex(ack),
        hex(ack_digest),
        caps.0,
        caps.1,
        caps.2,
    )
}

fn reserve_sql() -> String {
    format!(
        "SELECT (object_store_retention.object_store_dispatch_reserve_put_v1(
          'object-store-dispatch-reserve-put-v1','protocol-1','policy-1','boundary-1','cell-1','tenant-1',
          '{}','{}','{}','{}',7,decode('{}','hex'),'boundary-token',decode('{}','hex'),
          {BODY_SIZE},decode('{}','hex'),decode('{}','hex'),'allocation-1',5,3000,4000,1000,4,1,
          100,10,10,0,0,0,100,10,10,0,0,0,100,10,10,0,0,0,256,256,16384)).*",
        uuid_v7(1_003, "0423456789ab"), uuid_v7(1_000, "0123456789ab"),
        uuid_v7(1_001, "0223456789ab"), uuid_v7(1_002, "0323456789ab"),
        hex(&BOUNDARY), hex(&OBSERVATION), hex(&BODY), hex(&FINGERPRINT),
    )
}

async fn set_user(client: &tokio_postgres::Client, role: &str) {
    client
        .batch_execute(&format!("SET SESSION AUTHORIZATION {role};"))
        .await
        .unwrap_or_else(|error| panic!("set session user {role}: {error}"));
}

async fn reset_user(client: &tokio_postgres::Client) {
    client
        .batch_execute("RESET SESSION AUTHORIZATION;")
        .await
        .expect("reset session user");
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
    let result = serial_call(client, sql)
        .await
        .expect("provisioning install")
        .get(0);
    reset_user(client).await;
    result
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_progress_codec_is_exact_and_replay_safe() {
    let url = std::env::var("LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_CODEC_PG_URL")
        .expect("LORE_TEST_LOCAL_PUT_UPLOAD_PROGRESS_CODEC_PG_URL must name a fresh database");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable progress-codec database");
    let _connection = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "put-upload-progress-postgres",
        async move {
            let _ = connection.await;
        }
    ));
    client.batch_execute(
        "DO $$ BEGIN
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF;
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime NOLOGIN; END IF;
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance NOLOGIN; END IF;
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator NOLOGIN; END IF;
         END $$; GRANT object_dispatch_retention_owner TO CURRENT_USER;
         DO $$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO object_dispatch_retention_owner', current_database()); END $$;"
    ).await.expect("bootstrap roles");
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
    assert_eq!(install_as_migrator(&client, &format!(
        "SELECT (object_store_retention.object_store_retention_install_v1('object-store-retention-provisioning-v1','object-store-retention-authority-schema-v1',decode('{RETENTION_DIGEST}','hex'),1)).result_code"
    )).await, "CREATED");
    assert_eq!(install_as_migrator(&client, &format!(
        "SELECT (object_store_retention.object_store_dispatch_authority_install_v1('object-store-dispatch-authority-provisioning-v1','object-store-dispatch-authority-schema-v1',decode('{AUTHORITY_DIGEST}','hex'),1)).result_code"
    )).await, "CREATED");
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
    assert_eq!(install_as_migrator(&client, &format!(
        "SELECT (object_store_retention.object_store_dispatch_put_reservation_install_v1('object-store-dispatch-put-reservation-provisioning-v1','object-store-dispatch-put-reservation-schema-v1',decode('{PUT_SCHEMA_DIGEST}','hex'),1)).result_code"
    )).await, "CREATED");
    client
        .batch_execute(include_str!(
            "../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"
        ))
        .await
        .expect("apply initial record codec");

    let ack = validate_and_encode_object_store_reserve_put_ack(
        &ack_fixture(),
        &ReservePutAckLimits {
            max_identity_bytes: 256,
            max_durable_handle_bytes: 1,
            max_canonical_row_bytes: 16_384,
        },
    )
    .expect("independent RESERVED ACK");
    let quota = quota_preimage();
    let quota_digest = *blake3::hash(&quota).as_bytes();
    let initial_preimage = row_preimage(ack.canonical_bytes(), ack.ack_blake3(), 0, 0, 0, 1);
    let initial_digest = *blake3::hash(&initial_preimage).as_bytes();
    let progress_preimage = row_preimage(ack.canonical_bytes(), ack.ack_blake3(), 5, 2, 1, 3);
    let progress_digest = *blake3::hash(&progress_preimage).as_bytes();
    client
        .batch_execute(&provider(&[
            (&quota, &quota_digest),
            (ack.canonical_preimage(), ack.ack_blake3()),
            (&initial_preimage, &initial_digest),
            (&progress_preimage, &progress_digest),
        ]))
        .await
        .expect("install exact-preimage genuine BLAKE3 provider");

    set_user(&client, "object_dispatch_retention_owner").await;
    let before_0014 = client
        .query_one(
            &record_sql(
                "object_store_retention.local_put_reservation_record_v1",
                BODY_SIZE,
                0,
                0,
                0,
                1,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                (256, 256, 16_384),
            ),
            &[],
        )
        .await
        .expect("0012 initial codec");
    reset_user(&client).await;
    client
        .batch_execute(include_str!(
            "../migrations/0013_object_store_dispatch_reserve_put_mutation.sql"
        ))
        .await
        .expect("apply ReservePut mutation");
    client
        .batch_execute(include_str!(
            "../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql"
        ))
        .await
        .expect("apply progress codec");

    set_user(&client, "object_dispatch_retention_owner").await;
    let after_0014 = client
        .query_one(
            &record_sql(
                "object_store_retention.local_put_reservation_record_v1",
                BODY_SIZE,
                0,
                0,
                0,
                1,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                (256, 256, 16_384),
            ),
            &[],
        )
        .await
        .expect("0014 initial wrapper");
    assert_eq!(
        before_0014.get::<_, Vec<u8>>(0),
        after_0014.get::<_, Vec<u8>>(0)
    );
    assert_eq!(
        before_0014.get::<_, Vec<u8>>(1),
        after_0014.get::<_, Vec<u8>>(1)
    );
    assert_eq!(after_0014.get::<_, Vec<u8>>(0), complete(&initial_preimage));
    assert_eq!(after_0014.get::<_, Vec<u8>>(1), initial_digest);
    let progress = client
        .query_one(
            &record_sql(
                "object_store_retention.local_put_reserved_record_v2",
                BODY_SIZE,
                5,
                2,
                1,
                3,
                ack.canonical_bytes(),
                ack.ack_blake3(),
                (256, 256, 16_384),
            ),
            &[],
        )
        .await
        .expect("encode nonfinal progress");
    assert_eq!(progress.get::<_, Vec<u8>>(0), complete(&progress_preimage));
    assert_eq!(progress.get::<_, Vec<u8>>(1), progress_digest);

    for (label, expected_size, bytes, chunks, files, revision, caps, expected) in [
        (
            "partial without chunk",
            BODY_SIZE,
            5,
            0,
            1,
            1,
            (256, 256, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "wrong revision",
            BODY_SIZE,
            5,
            2,
            1,
            2,
            (256, 256, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "chunks exceed bytes",
            BODY_SIZE,
            1,
            2,
            1,
            3,
            (256, 256, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "chunk capacity exceeded",
            BODY_SIZE,
            9,
            2,
            1,
            3,
            (256, 256, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "full body",
            BODY_SIZE,
            10,
            2,
            1,
            3,
            (256, 256, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "zero body progress",
            0,
            1,
            1,
            1,
            2,
            (256, 256, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "identity hard cap",
            BODY_SIZE,
            0,
            0,
            0,
            1,
            (1025, 256, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "token hard cap",
            BODY_SIZE,
            0,
            0,
            0,
            1,
            (256, 4097, 16_384),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
        (
            "record hard cap",
            BODY_SIZE,
            0,
            0,
            0,
            1,
            (256, 256, 16_777_217),
            "LOCAL_PUT_RESERVED_RECORD_INVALID",
        ),
    ] {
        let error = match client
            .query_one(
                &record_sql(
                    "object_store_retention.local_put_reserved_record_v2",
                    expected_size,
                    bytes,
                    chunks,
                    files,
                    revision,
                    ack.canonical_bytes(),
                    ack.ack_blake3(),
                    caps,
                ),
                &[],
            )
            .await
        {
            Ok(_) => panic!("{label} unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error
                .as_db_error()
                .unwrap_or_else(|| panic!("{label}: untyped error {error}"))
                .message(),
            expected,
            "{label}"
        );
    }

    let wrong_ack = [0_u8; 32];
    let ack_error = match client
        .query_one(
            &record_sql(
                "object_store_retention.local_put_reserved_record_v2",
                BODY_SIZE,
                5,
                2,
                1,
                3,
                ack.canonical_bytes(),
                &wrong_ack,
                (256, 256, 16_384),
            ),
            &[],
        )
        .await
    {
        Ok(_) => panic!("wrong ACK unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(
        ack_error
            .as_db_error()
            .expect("typed ACK mismatch")
            .message(),
        "LOCAL_PUT_RESERVATION_ACK_MISMATCH"
    );
    reset_user(&client).await;

    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint';",
        )
        .await
        .expect("freeze database clock");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let created = serial_call(&client, &reserve_sql())
        .await
        .expect("create reservation");
    assert_eq!(created.get::<_, String>(0), "CREATED");
    assert_eq!(created.get::<_, Vec<u8>>(8), ack.canonical_bytes());
    reset_user(&client).await;
    let charged_before = client
        .query_one(
            "SELECT count(*), sum(used_bytes)::bigint, sum(used_rows)::bigint,
                sum(used_concurrency)::bigint, sum(counter_revision)::numeric::text
           FROM object_store_retention.object_dispatch_quota_usage",
            &[],
        )
        .await
        .expect("read initial charge");
    assert_eq!(charged_before.get::<_, i64>(0), 3);
    assert_eq!(charged_before.get::<_, Option<i64>>(1), Some(30));
    assert_eq!(charged_before.get::<_, Option<i64>>(2), Some(3));
    assert_eq!(charged_before.get::<_, Option<i64>>(3), Some(3));
    assert_eq!(charged_before.get::<_, String>(4), "6");

    client
        .execute(
            "UPDATE object_store_retention.object_dispatch_spool_objects
            SET partial_temp_bytes=5, partial_temp_chunks=2, partial_temp_files=1,
                canonical_record_bytes=$1::bytea, record_blake3=$2::bytea, spool_revision=3",
            &[&complete(&progress_preimage), &&progress_digest[..]],
        )
        .await
        .expect("persist exact nonfinal progress");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let replay = serial_call(&client, &reserve_sql())
        .await
        .expect("replay during progress");
    assert_eq!(replay.get::<_, String>(0), "REPLAY");
    assert_eq!(replay.get::<_, Vec<u8>>(8), ack.canonical_bytes());
    assert_eq!(replay.get::<_, Vec<u8>>(9), ack.ack_blake3());
    reset_user(&client).await;
    let charged_after = client
        .query_one(
            "SELECT count(*), sum(used_bytes)::bigint, sum(used_rows)::bigint,
                sum(used_concurrency)::bigint, sum(counter_revision)::numeric::text
           FROM object_store_retention.object_dispatch_quota_usage",
            &[],
        )
        .await
        .expect("read replay charge");
    for index in 0..5 {
        match index {
            0 => assert_eq!(
                charged_after.get::<_, i64>(index),
                charged_before.get::<_, i64>(index)
            ),
            1..=3 => assert_eq!(
                charged_after.get::<_, Option<i64>>(index),
                charged_before.get::<_, Option<i64>>(index)
            ),
            _ => assert_eq!(
                charged_after.get::<_, String>(index),
                charged_before.get::<_, String>(index)
            ),
        }
    }

    let protected_call = record_sql(
        "object_store_retention.local_put_reserved_record_v2",
        BODY_SIZE,
        5,
        2,
        1,
        3,
        ack.canonical_bytes(),
        ack.ack_blake3(),
        (256, 256, 16_384),
    );
    let protected_wrapper_call = record_sql(
        "object_store_retention.local_put_reservation_record_v1",
        BODY_SIZE,
        0,
        0,
        0,
        1,
        ack.canonical_bytes(),
        ack.ack_blake3(),
        (256, 256, 16_384),
    );
    let protected_projection_call = "SELECT object_store_retention.project_dispatch_reserved_put_v1(\
         NULL::object_store_retention.object_dispatch_spool_objects, 'REPLAY')";
    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        set_user(&client, role).await;
        for sql in [
            protected_call.as_str(),
            protected_wrapper_call.as_str(),
            protected_projection_call,
            "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
            "UPDATE object_store_retention.object_dispatch_spool_objects SET spool_revision=spool_revision WHERE false",
        ] {
            let error = match client.batch_execute(sql).await {
                Ok(()) => panic!("{role} unexpectedly executed {sql}"),
                Err(error) => error,
            };
            assert_eq!(
                error.as_db_error().expect("typed ACL denial").code().code(),
                "42501"
            );
        }
        reset_user(&client).await;
    }

    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea
         LANGUAGE sql IMMUTABLE STRICT AS 'SELECT NULL::bytea';",
        )
        .await
        .expect("install failing provider");
    set_user(&client, "object_dispatch_retention_owner").await;
    let provider_error = match client.query_one(&protected_call, &[]).await {
        Ok(_) => panic!("missing provider unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(
        provider_error
            .as_db_error()
            .expect("typed provider error")
            .message(),
        "LOCAL_BLAKE3_PROVIDER_INVALID_RESULT"
    );
    reset_user(&client).await;
}

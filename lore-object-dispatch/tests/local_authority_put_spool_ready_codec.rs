// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-dark SPOOL_READY snapshot codec contract. It proves canonical database snapshots only,
//! not filesystem writes, fsync, rename, or any transition/coordinator behavior.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::local_authority_put_spool_ready_codec::LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_put_spool_ready_codec::LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1;
use lore_object_dispatch::local_authority_put_spool_ready_codec::validate_embedded_local_authority_put_spool_ready_codec_migration_v1;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::PutSpoolReadyV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 17_033;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "180fed6b34db413c761e7dcd1e5250119aca5c50116977e8de54ca131408cf8c";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1)
        .expect("SPOOL_READY migration must remain UTF-8 SQL")
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
        .expect("body end");
    &sql[body_start..body_end]
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read source directory") {
        let path = entry.expect("entry").path();
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
        LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_put_spool_ready_codec_migration_v1());
}

#[test]
fn migration_is_owner_only_snapshot_codec_without_mutation_or_wiring() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n"));
    assert!(sql.ends_with("\nCOMMIT;\n"));
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 1);
    assert_eq!(sql.matches("CREATE OR REPLACE FUNCTION ").count(), 1);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 2);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 2);
    for forbidden in [
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "CREATE TABLE",
        "ALTER TABLE",
        "CREATE PROCEDURE",
        "GRANT EXECUTE",
        "fsync",
        "rename(",
        "tokio_postgres",
    ] {
        assert!(
            !sql.contains(forbidden),
            "unexpected snapshot surface: {forbidden}"
        );
    }
}

#[test]
fn ready_shape_requires_exact_commit_clocks_zero_partial_and_revision() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_put_spool_ready_record_v1(",
    );
    for required in [
        "committed_size IS DISTINCT FROM expected_size",
        "committed_blake3 IS DISTINCT FROM expected_blake3",
        "partial_temp_bytes <> 0 OR partial_temp_chunks <> 0 OR partial_temp_files <> 0",
        "spool_revision IS NULL OR spool_revision < 2",
        "ready_at_unix_ms < admission_clock_unix_ms",
        "ready_at_unix_ms >= expires_at_unix_ms",
        "maximum_durable_handle_bytes NOT BETWEEN 1 AND 4096",
    ] {
        assert!(
            body.contains(required),
            "missing ready invariant: {required}"
        );
    }
}

#[test]
fn ack_is_recomputed_as_state_two_and_record_binds_ready_evidence() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_put_spool_ready_record_v1(",
    );
    assert!(body.contains("upload_id, upload_fence,\n    2::smallint"));
    assert!(body.contains("LOCAL_PUT_SPOOL_READY_ACK_MISMATCH"));
    assert!(body.contains("object-store-dispatch-put-spool-ready-row-v1"));
    for field in [
        "local_canonical_u64_v1(committed_size)",
        "local_canonical_text_v1(\n         durable_handle",
        "local_canonical_u64_v1(spool_revision)",
        "ready_at_unix_ms::object_store_retention.uint64",
    ] {
        assert!(body.contains(field), "missing binding: {field}");
    }
}

#[test]
fn projection_preserves_lifecycle_one_and_authenticates_lifecycle_two_replay_only() {
    let body = function_body(
        migration(),
        "CREATE OR REPLACE FUNCTION object_store_retention.project_dispatch_reserved_put_v1(",
    );
    assert!(body.contains("stored.lifecycle_state NOT IN (1, 2)"));
    assert!(body.contains("stored.lifecycle_state = 2 AND result_code <> 'REPLAY'"));
    assert!(body.contains("IF stored.lifecycle_state = 1 THEN"));
    assert!(body.contains("local_put_reserved_record_v2("));
    assert!(body.contains("local_put_spool_ready_record_v1("));
    assert!(body.contains("DISPATCH_RESERVED_PUT_STORED_RECORD_MISMATCH"));
}

#[test]
fn functions_and_tables_are_owner_only() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC")
    );
    assert!(sql.contains(
        "REVOKE ALL ON FUNCTION object_store_retention.local_put_spool_ready_record_v1("
    ));
    assert!(sql.contains(
        "REVOKE ALL ON FUNCTION object_store_retention.project_dispatch_reserved_put_v1("
    ));
    assert!(sql.contains("REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM"));
    assert_eq!(sql.matches("GRANT ").count(), 0);
}

#[test]
fn artifact_is_embedded_only_and_source_dark() {
    let module = include_str!("../src/local_authority_put_spool_ready_codec.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql\")"
    ));
    assert!(
        include_str!("../src/lib.rs").contains("pub mod local_authority_put_spool_ready_codec;")
    );
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("source");
        assert!(
            !source.contains("local_put_spool_ready_record_v1("),
            "runtime call in {}",
            path.display()
        );
        if path.file_name().and_then(|name| name.to_str())
            != Some("local_authority_put_spool_ready_codec.rs")
        {
            assert!(
                !source.contains("LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1"),
                "migration bytes referenced by {}",
                path.display()
            );
        }
    }
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

fn spool_preimage(size: u64) -> Vec<u8> {
    let mut value = b"object-store-put-spool-ready-v1\0".to_vec();
    for text in [
        "protocol-1",
        "boundary-1",
        "cell-1",
        "tenant-1",
        &uuid_v7(1_000, "0123456789ab"),
        &uuid_v7(1_001, "0223456789ab"),
        &uuid_v7(1_002, "0323456789ab"),
    ] {
        push_text(&mut value, text);
    }
    value.extend_from_slice(&7_u64.to_be_bytes());
    push_text(&mut value, "put/body-1");
    value.extend_from_slice(&size.to_be_bytes());
    value.extend_from_slice(&BODY);
    value.extend_from_slice(&2_500_u64.to_be_bytes());
    value
}

fn ack_fixture(size: u64, ready: bool) -> ReservePutAckV1 {
    let mut value = ReservePutAckV1 {
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
        max_chunk_bytes: 16,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: 2_000,
        allocation_hard_expiry_unix_ms: 4_000,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    };
    if ready {
        value.state = PutReservationStateV1::PutReservationStateSpoolReady as i32;
        value.spool_ready = Some(PutSpoolReadyV1 {
            protocol_revision: value.protocol_revision.clone(),
            provider_boundary_id: value.provider_boundary_id.clone(),
            authenticated_cell_id: value.authenticated_cell_id.clone(),
            authenticated_tenant_id: value.authenticated_tenant_id.clone(),
            logical_request_id: value.logical_request_id.clone(),
            attempt_id: value.attempt_id.clone(),
            upload_id: value.upload_id.clone(),
            upload_fence: 7,
            durable_body_handle: "put/body-1".into(),
            body_size: size,
            body_blake3: BODY.to_vec().into(),
            ready_at_unix_ms: 2_500,
        });
    }
    value
}

fn reserved_preimage(ack: &[u8], digest: &[u8], size: u64) -> Vec<u8> {
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
    value.extend_from_slice(&size.to_be_bytes());
    value.extend_from_slice(&BODY);
    for _ in 0..3 {
        value.extend_from_slice(&0_u64.to_be_bytes());
    }
    push_bytes(&mut value, &complete(&quota_preimage(size)));
    value.extend_from_slice(&1_u64.to_be_bytes());
    value.extend_from_slice(&3_000_u64.to_be_bytes());
    value.extend_from_slice(&FINGERPRINT);
    push_text(&mut value, "allocation-1");
    for item in [5_u64, 3_000, 4_000, 2_000, 1_000, 16] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    push_bytes(&mut value, ack);
    value.extend_from_slice(digest);
    value.extend_from_slice(&1_u64.to_be_bytes());
    value.extend_from_slice(&2_000_u64.to_be_bytes());
    value
}

fn ready_preimage(ack: &[u8], digest: &[u8], size: u64, revision: u64) -> Vec<u8> {
    let mut value = b"object-store-dispatch-put-spool-ready-row-v1\0".to_vec();
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
    value.extend_from_slice(&[1, 1, 2, 1]);
    value.extend_from_slice(&BOUNDARY);
    push_text(&mut value, "boundary-token");
    value.extend_from_slice(&OBSERVATION);
    value.extend_from_slice(&size.to_be_bytes());
    value.extend_from_slice(&BODY);
    value.extend_from_slice(&size.to_be_bytes());
    value.extend_from_slice(&BODY);
    push_text(&mut value, "put/body-1");
    for _ in 0..3 {
        value.extend_from_slice(&0_u64.to_be_bytes());
    }
    push_bytes(&mut value, &complete(&quota_preimage(size)));
    value.extend_from_slice(&1_u64.to_be_bytes());
    value.extend_from_slice(&3_000_u64.to_be_bytes());
    value.extend_from_slice(&FINGERPRINT);
    push_text(&mut value, "allocation-1");
    for item in [5_u64, 3_000, 4_000, 2_000, 1_000, 16] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    push_bytes(&mut value, ack);
    value.extend_from_slice(digest);
    value.extend_from_slice(&revision.to_be_bytes());
    value.extend_from_slice(&2_000_u64.to_be_bytes());
    value.extend_from_slice(&2_500_u64.to_be_bytes());
    value
}

fn provider(vectors: &[(&[u8], &[u8])]) -> String {
    let cases = vectors
        .iter()
        .map(|(preimage, digest)| {
            format!(
                "WHEN '{}' THEN decode('{}','hex')",
                hex(preimage),
                hex(digest)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "CREATE FUNCTION public.blake3(payload bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT CASE encode(payload,'hex') {cases} ELSE NULL::bytea END $$;"
    )
}

#[derive(Clone)]
struct CodecCall<'a> {
    size: u64,
    committed: u64,
    committed_digest: &'a [u8],
    handle: &'a str,
    ready: i64,
    partial_bytes: u64,
    partial_chunks: u64,
    partial_files: u64,
    revision: u64,
    ack: &'a [u8],
    ack_digest: &'a [u8],
    caps: (i32, i32, i32, i32),
}
fn codec_sql(value: &CodecCall<'_>) -> String {
    format!("SELECT (object_store_retention.local_put_spool_ready_record_v1(
 'protocol-1','policy-1','boundary-1','cell-1','tenant-1','{}','{}','{}','{}',7,decode('{}','hex'),'boundary-token',decode('{}','hex'),{},
 decode('{}','hex'),{},decode('{}','hex'),'{}',{},{},{},decode('{}','hex'),'allocation-1',5,3000,4000,2000,1000,3000,{},16,{},1,1,1,
 decode('{}','hex'),decode('{}','hex'),{},{},{},{},{})).*",uuid_v7(1_003,"0423456789ab"),uuid_v7(1_000,"0123456789ab"),
 uuid_v7(1_001,"0223456789ab"),uuid_v7(1_002,"0323456789ab"),hex(&BOUNDARY),hex(&OBSERVATION),value.size,hex(&BODY),
 value.committed,hex(value.committed_digest),value.handle,value.partial_bytes,value.partial_chunks,value.partial_files,hex(&FINGERPRINT),value.ready,value.size,
 hex(value.ack),hex(value.ack_digest),value.revision,value.caps.0,value.caps.1,value.caps.2,value.caps.3)
}

fn reserve_sql(size: u64) -> String {
    format!("SELECT (object_store_retention.object_store_dispatch_reserve_put_v1(
 'object-store-dispatch-reserve-put-v1','protocol-1','policy-1','boundary-1','cell-1','tenant-1','{}','{}','{}','{}',7,
 decode('{}','hex'),'boundary-token',decode('{}','hex'),{},decode('{}','hex'),decode('{}','hex'),'allocation-1',5,3000,4000,1000,16,1,
 100,10,10,0,0,0,100,10,10,0,0,0,100,10,10,0,0,0,256,256,16777216)).*",uuid_v7(1_003,"0423456789ab"),
 uuid_v7(1_000,"0123456789ab"),uuid_v7(1_001,"0223456789ab"),uuid_v7(1_002,"0323456789ab"),hex(&BOUNDARY),hex(&OBSERVATION),size,hex(&BODY),hex(&FINGERPRINT))
}

async fn set_user(client: &tokio_postgres::Client, role: &str) {
    client
        .batch_execute(&format!("SET SESSION AUTHORIZATION {role};"))
        .await
        .unwrap_or_else(|e| panic!("set {role}: {e}"));
}
async fn reset_user(client: &tokio_postgres::Client) {
    client
        .batch_execute("RESET SESSION AUTHORIZATION;")
        .await
        .expect("reset");
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
        .batch_execute(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
        .await?;
    result
}
async fn install(client: &tokio_postgres::Client, sql: &str) -> String {
    set_user(client, "object_dispatch_retention_migrator").await;
    let value = serial_call(client, sql).await.expect("install").get(0);
    reset_user(client).await;
    value
}
fn message(error: &tokio_postgres::Error) -> &str {
    error
        .as_db_error()
        .map(|db| db.message())
        .unwrap_or("untyped")
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_ready_codec_is_exact_fail_closed_and_replay_safe() {
    let url =
        std::env::var("LORE_TEST_LOCAL_PUT_SPOOL_READY_CODEC_PG_URL").expect("fresh PG16 URL");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    let _connection = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "put-spool-ready-codec-postgres",
        async move {
            let _ = connection.await;
        }
    ));
    client.batch_execute("DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_owner')THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_runtime')THEN CREATE ROLE object_dispatch_retention_runtime NOLOGIN;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance')THEN CREATE ROLE object_dispatch_retention_maintenance NOLOGIN;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_migrator')THEN CREATE ROLE object_dispatch_retention_migrator NOLOGIN;END IF;
 END $$; GRANT object_dispatch_retention_owner TO CURRENT_USER;
 DO $$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO object_dispatch_retention_owner',current_database()); END $$;").await.expect("roles");
    for sql in [
        include_str!("../migrations/0002_object_store_retention_authority.sql"),
        include_str!("../migrations/0003_object_store_retention_provisioning.sql"),
        include_str!("../migrations/0007_object_store_dispatch_authority_core.sql"),
        include_str!("../migrations/0008_object_store_dispatch_authority_provisioning.sql"),
    ] {
        client.batch_execute(sql).await.expect("base migration");
    }
    assert_eq!(install(&client,&format!("SELECT(object_store_retention.object_store_retention_install_v1('object-store-retention-provisioning-v1','object-store-retention-authority-schema-v1',decode('{RETENTION_DIGEST}','hex'),1)).result_code")).await,"CREATED");
    assert_eq!(install(&client,&format!("SELECT(object_store_retention.object_store_dispatch_authority_install_v1('object-store-dispatch-authority-provisioning-v1','object-store-dispatch-authority-schema-v1',decode('{AUTHORITY_DIGEST}','hex'),1)).result_code")).await,"CREATED");
    for sql in [
        include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql"),
        include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql"),
        include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql"),
    ] {
        client.batch_execute(sql).await.expect("schema migration");
    }
    assert_eq!(install(&client,&format!("SELECT(object_store_retention.object_store_dispatch_put_reservation_install_v1('object-store-dispatch-put-reservation-provisioning-v1','object-store-dispatch-put-reservation-schema-v1',decode('{PUT_SCHEMA_DIGEST}','hex'),1)).result_code")).await,"CREATED");
    for sql in [
        include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"),
        include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql"),
        include_str!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql"),
        include_str!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql"),
        include_str!("../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql"),
    ] {
        client.batch_execute(sql).await.expect("codec chain");
    }
    client.batch_execute("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1()RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS'SELECT 2000::bigint';").await.expect("clock");
    let limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 4096,
        max_canonical_row_bytes: 16_777_216,
    };
    let reserved =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture(64, false), &limits)
            .expect("reserved ACK");
    let ready = validate_and_encode_object_store_reserve_put_ack(&ack_fixture(64, true), &limits)
        .expect("ready ACK");
    let zero_ready =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture(0, true), &limits)
            .expect("zero ready ACK");
    let reserved_row = reserved_preimage(reserved.canonical_bytes(), reserved.ack_blake3(), 64);
    let ready_row = ready_preimage(ready.canonical_bytes(), ready.ack_blake3(), 64, 2);
    let zero_row = ready_preimage(zero_ready.canonical_bytes(), zero_ready.ack_blake3(), 0, 2);
    let quota64 = quota_preimage(64);
    let quota0 = quota_preimage(0);
    let spool64 = spool_preimage(64);
    let spool0 = spool_preimage(0);
    let d64 = *blake3::hash(&quota64).as_bytes();
    let d0 = *blake3::hash(&quota0).as_bytes();
    let ds64 = *blake3::hash(&spool64).as_bytes();
    let ds0 = *blake3::hash(&spool0).as_bytes();
    let dr = *blake3::hash(&reserved_row).as_bytes();
    let dy = *blake3::hash(&ready_row).as_bytes();
    let dz = *blake3::hash(&zero_row).as_bytes();
    let provider_sql = provider(&[
        (&quota64, &d64),
        (&quota0, &d0),
        (&spool64, &ds64),
        (&spool0, &ds0),
        (reserved.canonical_preimage(), reserved.ack_blake3()),
        (ready.canonical_preimage(), ready.ack_blake3()),
        (zero_ready.canonical_preimage(), zero_ready.ack_blake3()),
        (&reserved_row, &dr),
        (&ready_row, &dy),
        (&zero_row, &dz),
    ]);
    client
        .batch_execute(&provider_sql)
        .await
        .expect("genuine BLAKE3 provider");
    let positive = CodecCall {
        size: 64,
        committed: 64,
        committed_digest: &BODY,
        handle: "put/body-1",
        ready: 2500,
        partial_bytes: 0,
        partial_chunks: 0,
        partial_files: 0,
        revision: 2,
        ack: ready.canonical_bytes(),
        ack_digest: ready.ack_blake3(),
        caps: (256, 256, 4096, 16_777_216),
    };
    let zero = CodecCall {
        size: 0,
        committed: 0,
        ack: zero_ready.canonical_bytes(),
        ack_digest: zero_ready.ack_blake3(),
        ..positive.clone()
    };
    set_user(&client, "object_dispatch_retention_owner").await;
    let positive_sql = client
        .query_one(&codec_sql(&positive), &[])
        .await
        .expect("positive ready");
    assert_eq!(positive_sql.get::<_, Vec<u8>>(0), complete(&ready_row));
    assert_eq!(positive_sql.get::<_, Vec<u8>>(1), dy);
    let zero_sql = client
        .query_one(&codec_sql(&zero), &[])
        .await
        .expect("zero ready");
    assert_eq!(zero_sql.get::<_, Vec<u8>>(0), complete(&zero_row));
    assert_eq!(zero_sql.get::<_, Vec<u8>>(1), dz);
    let max_revision = CodecCall {
        revision: u64::MAX,
        ..positive.clone()
    };
    reset_user(&client).await;
    let mechanics_provider = provider_sql
        .replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
        .replacen("ELSE NULL::bytea", "ELSE decode(repeat('00',32),'hex')", 1);
    client
        .batch_execute(&mechanics_provider)
        .await
        .expect("install mechanics-only max-revision provider");
    set_user(&client, "object_dispatch_retention_owner").await;
    let mechanics_revision = client
        .query_one(&codec_sql(&max_revision), &[])
        .await
        .expect("derive max-revision preimage");
    reset_user(&client).await;
    let mechanics_bytes = mechanics_revision.get::<_, Vec<u8>>(0);
    let max_revision_preimage = &mechanics_bytes[..mechanics_bytes.len() - 32];
    let max_revision_digest = *blake3::hash(max_revision_preimage).as_bytes();
    let max_case = format!(
        "WHEN '{}' THEN decode('{}','hex') ",
        hex(max_revision_preimage),
        hex(&max_revision_digest)
    );
    let extended_provider = provider_sql
        .replacen(
            "ELSE NULL::bytea",
            &format!("{max_case}ELSE NULL::bytea"),
            1,
        )
        .replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1);
    client
        .batch_execute(&extended_provider)
        .await
        .expect("install genuine max-revision mapping");
    set_user(&client, "object_dispatch_retention_owner").await;
    let max_revision_sql = client
        .query_one(&codec_sql(&max_revision), &[])
        .await
        .expect("u64::MAX revision is accepted without arithmetic");
    assert_eq!(
        max_revision_sql.get::<_, Vec<u8>>(0),
        complete(max_revision_preimage)
    );
    assert_eq!(max_revision_sql.get::<_, Vec<u8>>(1), max_revision_digest);
    for (label, value) in [
        (
            "size",
            CodecCall {
                committed: 63,
                ..positive.clone()
            },
        ),
        (
            "digest",
            CodecCall {
                committed_digest: &[0; 32],
                ..positive.clone()
            },
        ),
        (
            "handle",
            CodecCall {
                handle: "",
                ..positive.clone()
            },
        ),
        (
            "ready early",
            CodecCall {
                ready: 1999,
                ..positive.clone()
            },
        ),
        (
            "ready expiry",
            CodecCall {
                ready: 3000,
                ..positive.clone()
            },
        ),
        (
            "partial bytes",
            CodecCall {
                partial_bytes: 1,
                ..positive.clone()
            },
        ),
        (
            "partial chunks",
            CodecCall {
                partial_chunks: 1,
                ..positive.clone()
            },
        ),
        (
            "partial files",
            CodecCall {
                partial_files: 1,
                ..positive.clone()
            },
        ),
        (
            "revision",
            CodecCall {
                revision: 1,
                ..positive.clone()
            },
        ),
        (
            "identity cap",
            CodecCall {
                caps: (1025, 256, 4096, 16_777_216),
                ..positive.clone()
            },
        ),
        (
            "token cap",
            CodecCall {
                caps: (256, 4097, 4096, 16_777_216),
                ..positive.clone()
            },
        ),
        (
            "handle cap",
            CodecCall {
                caps: (256, 256, 4097, 16_777_216),
                ..positive.clone()
            },
        ),
        (
            "record cap",
            CodecCall {
                caps: (256, 256, 4096, 16_777_217),
                ..positive.clone()
            },
        ),
    ] {
        let error = client.query_one(&codec_sql(&value), &[]).await.unwrap_err();
        assert_ne!(message(&error), "", "{label}");
    }
    let wrong = [0_u8; 32];
    let ack_error = client
        .query_one(
            &codec_sql(&CodecCall {
                ack_digest: &wrong,
                ..positive.clone()
            }),
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(message(&ack_error), "LOCAL_PUT_SPOOL_READY_ACK_MISMATCH");
    let lifecycle_one_ack_error = client
        .query_one(
            &codec_sql(&CodecCall {
                ack: reserved.canonical_bytes(),
                ack_digest: reserved.ack_blake3(),
                ..positive.clone()
            }),
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(
        message(&lifecycle_one_ack_error),
        "LOCAL_PUT_SPOOL_READY_ACK_MISMATCH"
    );
    for (label, sql) in [
        (
            "UUID version",
            codec_sql(&positive).replacen(
                "00000000-03eb-7abc-8def-",
                "00000000-03eb-6abc-8def-",
                1,
            ),
        ),
        (
            "UUID variant",
            codec_sql(&positive).replacen(
                "00000000-03eb-7abc-8def-",
                "00000000-03eb-7abc-4def-",
                1,
            ),
        ),
    ] {
        let error = client.query_one(&sql, &[]).await.unwrap_err();
        assert_eq!(
            message(&error),
            "LOCAL_PUT_SPOOL_READY_RECORD_INVALID",
            "{label}"
        );
    }
    reset_user(&client).await;

    set_user(&client, "object_dispatch_retention_runtime").await;
    let created = serial_call(&client, &reserve_sql(64))
        .await
        .expect("reserve");
    assert_eq!(created.get::<_, String>(0), "CREATED");
    let lifecycle_one = serial_call(&client, &reserve_sql(64))
        .await
        .expect("lifecycle1 replay");
    assert_eq!(lifecycle_one.get::<_, String>(0), "REPLAY");
    assert_eq!(
        lifecycle_one.get::<_, Vec<u8>>(8),
        reserved.canonical_bytes()
    );
    reset_user(&client).await;
    let quota_before=client.query_one("SELECT pg_catalog.json_agg(q ORDER BY scope_kind)::text FROM object_store_retention.object_dispatch_quota_usage q",&[]).await.expect("quota").get::<_,String>(0);
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET lifecycle_state=2,committed_size=64,committed_blake3=$1::bytea,
  durable_handle='put/body-1',ready_at_unix_ms=2500,partial_temp_bytes=0,partial_temp_chunks=0,partial_temp_files=0,
  reserve_put_ack_canonical_bytes=$2::bytea,reserve_put_ack_blake3=$3::bytea,canonical_record_bytes=$4::bytea,record_blake3=$5::bytea,spool_revision=2",
  &[&&BODY[..],&ready.canonical_bytes(),&&ready.ack_blake3()[..],&complete(&ready_row),&&dy[..]]).await.expect("install ready row");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let replay = serial_call(&client, &reserve_sql(64))
        .await
        .expect("ready replay");
    assert_eq!(replay.get::<_, String>(0), "REPLAY");
    assert_eq!(replay.get::<_, Vec<u8>>(8), ready.canonical_bytes());
    reset_user(&client).await;
    assert_eq!(client.query_one("SELECT pg_catalog.json_agg(q ORDER BY scope_kind)::text FROM object_store_retention.object_dispatch_quota_usage q",&[]).await.expect("quota unchanged").get::<_,String>(0),quota_before);
    set_user(&client, "object_dispatch_retention_owner").await;
    let created_error=client.query_one("SELECT(object_store_retention.project_dispatch_reserved_put_v1(s,'CREATED')).* FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.unwrap_err();
    assert_eq!(
        message(&created_error),
        "DISPATCH_RESERVED_PUT_STORED_STATE_INVALID"
    );
    reset_user(&client).await;
    let valid_record = complete(&ready_row);
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET canonical_record_bytes=set_byte(canonical_record_bytes,0,(get_byte(canonical_record_bytes,0)+1)%256)",&[]).await.expect("tamper");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let tamper = serial_call(&client, &reserve_sql(64)).await.unwrap_err();
    assert_eq!(
        message(&tamper),
        "DISPATCH_RESERVED_PUT_STORED_RECORD_MISMATCH"
    );
    reset_user(&client).await;
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET canonical_record_bytes=$1::bytea",&[&valid_record]).await.expect("restore");
    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        set_user(&client, role).await;
        for sql in[codec_sql(&positive),"SELECT(object_store_retention.project_dispatch_reserved_put_v1(NULL::object_store_retention.object_dispatch_spool_objects,'REPLAY')).*".into(),
   "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects".into(),"UPDATE object_store_retention.object_dispatch_spool_objects SET spool_revision=spool_revision WHERE false".into()]{
    let error=client.batch_execute(&sql).await.unwrap_err();assert_eq!(error.as_db_error().expect("ACL").code().code(),"42501");}
        reset_user(&client).await;
    }
    client.batch_execute("CREATE OR REPLACE FUNCTION public.blake3(payload bytea)RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS'SELECT NULL::bytea';").await.expect("break provider");
    set_user(&client, "object_dispatch_retention_owner").await;
    let provider_error = client
        .query_one(&codec_sql(&positive), &[])
        .await
        .unwrap_err();
    assert_eq!(
        message(&provider_error),
        "LOCAL_BLAKE3_PROVIDER_INVALID_RESULT"
    );
    reset_user(&client).await;
}

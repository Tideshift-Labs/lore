// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-dark atomic SPOOL_READY database mutation contract. The database records the caller's
//! already-durable assertion; it cannot write, fsync, rename, or inspect filesystem bytes.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::local_authority_put_spool_ready_mutation::LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_put_spool_ready_mutation::LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1;
use lore_object_dispatch::local_authority_put_spool_ready_mutation::validate_embedded_local_authority_put_spool_ready_mutation_migration_v1;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::PutSpoolReadyV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_BYTES: usize = 13_373;
const EXPECTED_BLAKE3: &str = "1bf102fce2e86f48eed6295e1349795564c4aae48aa5ac5d5af5ab5233b0462c";
fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1).expect("UTF-8 SQL")
}
fn body<'a>(sql: &'a str, signature: &str) -> &'a str {
    let start = sql
        .find(signature)
        .unwrap_or_else(|| panic!("missing {signature}"));
    let begin = sql[start..].find("AS $$").map(|n| start + n).expect("body");
    let end = sql[begin + 5..]
        .find("\n$$;")
        .map(|n| begin + 5 + n)
        .expect("end");
    &sql[begin..end]
}
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources(&path, out)
        } else if path.extension().is_some_and(|v| v == "rs") {
            out.push(path)
        }
    }
}

#[test]
fn exact_identity() {
    assert_eq!(
        LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1.len(),
        EXPECTED_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_put_spool_ready_mutation_migration_v1());
}
#[test]
fn auth_api_isolation_schema_then_exact_row_lock() {
    let b = body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_spool_ready_v1(",
    );
    let auth = b.find("assert_dispatch_runtime_v1()").unwrap();
    let api = b
        .find("assert_dispatch_put_spool_ready_api_revision_v1(api_revision)")
        .unwrap();
    let iso = b.find("assert_serializable_write_v1()").unwrap();
    let schema = b.find("FOR SHARE;").unwrap();
    let row = b
        .find("AND spool.payload_kind = 1\n   FOR UPDATE;")
        .unwrap();
    assert!(auth < api && api < iso && iso < schema && schema < row);
}
#[test]
fn identity_then_current_record_auth() {
    let b = body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_spool_ready_v1(",
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
        assert!(b.contains(&format!("stored.{field} IS DISTINCT FROM {field}")));
    }
    assert!(
        b.find("UPLOAD_STREAM_IDENTITY_MISMATCH").unwrap()
            < b.find("project_dispatch_reserved_put_v1(stored, 'REPLAY')")
                .unwrap()
    );
}
#[test]
fn exact_replay_precedes_mutable_validation_clock_and_expiry() {
    let b = body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_spool_ready_v1(",
    );
    let replay = b.find("stored.spool_revision - 2").unwrap();
    let maxima = b.find("maximum_identity_bytes IS NULL").unwrap();
    let clock = b.find("database_now :=").unwrap();
    assert!(replay < maxima && maxima < clock);
    for item in [
        "final_chunk_index < stored.partial_temp_chunks",
        "final_chunk_index > stored.partial_temp_chunks",
        "stored.expected_size - stored.partial_temp_bytes <= stored.max_chunk_bytes",
        "database_now >= stored.expires_at_unix_ms",
    ] {
        assert!(b.contains(item));
    }
}

#[test]
fn overflow_and_atomic_update_conflict_paths_are_typed() {
    let b = body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_spool_ready_v1(",
    );
    let overflow = b
        .find("stored.spool_revision = 18446744073709551615")
        .expect("u64 revision overflow guard");
    let body_bounds = b
        .find("fsynced_body_size IS DISTINCT FROM stored.expected_size")
        .expect("final body validation");
    let update = b
        .find("UPDATE object_store_retention.object_dispatch_spool_objects")
        .expect("atomic row update");
    assert!(overflow < body_bounds && body_bounds < update);
    assert!(b.contains("IF affected_rows <> 1 THEN"));
    assert!(b.contains("DISPATCH_PUT_SPOOL_READY_CONFLICT"));
    assert!(b.contains("DISPATCH_PUT_SPOOL_READY_UNAVAILABLE"));
}
#[test]
fn atomic_update_clears_partial_and_preserves_quota() {
    let b = body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_put_spool_ready_v1(",
    );
    for item in [
        "lifecycle_state = 2",
        "partial_temp_bytes = 0",
        "partial_temp_chunks = 0",
        "partial_temp_files = 0",
        "reserve_put_ack_canonical_bytes = next_ack.canonical_bytes",
        "canonical_record_bytes = next_record.canonical_bytes",
        "spool_revision = next_revision",
        "ready_at_unix_ms = database_now",
    ] {
        assert!(b.contains(item));
    }
    assert!(!b.contains("UPDATE object_store_retention.object_dispatch_quota_usage"));
}
#[test]
fn runtime_only_main_owner_only_helpers_and_tables() {
    let sql = migration();
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 1);
    assert!(sql.contains(") TO object_dispatch_retention_runtime;"));
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC")
    );
    assert!(sql.contains("assert_dispatch_put_spool_ready_api_revision_v1("));
    assert!(sql.contains("project_dispatch_put_spool_ready_v1("));
    assert!(sql.contains("REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM"));
}
#[test]
fn source_dark_and_no_filesystem_or_provider_wiring() {
    let module = include_str!("../src/local_authority_put_spool_ready_mutation.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0017_object_store_dispatch_put_spool_ready_mutation.sql\")"
    ));
    assert!(module.contains("cannot\n//! write, fsync, rename, inspect"));
    assert!(
        include_str!("../src/lib.rs").contains("pub mod local_authority_put_spool_ready_mutation;")
    );
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    for path in files {
        let text = std::fs::read_to_string(&path).expect("source");
        assert!(
            !text.contains("object_store_dispatch_put_spool_ready_v1("),
            "runtime call {}",
            path.display()
        );
        if path.file_name().and_then(|v| v.to_str())
            != Some("local_authority_put_spool_ready_mutation.rs")
        {
            assert!(!text.contains("LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1"));
        }
    }
    for forbidden in [
        "tokio_postgres",
        "rename(",
        "std::fs",
        "File::",
        "provider wiring",
    ] {
        assert!(!module.contains(forbidden));
    }
}

const RETENTION: &str = "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";
const AUTHORITY: &str = "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";
const PUT: &str = "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67";
const BODY: [u8; 32] = [0x31; 32];
const BOUNDARY: [u8; 32] = [0x41; 32];
const OBS: [u8; 32] = [0x51; 32];
const FP: [u8; 32] = [0x61; 32];
fn uuid(ts: u64, tail: &str) -> String {
    let p = format!("{ts:012x}");
    format!("{}-{}-7abc-8def-{tail}", &p[..8], &p[8..])
}
fn text(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_be_bytes());
    v.extend_from_slice(s.as_bytes())
}
fn bytes(v: &mut Vec<u8>, b: &[u8]) {
    v.extend_from_slice(&(b.len() as u32).to_be_bytes());
    v.extend_from_slice(b)
}
fn done(p: &[u8]) -> Vec<u8> {
    let mut v = p.to_vec();
    v.extend_from_slice(blake3::hash(p).as_bytes());
    v
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn quota(size: u64) -> Vec<u8> {
    let mut v = b"object-store-quota-units-v1\0".to_vec();
    for x in [size, 1, 1] {
        v.extend_from_slice(&x.to_be_bytes())
    }
    v
}
fn ack(size: u64, ready: bool) -> ReservePutAckV1 {
    let mut v = ReservePutAckV1 {
        protocol_revision: "protocol-1".into(),
        policy_revision: "policy-1".into(),
        provider_boundary_id: "boundary-1".into(),
        authenticated_cell_id: "cell-1".into(),
        authenticated_tenant_id: "tenant-1".into(),
        logical_request_id: uuid(1000, "0123456789ab"),
        attempt_id: uuid(1001, "0223456789ab"),
        upload_id: uuid(1002, "0323456789ab"),
        upload_fence: 7,
        state: PutReservationStateV1::PutReservationStateReserved as i32,
        reserved_quota: Some(ObjectStoreQuotaUnitsV1 {
            bytes: size,
            rows: 1,
            concurrency: 1,
        }),
        expires_at_unix_ms: 3000,
        max_chunk_bytes: 6,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: 2000,
        allocation_hard_expiry_unix_ms: 4000,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    };
    if ready {
        v.state = PutReservationStateV1::PutReservationStateSpoolReady as i32;
        v.spool_ready = Some(PutSpoolReadyV1 {
            protocol_revision: v.protocol_revision.clone(),
            provider_boundary_id: v.provider_boundary_id.clone(),
            authenticated_cell_id: v.authenticated_cell_id.clone(),
            authenticated_tenant_id: v.authenticated_tenant_id.clone(),
            logical_request_id: v.logical_request_id.clone(),
            attempt_id: v.attempt_id.clone(),
            upload_id: v.upload_id.clone(),
            upload_fence: 7,
            durable_body_handle: "put/body-final".into(),
            body_size: size,
            body_blake3: BODY.to_vec().into(),
            ready_at_unix_ms: 2000,
        });
    }
    v
}
fn spool_child(size: u64) -> Vec<u8> {
    let mut v = b"object-store-put-spool-ready-v1\0".to_vec();
    for s in [
        "protocol-1",
        "boundary-1",
        "cell-1",
        "tenant-1",
        &uuid(1000, "0123456789ab"),
        &uuid(1001, "0223456789ab"),
        &uuid(1002, "0323456789ab"),
    ] {
        text(&mut v, s)
    }
    v.extend_from_slice(&7_u64.to_be_bytes());
    text(&mut v, "put/body-final");
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(&BODY);
    v.extend_from_slice(&2000_u64.to_be_bytes());
    v
}
fn row(
    ack: &[u8],
    digest: &[u8],
    size: u64,
    progress: (u64, u64, u64),
    revision: u64,
    ready: bool,
) -> Vec<u8> {
    let mut v = if ready {
        b"object-store-dispatch-put-spool-ready-row-v1\0".to_vec()
    } else {
        b"object-store-dispatch-put-reservation-row-v1\0".to_vec()
    };
    for s in [
        "object-store-dispatch-authority-schema-v1",
        "protocol-1",
        "policy-1",
        "boundary-1",
        "cell-1",
        "tenant-1",
        &uuid(1003, "0423456789ab"),
        &uuid(1000, "0123456789ab"),
        &uuid(1001, "0223456789ab"),
        &uuid(1002, "0323456789ab"),
    ] {
        text(&mut v, s)
    }
    v.extend_from_slice(&7_u64.to_be_bytes());
    v.extend_from_slice(if ready { &[1, 1, 2, 1] } else { &[1, 1, 1, 1] });
    v.extend_from_slice(&BOUNDARY);
    text(&mut v, "boundary-token");
    v.extend_from_slice(&OBS);
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(&BODY);
    if ready {
        v.extend_from_slice(&size.to_be_bytes());
        v.extend_from_slice(&BODY);
        text(&mut v, "put/body-final");
    }
    for x in [progress.0, progress.1, progress.2] {
        v.extend_from_slice(&x.to_be_bytes())
    }
    bytes(&mut v, &done(&quota(size)));
    v.extend_from_slice(&1_u64.to_be_bytes());
    v.extend_from_slice(&3000_u64.to_be_bytes());
    v.extend_from_slice(&FP);
    text(&mut v, "allocation-1");
    for x in [5_u64, 3000, 4000, 2000, 1000, 6] {
        v.extend_from_slice(&x.to_be_bytes())
    }
    bytes(&mut v, ack);
    v.extend_from_slice(digest);
    v.extend_from_slice(&revision.to_be_bytes());
    v.extend_from_slice(&2000_u64.to_be_bytes());
    if ready {
        v.extend_from_slice(&2000_u64.to_be_bytes())
    }
    v
}
fn provider(items: &[(&[u8], &[u8])]) -> String {
    let c = items
        .iter()
        .map(|(p, d)| format!("WHEN '{}' THEN decode('{}','hex')", hex(p), hex(d)))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT CASE encode(payload,'hex') {c} ELSE NULL::bytea END $$;"
    )
}
fn reserve(size: u64) -> String {
    format!(
        "SELECT(object_store_retention.object_store_dispatch_reserve_put_v1('object-store-dispatch-reserve-put-v1','protocol-1','policy-1','boundary-1','cell-1','tenant-1','{}','{}','{}','{}',7,decode('{}','hex'),'boundary-token',decode('{}','hex'),{},decode('{}','hex'),decode('{}','hex'),'allocation-1',5,3000,4000,1000,6,1,100,10,10,0,0,0,100,10,10,0,0,0,100,10,10,0,0,0,256,256,16777216)).*",
        uuid(1003, "0423456789ab"),
        uuid(1000, "0123456789ab"),
        uuid(1001, "0223456789ab"),
        uuid(1002, "0323456789ab"),
        hex(&BOUNDARY),
        hex(&OBS),
        size,
        hex(&BODY),
        hex(&FP)
    )
}
fn progress(index: u64, prefix: u64) -> String {
    format!(
        "SELECT(object_store_retention.object_store_dispatch_put_upload_progress_v1('object-store-dispatch-put-upload-progress-v1','protocol-1','boundary-1','cell-1','tenant-1','{}','{}','{}',7,{index},{prefix},256,256,16777216)).*",
        uuid(1000, "0123456789ab"),
        uuid(1001, "0223456789ab"),
        uuid(1002, "0323456789ab")
    )
}
fn final_sql(
    index: u64,
    size: u64,
    digest: &[u8],
    handle: &str,
    caps: (i32, i32, i32, i32),
) -> String {
    format!(
        "SELECT(object_store_retention.object_store_dispatch_put_spool_ready_v1('object-store-dispatch-put-spool-ready-v1','protocol-1','boundary-1','cell-1','tenant-1','{}','{}','{}',7,{index},{size},decode('{}','hex'),'{handle}',{},{},{},{})).*",
        uuid(1000, "0123456789ab"),
        uuid(1001, "0223456789ab"),
        uuid(1002, "0323456789ab"),
        hex(digest),
        caps.0,
        caps.1,
        caps.2,
        caps.3
    )
}
async fn user(c: &tokio_postgres::Client, r: &str) {
    c.batch_execute(&format!("SET SESSION AUTHORIZATION {r}"))
        .await
        .unwrap()
}
async fn reset(c: &tokio_postgres::Client) {
    c.batch_execute("RESET SESSION AUTHORIZATION")
        .await
        .unwrap()
}
async fn serial(
    c: &tokio_postgres::Client,
    s: &str,
) -> Result<tokio_postgres::Row, tokio_postgres::Error> {
    c.batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE")
        .await?;
    let r = c.query_one(s, &[]).await;
    c.batch_execute(if r.is_ok() { "COMMIT" } else { "ROLLBACK" })
        .await?;
    r
}
async fn install(c: &tokio_postgres::Client, s: &str) -> String {
    user(c, "object_dispatch_retention_migrator").await;
    let v = serial(c, s).await.unwrap().get(0);
    reset(c).await;
    v
}
fn msg(e: &tokio_postgres::Error) -> &str {
    e.as_db_error().map(|d| d.message()).unwrap_or("untyped")
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_spool_ready_is_atomic_replay_safe_and_source_dark() {
    let url = std::env::var("LORE_TEST_LOCAL_PUT_SPOOL_READY_MUTATION_PG_URL")
        .expect("LORE_TEST_LOCAL_PUT_SPOOL_READY_MUTATION_PG_URL must name a fresh database");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect spool-ready mutation database");
    let _connection = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "put-spool-ready-mutation-postgres",
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
        client.batch_execute(sql).await.expect("base migration");
    }
    assert_eq!(install(&client,&format!("SELECT (object_store_retention.object_store_retention_install_v1('object-store-retention-provisioning-v1','object-store-retention-authority-schema-v1',decode('{RETENTION}','hex'),1)).result_code")).await,"CREATED");
    assert_eq!(install(&client,&format!("SELECT (object_store_retention.object_store_dispatch_authority_install_v1('object-store-dispatch-authority-provisioning-v1','object-store-dispatch-authority-schema-v1',decode('{AUTHORITY}','hex'),1)).result_code")).await,"CREATED");
    for sql in [
        include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql"),
        include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql"),
        include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql"),
    ] {
        client
            .batch_execute(sql)
            .await
            .expect("PUT schema migration");
    }
    assert_eq!(install(&client,&format!("SELECT (object_store_retention.object_store_dispatch_put_reservation_install_v1('object-store-dispatch-put-reservation-provisioning-v1','object-store-dispatch-put-reservation-schema-v1',decode('{PUT}','hex'),1)).result_code")).await,"CREATED");
    for sql in [
        include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"),
        include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql"),
        include_str!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql"),
        include_str!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql"),
        include_str!("../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql"),
        include_str!("../migrations/0017_object_store_dispatch_put_spool_ready_mutation.sql"),
    ] {
        client.batch_execute(sql).await.expect("mutation chain");
    }
    client.batch_execute("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint';").await.expect("freeze clock");

    let limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 4096,
        max_canonical_row_bytes: 16_777_216,
    };
    let reserved10 = validate_and_encode_object_store_reserve_put_ack(&ack(10, false), &limits)
        .expect("reserved ACK");
    let ready10 = validate_and_encode_object_store_reserve_put_ack(&ack(10, true), &limits)
        .expect("ready ACK");
    let reserved0 = validate_and_encode_object_store_reserve_put_ack(&ack(0, false), &limits)
        .expect("zero reserved ACK");
    let ready0 = validate_and_encode_object_store_reserve_put_ack(&ack(0, true), &limits)
        .expect("zero ready ACK");
    let q10 = quota(10);
    let q0 = quota(0);
    let child10 = spool_child(10);
    let child0 = spool_child(0);
    let initial10 = row(
        reserved10.canonical_bytes(),
        reserved10.ack_blake3(),
        10,
        (0, 0, 0),
        1,
        false,
    );
    let progress3 = row(
        reserved10.canonical_bytes(),
        reserved10.ack_blake3(),
        10,
        (3, 1, 1),
        2,
        false,
    );
    let progress6 = row(
        reserved10.canonical_bytes(),
        reserved10.ack_blake3(),
        10,
        (6, 2, 1),
        3,
        false,
    );
    let final10 = row(
        ready10.canonical_bytes(),
        ready10.ack_blake3(),
        10,
        (0, 0, 0),
        4,
        true,
    );
    let initial0 = row(
        reserved0.canonical_bytes(),
        reserved0.ack_blake3(),
        0,
        (0, 0, 0),
        1,
        false,
    );
    let final0 = row(
        ready0.canonical_bytes(),
        ready0.ack_blake3(),
        0,
        (0, 0, 0),
        2,
        true,
    );
    let preimages: [&[u8]; 12] = [
        &q10,
        &q0,
        reserved10.canonical_preimage(),
        ready10.canonical_preimage(),
        reserved0.canonical_preimage(),
        ready0.canonical_preimage(),
        &child10,
        &child0,
        &initial10,
        &progress3,
        &progress6,
        &final10,
    ];
    let mut vectors: Vec<(&[u8], [u8; 32])> = preimages
        .iter()
        .map(|p| (*p, *blake3::hash(p).as_bytes()))
        .collect();
    vectors.push((&initial0, *blake3::hash(&initial0).as_bytes()));
    vectors.push((&final0, *blake3::hash(&final0).as_bytes()));
    let refs = vectors
        .iter()
        .map(|(p, d)| (*p, d.as_slice()))
        .collect::<Vec<_>>();
    let provider_sql = provider(&refs);
    client
        .batch_execute(&provider_sql)
        .await
        .expect("genuine exact-preimage BLAKE3 provider");

    user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        serial(&client, &reserve(10))
            .await
            .expect("reserve")
            .get::<_, String>(0),
        "CREATED"
    );
    assert_eq!(
        serial(&client, &progress(0, 3))
            .await
            .expect("first progress")
            .get::<_, String>(0),
        "APPLIED"
    );
    reset(&client).await;
    let before=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.expect("snapshot");
    user(&client, "object_dispatch_retention_runtime").await;
    for (label, sql, expected) in [
        (
            "old index",
            final_sql(
                0,
                10,
                &BODY,
                "put/body-final",
                (256, 4096, 4096, 16_777_216),
            ),
            "DISPATCH_PUT_SPOOL_READY_REPLAY_CONFLICT",
        ),
        (
            "gap",
            final_sql(
                2,
                10,
                &BODY,
                "put/body-final",
                (256, 4096, 4096, 16_777_216),
            ),
            "DISPATCH_PUT_UPLOAD_CHUNK_GAP",
        ),
        (
            "oversized remainder",
            final_sql(
                1,
                10,
                &BODY,
                "put/body-final",
                (256, 4096, 4096, 16_777_216),
            ),
            "DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT",
        ),
        (
            "size",
            final_sql(1, 9, &BODY, "put/body-final", (256, 4096, 4096, 16_777_216)),
            "DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT",
        ),
        (
            "digest",
            final_sql(
                1,
                10,
                &[0x32; 32],
                "put/body-final",
                (256, 4096, 4096, 16_777_216),
            ),
            "DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT",
        ),
        (
            "bad cap",
            final_sql(1, 10, &BODY, "put/body-final", (0, 4096, 4096, 16_777_216)),
            "DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT",
        ),
    ] {
        let error = serial(&client, &sql).await.expect_err(label);
        assert_eq!(msg(&error), expected, "{label}");
    }
    reset(&client).await;
    let after=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.expect("unchanged snapshot");
    assert_eq!(before.get::<_, String>(0), after.get::<_, String>(0));
    assert_eq!(before.get::<_, String>(1), after.get::<_, String>(1));
    user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        serial(&client, &progress(1, 6))
            .await
            .expect("second progress")
            .get::<_, String>(0),
        "APPLIED"
    );

    reset(&client).await;
    let pre_final=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.expect("pre-final snapshot");
    for (clock, expected) in [
        (3000, "UPLOAD_CLOSED"),
        (1999, "DISPATCH_PUT_SPOOL_READY_TIME_INVALID"),
    ] {
        client.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {clock}::bigint';")).await.expect("move clock");
        user(&client, "object_dispatch_retention_runtime").await;
        assert_eq!(
            msg(&serial(
                &client,
                &final_sql(
                    2,
                    10,
                    &BODY,
                    "put/body-final",
                    (256, 4096, 4096, 16_777_216)
                )
            )
            .await
            .expect_err("clock rejection")),
            expected
        );
        reset(&client).await;
    }
    client.batch_execute("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint'; CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS 'SELECT NULL::bytea';").await.expect("break provider");
    user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        msg(&serial(
            &client,
            &final_sql(
                2,
                10,
                &BODY,
                "put/body-final",
                (256, 4096, 4096, 16_777_216)
            )
        )
        .await
        .expect_err("provider failure")),
        "LOCAL_BLAKE3_PROVIDER_INVALID_RESULT"
    );
    reset(&client).await;
    client
        .batch_execute(&provider_sql)
        .await
        .expect("restore provider");
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET canonical_record_bytes=decode($1,'hex'),record_blake3=decode($2,'hex')",&[&hex(&done(&initial10)),&hex(blake3::hash(&initial10).as_bytes())]).await.expect("tamper authenticated record");
    user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        msg(&serial(
            &client,
            &final_sql(
                2,
                10,
                &BODY,
                "put/body-final",
                (256, 4096, 4096, 16_777_216)
            )
        )
        .await
        .expect_err("stored record tamper")),
        "DISPATCH_RESERVED_PUT_STORED_RECORD_MISMATCH"
    );
    reset(&client).await;
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET canonical_record_bytes=decode($1,'hex'),record_blake3=decode($2,'hex')",&[&hex(&done(&progress6)),&hex(blake3::hash(&progress6).as_bytes())]).await.expect("restore authenticated record");
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET reserve_put_ack_canonical_bytes=$1::bytea,reserve_put_ack_blake3=$2::bytea",&[&reserved0.canonical_bytes(),&reserved0.ack_blake3().as_slice()]).await.expect("tamper current ACK");
    user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        msg(&serial(
            &client,
            &final_sql(
                2,
                10,
                &BODY,
                "put/body-final",
                (256, 4096, 4096, 16_777_216)
            )
        )
        .await
        .expect_err("stored ACK tamper")),
        "LOCAL_PUT_RESERVATION_ACK_MISMATCH"
    );
    reset(&client).await;
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET reserve_put_ack_canonical_bytes=$1::bytea,reserve_put_ack_blake3=$2::bytea",&[&reserved10.canonical_bytes(),&reserved10.ack_blake3().as_slice()]).await.expect("restore current ACK");
    user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        msg(&serial(
            &client,
            &final_sql(2, 10, &BODY, "", (256, 4096, 4096, 16_777_216))
        )
        .await
        .expect_err("bad handle")),
        "LOCAL_CANONICAL_TEXT_INVALID"
    );
    reset(&client).await;
    let post_rejections=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.expect("post-rejection snapshot");
    assert_eq!(
        pre_final.get::<_, String>(0),
        post_rejections.get::<_, String>(0)
    );
    assert_eq!(
        pre_final.get::<_, String>(1),
        post_rejections.get::<_, String>(1)
    );

    let (peer, peer_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("peer");
    let _peer_connection =
        AbortOnDropHandle::new(lore_base::lore_spawn!("spool-ready-peer", async move {
            let _ = peer_connection.await;
        }));
    user(&client, "object_dispatch_retention_runtime").await;
    user(&peer, "object_dispatch_retention_runtime").await;
    let finish = final_sql(
        2,
        10,
        &BODY,
        "put/body-final",
        (256, 4096, 4096, 16_777_216),
    );
    let (left, right) = tokio::join!(serial(&client, &finish), serial(&peer, &finish));
    let loser = match (left, right) {
        (Ok(a), Err(e)) => {
            assert_eq!(a.get::<_, String>(0), "APPLIED");
            (e, &peer)
        }
        (Err(e), Ok(a)) => {
            assert_eq!(a.get::<_, String>(0), "APPLIED");
            (e, &client)
        }
        (a, b) => panic!("expected APPLIED/40001, got {a:?}/{b:?}"),
    };
    assert_eq!(
        loser.0.as_db_error().expect("typed loser").code().code(),
        "40001"
    );
    assert_eq!(
        serial(loser.1, &finish)
            .await
            .expect("loser retry")
            .get::<_, String>(0),
        "REPLAY"
    );
    reset(&client).await;
    reset(&peer).await;
    let stored=client.query_one("SELECT lifecycle_state,partial_temp_bytes::text,partial_temp_chunks::text,partial_temp_files::text,spool_revision::text,reserve_put_ack_canonical_bytes,reserve_put_ack_blake3,canonical_record_bytes,record_blake3,committed_size::text,committed_blake3,durable_handle,ready_at_unix_ms::text FROM object_store_retention.object_dispatch_spool_objects",&[]).await.expect("ready row");
    assert_eq!(
        (
            stored.get::<_, i16>(0),
            stored.get::<_, String>(1),
            stored.get::<_, String>(2),
            stored.get::<_, String>(3),
            stored.get::<_, String>(4)
        ),
        (2, "0".into(), "0".into(), "0".into(), "4".into())
    );
    assert_eq!(stored.get::<_, Vec<u8>>(5), ready10.canonical_bytes());
    assert_eq!(stored.get::<_, Vec<u8>>(6), ready10.ack_blake3());
    assert_eq!(stored.get::<_, Vec<u8>>(7), done(&final10));
    assert_eq!(
        stored.get::<_, Vec<u8>>(8),
        blake3::hash(&final10).as_bytes()
    );
    assert_eq!(
        (
            stored.get::<_, String>(9),
            stored.get::<_, Vec<u8>>(10),
            stored.get::<_, String>(11),
            stored.get::<_, String>(12)
        ),
        (
            "10".into(),
            BODY.to_vec(),
            "put/body-final".into(),
            "2000".into()
        )
    );
    let quota_after_final:String=client.query_one("SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q",&[]).await.expect("quota after final").get(0);
    assert_eq!(quota_after_final, pre_final.get::<_, String>(1));
    user(&client, "object_dispatch_retention_runtime").await;
    client.batch_execute("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 9999::bigint';").await.expect_err("runtime cannot replace clock");
    assert_eq!(
        serial(
            &client,
            &final_sql(2, 10, &BODY, "put/body-final", (1, 1, 1, 1))
        )
        .await
        .expect("replay ignores expiry and maxima drift")
        .get::<_, String>(0),
        "REPLAY"
    );
    for sql in [
        final_sql(1, 10, &BODY, "put/body-final", (1, 1, 1, 1)),
        final_sql(2, 9, &BODY, "put/body-final", (1, 1, 1, 1)),
        final_sql(2, 10, &[0x32; 32], "put/body-final", (1, 1, 1, 1)),
        final_sql(2, 10, &BODY, "put/other", (1, 1, 1, 1)),
    ] {
        assert_eq!(
            msg(&serial(&client, &sql).await.expect_err("changed replay")),
            "DISPATCH_PUT_SPOOL_READY_REPLAY_CONFLICT"
        );
    }
    reset(&client).await;

    // Build a second, fully authenticated RESERVED target from the finalized row while retaining
    // the first row as a durable-handle blocker. The mutation must surface PostgreSQL's typed
    // uniqueness rejection and its transaction must leave the target and all quota counters exact.
    client
        .batch_execute(&format!(
            "UPDATE object_store_retention.object_dispatch_spool_objects SET
               spool_object_id='{}',logical_request_id='{}',attempt_id='{}',upload_id='{}';
             CREATE TEMP TABLE duplicate_handle_target AS
               SELECT * FROM object_store_retention.object_dispatch_spool_objects;",
            uuid(1103, "1423456789ab"),
            uuid(1100, "1123456789ab"),
            uuid(1101, "1223456789ab"),
            uuid(1102, "1323456789ab")
        ))
        .await
        .expect("create duplicate-handle blocker and target template");
    client
        .execute(
            "UPDATE duplicate_handle_target SET
      spool_object_id=$1::text::uuid,logical_request_id=$2::text::uuid,attempt_id=$3::text::uuid,upload_id=$4::text::uuid,
      lifecycle_state=1,committed_size=NULL,committed_blake3=NULL,durable_handle=NULL,
      partial_temp_bytes=6,partial_temp_chunks=2,partial_temp_files=1,
      reserve_put_ack_canonical_bytes=$5::bytea,reserve_put_ack_blake3=$6::bytea,
      canonical_record_bytes=$7::bytea,record_blake3=$8::bytea,spool_revision=3,ready_at_unix_ms=NULL",
            &[
                &uuid(1003, "0423456789ab"),
                &uuid(1000, "0123456789ab"),
                &uuid(1001, "0223456789ab"),
                &uuid(1002, "0323456789ab"),
                &reserved10.canonical_bytes(),
                &reserved10.ack_blake3().as_slice(),
                &done(&progress6),
                &blake3::hash(&progress6).as_bytes().as_slice(),
            ],
        )
        .await
        .expect("authenticate duplicate-handle target");
    client.batch_execute("INSERT INTO object_store_retention.object_dispatch_spool_objects SELECT * FROM duplicate_handle_target; DROP TABLE duplicate_handle_target;").await.expect("insert duplicate-handle target");
    let duplicate_before=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s WHERE logical_request_id=$1::text::uuid",&[&uuid(1000,"0123456789ab")]).await.expect("duplicate target snapshot");
    user(&client, "object_dispatch_retention_runtime").await;
    let duplicate = serial(&client, &finish)
        .await
        .expect_err("duplicate durable handle");
    assert_eq!(
        duplicate
            .as_db_error()
            .expect("typed duplicate")
            .code()
            .code(),
        "23505"
    );
    reset(&client).await;
    let duplicate_after=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s WHERE logical_request_id=$1::text::uuid",&[&uuid(1000,"0123456789ab")]).await.expect("duplicate target unchanged");
    assert_eq!(
        duplicate_before.get::<_, String>(0),
        duplicate_after.get::<_, String>(0)
    );
    assert_eq!(
        duplicate_before.get::<_, String>(1),
        duplicate_after.get::<_, String>(1)
    );

    client.batch_execute("DELETE FROM object_store_retention.object_dispatch_spool_objects; UPDATE object_store_retention.object_dispatch_quota_usage SET used_bytes=0,used_rows=0,used_concurrency=0,updated_at_unix_ms=0,counter_revision=1; CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint';").await.expect("reset zero flow");
    user(&client, "object_dispatch_retention_runtime").await;
    assert_eq!(
        serial(&client, &reserve(0))
            .await
            .expect("zero reserve")
            .get::<_, String>(0),
        "CREATED"
    );
    assert_eq!(
        serial(
            &client,
            &final_sql(0, 0, &BODY, "put/body-final", (256, 4096, 4096, 16_777_216))
        )
        .await
        .expect("zero final")
        .get::<_, String>(0),
        "APPLIED"
    );
    reset(&client).await;
    let zero=client.query_one("SELECT lifecycle_state,spool_revision::text,canonical_record_bytes,record_blake3 FROM object_store_retention.object_dispatch_spool_objects",&[]).await.expect("zero row");
    assert_eq!(
        (zero.get::<_, i16>(0), zero.get::<_, String>(1)),
        (2, "2".into())
    );
    assert_eq!(zero.get::<_, Vec<u8>>(2), done(&final0));
    assert_eq!(zero.get::<_, Vec<u8>>(3), blake3::hash(&final0).as_bytes());

    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET
      lifecycle_state=1,committed_size=NULL,committed_blake3=NULL,durable_handle=NULL,ready_at_unix_ms=NULL,
      expected_size=18446744073709551615,quota_bytes=18446744073709551615,max_chunk_bytes=1,
      partial_temp_bytes=18446744073709551614,partial_temp_chunks=18446744073709551614,
      partial_temp_files=1,spool_revision=18446744073709551615",&[]).await.expect("prepare near-u64 lifecycle-1 fields");
    let mechanics_provider = provider_sql.replacen(
        "ELSE NULL::bytea",
        "ELSE pg_catalog.decode(pg_catalog.repeat('00',32),'hex')",
        1,
    );
    client
        .batch_execute(&mechanics_provider)
        .await
        .expect("install mechanics-only provider");
    user(&client, "object_dispatch_retention_owner").await;
    let mechanics_quota = client
        .query_one(
            "SELECT object_store_retention.local_quota_child_v1(18446744073709551615,1,1,16777216)",
            &[],
        )
        .await
        .expect("derive near-u64 quota preimage");
    reset(&client).await;
    let mechanics_quota_bytes = mechanics_quota.get::<_, Vec<u8>>(0);
    let quota_preimage = &mechanics_quota_bytes[..mechanics_quota_bytes.len() - 32];
    let quota_digest = *blake3::hash(quota_preimage).as_bytes();
    let quota_case = format!(
        "WHEN '{}' THEN pg_catalog.decode('{}','hex') ",
        hex(quota_preimage),
        hex(&quota_digest)
    );
    let provider_with_quota = provider_sql.replacen(
        "ELSE NULL::bytea",
        &format!("{quota_case}ELSE pg_catalog.decode(pg_catalog.repeat('00',32),'hex')"),
        1,
    );
    client
        .batch_execute(&provider_with_quota)
        .await
        .expect("install genuine near-u64 quota mapping");
    user(&client, "object_dispatch_retention_owner").await;
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
        .expect("derive near-u64 ACK preimage");
    reset(&client).await;
    let mechanics_ack_bytes = mechanics_ack.get::<_, Vec<u8>>(0);
    let ack_preimage = &mechanics_ack_bytes[..mechanics_ack_bytes.len() - 32];
    let ack_digest = *blake3::hash(ack_preimage).as_bytes();
    let ack_case = format!(
        "WHEN '{}' THEN pg_catalog.decode('{}','hex') ",
        hex(ack_preimage),
        hex(&ack_digest)
    );
    let provider_with_ack = provider_sql.replacen(
        "ELSE NULL::bytea",
        &format!("{quota_case}{ack_case}ELSE pg_catalog.decode(pg_catalog.repeat('00',32),'hex')"),
        1,
    );
    client
        .batch_execute(&provider_with_ack)
        .await
        .expect("install genuine near-u64 ACK mapping");
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET reserve_put_ack_canonical_bytes=$1::bytea,reserve_put_ack_blake3=$2::bytea",&[&done(ack_preimage),&ack_digest.as_slice()]).await.expect("install near-u64 ACK");
    user(&client, "object_dispatch_retention_owner").await;
    let mechanics_record=client.query_one("SELECT (object_store_retention.local_put_reserved_record_v2(
      s.protocol_revision,s.policy_revision,s.provider_boundary_id,s.authenticated_cell_id,
      s.authenticated_tenant_id,s.spool_object_id,s.logical_request_id,s.attempt_id,s.upload_id,
      s.upload_fence,s.boundary_blake3,s.boundary_token,s.observation_binding_blake3,s.expected_size,
      s.expected_blake3,s.partial_temp_bytes,s.partial_temp_chunks,s.partial_temp_files,
      s.put_reservation_fingerprint,s.allocation_revision,s.allocation_fence,
      s.reservation_deadline_unix_ms,s.allocation_hard_expiry_unix_ms,s.admission_clock_unix_ms,
      s.prepared_ttl_ms,s.expires_at_unix_ms,s.max_chunk_bytes,s.quota_bytes,s.quota_rows,
      s.quota_concurrency,s.quota_revision,s.reserve_put_ack_canonical_bytes,
      s.reserve_put_ack_blake3,s.spool_revision,1024,4096,16777216)).*
      FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.expect("derive near-u64 row preimage");
    reset(&client).await;
    let mechanics_record_bytes = mechanics_record.get::<_, Vec<u8>>(0);
    let record_preimage = &mechanics_record_bytes[..mechanics_record_bytes.len() - 32];
    let record_digest = *blake3::hash(record_preimage).as_bytes();
    let record_case = format!(
        "WHEN '{}' THEN pg_catalog.decode('{}','hex') ",
        hex(record_preimage),
        hex(&record_digest)
    );
    let extreme_provider = provider_sql.replacen(
        "ELSE NULL::bytea",
        &format!("{quota_case}{ack_case}{record_case}ELSE NULL::bytea"),
        1,
    );
    client
        .batch_execute(&extreme_provider)
        .await
        .expect("install genuine near-u64 row mapping");
    client.execute("UPDATE object_store_retention.object_dispatch_spool_objects SET canonical_record_bytes=$1::bytea,record_blake3=$2::bytea",&[&done(record_preimage),&record_digest.as_slice()]).await.expect("authenticate near-u64 row");
    let overflow_before=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.expect("overflow snapshot");
    user(&client, "object_dispatch_retention_runtime").await;
    let overflow = serial(
        &client,
        &final_sql(
            u64::MAX - 1,
            u64::MAX,
            &BODY,
            "x",
            (1024, 4096, 1, 16_777_216),
        ),
    )
    .await
    .expect_err("revision overflow");
    assert_eq!(
        overflow
            .as_db_error()
            .expect("typed overflow")
            .code()
            .code(),
        "22003"
    );
    assert_eq!(msg(&overflow), "DISPATCH_PUT_SPOOL_READY_COUNTER_OVERFLOW");
    reset(&client).await;
    let overflow_after=client.query_one("SELECT row_to_json(s)::text,(SELECT json_agg(row_to_json(q) ORDER BY scope_kind,scope_id)::text FROM object_store_retention.object_dispatch_quota_usage q) FROM object_store_retention.object_dispatch_spool_objects s",&[]).await.expect("overflow unchanged");
    assert_eq!(
        overflow_before.get::<_, String>(0),
        overflow_after.get::<_, String>(0)
    );
    assert_eq!(
        overflow_before.get::<_, String>(1),
        overflow_after.get::<_, String>(1)
    );

    for role in [
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        user(&client, role).await;
        for sql in [
            &final_sql(0, 0, &BODY, "put/body-final", (256, 4096, 4096, 16_777_216)),
            "SELECT object_store_retention.assert_dispatch_put_spool_ready_api_revision_v1('x')",
            "SELECT object_store_retention.project_dispatch_put_spool_ready_v1(NULL,'APPLIED')",
            "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
            "UPDATE object_store_retention.object_dispatch_spool_objects SET spool_revision=spool_revision",
        ] {
            assert_eq!(
                client
                    .execute(sql, &[])
                    .await
                    .expect_err("role denied")
                    .as_db_error()
                    .expect("typed role ACL")
                    .code()
                    .code(),
                "42501"
            );
        }
        reset(&client).await;
    }
    user(&client, "object_dispatch_retention_runtime").await;
    for sql in [
        "SELECT object_store_retention.assert_dispatch_put_spool_ready_api_revision_v1('x')",
        "SELECT object_store_retention.project_dispatch_put_spool_ready_v1(NULL,'APPLIED')",
        "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
        "UPDATE object_store_retention.object_dispatch_spool_objects SET spool_revision=spool_revision",
    ] {
        assert_eq!(
            client
                .execute(sql, &[])
                .await
                .expect_err("runtime helper/table denied")
                .as_db_error()
                .expect("typed runtime ACL")
                .code()
                .code(),
            "42501"
        );
    }
    reset(&client).await;
}

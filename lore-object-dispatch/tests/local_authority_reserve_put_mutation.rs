// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static and opt-in PostgreSQL 16 contract for the source-dark atomic ReservePut mutation.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::local_authority_reserve_put_mutation::LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_reserve_put_mutation::LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1;
use lore_object_dispatch::local_authority_reserve_put_mutation::validate_embedded_local_authority_reserve_put_mutation_migration_v1;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 23_166;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "eb5d413b9d5dd5d45802b3acaca193cc6b5ac783e38a4c00002a9f9abf77ed7a";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1)
        .expect("ReservePut mutation migration must remain UTF-8 SQL")
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
        LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_reserve_put_mutation_migration_v1());
}

#[test]
fn migration_is_one_owner_transaction_with_five_fixed_security_definers() {
    let sql = migration();
    assert!(sql.starts_with("-- Copyright 2026 Tideshift Labs\n"));
    assert!(sql.ends_with("\nCOMMIT;\n"));
    assert_eq!(sql.matches("\nBEGIN;\n").count(), 1);
    assert_eq!(sql.matches("\nCOMMIT;\n").count(), 1);
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 5);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 5);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 5);
    assert!(!sql.contains("CREATE TABLE"));
    assert!(!sql.contains("ALTER TABLE"));
}

#[test]
fn entrypoint_authorizes_before_api_transaction_schema_and_input_validation() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    let auth = body
        .find("PERFORM object_store_retention.assert_dispatch_runtime_v1();")
        .expect("runtime auth");
    let api = body
        .find("assert_dispatch_reserve_put_api_revision_v1(api_revision)")
        .expect("API check");
    let transaction = body
        .find("assert_serializable_write_v1()")
        .expect("transaction check");
    let schema = body
        .find("SELECT * INTO STRICT schema_state")
        .expect("schema check");
    let input = body
        .find("IF provider_boundary_id IS NULL")
        .expect("input check");
    assert!(auth < api && api < transaction && transaction < schema && schema < input);
}

#[test]
fn lock_order_is_schema_then_exact_spool_then_three_quota_scopes() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    let schema = body
        .find("WHERE singleton\n   FOR SHARE;")
        .expect("schema lock");
    let spool = body
        .find("AND spool.payload_kind = 1\n   FOR UPDATE;")
        .expect("spool lock");
    let quota = body
        .find("ORDER BY quota.scope_kind\n     FOR UPDATE")
        .expect("quota locks");
    assert!(schema < spool && spool < quota);
    assert!(body.contains("locked_quota_rows <> 3"));
    assert!(body.contains("affected_quota_rows <> 3"));
}

#[test]
fn uuidv7_windows_are_inclusive_and_overflow_safe() {
    let sql = migration();
    let body = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    assert!(sql.contains("RAISE EXCEPTION 'INVALID_UUIDV7' USING ERRCODE = '22023'"));
    assert!(body.contains("RAISE EXCEPTION 'UUIDV7_TIMESTAMP_TOO_FAR_IN_FUTURE'"));
    assert!(body.contains("RAISE EXCEPTION 'EXPIRED_OR_UNKNOWN' USING ERRCODE = '22023'"));
    assert!(body.contains("greatest(0, admission_clock - 31536000000)"));
    assert!(body.contains("uuid_upper_unix_ms := admission_clock + 300000"));
    assert!(body.contains("logical_request_unix_ms > uuid_upper_unix_ms"));
    assert!(body.contains("logical_request_unix_ms < uuid_lower_unix_ms"));
    assert!(body.contains("admission_clock > 9223372036854475807"));
}

#[test]
fn expiry_uses_checked_exact_minimum_with_ties_allowed() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    for required in [
        "prepared_expiry := admission_clock::numeric + prepared_ttl_ms::numeric",
        "prepared_expiry > 9223372036854775807",
        "expires_at := least(\n    reservation_deadline_unix_ms,\n    allocation_hard_expiry_unix_ms,\n    prepared_expiry::bigint\n  );",
    ] {
        assert!(body.contains(required), "missing expiry rule: {required}");
    }
}

#[test]
fn quota_capacity_pins_max_plus_low_water_for_every_scope_and_dimension() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    for scope in ["global", "cell", "tenant"] {
        for (used, delta) in [
            ("used_bytes", "expected_size"),
            ("used_rows", "1"),
            ("used_concurrency", "1"),
        ] {
            assert!(body.contains(&format!(
                "quota_counter.{used} + {delta} + {scope}_low_water_{} > {scope}_max_{}",
                used.trim_start_matches("used_"),
                used.trim_start_matches("used_")
            )));
        }
    }
    assert!(body.contains("quota_counter.counter_revision = 18446744073709551615"));
    assert!(body.contains("DISPATCH_RESERVE_PUT_COUNTER_OVERFLOW"));
    assert!(body.contains("DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED"));
}

#[test]
fn quota_initialization_and_update_are_exact_three_scope_atomic() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    for scope in [
        "provider_boundary_id, 1,\n     provider_boundary_id",
        "provider_boundary_id, 2,\n     authenticated_cell_id",
        "provider_boundary_id, 3,\n     authenticated_tenant_id",
    ] {
        assert!(body.contains(scope), "missing quota scope: {scope}");
    }
    assert!(body.contains("used_bytes = quota.used_bytes + expected_size"));
    assert!(body.contains("used_rows = quota.used_rows + 1"));
    assert!(body.contains("used_concurrency = quota.used_concurrency + 1"));
    assert!(
        body.find("UPDATE object_store_retention.object_dispatch_quota_usage")
            < body.find("INSERT INTO object_store_retention.object_dispatch_spool_objects")
    );
}

#[test]
fn replay_precedes_mutable_validation_and_charging_but_conflicts_stable_intent() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    let replay = body.find("IF FOUND THEN").expect("replay branch");
    let validation = body
        .find("IF provider_boundary_id IS NULL")
        .expect("first-seen validation");
    let quota = body
        .find("INSERT INTO object_store_retention.object_dispatch_quota_usage")
        .expect("quota mutation");
    assert!(replay < validation && validation < quota);
    for stable in [
        "stored.protocol_revision IS DISTINCT FROM protocol_revision",
        "stored.spool_object_id IS DISTINCT FROM spool_object_id",
        "stored.provider_boundary_id IS DISTINCT FROM provider_boundary_id",
        "stored.authenticated_cell_id IS DISTINCT FROM authenticated_cell_id",
        "stored.authenticated_tenant_id IS DISTINCT FROM authenticated_tenant_id",
        "stored.upload_id IS DISTINCT FROM upload_id",
        "stored.upload_fence IS DISTINCT FROM upload_fence",
        "stored.boundary_blake3 IS DISTINCT FROM boundary_blake3",
        "stored.boundary_token IS DISTINCT FROM boundary_token",
        "stored.observation_binding_blake3 IS DISTINCT FROM observation_binding_blake3",
        "stored.expected_size IS DISTINCT FROM expected_size",
        "stored.expected_blake3 IS DISTINCT FROM expected_blake3",
        "stored.put_reservation_fingerprint IS DISTINCT FROM put_reservation_fingerprint",
        "stored.reservation_deadline_unix_ms IS DISTINCT FROM reservation_deadline_unix_ms",
    ] {
        assert!(
            body.contains(stable),
            "missing stable replay field: {stable}"
        );
    }
    for mutable in [
        "stored.policy_revision",
        "stored.allocation_revision",
        "stored.allocation_fence",
    ] {
        assert!(
            !body.contains(mutable),
            "mutable replay field became conflicting: {mutable}"
        );
    }
    assert!(body.contains("project_dispatch_reserved_put_v1(stored, 'REPLAY')"));
}

#[test]
fn created_row_persists_exact_ack_record_and_zero_byte_quota_shape() {
    let body = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.object_store_dispatch_reserve_put_v1(",
    );
    assert!(body.contains("ack_record := object_store_retention.local_reserve_put_ack_v1("));
    assert!(
        body.contains("spool_record := object_store_retention.local_put_reservation_record_v1(")
    );
    assert!(body.contains("expected_size,\n    1,\n    1,\n    quota_revision"));
    assert!(body.contains("ack_record.canonical_bytes, ack_record.record_blake3"));
    assert!(body.contains("spool_record.canonical_bytes, spool_record.record_blake3, 1"));
    assert!(!body.contains("expected_size = 0"));
}

#[test]
fn acl_grants_runtime_only_main_entrypoint_and_no_tables() {
    let sql = migration();
    assert_eq!(sql.matches("GRANT EXECUTE ON FUNCTION").count(), 1);
    assert!(sql.contains("object_store_retention.object_store_dispatch_reserve_put_v1("));
    assert!(sql.contains(") TO object_dispatch_retention_runtime;"));
    assert!(sql.contains(
        "REVOKE ALL ON ALL TABLES IN SCHEMA object_store_retention FROM\n  object_dispatch_retention_runtime,"
    ));
    assert!(!sql.contains("GRANT SELECT"));
    assert!(!sql.contains("GRANT INSERT"));
    assert!(!sql.contains("GRANT UPDATE"));
}

#[test]
fn artifact_is_embedded_only_and_runtime_source_dark() {
    let module = include_str!("../src/local_authority_reserve_put_mutation.rs");
    let library = include_str!("../src/lib.rs");
    assert!(module.contains(
        "include_bytes!(\"../migrations/0013_object_store_dispatch_reserve_put_mutation.sql\")"
    ));
    assert!(library.contains("pub mod local_authority_reserve_put_mutation;"));
    for forbidden in ["tokio_postgres", "batch_execute", ".execute(", ".await"] {
        assert!(!module.contains(forbidden));
    }
    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    // Narrowed by WP-114 CD-3, recorded in WP-114: `src/dispatch_client.rs` is the sanctioned
    // typed caller of this procedure, so it is the one file allowed to name it - the same shape as
    // the installer exclusion in the dispatcher-identity tier. The claim this test still makes, and
    // the one that matters, is that no OTHER crate source calls it. That the typed client itself is
    // composed nowhere is asserted by `tests/dispatch_client.rs`.
    let sanctioned = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("dispatch_client.rs");
    let mut sanctioned_seen = false;
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read production source");
        // The exemption is per-check, not per-file, so any assertion added to this loop later still
        // applies to the typed client.
        if path == sanctioned {
            sanctioned_seen = source.contains("object_store_dispatch_reserve_put_v1(");
        } else {
            assert!(
                !source.contains("object_store_dispatch_reserve_put_v1("),
                "runtime source {} calls source-dark mutation",
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
const ADMISSION: i64 = 2_000;
const BOUNDARY: [u8; 32] = [0x41; 32];
const OBSERVATION: [u8; 32] = [0x51; 32];
const BODY: [u8; 32] = [0x31; 32];
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

fn quota_preimage(expected_size: u64) -> Vec<u8> {
    let mut value = b"object-store-quota-units-v1\0".to_vec();
    for item in [expected_size, 1, 1] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    value
}

fn ack_fixture_for(call: &Call<'_>) -> ReservePutAckV1 {
    ReservePutAckV1 {
        protocol_revision: call.protocol.into(),
        policy_revision: call.policy.into(),
        provider_boundary_id: "boundary-1".into(),
        authenticated_cell_id: "cell-1".into(),
        authenticated_tenant_id: "tenant-1".into(),
        logical_request_id: call.logical.into(),
        attempt_id: call.attempt.into(),
        upload_id: uuid_v7(1_002, "0323456789ab"),
        upload_fence: 7,
        state: PutReservationStateV1::PutReservationStateReserved as i32,
        reserved_quota: Some(ObjectStoreQuotaUnitsV1 {
            bytes: call.expected_size,
            rows: 1,
            concurrency: 1,
        }),
        expires_at_unix_ms: call
            .deadline
            .min(call.hard_expiry)
            .min(ADMISSION + call.ttl),
        max_chunk_bytes: 16,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: ADMISSION,
        allocation_hard_expiry_unix_ms: call.hard_expiry,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    }
}

fn row_preimage_for(call: &Call<'_>, ack: &[u8], ack_digest: &[u8]) -> Vec<u8> {
    let mut value = b"object-store-dispatch-put-reservation-row-v1\0".to_vec();
    for text in [
        "object-store-dispatch-authority-schema-v1",
        call.protocol,
        call.policy,
        "boundary-1",
        "cell-1",
        "tenant-1",
        &uuid_v7(1_003, "0423456789ab"),
        call.logical,
        call.attempt,
        &uuid_v7(1_002, "0323456789ab"),
    ] {
        push_text(&mut value, text);
    }
    value.extend_from_slice(&7_u64.to_be_bytes());
    value.extend_from_slice(&[1, 1, 1, 1]);
    value.extend_from_slice(&BOUNDARY);
    push_text(&mut value, "boundary-token");
    value.extend_from_slice(&OBSERVATION);
    value.extend_from_slice(&call.expected_size.to_be_bytes());
    value.extend_from_slice(&BODY);
    for _ in 0..3 {
        value.extend_from_slice(&0_u64.to_be_bytes());
    }
    push_bytes(&mut value, &complete(&quota_preimage(call.expected_size)));
    value.extend_from_slice(&1_u64.to_be_bytes());
    value.extend_from_slice(
        &(call
            .deadline
            .min(call.hard_expiry)
            .min(ADMISSION + call.ttl) as u64)
            .to_be_bytes(),
    );
    value.extend_from_slice(&FINGERPRINT);
    push_text(&mut value, call.allocation);
    for item in [
        5_u64,
        call.deadline as u64,
        call.hard_expiry as u64,
        ADMISSION as u64,
        call.ttl as u64,
        16,
    ] {
        value.extend_from_slice(&item.to_be_bytes());
    }
    push_bytes(&mut value, ack);
    value.extend_from_slice(ack_digest);
    value.extend_from_slice(&1_u64.to_be_bytes());
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

#[derive(Clone)]
struct Call<'a> {
    protocol: &'a str,
    policy: &'a str,
    allocation: &'a str,
    logical: &'a str,
    attempt: &'a str,
    boundary_token: &'a str,
    deadline: i64,
    hard_expiry: i64,
    ttl: i64,
    expected_size: u64,
    global_max_bytes: u64,
    global_max_rows: u64,
    global_max_concurrency: u64,
    global_low_bytes: u64,
    global_low_rows: u64,
    global_low_concurrency: u64,
    cell_max_bytes: u64,
    cell_max_rows: u64,
    cell_max_concurrency: u64,
    cell_low_bytes: u64,
    cell_low_rows: u64,
    cell_low_concurrency: u64,
    tenant_max_bytes: u64,
    tenant_max_rows: u64,
    tenant_max_concurrency: u64,
    tenant_low_bytes: u64,
    tenant_low_rows: u64,
    tenant_low_concurrency: u64,
}

impl Default for Call<'static> {
    fn default() -> Self {
        Self {
            protocol: "protocol-1",
            policy: "policy-1",
            allocation: "allocation-1",
            logical: "00000000-03e8-7abc-8def-0123456789ab",
            attempt: "00000000-03e9-7abc-8def-0223456789ab",
            boundary_token: "boundary-token",
            deadline: 3_000,
            hard_expiry: 4_000,
            ttl: 1_000,
            expected_size: 0,
            global_max_bytes: 10,
            global_max_rows: 10,
            global_max_concurrency: 10,
            global_low_bytes: 0,
            global_low_rows: 0,
            global_low_concurrency: 0,
            cell_max_bytes: 10,
            cell_max_rows: 10,
            cell_max_concurrency: 10,
            cell_low_bytes: 0,
            cell_low_rows: 0,
            cell_low_concurrency: 0,
            tenant_max_bytes: 10,
            tenant_max_rows: 10,
            tenant_max_concurrency: 10,
            tenant_low_bytes: 0,
            tenant_low_rows: 0,
            tenant_low_concurrency: 0,
        }
    }
}

fn reserve_sql(value: &Call<'_>, api: &str) -> String {
    format!(
        "SELECT (object_store_retention.object_store_dispatch_reserve_put_v1(
          '{api}', '{protocol}', '{policy}', 'boundary-1', 'cell-1', 'tenant-1',
          '00000000-03eb-7abc-8def-0423456789ab', '{logical}', '{attempt}',
          '00000000-03ea-7abc-8def-0323456789ab', 7, decode('{boundary}', 'hex'),
          '{boundary_token}', decode('{observation}', 'hex'), {expected_size}, decode('{body}', 'hex'),
          decode('{fingerprint}', 'hex'), '{allocation}', 5, {deadline}, {hard_expiry}, {ttl},
          16, 1,
          {global_max_bytes}, {global_max_rows}, {global_max_concurrency},
          {global_low_bytes}, {global_low_rows}, {global_low_concurrency},
          {cell_max_bytes}, {cell_max_rows}, {cell_max_concurrency},
          {cell_low_bytes}, {cell_low_rows}, {cell_low_concurrency},
          {tenant_max_bytes}, {tenant_max_rows}, {tenant_max_concurrency},
          {tenant_low_bytes}, {tenant_low_rows}, {tenant_low_concurrency},
          256, 256, 16384)).*",
        protocol = value.protocol,
        policy = value.policy,
        allocation = value.allocation,
        logical = value.logical,
        attempt = value.attempt,
        boundary_token = value.boundary_token,
        deadline = value.deadline,
        hard_expiry = value.hard_expiry,
        ttl = value.ttl,
        expected_size = value.expected_size,
        global_max_bytes = value.global_max_bytes,
        global_max_rows = value.global_max_rows,
        global_max_concurrency = value.global_max_concurrency,
        global_low_bytes = value.global_low_bytes,
        global_low_rows = value.global_low_rows,
        global_low_concurrency = value.global_low_concurrency,
        cell_max_bytes = value.cell_max_bytes,
        cell_max_rows = value.cell_max_rows,
        cell_max_concurrency = value.cell_max_concurrency,
        cell_low_bytes = value.cell_low_bytes,
        cell_low_rows = value.cell_low_rows,
        cell_low_concurrency = value.cell_low_concurrency,
        tenant_max_bytes = value.tenant_max_bytes,
        tenant_max_rows = value.tenant_max_rows,
        tenant_max_concurrency = value.tenant_max_concurrency,
        tenant_low_bytes = value.tenant_low_bytes,
        tenant_low_rows = value.tenant_low_rows,
        tenant_low_concurrency = value.tenant_low_concurrency,
        boundary = hex(&BOUNDARY),
        observation = hex(&OBSERVATION),
        body = hex(&BODY),
        fingerprint = hex(&FINGERPRINT),
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

async fn assert_permission_denied_as(client: &tokio_postgres::Client, role: &str, sql: &str) {
    set_user(client, role).await;
    let error = match client.batch_execute(sql).await {
        Ok(()) => panic!("{role} unexpectedly executed protected SQL: {sql}"),
        Err(error) => error,
    };
    assert_eq!(
        error
            .as_db_error()
            .unwrap_or_else(|| panic!("{role}: untyped denial for {sql}: {error}"))
            .code()
            .code(),
        "42501",
        "{role}: {sql}"
    );
    reset_user(client).await;
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
async fn live_postgres_reserve_put_is_atomic_exact_and_replay_safe() {
    let url = std::env::var("LORE_TEST_LOCAL_RESERVE_PUT_MUTATION_PG_URL").expect(
        "LORE_TEST_LOCAL_RESERVE_PUT_MUTATION_PG_URL must name a fresh disposable database",
    );
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable ReservePut database");
    let _connection = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "reserve-put-mutation-postgres",
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
    for sql in [
        include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"),
        include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql"),
    ] {
        client
            .batch_execute(sql)
            .await
            .expect("apply mutation migration");
    }

    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint';",
        )
        .await
        .expect("freeze database clock");
    let default_call = Call::default();
    let past_logical = uuid_v7(0, "1123456789ab");
    let past_attempt = uuid_v7(0, "1223456789ab");
    let past_call = Call {
        logical: &past_logical,
        attempt: &past_attempt,
        ..Call::default()
    };
    let future_logical = uuid_v7(302_000, "2123456789ab");
    let future_attempt = uuid_v7(302_000, "2223456789ab");
    let future_call = Call {
        logical: &future_logical,
        attempt: &future_attempt,
        ..Call::default()
    };
    let allocation_logical = uuid_v7(1_100, "3123456789ab");
    let allocation_attempt = uuid_v7(1_101, "3223456789ab");
    let allocation_min_call = Call {
        logical: &allocation_logical,
        attempt: &allocation_attempt,
        deadline: 3_500,
        hard_expiry: 2_500,
        ttl: 2_000,
        ..Call::default()
    };
    let byte_capacity_call = Call {
        expected_size: 1,
        ..Call::default()
    };
    let limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 1,
        max_canonical_row_bytes: 16_384,
    };
    let ack =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture_for(&default_call), &limits)
            .expect("independent zero-byte ACK");
    let past_ack =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture_for(&past_call), &limits)
            .expect("inclusive past-boundary ACK");
    let future_ack =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture_for(&future_call), &limits)
            .expect("inclusive future-boundary ACK");
    let allocation_ack = validate_and_encode_object_store_reserve_put_ack(
        &ack_fixture_for(&allocation_min_call),
        &ReservePutAckLimits {
            max_identity_bytes: 256,
            max_durable_handle_bytes: 1,
            max_canonical_row_bytes: 16_384,
        },
    )
    .expect("allocation-minimum ACK");
    let byte_capacity_ack = validate_and_encode_object_store_reserve_put_ack(
        &ack_fixture_for(&byte_capacity_call),
        &limits,
    )
    .expect("one-byte capacity ACK");
    let quota = quota_preimage(0);
    let quota_digest = *blake3::hash(&quota).as_bytes();
    let byte_quota = quota_preimage(1);
    let byte_quota_digest = *blake3::hash(&byte_quota).as_bytes();
    let row_preimage = row_preimage_for(&default_call, ack.canonical_bytes(), ack.ack_blake3());
    let row_digest = *blake3::hash(&row_preimage).as_bytes();
    let past_row = row_preimage_for(
        &past_call,
        past_ack.canonical_bytes(),
        past_ack.ack_blake3(),
    );
    let past_row_digest = *blake3::hash(&past_row).as_bytes();
    let future_row = row_preimage_for(
        &future_call,
        future_ack.canonical_bytes(),
        future_ack.ack_blake3(),
    );
    let future_row_digest = *blake3::hash(&future_row).as_bytes();
    let allocation_row = row_preimage_for(
        &allocation_min_call,
        allocation_ack.canonical_bytes(),
        allocation_ack.ack_blake3(),
    );
    let allocation_row_digest = *blake3::hash(&allocation_row).as_bytes();
    let byte_capacity_row = row_preimage_for(
        &byte_capacity_call,
        byte_capacity_ack.canonical_bytes(),
        byte_capacity_ack.ack_blake3(),
    );
    let byte_capacity_row_digest = *blake3::hash(&byte_capacity_row).as_bytes();
    client
        .batch_execute(&provider(&[
            (&quota, &quota_digest),
            (&byte_quota, &byte_quota_digest),
            (ack.canonical_preimage(), ack.ack_blake3()),
            (&row_preimage, &row_digest),
            (past_ack.canonical_preimage(), past_ack.ack_blake3()),
            (&past_row, &past_row_digest),
            (future_ack.canonical_preimage(), future_ack.ack_blake3()),
            (&future_row, &future_row_digest),
            (
                allocation_ack.canonical_preimage(),
                allocation_ack.ack_blake3(),
            ),
            (&allocation_row, &allocation_row_digest),
            (
                byte_capacity_ack.canonical_preimage(),
                byte_capacity_ack.ack_blake3(),
            ),
            (&byte_capacity_row, &byte_capacity_row_digest),
        ]))
        .await
        .expect("install genuine exact-preimage provider");

    set_user(&client, "object_dispatch_retention_owner").await;
    let auth_error = serial_call(&client, &reserve_sql(&Call::default(), "bad-api"))
        .await
        .expect_err("auth must precede bad API");
    assert_eq!(
        auth_error
            .as_db_error()
            .expect("typed auth error")
            .message(),
        "DISPATCH_RUNTIME_UNAUTHORIZED"
    );
    reset_user(&client).await;

    let (duplicate_client, duplicate_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect concurrent duplicate session");
    let _duplicate_connection = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "reserve-put-duplicate-postgres",
        async move {
            let _ = duplicate_connection.await;
        }
    ));
    set_user(&client, "object_dispatch_retention_runtime").await;
    set_user(&duplicate_client, "object_dispatch_retention_runtime").await;
    let fresh_sql = reserve_sql(&Call::default(), "object-store-dispatch-reserve-put-v1");
    let (first_fresh, second_fresh) = tokio::join!(
        serial_call(&client, &fresh_sql),
        serial_call(&duplicate_client, &fresh_sql)
    );
    let (created, loser_is_duplicate, serialization_failure) = match (first_fresh, second_fresh) {
        (Ok(created), Err(loser)) => (created, true, loser),
        (Err(loser), Ok(created)) => (created, false, loser),
        (first, second) => panic!(
            "fresh duplicate race must yield one CREATED and one 40001, got first={first:?}, second={second:?}"
        ),
    };
    assert_eq!(created.get::<_, String>(0), "CREATED");
    assert_eq!(created.get::<_, i64>(7), 3_000, "deadline/TTL tie wins");
    assert_eq!(created.get::<_, Vec<u8>>(8), ack.canonical_bytes());
    assert_eq!(created.get::<_, Vec<u8>>(9), ack.ack_blake3());
    assert_eq!(
        serialization_failure
            .as_db_error()
            .expect("typed concurrent loser")
            .code()
            .code(),
        "40001"
    );
    let losing_client = if loser_is_duplicate {
        &duplicate_client
    } else {
        &client
    };
    let exact_retry = serial_call(losing_client, &fresh_sql)
        .await
        .expect("exact retry after 40001");
    assert_eq!(exact_retry.get::<_, String>(0), "REPLAY");

    let replay = serial_call(
        &client,
        &reserve_sql(
            &Call {
                policy: "policy-mutated",
                allocation: "allocation-mutated",
                hard_expiry: 5_000,
                ttl: 2_000,
                ..Call::default()
            },
            "object-store-dispatch-reserve-put-v1",
        ),
    )
    .await
    .expect("mutable replay");
    assert_eq!(replay.get::<_, String>(0), "REPLAY");
    assert_eq!(replay.get::<_, Vec<u8>>(8), ack.canonical_bytes());
    let conflict = serial_call(
        &client,
        &reserve_sql(
            &Call {
                protocol: "protocol-2",
                ..Call::default()
            },
            "object-store-dispatch-reserve-put-v1",
        ),
    )
    .await
    .expect_err("changed protocol conflict");
    assert_eq!(
        conflict
            .as_db_error()
            .expect("typed replay conflict")
            .message(),
        "DISPATCH_RESERVE_PUT_REPLAY_CONFLICT"
    );

    reset_user(&duplicate_client).await;
    reset_user(&client).await;

    let counts = client.query_one(
        "SELECT (SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects),
                (SELECT count(*) FROM object_store_retention.object_dispatch_quota_usage),
                (SELECT sum(used_rows)::bigint FROM object_store_retention.object_dispatch_quota_usage),
                (SELECT bool_and(used_bytes=0 AND used_rows=1 AND used_concurrency=1 AND counter_revision=2)
                   FROM object_store_retention.object_dispatch_quota_usage)", &[]
    ).await.expect("read atomic effects");
    assert_eq!(counts.get::<_, i64>(0), 1);
    assert_eq!(counts.get::<_, i64>(1), 3);
    assert_eq!(counts.get::<_, Option<i64>>(2), Some(3));
    assert!(counts.get::<_, bool>(3));
    let stored = client
        .query_one(
            "SELECT canonical_record_bytes, record_blake3, reserve_put_ack_canonical_bytes,
                reserve_put_ack_blake3 FROM object_store_retention.object_dispatch_spool_objects",
            &[],
        )
        .await
        .expect("read persisted evidence");
    assert_eq!(stored.get::<_, Vec<u8>>(0), complete(&row_preimage));
    assert_eq!(stored.get::<_, Vec<u8>>(1), row_digest);
    assert_eq!(stored.get::<_, Vec<u8>>(2), ack.canonical_bytes());
    assert_eq!(stored.get::<_, Vec<u8>>(3), ack.ack_blake3());

    client.batch_execute("DELETE FROM object_store_retention.object_dispatch_spool_objects;
      UPDATE object_store_retention.object_dispatch_quota_usage SET used_bytes=0,used_rows=0,used_concurrency=0,counter_revision=1;")
      .await.expect("reset rejection fixture");

    for (label, call, expected_ack, expected_expiry) in [
        ("inclusive past UUID", &past_call, &past_ack, 3_000_i64),
        (
            "inclusive future UUID",
            &future_call,
            &future_ack,
            3_000_i64,
        ),
        (
            "allocation hard-expiry minimum",
            &allocation_min_call,
            &allocation_ack,
            2_500_i64,
        ),
    ] {
        set_user(&client, "object_dispatch_retention_runtime").await;
        let result = serial_call(
            &client,
            &reserve_sql(call, "object-store-dispatch-reserve-put-v1"),
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "{label}: {}",
                error
                    .as_db_error()
                    .map_or_else(|| error.to_string(), |db| db.message().to_string())
            )
        });
        assert_eq!(result.get::<_, String>(0), "CREATED", "{label}");
        assert_eq!(result.get::<_, i64>(7), expected_expiry, "{label}");
        assert_eq!(
            result.get::<_, Vec<u8>>(8),
            expected_ack.canonical_bytes(),
            "{label}"
        );
        reset_user(&client).await;
        let effects = client
            .query_one(
                "SELECT (SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects),
                        (SELECT sum(used_rows)::bigint FROM object_store_retention.object_dispatch_quota_usage)",
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("{label} effects: {error}"));
        assert_eq!(effects.get::<_, i64>(0), 1, "{label}");
        assert_eq!(effects.get::<_, Option<i64>>(1), Some(3), "{label}");
        client.batch_execute("DELETE FROM object_store_retention.object_dispatch_spool_objects;
          UPDATE object_store_retention.object_dispatch_quota_usage SET used_bytes=0,used_rows=0,used_concurrency=0,counter_revision=1;")
          .await.unwrap_or_else(|error| panic!("reset {label}: {error}"));
    }

    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
             AS 'SELECT 31536002000::bigint';",
        )
        .await
        .expect("advance clock for stale UUID");
    let stale_logical = uuid_v7(1_999, "4123456789ab");
    let stale_attempt = uuid_v7(1_999, "4223456789ab");
    let stale_call = Call {
        logical: &stale_logical,
        attempt: &stale_attempt,
        deadline: 31_536_003_000,
        hard_expiry: 31_536_004_000,
        ..Call::default()
    };
    set_user(&client, "object_dispatch_retention_runtime").await;
    let stale = serial_call(
        &client,
        &reserve_sql(&stale_call, "object-store-dispatch-reserve-put-v1"),
    )
    .await
    .expect_err("UUID one millisecond below inclusive past boundary");
    assert_eq!(
        stale.as_db_error().expect("typed stale UUID").message(),
        "EXPIRED_OR_UNKNOWN"
    );
    reset_user(&client).await;

    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
             AS 'SELECT 9223372036854775806::bigint';",
        )
        .await
        .expect("advance clock for checked expiry overflow");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let time_overflow = serial_call(
        &client,
        &reserve_sql(
            &Call {
                deadline: i64::MAX,
                hard_expiry: i64::MAX,
                ttl: 2,
                ..Call::default()
            },
            "object-store-dispatch-reserve-put-v1",
        ),
    )
    .await
    .expect_err("checked prepared-expiry overflow");
    assert_eq!(
        time_overflow
            .as_db_error()
            .expect("typed time overflow")
            .message(),
        "DISPATCH_RESERVE_PUT_TIME_OVERFLOW"
    );
    reset_user(&client).await;
    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT 2000::bigint';",
        )
        .await
        .expect("restore fixture clock");

    set_user(&client, "object_dispatch_retention_runtime").await;
    macro_rules! capacity_case {
        ($label:literal, $($field:ident = $value:expr),+ $(,)?) => {{
            let mut call = Call::default();
            $(call.$field = $value;)+
            ($label, call, "DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED")
        }};
    }
    for (label, call, expected) in [
        capacity_case!("global bytes cap", expected_size = 1, global_max_bytes = 0),
        capacity_case!(
            "global bytes low-water",
            expected_size = 1,
            global_max_bytes = 1,
            global_low_bytes = 1
        ),
        capacity_case!("global rows cap", global_max_rows = 0),
        capacity_case!(
            "global rows low-water",
            global_max_rows = 1,
            global_low_rows = 1
        ),
        capacity_case!("global concurrency cap", global_max_concurrency = 0),
        capacity_case!(
            "global concurrency low-water",
            global_max_concurrency = 1,
            global_low_concurrency = 1
        ),
        capacity_case!("cell bytes cap", expected_size = 1, cell_max_bytes = 0),
        capacity_case!(
            "cell bytes low-water",
            expected_size = 1,
            cell_max_bytes = 1,
            cell_low_bytes = 1
        ),
        capacity_case!("cell rows cap", cell_max_rows = 0),
        capacity_case!("cell rows low-water", cell_max_rows = 1, cell_low_rows = 1),
        capacity_case!("cell concurrency cap", cell_max_concurrency = 0),
        capacity_case!(
            "cell concurrency low-water",
            cell_max_concurrency = 1,
            cell_low_concurrency = 1
        ),
        capacity_case!("tenant bytes cap", expected_size = 1, tenant_max_bytes = 0),
        capacity_case!(
            "tenant bytes low-water",
            expected_size = 1,
            tenant_max_bytes = 1,
            tenant_low_bytes = 1
        ),
        capacity_case!("tenant rows cap", tenant_max_rows = 0),
        capacity_case!(
            "tenant rows low-water",
            tenant_max_rows = 1,
            tenant_low_rows = 1
        ),
        capacity_case!("tenant concurrency cap", tenant_max_concurrency = 0),
        capacity_case!(
            "tenant concurrency low-water",
            tenant_max_concurrency = 1,
            tenant_low_concurrency = 1
        ),
        (
            "future UUID",
            Call {
                logical: "00000004-9f11-7abc-8def-0123456789ab",
                ..Call::default()
            },
            "UUIDV7_TIMESTAMP_TOO_FAR_IN_FUTURE",
        ),
    ] {
        let error = serial_call(
            &client,
            &reserve_sql(&call, "object-store-dispatch-reserve-put-v1"),
        )
        .await
        .expect_err("rejected ReservePut");
        assert_eq!(
            error
                .as_db_error()
                .unwrap_or_else(|| panic!("{label}: untyped error {error}"))
                .message(),
            expected,
            "{label}"
        );
    }
    reset_user(&client).await;
    let rejected_counts = client.query_one(
        "SELECT (SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects),
                (SELECT coalesce(sum(used_rows),0)::bigint FROM object_store_retention.object_dispatch_quota_usage)", &[]
    ).await.expect("read rejection effects");
    assert_eq!(rejected_counts.get::<_, i64>(0), 0);
    assert_eq!(rejected_counts.get::<_, i64>(1), 0);

    client
        .batch_execute(
            "UPDATE object_store_retention.object_dispatch_quota_usage
             SET counter_revision=18446744073709551615;",
        )
        .await
        .expect("prepare counter overflow");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let overflow = serial_call(
        &client,
        &reserve_sql(&Call::default(), "object-store-dispatch-reserve-put-v1"),
    )
    .await
    .expect_err("counter revision overflow must reject atomically");
    assert_eq!(
        overflow.as_db_error().expect("typed overflow").message(),
        "DISPATCH_RESERVE_PUT_COUNTER_OVERFLOW"
    );
    reset_user(&client).await;
    let overflow_effects = client
        .query_one(
            "SELECT (SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects),
                    (SELECT coalesce(sum(used_rows),0)::bigint FROM object_store_retention.object_dispatch_quota_usage)",
            &[],
        )
        .await
        .expect("read overflow effects");
    assert_eq!(overflow_effects.get::<_, i64>(0), 0);
    assert_eq!(overflow_effects.get::<_, i64>(1), 0);

    client
        .batch_execute(
            "UPDATE object_store_retention.object_dispatch_quota_usage SET counter_revision=1;
             CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea
             LANGUAGE sql IMMUTABLE STRICT AS 'SELECT NULL::bytea';",
        )
        .await
        .expect("install failing provider");
    set_user(&client, "object_dispatch_retention_runtime").await;
    let provider_error = serial_call(
        &client,
        &reserve_sql(&Call::default(), "object-store-dispatch-reserve-put-v1"),
    )
    .await
    .expect_err("provider failure must reject atomically");
    assert_eq!(
        provider_error
            .as_db_error()
            .expect("typed provider error")
            .message(),
        "LOCAL_BLAKE3_PROVIDER_INVALID_RESULT"
    );
    reset_user(&client).await;
    let provider_effects = client
        .query_one(
            "SELECT (SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects),
                    (SELECT coalesce(sum(used_rows),0)::bigint FROM object_store_retention.object_dispatch_quota_usage)",
            &[],
        )
        .await
        .expect("read provider failure effects");
    assert_eq!(provider_effects.get::<_, i64>(0), 0);
    assert_eq!(provider_effects.get::<_, i64>(1), 0);

    let helper_calls = client
        .query(
            "SELECT pg_catalog.format(
                 'SELECT %I.%I(%s)', namespace.nspname, procedure.proname,
                 coalesce((SELECT string_agg(
                             CASE WHEN argument = 'uuid'::regtype
                               THEN '''00000000-03e8-7abc-8def-0123456789ab''::uuid'
                               ELSE 'NULL::' || pg_catalog.format_type(argument, NULL)
                             END, ',')
                           FROM unnest(procedure.proargtypes::oid[]) AS argument), ''))
             FROM pg_catalog.pg_proc AS procedure
             JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
             WHERE namespace.nspname='object_store_retention'
               AND procedure.proname IN (
                 'assert_dispatch_runtime_v1',
                 'assert_dispatch_reserve_put_api_revision_v1',
                 'local_uuid_v7_unix_ms_v1',
                 'project_dispatch_reserved_put_v1')
             ORDER BY procedure.proname",
            &[],
        )
        .await
        .expect("enumerate protected helper calls")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(helper_calls.len(), 4);
    for role in [
        "object_dispatch_retention_runtime",
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        for helper_call in &helper_calls {
            assert_permission_denied_as(&client, role, helper_call).await;
        }
        assert_permission_denied_as(
            &client,
            role,
            "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
        )
        .await;
        assert_permission_denied_as(
            &client,
            role,
            "UPDATE object_store_retention.object_dispatch_quota_usage SET used_rows=used_rows WHERE false",
        )
        .await;
    }
}

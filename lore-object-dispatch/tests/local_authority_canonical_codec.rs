// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static contract plus an explicit live PostgreSQL/Rust codec vector.
//!
//! The ignored live tier requires `LORE_TEST_LOCAL_CODEC_PG_URL`, an admin URL for a disposable
//! database with migrations 0002 and 0009 installed. It transactionally replaces
//! `public.blake3(bytea)` with an exact-preimage lookup containing four genuine BLAKE3 vectors.
//! That provider proves codec mechanics only; it is not production-provider or readiness evidence.

use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::local_authority_canonical_codec::LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_BLAKE3_V1;
use lore_object_dispatch::local_authority_canonical_codec::LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1;
use lore_object_dispatch::local_authority_canonical_codec::validate_embedded_local_authority_canonical_codec_migration_v1;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::PutSpoolReadyV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio_util::task::AbortOnDropHandle;

const EXPECTED_MIGRATION_BYTES: usize = 16_704;
const EXPECTED_MIGRATION_BLAKE3: &str =
    "b0803eacad028566e9fd5559f8f8069c44ad290d5631a8cef1a4f7c9669ea12a";
const DECOMPOSED_NFC_SQL_LITERAL: &str = r"U&'e\0301'";
const ADMISSION_UNIX_MS: i64 = 2_000;
const EXPIRES_UNIX_MS: i64 = 3_000;
const ALLOCATION_EXPIRY_UNIX_MS: i64 = 4_000;
const BODY_BLAKE3: [u8; 32] = [0x31; 32];
const QUOTA_BLAKE3_HEX: &str = "7a37a7c8e7e1643133e5606b00f899d7b4a5c9d20b87d2cba145e2128eb29857";
const SPOOL_BLAKE3_HEX: &str = "ea2e8f06fcd97cc804a80d161ea545547947d63de5b8592022f5a46f9bd824b1";
const RESERVED_BLAKE3_HEX: &str =
    "674cb16cc9f7952d3200d03d476176d2aa8cd998042d5b5548d434eb01ae3861";
const READY_BLAKE3_HEX: &str = "8c5de9479ea53a44bf5bcc0514d16bb25bd8baa22558bd7f080c4c04e196d8ee";

fn migration() -> &'static str {
    std::str::from_utf8(LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1)
        .expect("local authority canonical-codec migration must remain UTF-8 SQL")
}

fn function_body<'a>(sql: &'a str, function_name: &str) -> &'a str {
    let start = sql
        .find(function_name)
        .unwrap_or_else(|| panic!("missing function: {function_name}"));
    let body_start = sql[start..]
        .find("AS $$")
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("missing function body: {function_name}"));
    let body_end = sql[body_start + 5..]
        .find("\n$$;")
        .map(|offset| body_start + 5 + offset)
        .unwrap_or_else(|| panic!("missing function body terminator: {function_name}"));
    &sql[body_start..body_end]
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read production source directory") {
        let entry = entry.expect("read production source entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

fn uuid_v7(timestamp_unix_ms: u64, tail: &str) -> String {
    let timestamp = format!("{timestamp_unix_ms:012x}");
    format!("{}-{}-7abc-8def-{tail}", &timestamp[..8], &timestamp[8..])
}

fn push_text(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("live fixture text length must fit u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}

fn push_framed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("live fixture child length must fit u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn complete_record(preimage: &[u8]) -> Vec<u8> {
    let mut complete = preimage.to_vec();
    complete.extend_from_slice(blake3::hash(preimage).as_bytes());
    complete
}

fn quota_preimage() -> Vec<u8> {
    let mut preimage = b"object-store-quota-units-v1\0".to_vec();
    for value in [64_u64, 1, 1] {
        preimage.extend_from_slice(&value.to_be_bytes());
    }
    preimage
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
            bytes: 64,
            rows: 1,
            concurrency: 1,
        }),
        expires_at_unix_ms: EXPIRES_UNIX_MS,
        max_chunk_bytes: 16,
        spool_ready: None,
        payload_release_receipt: None,
        admission_clock_unix_ms: ADMISSION_UNIX_MS,
        allocation_hard_expiry_unix_ms: ALLOCATION_EXPIRY_UNIX_MS,
        closure: None,
        no_dispatch_proof: None,
        ack_blake3: Default::default(),
    }
}

fn spool_ready(parent: &ReservePutAckV1) -> PutSpoolReadyV1 {
    PutSpoolReadyV1 {
        protocol_revision: parent.protocol_revision.clone(),
        provider_boundary_id: parent.provider_boundary_id.clone(),
        authenticated_cell_id: parent.authenticated_cell_id.clone(),
        authenticated_tenant_id: parent.authenticated_tenant_id.clone(),
        logical_request_id: parent.logical_request_id.clone(),
        attempt_id: parent.attempt_id.clone(),
        upload_id: parent.upload_id.clone(),
        upload_fence: parent.upload_fence,
        durable_body_handle: "put/body-1".to_string(),
        body_size: 64,
        body_blake3: BODY_BLAKE3.to_vec().into(),
        ready_at_unix_ms: 2_500,
    }
}

fn spool_preimage(value: &PutSpoolReadyV1) -> Vec<u8> {
    let mut preimage = b"object-store-put-spool-ready-v1\0".to_vec();
    for identity in [
        &value.protocol_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
        &value.logical_request_id,
        &value.attempt_id,
        &value.upload_id,
    ] {
        push_text(&mut preimage, identity);
    }
    preimage.extend_from_slice(&value.upload_fence.to_be_bytes());
    push_text(&mut preimage, &value.durable_body_handle);
    preimage.extend_from_slice(&value.body_size.to_be_bytes());
    preimage.extend_from_slice(&value.body_blake3);
    preimage.extend_from_slice(&(value.ready_at_unix_ms as u64).to_be_bytes());
    preimage
}

fn expected_ack_preimage(value: &ReservePutAckV1) -> Vec<u8> {
    let mut preimage = b"object-store-reserve-put-ack-v1\0".to_vec();
    for identity in [
        &value.protocol_revision,
        &value.policy_revision,
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
        &value.logical_request_id,
        &value.attempt_id,
        &value.upload_id,
    ] {
        push_text(&mut preimage, identity);
    }
    preimage.extend_from_slice(&value.upload_fence.to_be_bytes());
    preimage.extend_from_slice(&(value.state as u32).to_be_bytes());
    push_framed(&mut preimage, &complete_record(&quota_preimage()));
    preimage.extend_from_slice(&(value.expires_at_unix_ms as u64).to_be_bytes());
    preimage.extend_from_slice(&value.max_chunk_bytes.to_be_bytes());
    preimage.push(u8::from(value.spool_ready.is_some()));
    if let Some(spool) = value.spool_ready.as_ref() {
        push_framed(&mut preimage, &complete_record(&spool_preimage(spool)));
    }
    preimage.push(0);
    preimage.extend_from_slice(&(value.admission_clock_unix_ms as u64).to_be_bytes());
    preimage.extend_from_slice(&(value.allocation_hard_expiry_unix_ms as u64).to_be_bytes());
    preimage.push(0);
    preimage.push(0);
    preimage
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn exact_lookup_provider(entries: &[(&[u8], &[u8; 32])]) -> String {
    let branches = entries
        .iter()
        .map(|(preimage, digest)| {
            format!(
                "WHEN '{}' THEN RETURN pg_catalog.decode('{}', 'hex');",
                hex(preimage),
                hex(*digest)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "CREATE OR REPLACE FUNCTION public.blake3(payload bytea)\n\
         RETURNS bytea LANGUAGE plpgsql IMMUTABLE STRICT AS $lookup$\n\
         BEGIN\n\
           CASE pg_catalog.encode(payload, 'hex')\n{branches}\n\
             ELSE RETURN NULL;\n\
           END CASE;\n\
         END\n\
         $lookup$;"
    )
}

fn sql_ack_call(value: &ReservePutAckV1) -> String {
    let spool = value.spool_ready.as_ref();
    let durable_handle = spool
        .map(|spool| format!("'{}'::text", spool.durable_body_handle))
        .unwrap_or_else(|| "NULL::text".to_string());
    let body_size = spool
        .map(|spool| format!("{}::object_store_retention.uint64", spool.body_size))
        .unwrap_or_else(|| "NULL::object_store_retention.uint64".to_string());
    let body_blake3 = spool
        .map(|spool| format!("pg_catalog.decode('{}', 'hex')", hex(&spool.body_blake3)))
        .unwrap_or_else(|| "NULL::bytea".to_string());
    let ready_at = spool
        .map(|spool| format!("{}::bigint", spool.ready_at_unix_ms))
        .unwrap_or_else(|| "NULL::bigint".to_string());
    format!(
        "SELECT (encoded).canonical_bytes, (encoded).record_blake3\n\
           FROM (SELECT object_store_retention.local_reserve_put_ack_v1(\n\
             '{protocol}', '{policy}', '{boundary}', '{cell}', '{tenant}',\n\
             '{logical}'::uuid, '{attempt}'::uuid, '{upload}'::uuid,\n\
             {fence}::object_store_retention.uint64, {state}::smallint,\n\
             64::object_store_retention.uint64, 1::object_store_retention.uint64,\n\
             1::object_store_retention.uint64, {expires}::bigint,\n\
             16::object_store_retention.uint64, {durable_handle}, {body_size},\n\
             {body_blake3}, {ready_at}, {admission}::bigint, {allocation}::bigint,\n\
             256, 256, 16384\n\
           ) AS encoded) AS codec",
        protocol = value.protocol_revision,
        policy = value.policy_revision,
        boundary = value.provider_boundary_id,
        cell = value.authenticated_cell_id,
        tenant = value.authenticated_tenant_id,
        logical = value.logical_request_id,
        attempt = value.attempt_id,
        upload = value.upload_id,
        fence = value.upload_fence,
        state = value.state,
        expires = value.expires_at_unix_ms,
        admission = value.admission_clock_unix_ms,
        allocation = value.allocation_hard_expiry_unix_ms,
    )
}

#[test]
fn embedded_codec_migration_has_exact_frozen_identity() {
    assert_eq!(
        LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1.len(),
        EXPECTED_MIGRATION_BYTES
    );
    assert_eq!(
        blake3::hash(LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1)
            .to_hex()
            .as_str(),
        EXPECTED_MIGRATION_BLAKE3
    );
    assert_eq!(
        LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_BLAKE3_V1.as_slice(),
        blake3::hash(LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1).as_bytes()
    );
    assert!(validate_embedded_local_authority_canonical_codec_migration_v1());
}

#[test]
fn migration_is_lf_normalized_and_one_owner_transaction() {
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
    assert!(!LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1.contains(&b'\r'));
    assert!(
        include_str!("../../.gitattributes")
            .lines()
            .any(|line| line == "lore-object-dispatch/migrations/*.sql text eol=lf")
    );
}

#[test]
fn every_codec_helper_is_security_definer_with_fixed_catalog_search_path() {
    let sql = migration();
    assert_eq!(sql.matches("CREATE FUNCTION ").count(), 11);
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 11);
    assert_eq!(sql.matches("SET search_path = pg_catalog").count(), 11);
    assert!(!sql.contains("SET search_path = public"));
    assert!(!sql.contains("SET search_path = object_store_retention"));
}

#[test]
fn blake3_provider_seam_fails_closed_and_exact_assertion_recomputes() {
    let sql = migration();
    let provider = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_blake3_v1(payload bytea)",
    );
    for required in [
        "pg_catalog.to_regprocedure('public.blake3(bytea)') IS NULL",
        "RAISE EXCEPTION 'LOCAL_BLAKE3_PROVIDER_UNAVAILABLE' USING ERRCODE = '55000'",
        "EXECUTE 'SELECT public.blake3($1)' INTO STRICT answer USING payload",
        "answer IS NULL OR pg_catalog.octet_length(answer) <> 32",
        "RAISE EXCEPTION 'LOCAL_BLAKE3_PROVIDER_INVALID_RESULT' USING ERRCODE = '55000'",
    ] {
        assert!(
            provider.contains(required),
            "missing provider guard: {required}"
        );
    }
    let assertion = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_assert_blake3_v1(payload bytea, expected bytea)",
    );
    for required in [
        "expected IS NULL OR pg_catalog.octet_length(expected) <> 32",
        "object_store_retention.local_blake3_v1(payload) IS DISTINCT FROM expected",
        "RAISE EXCEPTION 'LOCAL_BLAKE3_MISMATCH' USING ERRCODE = '22000'",
    ] {
        assert!(
            assertion.contains(required),
            "missing digest assertion: {required}"
        );
    }
    assert!(!sql.contains("pg_catalog.sha256(payload)"));
}

#[test]
fn integer_codecs_match_bounded_big_endian_rust_framing() {
    let sql = migration();
    let u8_codec = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_canonical_u8_v1(value integer)",
    );
    assert!(u8_codec.contains("value < 0 OR value > 255"));
    assert!(u8_codec.contains("pg_catalog.set_byte(answer, 0, value)"));

    let u32_codec = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_canonical_u32_v1(value bigint)",
    );
    assert!(u32_codec.contains("value < 0 OR value > 4294967295"));
    assert!(u32_codec.contains("FOR index_value IN REVERSE 3..0 LOOP"));
    assert!(u32_codec.contains("(remaining % 256)::integer"));

    let u64_codec = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_canonical_u64_v1(\n  value object_store_retention.uint64\n)",
    );
    assert!(u64_codec.contains("FOR index_value IN REVERSE 7..0 LOOP"));
    assert!(u64_codec.contains("pg_catalog.mod(remaining, 256)::integer"));
    assert!(u64_codec.contains("pg_catalog.trunc(remaining / 256)"));
}

#[test]
fn bytes_and_text_codecs_pin_u32_length_utf8_nfc_and_bounds() {
    let sql = migration();
    let bytes = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_canonical_bytes_v1(value bytea, maximum_bytes integer)",
    );
    assert!(bytes.contains("maximum_bytes <= 0 OR pg_catalog.octet_length(value) > maximum_bytes"));
    assert!(bytes.contains(
        "object_store_retention.local_canonical_u32_v1(pg_catalog.octet_length(value)) || value"
    ));

    let text = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_canonical_text_v1(value text, maximum_bytes integer)",
    );
    for required in [
        "pg_catalog.convert_to(value, 'UTF8')",
        "maximum_bytes <= 0",
        "pg_catalog.octet_length(payload) = 0",
        "pg_catalog.octet_length(payload) > maximum_bytes",
        "value IS DISTINCT FROM pg_catalog.normalize(value, 'NFC')",
        "local_canonical_u32_v1(pg_catalog.octet_length(payload)) || payload",
    ] {
        assert!(
            text.contains(required),
            "missing canonical text rule: {required}"
        );
    }
    assert_eq!(DECOMPOSED_NFC_SQL_LITERAL.matches('\\').count(), 1);
    assert_eq!(DECOMPOSED_NFC_SQL_LITERAL, r"U&'e\0301'");
}

#[test]
fn complete_record_hashes_preimage_and_appends_exact_digest_with_inclusive_bound() {
    let complete = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_complete_record_v1(",
    );
    for required in [
        "maximum_record_bytes <= 32",
        "pg_catalog.octet_length(preimage) > maximum_record_bytes - 32",
        "digest := object_store_retention.local_blake3_v1(preimage)",
        "RETURN ROW(preimage || digest, digest)::object_store_retention.local_canonical_record_v1",
    ] {
        assert!(
            complete.contains(required),
            "missing complete-record rule: {required}"
        );
    }
}

#[test]
fn quota_child_matches_rust_domain_order_and_nonempty_rule() {
    let quota = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_quota_child_v1(",
    );
    for required in [
        "quota_bytes IS NULL OR quota_rows IS NULL OR quota_concurrency IS NULL",
        "quota_bytes = 0 AND quota_rows = 0 AND quota_concurrency = 0",
        "pg_catalog.convert_to('object-store-quota-units-v1', 'UTF8')",
        "pg_catalog.decode('00', 'hex')",
        "local_canonical_u64_v1(quota_bytes)",
        "local_canonical_u64_v1(quota_rows)",
        "local_canonical_u64_v1(quota_concurrency)",
        "local_complete_record_v1(preimage, maximum_record_bytes)",
    ] {
        assert!(
            quota.contains(required),
            "missing quota codec rule: {required}"
        );
    }
}

#[test]
fn spool_ready_child_binds_exact_parent_identity_payload_and_clock_window() {
    let spool = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_put_spool_ready_child_v1(",
    );
    for required in [
        "pg_catalog.convert_to('object-store-put-spool-ready-v1', 'UTF8')",
        "logical_request_id IS NULL OR attempt_id IS NULL OR upload_id IS NULL",
        "upload_fence IS NULL OR upload_fence = 0",
        "body_blake3 IS NULL OR pg_catalog.octet_length(body_blake3) <> 32",
        "ready_at_unix_ms < admission_clock_unix_ms",
        "ready_at_unix_ms >= expires_at_unix_ms",
        "pg_catalog.uuid_send(logical_request_id)",
        "pg_catalog.uuid_send(attempt_id)",
        "pg_catalog.uuid_send(upload_id)",
        "local_canonical_text_v1(protocol_revision, maximum_identity_bytes)",
        "local_canonical_text_v1(provider_boundary_id, maximum_identity_bytes)",
        "local_canonical_text_v1(authenticated_cell_id, maximum_identity_bytes)",
        "local_canonical_text_v1(authenticated_tenant_id, maximum_identity_bytes)",
        "local_canonical_text_v1(logical_request_id::text, maximum_identity_bytes)",
        "local_canonical_text_v1(attempt_id::text, maximum_identity_bytes)",
        "local_canonical_text_v1(upload_id::text, maximum_identity_bytes)",
        "local_canonical_u64_v1(upload_fence)",
        "durable_body_handle, maximum_durable_handle_bytes",
        "local_canonical_u64_v1(body_size)",
        "|| body_blake3",
        "ready_at_unix_ms::object_store_retention.uint64",
    ] {
        assert!(
            spool.contains(required),
            "missing spool-ready rule: {required}"
        );
    }
}

#[test]
fn reserve_put_ack_encodes_exact_reserved_and_spool_ready_shapes() {
    let ack = function_body(
        migration(),
        "CREATE FUNCTION object_store_retention.local_reserve_put_ack_v1(",
    );
    for required in [
        "ack_state IS NULL OR ack_state NOT IN (1, 2)",
        "ack_state = 1 AND pg_catalog.num_nonnulls(",
        "ack_state = 2 AND pg_catalog.num_nonnulls(",
        "ack_state = 2 AND body_size IS DISTINCT FROM quota_bytes",
        "pg_catalog.convert_to('object-store-reserve-put-ack-v1', 'UTF8')",
        "local_canonical_u32_v1(ack_state)",
        "local_canonical_bytes_v1(quota_child, maximum_record_bytes)",
        "expires_at_unix_ms::object_store_retention.uint64",
        "local_canonical_u64_v1(max_chunk_bytes)",
        "local_canonical_u8_v1((spool_child IS NOT NULL)::integer)",
        "local_canonical_bytes_v1(\n              spool_child, maximum_record_bytes",
        "local_canonical_u8_v1(0)",
        "admission_clock_unix_ms::object_store_retention.uint64",
        "allocation_hard_expiry_unix_ms::object_store_retention.uint64",
        "RETURN object_store_retention.local_complete_record_v1(preimage, maximum_record_bytes)",
    ] {
        assert!(ack.contains(required), "missing ACK codec rule: {required}");
    }
    assert_eq!(ack.matches("local_canonical_u8_v1(0)").count(), 3);
    for forbidden in [
        "payload_release_receipt",
        "closure",
        "no_dispatch_proof",
        "ack_blake3 bytea",
        "canonical_bytes bytea",
    ] {
        assert!(
            !ack.contains(forbidden),
            "out-of-scope ACK input: {forbidden}"
        );
    }
}

#[test]
fn sql_shape_matches_rust_codec_domains_and_keeps_687_byte_terminal_vector_out_of_scope() {
    let sql = migration();
    let rust_codec = include_str!("../src/reserve_put_ack.rs");
    for domain in [
        "object-store-quota-units-v1",
        "object-store-put-spool-ready-v1",
        "object-store-reserve-put-ack-v1",
    ] {
        assert!(
            sql.contains(domain),
            "SQL codec missing Rust domain: {domain}"
        );
        assert!(
            rust_codec.contains(domain),
            "Rust codec missing domain: {domain}"
        );
    }
    for order_anchor in [
        ".u64(value.upload_fence)",
        ".u32(value.state as u32)",
        "write_framed(&mut output, &quota_bytes)?",
        ".u64(expires)",
        ".u64(value.max_chunk_bytes)",
        "write_optional_framed(&mut output, spool.as_deref())?",
        ".u64(admission)",
        ".u64(allocation_expiry)",
    ] {
        assert!(
            rust_codec.contains(order_anchor),
            "Rust order anchor moved: {order_anchor}"
        );
    }
    let compact_fixture = include_str!("compaction.rs");
    assert!(compact_fixture.contains("assert_eq!(source_ack.canonical_bytes().len(), 687);"));
    assert!(
        compact_fixture
            .contains("9be99cf8cf771dae54f540a31ff5074839c4a3a71e928da7ba2885bdb2b623c5")
    );
    assert!(sql.contains("ack_state NOT IN (1, 2)"));
    assert!(!sql.contains("LOCAL_RESERVE_PUT_ACK_687"));
}

#[test]
fn top_level_codecs_require_positive_nonnull_limits_instead_of_returning_null() {
    let sql = migration();
    let quota = function_body(
        sql,
        "CREATE FUNCTION object_store_retention.local_quota_child_v1(",
    );
    for required in ["maximum_record_bytes IS NULL", "maximum_record_bytes <= 0"] {
        assert!(
            quota.contains(required),
            "quota limit does not fail closed: {required}"
        );
    }
    for function in [
        "CREATE FUNCTION object_store_retention.local_put_spool_ready_child_v1(",
        "CREATE FUNCTION object_store_retention.local_reserve_put_ack_v1(",
    ] {
        let body = function_body(sql, function);
        for required in [
            "maximum_identity_bytes IS NULL",
            "maximum_identity_bytes <= 0",
            "maximum_durable_handle_bytes IS NULL",
            "maximum_durable_handle_bytes <= 0",
            "maximum_record_bytes IS NULL",
            "maximum_record_bytes <= 0",
        ] {
            assert!(
                body.contains(required),
                "codec limit does not fail closed: {required}"
            );
        }
    }
}

#[test]
fn helper_acl_is_owner_only_with_no_public_or_service_role_execute() {
    let sql = migration();
    assert!(
        sql.contains("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA object_store_retention FROM PUBLIC;")
    );
    assert!(sql.contains("DECLARE helper regprocedure;"));
    assert!(sql.contains("procedure.oid::regprocedure"));
    for helper in [
        "local_blake3_v1",
        "local_assert_blake3_v1",
        "local_canonical_u8_v1",
        "local_canonical_u32_v1",
        "local_canonical_u64_v1",
        "local_canonical_bytes_v1",
        "local_canonical_text_v1",
        "local_complete_record_v1",
        "local_quota_child_v1",
        "local_put_spool_ready_child_v1",
        "local_reserve_put_ack_v1",
    ] {
        assert_eq!(
            sql.matches(&format!("'{helper}'")).count(),
            1,
            "named-role revoke inventory must include helper exactly once: {helper}"
        );
    }
    assert!(sql.contains(
        "'REVOKE ALL ON FUNCTION %s FROM object_dispatch_retention_runtime, object_dispatch_retention_maintenance, object_dispatch_retention_migrator'"
    ));
    assert!(sql.contains(
        "REVOKE ALL ON TYPE object_store_retention.local_canonical_record_v1 FROM PUBLIC;"
    ));
    assert!(!sql.contains("GRANT EXECUTE"));
    assert!(!sql.contains("GRANT USAGE"));
}

#[test]
fn codec_slice_has_no_tables_mutations_or_runtime_provider_wiring() {
    let sql = migration();
    for forbidden in [
        "CREATE TABLE",
        "ALTER TABLE",
        "CREATE PROCEDURE",
        "INSERT INTO",
        "UPDATE object_store_retention",
        "DELETE FROM",
        "LOCK TABLE",
        "quota_usage SET",
        "object_dispatch_requests",
        "object_dispatch_spool_objects",
        "provider_access_key",
        "provider_secret",
        "bucket_route",
        "endpoint_url",
    ] {
        assert!(
            !sql.contains(forbidden),
            "codec slice contains excluded effect: {forbidden}"
        );
    }
}

#[test]
fn codec_artifact_is_embedded_only_and_production_sources_do_not_call_sql_helpers() {
    let module = include_str!("../src/local_authority_canonical_codec.rs");
    let library = include_str!("../src/lib.rs");
    for forbidden in ["tokio_postgres", "batch_execute", ".execute(", ".await"] {
        assert!(
            !module.contains(forbidden),
            "embedded module contains runtime call: {forbidden}"
        );
    }
    assert!(library.contains("pub mod local_authority_canonical_codec;"));

    let mut sources = Vec::new();
    collect_rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources.sort();
    assert!(
        !sources.is_empty(),
        "production source inventory must not be empty"
    );
    for source_path in sources {
        let source = std::fs::read_to_string(&source_path).expect("read production Rust source");
        for sql_identifier in [
            "object_store_retention.local_reserve_put_ack_v1",
            "object_store_retention.local_put_spool_ready_child_v1",
        ] {
            assert!(
                !source.contains(sql_identifier),
                "source-dark SQL identifier {sql_identifier} appeared in {}",
                source_path.display()
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with migrations 0002 and 0009 installed"]
async fn live_postgres_reserved_and_spool_ready_bytes_match_independent_rust_vectors() {
    let postgres_url = std::env::var("LORE_TEST_LOCAL_CODEC_PG_URL")
        .expect("LORE_TEST_LOCAL_CODEC_PG_URL is required for the ignored live codec tier");

    let quota_preimage = quota_preimage();
    let quota_digest = *blake3::hash(&quota_preimage).as_bytes();
    assert_eq!(quota_preimage.len(), 52);
    assert_eq!(hex(&quota_digest), QUOTA_BLAKE3_HEX);

    let reserved = reserved_ack();
    let reserved_preimage = expected_ack_preimage(&reserved);
    let reserved_digest = *blake3::hash(&reserved_preimage).as_bytes();
    let reserved_bytes = complete_record(&reserved_preimage);
    assert_eq!(reserved_preimage.len(), 350);
    assert_eq!(reserved_bytes.len(), 382);
    assert_eq!(hex(&reserved_digest), RESERVED_BLAKE3_HEX);

    let mut ready = reserved.clone();
    ready.state = PutReservationStateV1::PutReservationStateSpoolReady as i32;
    ready.spool_ready = Some(spool_ready(&ready));
    let ready_child_preimage = spool_preimage(ready.spool_ready.as_ref().expect("READY child"));
    let ready_child_digest = *blake3::hash(&ready_child_preimage).as_bytes();
    assert_eq!(ready_child_preimage.len(), 272);
    assert_eq!(hex(&ready_child_digest), SPOOL_BLAKE3_HEX);
    let ready_preimage = expected_ack_preimage(&ready);
    let ready_digest = *blake3::hash(&ready_preimage).as_bytes();
    let ready_bytes = complete_record(&ready_preimage);
    assert_eq!(ready_preimage.len(), 658);
    assert_eq!(ready_bytes.len(), 690);
    assert_eq!(hex(&ready_digest), READY_BLAKE3_HEX);

    let limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 256,
        max_canonical_row_bytes: 16_384,
    };
    let rust_reserved = validate_and_encode_object_store_reserve_put_ack(&reserved, &limits)
        .expect("Rust RESERVED vector");
    let rust_ready = validate_and_encode_object_store_reserve_put_ack(&ready, &limits)
        .expect("Rust SPOOL_READY vector");
    assert_eq!(rust_reserved.canonical_preimage(), reserved_preimage);
    assert_eq!(rust_reserved.canonical_bytes(), reserved_bytes);
    assert_eq!(rust_reserved.ack_blake3(), &reserved_digest);
    assert_eq!(rust_ready.canonical_preimage(), ready_preimage);
    assert_eq!(rust_ready.canonical_bytes(), ready_bytes);
    assert_eq!(rust_ready.ack_blake3(), &ready_digest);

    let (client, connection) = tokio_postgres::connect(&postgres_url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable codec PostgreSQL database");
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "local-codec-live-postgres",
        async move {
            let _ = connection.await;
        }
    ));
    client
        .batch_execute(
            "BEGIN;
             SELECT pg_catalog.pg_advisory_xact_lock(834215917042122);
             CREATE OR REPLACE FUNCTION public.blake3(payload bytea)
             RETURNS bytea LANGUAGE sql IMMUTABLE STRICT
             AS 'SELECT NULL::bytea';
             SAVEPOINT null_provider;",
        )
        .await
        .expect("install transaction-local NULL provider");
    let null_error = client
        .query_one(
            "SELECT object_store_retention.local_blake3_v1(pg_catalog.decode('00', 'hex'))",
            &[],
        )
        .await
        .expect_err("NULL provider result must fail closed");
    let null_database_error = null_error
        .as_db_error()
        .expect("NULL provider failure must be a typed PostgreSQL error");
    assert_eq!(null_database_error.code().code(), "55000");
    assert_eq!(
        null_database_error.message(),
        "LOCAL_BLAKE3_PROVIDER_INVALID_RESULT"
    );
    client
        .batch_execute("ROLLBACK TO SAVEPOINT null_provider;")
        .await
        .expect("recover after expected NULL-provider rejection");

    let lookup_provider = exact_lookup_provider(&[
        (&quota_preimage, &quota_digest),
        (&ready_child_preimage, &ready_child_digest),
        (&reserved_preimage, &reserved_digest),
        (&ready_preimage, &ready_digest),
    ]);
    client
        .batch_execute(&lookup_provider)
        .await
        .expect("install exact-preimage mechanics-only BLAKE3 provider");

    for (value, expected_bytes, expected_digest) in [
        (&reserved, &reserved_bytes, &reserved_digest),
        (&ready, &ready_bytes, &ready_digest),
    ] {
        let row = client
            .query_one(&sql_ack_call(value), &[])
            .await
            .expect("SQL codec must accept the exact Rust vector");
        let sql_bytes: Vec<u8> = row.get(0);
        let sql_digest: Vec<u8> = row.get(1);
        assert_eq!(&sql_bytes, expected_bytes);
        assert_eq!(sql_digest.as_slice(), expected_digest);
    }

    client
        .batch_execute("ROLLBACK;")
        .await
        .expect("remove mechanics-only provider and release live-test lease");
}

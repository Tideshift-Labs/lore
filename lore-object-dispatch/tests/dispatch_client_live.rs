// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Live proof that the WP-114 CD-3 typed client agrees with the installed cell procedures.
//!
//! Artifact identity does not prove a client agrees with a procedure. The first live driver run
//! against an earlier slice caught signature order, rows/bytes/retention semantics, a typed
//! `NOT_FOUND`, and a text-to-domain cast that every static check had found plausible. So every
//! procedure the typed client calls is driven here, through the public client API, against a real
//! PostgreSQL 16 with the full chain installed.
//!
//! Unlike the sibling live tiers, this one connects **as the authority roles themselves** rather
//! than using `SET SESSION AUTHORIZATION`, because the pool's whole point is that it carries its
//! own credential: the runtime pool logs in as `object_dispatch_retention_runtime` and the
//! maintenance pool as `object_dispatch_retention_maintenance`.
//!
//! Gated on `LORE_TEST_LOCAL_DISPATCH_CLIENT_PG_URL` and `#[ignore]`d. Always run it through
//! `tests/run-local-authority-live.ps1`, which distinguishes PASS, FAIL and NOT RUN; an `--ignored`
//! run with no environment set exits early with 0 passed, which is NOT RUN and never evidence.
//!
//! Two faults are injected rather than waited for: SQLSTATE `40001`, through a trigger, to drive
//! the retry budget; and a lost `COMMIT`, through the plaintext proxy at the bottom of this file,
//! to drive the ambiguity path end to end. The retention tier's own fault proxy could not be reused
//! for the second: its downstream listener requires a client certificate, and the dispatch pool has
//! no client-certificate mode because CR-033 D1 dropped that contract with the external authority
//! database.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_object_dispatch::DispatchAuthorityError;
use lore_object_dispatch::DispatchDisposition;
use lore_object_dispatch::DispatchMaintenanceClient;
use lore_object_dispatch::DispatchPoolConfig;
use lore_object_dispatch::DispatchPoolRole;
use lore_object_dispatch::DispatchRecordLimits;
use lore_object_dispatch::DispatchRuntimeClient;
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;
use lore_object_dispatch::EnrollParticipantRequest;
use lore_object_dispatch::PutSpoolReadyRequest;
use lore_object_dispatch::PutStreamIdentity;
use lore_object_dispatch::PutUploadProgressRequest;
use lore_object_dispatch::RegisterDispatcherRequest;
use lore_object_dispatch::ReservePutAckLimits;
use lore_object_dispatch::ReservePutQuotaScope;
use lore_object_dispatch::ReservePutRequest;
use lore_object_dispatch::STAGING_DISPATCH_CONNECTION_BUDGET;
use lore_object_dispatch::validate_and_encode_object_store_reserve_put_ack;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;
use lore_proto::lore::object_dispatch::v1::PutReservationStateV1;
use lore_proto::lore::object_dispatch::v1::PutSpoolReadyV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const RETENTION_SCHEMA_BLAKE3: &str =
    "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd";
const AUTHORITY_SCHEMA_BLAKE3: &str =
    "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff";
const PUT_RESERVATION_SCHEMA_BLAKE3: &str =
    "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67";
const DISPATCHER_IDENTITY_SCHEMA_BLAKE3: &str =
    "a7d54d94d0fa5035872eb9b3426cbbe6471bcf9ae34ed41877542f050e1aaad9";

const BODY: [u8; 32] = [0x31; 32];
const BOUNDARY: [u8; 32] = [0x41; 32];
const OBSERVATION: [u8; 32] = [0x51; 32];
const FINGERPRINT: [u8; 32] = [0x61; 32];

const SIZE: u64 = 10;
const DURABLE_HANDLE: &str = "put/body-final";
const PARTICIPANT_KEY: [u8; 32] = [0xaa; 32];
const DISPATCHER_ID: &str = "dispatcher-a";
const REGISTRATION_BOUNDARY: &str = "boundary-a";
const SERVICE_INSTANCE: &str = "instance-a-1";
const UNENROLLED_KEY: [u8; 32] = [0x77; 32];
/// 0018 admits one ACTIVE dispatcher per participant, so the injected-conflict coverage below
/// cannot reuse `dispatcher-a`: a second generation while the first is ACTIVE is a genuine unique
/// violation, not a retry. Each probe gets its own enrolled participant.
const RETRY_KEY: [u8; 32] = [0xbb; 32];
const RETRY_DISPATCHER_ID: &str = "dispatcher-b";
const RETRY_INSTANCE: &str = "instance-b-1";
const EXHAUST_KEY: [u8; 32] = [0xcc; 32];
const EXHAUST_DISPATCHER_ID: &str = "dispatcher-c";
const EXHAUST_INSTANCE: &str = "instance-c-1";
const AMBIGUOUS_KEY: [u8; 32] = [0xee; 32];
const AMBIGUOUS_DISPATCHER_ID: &str = "dispatcher-e";
const AMBIGUOUS_INSTANCE: &str = "instance-e-1";

fn uuid_text(timestamp: u64, tail: &str) -> String {
    let padded = format!("{timestamp:012x}");
    format!("{}-{}-7abc-8def-{tail}", &padded[..8], &padded[8..])
}

fn logical_request_id() -> String {
    uuid_text(1000, "0123456789ab")
}
fn attempt_id() -> String {
    uuid_text(1001, "0223456789ab")
}
fn upload_id() -> String {
    uuid_text(1002, "0323456789ab")
}
fn spool_object_id() -> String {
    uuid_text(1003, "0423456789ab")
}

fn parse(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("fixture UUID")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn push_text(buffer: &mut Vec<u8>, value: &str) {
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
}

fn push_bytes(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value);
}

fn complete(preimage: &[u8]) -> Vec<u8> {
    let mut value = preimage.to_vec();
    value.extend_from_slice(blake3::hash(preimage).as_bytes());
    value
}

fn quota_preimage(size: u64) -> Vec<u8> {
    let mut value = b"object-store-quota-units-v1\0".to_vec();
    for field in [size, 1, 1] {
        value.extend_from_slice(&field.to_be_bytes());
    }
    value
}

fn ack_fixture(size: u64, ready: bool) -> ReservePutAckV1 {
    let mut value = ReservePutAckV1 {
        protocol_revision: "protocol-1".into(),
        policy_revision: "policy-1".into(),
        provider_boundary_id: "boundary-1".into(),
        authenticated_cell_id: "cell-1".into(),
        authenticated_tenant_id: "tenant-1".into(),
        logical_request_id: logical_request_id(),
        attempt_id: attempt_id(),
        upload_id: upload_id(),
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
            durable_body_handle: DURABLE_HANDLE.into(),
            body_size: size,
            body_blake3: BODY.to_vec().into(),
            ready_at_unix_ms: 2000,
        });
    }
    value
}

fn spool_child_preimage(size: u64) -> Vec<u8> {
    let mut value = b"object-store-put-spool-ready-v1\0".to_vec();
    for field in [
        "protocol-1",
        "boundary-1",
        "cell-1",
        "tenant-1",
        &logical_request_id(),
        &attempt_id(),
        &upload_id(),
    ] {
        push_text(&mut value, field);
    }
    value.extend_from_slice(&7_u64.to_be_bytes());
    push_text(&mut value, DURABLE_HANDLE);
    value.extend_from_slice(&size.to_be_bytes());
    value.extend_from_slice(&BODY);
    value.extend_from_slice(&2000_u64.to_be_bytes());
    value
}

fn row_preimage(
    ack_canonical: &[u8],
    ack_digest: &[u8],
    size: u64,
    progress: (u64, u64, u64),
    revision: u64,
    ready: bool,
) -> Vec<u8> {
    let mut value = if ready {
        b"object-store-dispatch-put-spool-ready-row-v1\0".to_vec()
    } else {
        b"object-store-dispatch-put-reservation-row-v1\0".to_vec()
    };
    for field in [
        "object-store-dispatch-authority-schema-v1",
        "protocol-1",
        "policy-1",
        "boundary-1",
        "cell-1",
        "tenant-1",
        &spool_object_id(),
        &logical_request_id(),
        &attempt_id(),
        &upload_id(),
    ] {
        push_text(&mut value, field);
    }
    value.extend_from_slice(&7_u64.to_be_bytes());
    value.extend_from_slice(if ready { &[1, 1, 2, 1] } else { &[1, 1, 1, 1] });
    value.extend_from_slice(&BOUNDARY);
    push_text(&mut value, "boundary-token");
    value.extend_from_slice(&OBSERVATION);
    value.extend_from_slice(&size.to_be_bytes());
    value.extend_from_slice(&BODY);
    if ready {
        value.extend_from_slice(&size.to_be_bytes());
        value.extend_from_slice(&BODY);
        push_text(&mut value, DURABLE_HANDLE);
    }
    for field in [progress.0, progress.1, progress.2] {
        value.extend_from_slice(&field.to_be_bytes());
    }
    push_bytes(&mut value, &complete(&quota_preimage(size)));
    value.extend_from_slice(&1_u64.to_be_bytes());
    value.extend_from_slice(&3000_u64.to_be_bytes());
    value.extend_from_slice(&FINGERPRINT);
    push_text(&mut value, "allocation-1");
    for field in [5_u64, 3000, 4000, 2000, 1000, 6] {
        value.extend_from_slice(&field.to_be_bytes());
    }
    push_bytes(&mut value, ack_canonical);
    value.extend_from_slice(ack_digest);
    value.extend_from_slice(&revision.to_be_bytes());
    value.extend_from_slice(&2000_u64.to_be_bytes());
    if ready {
        value.extend_from_slice(&2000_u64.to_be_bytes());
    }
    value
}

fn registration_record_preimage(
    dispatcher_id: &str,
    generation: u64,
    service_instance_id: &str,
) -> Vec<u8> {
    let mut preimage = b"object-store-dispatch-dispatcher-registration-row-v1".to_vec();
    preimage.push(0);
    push_text(&mut preimage, "object-store-dispatch-authority-schema-v1");
    push_text(&mut preimage, dispatcher_id);
    preimage.extend_from_slice(&generation.to_be_bytes());
    push_text(&mut preimage, REGISTRATION_BOUNDARY);
    push_text(&mut preimage, service_instance_id);
    preimage.extend_from_slice(&generation.to_be_bytes());
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    push_text(&mut preimage, "allocation-1");
    preimage.extend_from_slice(&1_u64.to_be_bytes());
    push_text(&mut preimage, "credential-1");
    preimage.push(1);
    for field in [1000_u64, 1100, 2000, 1100] {
        preimage.extend_from_slice(&field.to_be_bytes());
    }
    preimage
}

/// PostgreSQL 16 has no BLAKE3, so the schema calls out to `public.blake3`. This installs an exact
/// lookup over the preimages this run's sequence hashes: a genuine digest for each, and NULL for
/// anything else, so an unplanned preimage fails closed rather than silently returning garbage.
fn blake3_provider_sql(vectors: &[(Vec<u8>, [u8; 32])]) -> String {
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
        "CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea
         LANGUAGE sql IMMUTABLE STRICT
         AS $$ SELECT CASE pg_catalog.encode(payload, 'hex')
           {cases}
           ELSE NULL::bytea
         END $$;"
    )
}

fn identity() -> PutStreamIdentity {
    PutStreamIdentity {
        provider_boundary_id: "boundary-1".into(),
        authenticated_cell_id: "cell-1".into(),
        authenticated_tenant_id: "tenant-1".into(),
        logical_request_id: parse(&logical_request_id()),
        attempt_id: parse(&attempt_id()),
        upload_id: parse(&upload_id()),
        upload_fence: 7,
    }
}

fn quota_scope() -> ReservePutQuotaScope {
    ReservePutQuotaScope {
        max_bytes: 100,
        max_rows: 10,
        max_concurrency: 10,
        low_water_bytes: 0,
        low_water_rows: 0,
        low_water_concurrency: 0,
    }
}

fn reserve_request() -> ReservePutRequest {
    ReservePutRequest {
        protocol_revision: "protocol-1".into(),
        policy_revision: "policy-1".into(),
        identity: identity(),
        spool_object_id: parse(&spool_object_id()),
        boundary_blake3: BOUNDARY,
        boundary_token: "boundary-token".into(),
        observation_binding_blake3: OBSERVATION,
        expected_size: SIZE,
        expected_blake3: BODY,
        put_reservation_fingerprint: FINGERPRINT,
        allocation_revision: "allocation-1".into(),
        allocation_fence: 5,
        reservation_deadline_unix_ms: 3000,
        allocation_hard_expiry_unix_ms: 4000,
        prepared_ttl_ms: 1000,
        max_chunk_bytes: 6,
        quota_revision: 1,
        global_quota: quota_scope(),
        cell_quota: quota_scope(),
        tenant_quota: quota_scope(),
        limits: DispatchRecordLimits {
            maximum_identity_bytes: 256,
            maximum_boundary_token_bytes: 256,
            maximum_record_bytes: 16_777_216,
        },
    }
}

fn progress_request(chunk_index: u64, fsynced_prefix_bytes: u64) -> PutUploadProgressRequest {
    PutUploadProgressRequest {
        protocol_revision: "protocol-1".into(),
        identity: identity(),
        chunk_index,
        fsynced_prefix_bytes,
        limits: DispatchRecordLimits {
            maximum_identity_bytes: 256,
            maximum_boundary_token_bytes: 4096,
            maximum_record_bytes: 16_777_216,
        },
    }
}

fn ready_request(final_chunk_index: u64) -> PutSpoolReadyRequest {
    PutSpoolReadyRequest {
        protocol_revision: "protocol-1".into(),
        identity: identity(),
        final_chunk_index,
        fsynced_body_size: SIZE,
        fsynced_body_blake3: BODY,
        durable_handle: DURABLE_HANDLE.into(),
        maximum_identity_bytes: 256,
        maximum_boundary_token_bytes: 4096,
        maximum_durable_handle_bytes: 4096,
        maximum_record_bytes: 16_777_216,
    }
}

fn registration_request(generation: u64) -> RegisterDispatcherRequest {
    registration_request_for(PARTICIPANT_KEY, generation, SERVICE_INSTANCE)
}

fn registration_request_for(
    participant_key: [u8; 32],
    generation: u64,
    service_instance_id: &str,
) -> RegisterDispatcherRequest {
    RegisterDispatcherRequest {
        participant_key,
        next_generation: generation,
        service_instance_id: service_instance_id.into(),
        dispatcher_fence: generation,
        authority_revision: 1,
        allocation_revision: "allocation-1".into(),
        allocation_fence: 1,
        provider_credential_revision: "credential-1".into(),
        acquired_at_unix_ms: 1000,
        renewed_at_unix_ms: 1100,
        expires_at_unix_ms: 2000,
        state_changed_at_unix_ms: 1100,
    }
}

fn database_name(url: &str) -> String {
    url.rsplit_once('/')
        .map(|(_, database)| database.to_string())
        .expect("database name from the runner URL")
}

fn pool_config(
    base_url: &str,
    role: DispatchPoolRole,
    statement_timeout: Duration,
) -> DispatchPoolConfig {
    // The runner hands out `postgresql://postgres@localhost:PORT/DB`. Swap the user for the
    // authority role this pool must connect as, and pin `sslmode=disable` for the plaintext
    // container.
    let without_scheme = base_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base_url);
    let host_and_path = without_scheme
        .split_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(without_scheme);
    DispatchPoolConfig {
        postgres_url: format!(
            "postgresql://{}@{host_and_path}?sslmode=disable",
            role.role_name()
        ),
        role,
        pool_max: 2,
        connect_timeout: Duration::from_secs(10),
        acquire_timeout: Duration::from_secs(10),
        statement_timeout,
        lock_timeout: Duration::from_millis(2_000),
        tls: DispatchTlsMode::Disabled,
        budget: STAGING_DISPATCH_CONNECTION_BUDGET,
    }
}

async fn install_as_migrator(client: &tokio_postgres::Client, sql: &str) -> String {
    client
        .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_migrator;")
        .await
        .expect("assume migrator");
    client
        .batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;")
        .await
        .expect("begin serializable");
    let row = client.query_one(sql, &[]).await;
    client
        .batch_execute(if row.is_ok() { "COMMIT;" } else { "ROLLBACK;" })
        .await
        .expect("close install transaction");
    client
        .batch_execute("RESET SESSION AUTHORIZATION;")
        .await
        .expect("reset authorization");
    row.expect("install call").get(0)
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_typed_client_agrees_with_every_called_cell_procedure() {
    let url = std::env::var("LORE_TEST_LOCAL_DISPATCH_CLIENT_PG_URL")
        .expect("LORE_TEST_LOCAL_DISPATCH_CLIENT_PG_URL must name a fresh disposable database");
    let (admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable dispatch-client database");
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "dispatch-client-live-postgres",
        async move {
            let _ = connection.await;
        }
    ));

    // The authority roles exist NOLOGIN in the sibling tiers, which reach them through SET SESSION
    // AUTHORIZATION. The pool carries its own credential instead, so both roles need LOGIN here.
    admin
        .batch_execute(
            "DO $$ BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime NOLOGIN; END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance NOLOGIN; END IF;
               IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator NOLOGIN; END IF;
             END $$;
             ALTER ROLE object_dispatch_retention_runtime LOGIN;
             ALTER ROLE object_dispatch_retention_maintenance LOGIN;
             GRANT object_dispatch_retention_owner TO CURRENT_USER;
             DO $$ BEGIN EXECUTE pg_catalog.format(
               'GRANT CREATE ON DATABASE %I TO object_dispatch_retention_owner',
               pg_catalog.current_database()
             ); END $$;",
        )
        .await
        .expect("bootstrap disposable roles with login");

    for migration in [
        include_str!("../migrations/0002_object_store_retention_authority.sql"),
        include_str!("../migrations/0003_object_store_retention_provisioning.sql"),
        include_str!("../migrations/0007_object_store_dispatch_authority_core.sql"),
        include_str!("../migrations/0008_object_store_dispatch_authority_provisioning.sql"),
    ] {
        admin
            .batch_execute(migration)
            .await
            .expect("apply base migration");
    }
    assert_eq!(
        install_as_migrator(
            &admin,
            &format!(
                "SELECT (object_store_retention.object_store_retention_install_v1(
                   'object-store-retention-provisioning-v1',
                   'object-store-retention-authority-schema-v1',
                   pg_catalog.decode('{RETENTION_SCHEMA_BLAKE3}', 'hex'), 1)).result_code"
            )
        )
        .await,
        "CREATED"
    );
    assert_eq!(
        install_as_migrator(
            &admin,
            &format!(
                "SELECT (object_store_retention.object_store_dispatch_authority_install_v1(
                   'object-store-dispatch-authority-provisioning-v1',
                   'object-store-dispatch-authority-schema-v1',
                   pg_catalog.decode('{AUTHORITY_SCHEMA_BLAKE3}', 'hex'), 1)).result_code"
            )
        )
        .await,
        "CREATED"
    );
    for migration in [
        include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql"),
        include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql"),
        include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql"),
    ] {
        admin
            .batch_execute(migration)
            .await
            .expect("apply put-reservation migration");
    }
    assert_eq!(
        install_as_migrator(
            &admin,
            &format!(
                "SELECT (object_store_retention.object_store_dispatch_put_reservation_install_v1(
                   'object-store-dispatch-put-reservation-provisioning-v1',
                   'object-store-dispatch-put-reservation-schema-v1',
                   pg_catalog.decode('{PUT_RESERVATION_SCHEMA_BLAKE3}', 'hex'), 1)).result_code"
            )
        )
        .await,
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
        admin
            .batch_execute(migration)
            .await
            .expect("apply mutation chain and dispatcher identity");
    }
    assert_eq!(
        install_as_migrator(
            &admin,
            &format!(
                "SELECT (object_store_retention.object_store_dispatch_dispatcher_identity_install_v1(
                   'object-store-dispatch-dispatcher-identity-provisioning-v1',
                   'object-store-dispatch-dispatcher-identity-schema-v1',
                   pg_catalog.decode('{DISPATCHER_IDENTITY_SCHEMA_BLAKE3}', 'hex'), 1)).result_code"
            )
        )
        .await,
        "CREATED"
    );
    admin
        .batch_execute(
            "CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
             AS 'SELECT 2000::bigint';",
        )
        .await
        .expect("freeze the database clock");

    // Every preimage this run's sequence hashes, with its genuine digest.
    let ack_limits = ReservePutAckLimits {
        max_identity_bytes: 256,
        max_durable_handle_bytes: 4096,
        max_canonical_row_bytes: 16_777_216,
    };
    let reserved =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture(SIZE, false), &ack_limits)
            .expect("independent reserved ACK");
    let ready =
        validate_and_encode_object_store_reserve_put_ack(&ack_fixture(SIZE, true), &ack_limits)
            .expect("independent ready ACK");
    let initial_row = row_preimage(
        reserved.canonical_bytes(),
        reserved.ack_blake3(),
        SIZE,
        (0, 0, 0),
        1,
        false,
    );
    let progress_three = row_preimage(
        reserved.canonical_bytes(),
        reserved.ack_blake3(),
        SIZE,
        (3, 1, 1),
        2,
        false,
    );
    let progress_six = row_preimage(
        reserved.canonical_bytes(),
        reserved.ack_blake3(),
        SIZE,
        (6, 2, 1),
        3,
        false,
    );
    let final_row = row_preimage(
        ready.canonical_bytes(),
        ready.ack_blake3(),
        SIZE,
        (0, 0, 0),
        4,
        true,
    );
    let mut vectors: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
    for preimage in [
        quota_preimage(SIZE),
        reserved.canonical_preimage().to_vec(),
        ready.canonical_preimage().to_vec(),
        spool_child_preimage(SIZE),
        initial_row,
        progress_three,
        progress_six,
        final_row,
        PARTICIPANT_KEY.to_vec(),
        // An unenrolled key still gets hashed for the lookup, so its digest must resolve or the
        // probe would fail closed on the provider instead of on the enrollment check.
        UNENROLLED_KEY.to_vec(),
        registration_record_preimage(DISPATCHER_ID, 1, SERVICE_INSTANCE),
        // The injected-conflict coverage below. The exhaustion probe never commits, but its record
        // is computed before the insert the trigger rejects, so its preimage must resolve or the
        // probe would fail closed on the digest provider instead of on the retry budget.
        RETRY_KEY.to_vec(),
        EXHAUST_KEY.to_vec(),
        registration_record_preimage(RETRY_DISPATCHER_ID, 1, RETRY_INSTANCE),
        registration_record_preimage(EXHAUST_DISPATCHER_ID, 1, EXHAUST_INSTANCE),
        // The lost-COMMIT coverage below.
        AMBIGUOUS_KEY.to_vec(),
        registration_record_preimage(AMBIGUOUS_DISPATCHER_ID, 1, AMBIGUOUS_INSTANCE),
    ] {
        let digest = *blake3::hash(&preimage).as_bytes();
        vectors.push((preimage, digest));
    }
    admin
        .batch_execute(&blake3_provider_sql(&vectors))
        .await
        .expect("install the exact-preimage BLAKE3 provider");

    // ---------------------------------------------------------------------------------------
    // The typed client takes over from here. Nothing below uses SET SESSION AUTHORIZATION.
    // ---------------------------------------------------------------------------------------
    let runtime = DispatchRuntimeClient::new(
        DispatchRuntimePool::new(pool_config(
            &url,
            DispatchPoolRole::Runtime,
            Duration::from_millis(5_000),
        ))
        .expect("runtime pool"),
    )
    .expect("runtime client");
    let maintenance = DispatchMaintenanceClient::new(
        DispatchRuntimePool::new(pool_config(
            &url,
            DispatchPoolRole::Maintenance,
            Duration::from_millis(5_000),
        ))
        .expect("maintenance pool"),
    )
    .expect("maintenance client");

    // 0019's readback: the runtime role may call it, and every installed layer reports its
    // identity tuple. This is also the read-only path, which is never retried.
    let state = runtime
        .read_dispatcher_identity_state()
        .await
        .expect("dispatcher identity readback");
    assert_eq!(
        state.retention.schema_revision,
        "object-store-retention-authority-schema-v1"
    );
    assert_eq!(
        state.local_authority.schema_revision,
        "object-store-dispatch-authority-schema-v1"
    );
    assert_eq!(
        state.put_reservation.schema_revision,
        "object-store-dispatch-put-reservation-schema-v1"
    );
    assert_eq!(
        state.dispatcher_identity.schema_revision,
        "object-store-dispatch-dispatcher-identity-schema-v1"
    );
    assert_eq!(
        hex(&state.dispatcher_identity.migration_blake3),
        DISPATCHER_IDENTITY_SCHEMA_BLAKE3
    );
    assert_eq!(state.dispatcher_identity.install_revision, 1);

    // 0020 enrollment is maintenance-only, and the runtime role is refused at the database. That
    // grant separation is what makes two separately credentialed clients necessary rather than
    // decorative.
    let (runtime_raw, runtime_connection) = tokio_postgres::connect(
        &format!(
            "postgresql://object_dispatch_retention_runtime@{}?sslmode=disable",
            url.split_once('@')
                .map(|(_, rest)| rest)
                .unwrap_or_default()
        ),
        tokio_postgres::NoTls,
    )
    .await
    .expect("connect as the runtime role");
    let _runtime_raw_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "dispatch-client-live-runtime-probe",
        async move {
            let _ = runtime_connection.await;
        }
    ));
    let denied = runtime_raw
        .query_one(
            "SELECT (object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(
               'object-store-dispatch-dispatcher-registration-v1', 'boundary-a', 'dispatcher-a',
               pg_catalog.decode($1, 'hex'))).result_code",
            &[&hex(blake3::hash(&PARTICIPANT_KEY).as_bytes())],
        )
        .await
        .expect_err("runtime must not reach maintenance-only enrollment");
    assert_eq!(
        denied.as_db_error().expect("typed denial").code().code(),
        "42501",
        "runtime reached maintenance-only enrollment"
    );

    // Enrollment, then its replay. Both are provable dispositions, and they are distinct.
    let enroll = EnrollParticipantRequest {
        provider_boundary_id: REGISTRATION_BOUNDARY.into(),
        dispatcher_id: DISPATCHER_ID.into(),
        participant_key_blake3: *blake3::hash(&PARTICIPANT_KEY).as_bytes(),
    };
    let created = maintenance
        .enroll_dispatcher_participant(&enroll)
        .await
        .expect("enroll participant");
    assert_eq!(created.disposition, DispatchDisposition::Applied);
    assert_eq!(created.value.dispatcher_id, DISPATCHER_ID);
    assert_eq!(created.value.provider_boundary_id, REGISTRATION_BOUNDARY);
    let replayed = maintenance
        .enroll_dispatcher_participant(&enroll)
        .await
        .expect("replay enrollment");
    assert_eq!(replayed.disposition, DispatchDisposition::Replayed);
    assert_eq!(replayed.value, created.value);

    // Registration proves possession of the enrolled key; the authority mints both identity
    // columns, so the client checks only what the call supplied.
    let registered = runtime
        .register_dispatcher(&registration_request(1))
        .await
        .expect("register dispatcher generation 1");
    assert_eq!(registered.disposition, DispatchDisposition::Applied);
    assert_eq!(registered.value.dispatcher_id, DISPATCHER_ID);
    assert_eq!(registered.value.provider_boundary_id, REGISTRATION_BOUNDARY);
    assert_eq!(registered.value.lease_generation, 1);
    assert_eq!(registered.value.dispatcher_fence, 1);
    assert_eq!(registered.value.service_instance_id, SERVICE_INSTANCE);
    assert_eq!(registered.value.state, 1);
    assert_eq!(
        registered.value.record_blake3,
        *blake3::hash(&registration_record_preimage(
            DISPATCHER_ID,
            1,
            SERVICE_INSTANCE
        ))
        .as_bytes()
    );
    let registered_again = runtime
        .register_dispatcher(&registration_request(1))
        .await
        .expect("replay registration");
    assert_eq!(registered_again.disposition, DispatchDisposition::Replayed);
    assert_eq!(registered_again.value, registered.value);

    // A generation that does not advance past the participant's current maximum is refused. Note
    // the rule the procedure actually enforces is `next_generation > max`, not `= max + 1`: a
    // generation of 3 after 1 is accepted, so the discriminating probe is one that does not
    // advance at all. It arrives as its own named refusal rather than as a generic unavailability.
    assert_eq!(
        runtime
            .register_dispatcher(&registration_request(0))
            .await
            .expect_err("non-monotonic generation"),
        DispatchAuthorityError::GenerationNotMonotonic
    );

    // An unenrolled participant key is an authentication refusal, not an invalid argument, and it
    // is raised before the record codec runs - no preimage for generation 2 is in the provider, so
    // a refusal raised any later would surface as SchemaUnavailable instead.
    let mut unenrolled = registration_request(2);
    unenrolled.participant_key = UNENROLLED_KEY;
    assert_eq!(
        runtime
            .register_dispatcher(&unenrolled)
            .await
            .expect_err("unenrolled participant key"),
        DispatchAuthorityError::ParticipantAuthenticationRequired
    );

    // ---------------------------------------------------------------------------------------
    // The bounded-execution envelope's retry loop, driven rather than read.
    //
    // A trigger injects SQLSTATE 40001 into the registration insert for a controlled number of
    // attempts. The attempt counter is a SEQUENCE, so `nextval` survives the aborted transaction
    // and counts real attempts rather than committed ones.
    //
    // The client under test here has `pool_max = 1`. That is the point: if the retry loop held its
    // pooled session across the backoff, the second attempt could never acquire a slot and would
    // fail closed instead of succeeding. Passing proves the session is released before sleeping.
    // ---------------------------------------------------------------------------------------
    // The trigger function is SECURITY DEFINER so it reads its own control table as its superuser
    // owner. The runtime role has no privileges on either, and a permission error inside the
    // trigger would surface as an authorization refusal rather than as the injected conflict.
    admin
        .batch_execute(
            "CREATE SEQUENCE public.injected_attempts;
             CREATE TABLE public.injection_control(fail_first int NOT NULL);
             INSERT INTO public.injection_control VALUES (0);
             CREATE FUNCTION public.inject_serialization_failure() RETURNS trigger
               LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
             DECLARE fail_through int;
             BEGIN
               SELECT fail_first INTO fail_through FROM public.injection_control;
               IF pg_catalog.nextval('public.injected_attempts') <= fail_through THEN
                 RAISE EXCEPTION 'INJECTED_SERIALIZATION_FAILURE' USING ERRCODE = '40001';
               END IF;
               RETURN NEW;
             END $$;
             CREATE TRIGGER inject_serialization
               BEFORE INSERT ON object_store_retention.object_dispatch_dispatchers
               FOR EACH ROW EXECUTE FUNCTION public.inject_serialization_failure();",
        )
        .await
        .expect("install the 40001 injection trigger");

    let mut single_slot = pool_config(
        &url,
        DispatchPoolRole::Runtime,
        Duration::from_millis(5_000),
    );
    single_slot.pool_max = 1;
    single_slot.acquire_timeout = Duration::from_millis(500);
    let retrying = DispatchRuntimeClient::new(
        DispatchRuntimePool::new(single_slot).expect("single-slot runtime pool"),
    )
    .expect("single-slot runtime client");

    // Each probe registers a participant of its own. 0018 admits one ACTIVE dispatcher per
    // participant, so reusing `dispatcher-a` would produce a genuine unique violation rather than
    // a retry, and the probe would prove nothing about the retry loop.
    for (dispatcher_id, key) in [
        (RETRY_DISPATCHER_ID, RETRY_KEY),
        (EXHAUST_DISPATCHER_ID, EXHAUST_KEY),
    ] {
        maintenance
            .enroll_dispatcher_participant(&EnrollParticipantRequest {
                provider_boundary_id: REGISTRATION_BOUNDARY.into(),
                dispatcher_id: dispatcher_id.into(),
                participant_key_blake3: *blake3::hash(&key).as_bytes(),
            })
            .await
            .unwrap_or_else(|error| panic!("enrol {dispatcher_id}: {error}"));
    }

    // Two injected conflicts, then success on the third attempt.
    admin
        .batch_execute(
            "UPDATE public.injection_control SET fail_first = 2;
             SELECT pg_catalog.setval('public.injected_attempts', 1, false);",
        )
        .await
        .expect("arm two injected conflicts");
    let started = std::time::Instant::now();
    let retried = retrying
        .register_dispatcher(&registration_request_for(RETRY_KEY, 1, RETRY_INSTANCE))
        .await
        .expect("registration succeeds on the third attempt");
    let elapsed = started.elapsed();
    assert_eq!(retried.disposition, DispatchDisposition::Applied);
    assert_eq!(retried.value.dispatcher_id, RETRY_DISPATCHER_ID);
    assert_eq!(retried.value.lease_generation, 1);
    // 25 ms then 100 ms of backoff must actually have been spent.
    assert!(
        elapsed >= Duration::from_millis(125),
        "retry backoff was not spent: {elapsed:?}"
    );
    let attempts: i64 = admin
        .query_one("SELECT last_value FROM public.injected_attempts", &[])
        .await
        .expect("read the attempt counter")
        .get(0);
    assert_eq!(attempts, 3, "expected exactly three attempts");

    // Conflicts on every attempt: the budget is exactly three, and the outcome is RetryExhausted
    // rather than an ambiguity - nothing was ever sent to COMMIT.
    admin
        .batch_execute(
            "UPDATE public.injection_control SET fail_first = 1000;
             SELECT pg_catalog.setval('public.injected_attempts', 1, false);",
        )
        .await
        .expect("arm unbounded injected conflicts");
    assert_eq!(
        retrying
            .register_dispatcher(&registration_request_for(EXHAUST_KEY, 1, EXHAUST_INSTANCE))
            .await
            .expect_err("retry budget exhausted"),
        DispatchAuthorityError::RetryExhausted
    );
    let attempts: i64 = admin
        .query_one("SELECT last_value FROM public.injected_attempts", &[])
        .await
        .expect("read the attempt counter")
        .get(0);
    assert_eq!(
        attempts, 3,
        "the retry budget is not exactly three attempts"
    );

    admin
        .batch_execute(
            "DROP TRIGGER inject_serialization ON object_store_retention.object_dispatch_dispatchers;
             DROP FUNCTION public.inject_serialization_failure();
             DROP TABLE public.injection_control;
             DROP SEQUENCE public.injected_attempts;",
        )
        .await
        .expect("remove the injection trigger");

    // ---------------------------------------------------------------------------------------
    // The ambiguity path, executed rather than read.
    //
    // A plaintext proxy drops the `CommandComplete` for one `COMMIT` and closes the connection.
    // The server committed; the client's `COMMIT` never completes, so `classify_commit` sees an
    // error with no SQLSTATE and the outcome is genuinely unknown. `run_mutation` then sets
    // `ambiguity_seen`, poisons the session, and spends its next attempt on the authoritative
    // re-issue, which finds the record already present and answers `REPLAY`.
    //
    // Every arm this exercises - `commit_sent` true, `classify_commit`'s no-SQLSTATE branch,
    // `ambiguity_seen`, the poisoned lease, `after_ambiguity()` - had no behavioural coverage
    // before; they were pinned only by source-text assertions.
    // ---------------------------------------------------------------------------------------
    let direct = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('@'))
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once('/'))
        .map(|(host, _)| host.to_string())
        .expect("host:port from the runner URL");
    let proxy = LostCommitProxy::start(direct).await;
    let mut through_proxy = pool_config(
        &url,
        DispatchPoolRole::Runtime,
        Duration::from_millis(5_000),
    );
    through_proxy.postgres_url = format!(
        "postgresql://{}@127.0.0.1:{}/{}?sslmode=disable",
        DispatchPoolRole::Runtime.role_name(),
        proxy.port,
        database_name(&url),
    );
    let ambiguous_client = DispatchRuntimeClient::new(
        DispatchRuntimePool::new(through_proxy).expect("proxied runtime pool"),
    )
    .expect("proxied runtime client");

    maintenance
        .enroll_dispatcher_participant(&EnrollParticipantRequest {
            provider_boundary_id: REGISTRATION_BOUNDARY.into(),
            dispatcher_id: AMBIGUOUS_DISPATCHER_ID.into(),
            participant_key_blake3: *blake3::hash(&AMBIGUOUS_KEY).as_bytes(),
        })
        .await
        .expect("enrol the ambiguity participant");

    proxy.drop_next_commit_response();
    let resolved = ambiguous_client
        .register_dispatcher(&registration_request_for(
            AMBIGUOUS_KEY,
            1,
            AMBIGUOUS_INSTANCE,
        ))
        .await
        .expect("the ambiguous commit resolves");
    assert!(
        proxy.fault_fired(),
        "the proxy never dropped a COMMIT response, so this proved nothing"
    );
    assert_eq!(
        resolved.disposition,
        DispatchDisposition::ReplayedAfterAmbiguousCommit,
        "an unresolved COMMIT that had in fact committed must resolve to a replay"
    );
    assert_eq!(resolved.value.dispatcher_id, AMBIGUOUS_DISPATCHER_ID);
    assert_eq!(resolved.value.lease_generation, 1);

    // The first attempt really did commit, exactly once - the resolution adopted it rather than
    // writing a second effect.
    let rows: i64 = admin
        .query_one(
            "SELECT pg_catalog.count(*) FROM object_store_retention.object_dispatch_dispatchers
             WHERE dispatcher_id = $1",
            &[&AMBIGUOUS_DISPATCHER_ID],
        )
        .await
        .expect("count the ambiguity participant's rows")
        .get(0);
    assert_eq!(rows, 1, "the resolution wrote a second effect");

    // 0013: admission, then its replay.
    let reserve = reserve_request();
    let reserved_outcome = runtime.reserve_put(&reserve).await.expect("reserve put");
    assert_eq!(reserved_outcome.disposition, DispatchDisposition::Applied);
    assert_eq!(
        reserved_outcome.value.spool_object_id,
        reserve.spool_object_id
    );
    assert_eq!(reserved_outcome.value.upload_fence, 7);
    assert_eq!(reserved_outcome.value.admission_clock_unix_ms, 2000);
    assert_eq!(reserved_outcome.value.expires_at_unix_ms, 3000);
    assert_eq!(
        reserved_outcome.value.reserve_put_ack_canonical_bytes,
        reserved.canonical_bytes(),
        "the database's ACK bytes differ from the independent Rust encoding"
    );
    assert_eq!(
        reserved_outcome.value.reserve_put_ack_blake3,
        *reserved.ack_blake3()
    );
    // Re-issuing the identical call is exactly the authoritative read the ambiguity resolution
    // performs. It returns REPLAY bound to the same descriptor.
    let reserved_replay = runtime.reserve_put(&reserve).await.expect("replay reserve");
    assert_eq!(reserved_replay.disposition, DispatchDisposition::Replayed);
    assert_eq!(reserved_replay.value, reserved_outcome.value);

    // 0015: the first non-final chunk, then its replay, then a gap.
    let first = runtime
        .put_upload_progress(&progress_request(0, 3))
        .await
        .expect("first progress");
    assert_eq!(first.disposition, DispatchDisposition::Applied);
    assert_eq!(first.value.committed_prefix_bytes, 3);
    assert_eq!(first.value.committed_prefix_chunks, 1);
    assert_eq!(first.value.spool_revision, 2);
    let first_replay = runtime
        .put_upload_progress(&progress_request(0, 3))
        .await
        .expect("replay first progress");
    assert_eq!(first_replay.disposition, DispatchDisposition::Replayed);
    assert_eq!(first_replay.value, first.value);
    assert_eq!(
        runtime
            .put_upload_progress(&progress_request(5, 9))
            .await
            .expect_err("chunk gap"),
        DispatchAuthorityError::ChunkGap
    );

    let second = runtime
        .put_upload_progress(&progress_request(1, 6))
        .await
        .expect("second progress");
    assert_eq!(second.disposition, DispatchDisposition::Applied);
    assert_eq!(second.value.committed_prefix_bytes, 6);
    assert_eq!(second.value.committed_prefix_chunks, 2);
    assert_eq!(second.value.spool_revision, 3);

    // 0017: the already-durable body assertion, then its replay.
    let ready_outcome = runtime
        .put_spool_ready(&ready_request(2))
        .await
        .expect("spool ready");
    assert_eq!(ready_outcome.disposition, DispatchDisposition::Applied);
    assert_eq!(ready_outcome.value.durable_handle, DURABLE_HANDLE);
    assert_eq!(ready_outcome.value.committed_size, SIZE);
    assert_eq!(ready_outcome.value.committed_blake3, BODY);
    assert_eq!(ready_outcome.value.ready_at_unix_ms, 2000);
    assert_eq!(ready_outcome.value.spool_revision, 4);
    assert_eq!(
        ready_outcome.value.reserve_put_ack_canonical_bytes,
        ready.canonical_bytes(),
        "the database's ready ACK bytes differ from the independent Rust encoding"
    );
    let ready_replay = runtime
        .put_spool_ready(&ready_request(2))
        .await
        .expect("replay spool ready");
    assert_eq!(ready_replay.disposition, DispatchDisposition::Replayed);
    assert_eq!(ready_replay.value, ready_outcome.value);

    // The bounded-execution envelope is in force, not merely emitted: a pool whose
    // `statement_timeout` is one millisecond cannot complete a reservation, and the abort arrives
    // as OperationTimeout rather than as a generic unavailability.
    //
    // What this does not distinguish: whether PostgreSQL aborted the reservation itself or the
    // `SET LOCAL lock_timeout` statement that follows the one-millisecond budget in the same
    // preamble. Both are `57014` and both mean the same thing here - the `SET LOCAL` landed and is
    // being enforced - which is the claim being made.
    let impatient = DispatchRuntimeClient::new(
        DispatchRuntimePool::new(pool_config(
            &url,
            DispatchPoolRole::Runtime,
            Duration::from_millis(1),
        ))
        .expect("impatient runtime pool"),
    )
    .expect("impatient runtime client");
    let mut other = reserve_request();
    other.spool_object_id = parse(&uuid_text(1004, "0523456789ab"));
    assert_eq!(
        impatient
            .reserve_put(&other)
            .await
            .expect_err("statement timeout"),
        DispatchAuthorityError::OperationTimeout,
        "SET LOCAL statement_timeout did not abort the call"
    );

    // No pool exceeds its own `pool_max`. This test constructed three runtime-role pools - the
    // main one (2), the single-slot retry one (1), and the impatient one (2) - so five is the sum
    // of what they are allowed to hold, and holding more would mean a pool opened a connection
    // outside its permit.
    //
    // The retry coverage above additionally exercises the `pool_max = 1` case end to end. What that
    // demonstrates, verified by mutation, is narrower than "the pool bound is load-bearing": a
    // retry loop that *retains* its lease across the backoff (rather than dropping it) surfaces as
    // `Pool(PoolExhausted)` instead of a successful third attempt. `DispatchLease`'s `Drop` frees the
    // permit, so merely forgetting to call `release()` would still pass; the probe guards the
    // retention case and a future refactor, not every way the discipline could be lost.
    const DECLARED_RUNTIME_SLOTS: i64 = 2 + 1 + 2;
    let backends: i64 = admin
        .query_one(
            "SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity
             WHERE usename = 'object_dispatch_retention_runtime'
               AND datname = pg_catalog.current_database()",
            &[],
        )
        .await
        .expect("count runtime backends")
        .get(0);
    assert!(
        backends <= DECLARED_RUNTIME_SLOTS,
        "runtime role holds {backends} backends against {DECLARED_RUNTIME_SLOTS} declared slots"
    );
}

// ---------------------------------------------------------------------------------------------
// A plaintext lost-`COMMIT` fault proxy
//
// The retention tier's `RetentionFaultProxy` already injects this fault, but its downstream
// listener requires a client certificate (`WebPkiClientVerifier::builder(..).build()` is mandatory
// mTLS) and checks the peer's common name. The dispatch pool deliberately has no client-certificate
// mode - CR-033 D1 dropped that contract along with the external authority database - so it cannot
// present one, and widening the shared proxy would change a fixture another tier depends on. This
// injects the same fault against a plaintext connection, `DispatchTlsMode::Disabled`. That is one
// of the pool's two modes, not a claim about what a cell will run: the crate is source-dark, no
// composition path selects a mode, and choosing one is CD-6's. `DispatchTlsMode::PinnedRootCa` has
// no live coverage in this tier at all - recorded as a CD-6 obligation in WP-114.
//
// Only the server-to-client direction is parsed. PostgreSQL backend messages are always tagged, so
// no startup-message special case is needed: when armed, the `CommandComplete` frame carrying
// `COMMIT` is dropped and the connection is closed instead of forwarded. The server has committed;
// the client never learns it did. That is exactly the state `AmbiguousCommit` exists for.
// ---------------------------------------------------------------------------------------------

struct LostCommitProxy {
    port: u16,
    arm: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
    _task: AbortOnDropHandle<()>,
}

impl LostCommitProxy {
    async fn start(upstream: String) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind lost-commit proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let arm = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let task_arm = Arc::clone(&arm);
        let task_fired = Arc::clone(&fired);
        let task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "dispatch-lost-commit-proxy",
            async move {
                let mut connections = Vec::new();
                while let Ok((downstream, _)) = listener.accept().await {
                    let upstream = upstream.clone();
                    let arm = Arc::clone(&task_arm);
                    let fired = Arc::clone(&task_fired);
                    connections.push(AbortOnDropHandle::new(lore_base::lore_spawn!(
                        "dispatch-lost-commit-connection",
                        async move {
                            if let Ok(server) = TcpStream::connect(&upstream).await {
                                relay(downstream, server, arm, fired).await;
                            }
                        }
                    )));
                }
            }
        ));
        Self {
            port,
            arm,
            fired,
            _task: task,
        }
    }

    /// Drop the next `COMMIT` response instead of forwarding it, once.
    fn drop_next_commit_response(&self) {
        self.fired.store(false, Ordering::Release);
        self.arm.store(true, Ordering::Release);
    }

    fn fault_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }
}

async fn relay(
    downstream: TcpStream,
    upstream: TcpStream,
    arm: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
) {
    let (mut downstream_read, mut downstream_write) = downstream.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let forward = async move {
        // Client to server is copied verbatim; nothing about the fault depends on it.
        let _ = tokio::io::copy(&mut downstream_read, &mut upstream_write).await;
    };
    let backward = async move {
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let read = match upstream_read.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            buffer.extend_from_slice(&chunk[..read]);
            let mut offset = 0usize;
            while buffer.len() - offset >= 5 {
                let tag = buffer[offset];
                let Ok(length) = <[u8; 4]>::try_from(&buffer[offset + 1..offset + 5]) else {
                    return;
                };
                let length = u32::from_be_bytes(length) as usize;
                if length < 4 {
                    return;
                }
                let total = 1 + length;
                if buffer.len() - offset < total {
                    break;
                }
                let is_commit_complete = tag == b'C'
                    && &buffer[offset + 5..offset + total] == b"COMMIT\0"
                    && arm.swap(false, Ordering::AcqRel);
                if is_commit_complete {
                    // The server committed. Close without forwarding, so the client's `COMMIT`
                    // never completes and its outcome is genuinely unknown to it.
                    fired.store(true, Ordering::Release);
                    return;
                }
                if downstream_write
                    .write_all(&buffer[offset..offset + total])
                    .await
                    .is_err()
                {
                    return;
                }
                offset += total;
            }
            buffer.drain(..offset);
            if downstream_write.flush().await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        () = forward => {}
        () = backward => {}
    }
}

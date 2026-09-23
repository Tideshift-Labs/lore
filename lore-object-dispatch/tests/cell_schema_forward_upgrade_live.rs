// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Live PostgreSQL 16 proof for CR-038's forward schema upgrade and spool metadata true-up.
//!
//! Every test here is `#[ignore]` and gated on its own `LORE_TEST_CELL_SCHEMA_UPGRADE_*_PG_URL`,
//! which must name a **fresh disposable** database, reached as the `postgres` superuser. Tests
//! derive the `object_dispatch_retention_{migrator,runtime,maintenance}` URLs from it by swapping
//! the user, matching `tests/dispatch_client_live.rs`'s `pool_config` convention. The four
//! `object_dispatch_retention_*` roles must already exist cluster-wide (owner NOLOGIN, the other
//! three LOGIN, the migrator a non-inheriting member of owner) -- `run-cell-schema-forward-upgrade-live.ps1`
//! creates them once per container, exactly as `run-cell-schema-install-live.ps1` does for the
//! migrator alone.
//!
//! Real reservation traffic (the flagship wedge/upgrade test) needs a genuine BLAKE3 provider at
//! `public.blake3(bytea)`, because `local_blake3_v1` refuses to run without one. This crate has no
//! BLAKE3 extension of its own (by design -- see `cell_schema_install.rs`'s module doc); the
//! runner supplies it via `plpython3u` and the `blake3` PyPI package, the same fixture shape as
//! `examples/write-behind-test-fixture.rs` and `lore-postgres/tests/run-write-behind-linux.ps1`'s
//! `Dockerfile.postgres-blake3`. An `--ignored` run with the environment unset panics in `connect`
//! and reports FAIL, not NOT RUN; the runner is what turns "matched zero tests" into its own NOT
//! RUN state.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_object_dispatch::DispatchConnectionBudget;
use lore_object_dispatch::DispatchDatabaseIdentity;
use lore_object_dispatch::DispatchPoolConfig;
use lore_object_dispatch::DispatchPoolRole;
use lore_object_dispatch::DispatchRecordLimits;
use lore_object_dispatch::DispatchRuntimeClient;
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;
use lore_object_dispatch::PutStreamIdentity;
use lore_object_dispatch::ReservePutQuotaScope;
use lore_object_dispatch::ReservePutRequest;
use lore_object_dispatch::cell_schema_install::CELL_SCHEMA_CURRENT;
use lore_object_dispatch::cell_schema_install::CellSchemaError;
use lore_object_dispatch::cell_schema_install::CellSchemaRevision;
use lore_object_dispatch::cell_schema_install::CellUpgradeDisposition;
use lore_object_dispatch::cell_schema_install::attest_cell_schema;
use lore_object_dispatch::cell_schema_install::install_cell_schema;
use lore_object_dispatch::cell_schema_install::install_cell_schema_at;
use lore_object_dispatch::cell_schema_install::upgrade_cell_schema;
use lore_object_dispatch::drain_policy::DrainClient;
use lore_object_dispatch::drain_policy::DrainDescriptor;
use lore_object_dispatch::drain_policy::DrainError;
use lore_object_dispatch::drain_policy::DrainPolicy;
use lore_object_dispatch::drain_policy::DrainStagePolicy;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

// -------------------------------------------------------------------------------------------
// Connection helpers
// -------------------------------------------------------------------------------------------

struct Admin {
    client: tokio_postgres::Client,
    _connection: AbortOnDropHandle<()>,
    base_url: String,
}

async fn admin(variable: &str) -> Admin {
    let base_url = std::env::var(variable).unwrap_or_else(|_| {
        panic!("{variable} must name a fresh disposable database, superuser URL")
    });
    admin_at(base_url).await
}

/// Reconnect an admin session to an already-validated URL. Used to re-establish the admin
/// connection after it was deliberately dropped to let an upgrade call see an exclusive session.
async fn admin_at(base_url: String) -> Admin {
    assert!(
        base_url.contains("postgres@") || base_url.contains("://postgres:"),
        "admin URL must authenticate as the postgres superuser"
    );
    let (client, connection) = tokio_postgres::connect(&base_url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable database as superuser");
    let handle = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "cell-schema-forward-upgrade-live-admin",
        async move {
            let _ = connection.await;
        }
    ));
    Admin {
        client,
        _connection: handle,
        base_url,
    }
}

fn url_as(base_url: &str, role: &str) -> String {
    let without_scheme = base_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base_url);
    let host_and_path = without_scheme
        .split_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(without_scheme);
    format!("postgresql://{role}@{host_and_path}")
}

async fn connect_as(base_url: &str, role: &str) -> (tokio_postgres::Client, AbortOnDropHandle<()>) {
    let url = url_as(base_url, role);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap_or_else(|error| panic!("connect as {role}: {error}"));
    let handle = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "cell-schema-forward-upgrade-live",
        async move {
            let _ = connection.await;
        }
    ));
    (client, handle)
}

/// The exact original body of `local_canonical_u8_v1` (migration 0009), reproduced byte-for-byte
/// including whitespace: `pg_get_functiondef` reconstructs a plpgsql function's body verbatim from
/// the stored `prosrc`, so a restore that merely calls the same logic with different indentation
/// still drifts the `functions` catalog section.
const LOCAL_CANONICAL_U8_V1_ORIGINAL_BODY: &str =
    "CREATE OR REPLACE FUNCTION object_store_retention.local_canonical_u8_v1(value integer)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE answer bytea := pg_catalog.decode('00', 'hex');
BEGIN
  IF value < 0 OR value > 255 THEN
    RAISE EXCEPTION 'LOCAL_CANONICAL_U8_INVALID' USING ERRCODE = '22023';
  END IF;
  RETURN pg_catalog.set_byte(answer, 0, value);
END
$$;";

/// Poll until no OTHER session is connected to the cell database, from the migrator connection's
/// own point of view (the same query `upgrade_cell_schema`'s D4 check runs). A real R27->current
/// upgrade call refuses outright (`ReplicasActive`) while any other session -- including this
/// fixture's own admin/superuser connection or a runtime pool's pooled connection -- is still
/// open, so every test must explicitly drop every other handle and wait here before its first
/// real upgrade call. A call already at the current state skips this check entirely (D4 only
/// gates the one state transition), so recovery/no-op upgrade calls need no such wait.
async fn wait_until_exclusive(migrator: &tokio_postgres::Client) {
    for _ in 0..100 {
        let others: i64 = migrator
            .query_one(
                "SELECT (numbackends - 1)::bigint FROM pg_catalog.pg_stat_database \
                 WHERE datname = pg_catalog.current_database()",
                &[],
            )
            .await
            .expect("read backend count")
            .get(0);
        if others <= 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "another session on the cell database never disconnected; a fixture connection (admin, \
         pool, or a second migrator) was left open before an upgrade call that needs exclusivity"
    );
}

/// Returns the pool-facing identity plus the two raw values, because
/// `DispatchDatabaseIdentity`'s fields are deliberately private and the budget fixture below
/// needs to carry the raw values into its own canonical encoding.
async fn database_identity(
    admin: &tokio_postgres::Client,
) -> (DispatchDatabaseIdentity, String, u32) {
    let row = admin
        .query_one(
            "SELECT (SELECT system_identifier::text FROM pg_control_system()), \
             (SELECT oid::bigint FROM pg_database WHERE datname = current_database())",
            &[],
        )
        .await
        .expect("physical database identity");
    let system: String = row.get(0);
    let oid: i64 = row.get(1);
    let oid = u32::try_from(oid).expect("database oid");
    let identity = DispatchDatabaseIdentity::new(system.parse().expect("system identifier"), oid)
        .expect("valid physical identity");
    (identity, system, oid)
}

fn runtime_pool_config(base_url: &str, identity: DispatchDatabaseIdentity) -> DispatchPoolConfig {
    DispatchPoolConfig {
        postgres_url: format!(
            "{}?sslmode=disable",
            url_as(base_url, "object_dispatch_retention_runtime")
        ),
        role: DispatchPoolRole::Runtime,
        expected_database_identity: identity,
        pool_max: 2,
        connect_timeout: Duration::from_secs(10),
        acquire_timeout: Duration::from_secs(10),
        statement_timeout: Duration::from_secs(10),
        lock_timeout: Duration::from_millis(2_000),
        tls: DispatchTlsMode::Disabled,
        budget: DispatchConnectionBudget::new(1, 1, 1, 1, 2, 0).expect("live process budget"),
    }
}

/// Install a genuine BLAKE3 provider. `local_blake3_v1` refuses to run without one
/// (`LOCAL_BLAKE3_PROVIDER_UNAVAILABLE`); the runner's image carries `plpython3u` and the `blake3`
/// PyPI package for exactly this purpose.
async fn install_blake3_provider(admin: &tokio_postgres::Client) {
    admin
        .batch_execute(
            "CREATE EXTENSION IF NOT EXISTS plpython3u;
             CREATE OR REPLACE FUNCTION public.blake3(payload bytea) RETURNS bytea
             LANGUAGE plpython3u IMMUTABLE STRICT AS $$
import blake3
return blake3.blake3(bytes(payload)).digest()
$$;",
        )
        .await
        .expect(
            "install a real BLAKE3 provider; requires the postgres-blake3 image \
             (run-cell-schema-forward-upgrade-live.ps1)",
        );
}

async fn now_ms(admin: &tokio_postgres::Client) -> i64 {
    admin
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .expect("database clock")
        .get(0)
}

// -------------------------------------------------------------------------------------------
// Budget configuration fixture (adapted from `examples/write-behind-test-fixture.rs`; that file
// is a standalone binary and cannot be imported as a library, so the identical publish shape is
// reproduced here against the same PUBLISH_SQL contract).
// -------------------------------------------------------------------------------------------

const BUDGET_PUBLISH_SQL: &str = "SELECT r.result_code FROM
object_store_retention.object_store_dispatch_publish_budget_configuration_v1(
'object-store-dispatch-budget-limiter-v1', $1, $2, $3::text::object_store_retention.uint64, $4,
'object-store-frozen-capacity-budget-core-v1', 'object-store-exact-target-cache-disposition-v1',
'object-store-budget-frozen-envelope-v1', 1::smallint, $5, $3::text::object_store_retention.uint64,
1::smallint, $5, $3::text::object_store_retention.uint64,
1::smallint, $5, $3::text::object_store_retention.uint64, $5, $5, $1, $1,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$6, $7, $8, $6, $3::text::object_store_retention.uint64,
$9, $10, $11::text::object_store_retention.uint64, $12,
$13, $6, $8, $14, $3::text::object_store_retention.uint64, 1::smallint,
NULL::text, NULL::text, NULL::bytea, NULL::bytea, $14, $15::text::jsonb, $16::text::jsonb) AS r";

struct BudgetFixture {
    allocation_revision: &'static str,
    allocation_fence: u64,
    expiry_ms: i64,
}

async fn publish_budget(
    admin: &tokio_postgres::Client,
    boundary: &str,
    cell: &str,
    system_identifier: &str,
    database_oid: u32,
    now: i64,
) -> BudgetFixture {
    let fixture = BudgetFixture {
        allocation_revision: "forward-upgrade-budget-v1",
        allocation_fence: 1,
        expiry_ms: now + 3_600_000,
    };
    #[derive(serde::Serialize)]
    struct Config<'a> {
        #[serde(rename = "schemaRevision")]
        schema_revision: &'a str,
        provenance: &'a str,
        #[serde(rename = "cellId")]
        cell_id: &'a str,
        #[serde(rename = "providerBoundaryId")]
        provider_boundary_id: &'a str,
        #[serde(rename = "providerEndpoint")]
        provider_endpoint: &'a str,
        #[serde(rename = "providerBucket")]
        provider_bucket: &'a str,
        #[serde(rename = "evidenceReference")]
        evidence_reference: &'a str,
        #[serde(rename = "systemIdentifier")]
        system_identifier: String,
        #[serde(rename = "databaseOid")]
        database_oid: u32,
        #[serde(rename = "allocationRevision")]
        allocation_revision: &'a str,
        #[serde(rename = "allocationFence")]
        allocation_fence: u64,
        #[serde(rename = "issuedAtUnixMs")]
        issued_at_unix_ms: i64,
        #[serde(rename = "hardExpiresAtUnixMs")]
        hard_expires_at_unix_ms: i64,
        #[serde(rename = "sharedUnits")]
        shared_units: u64,
        #[serde(rename = "classUnits")]
        class_units: u64,
        #[serde(rename = "listUnits")]
        list_units: u64,
        #[serde(rename = "refillIntervalMs")]
        refill_interval_ms: u64,
        predecessor: Option<()>,
    }
    let config = Config {
        schema_revision: "local-cell-budget-policy-v2",
        provenance: "operator-selected-local-development-limit-v1",
        cell_id: cell,
        provider_boundary_id: boundary,
        provider_endpoint: "http://minio:9000",
        provider_bucket: "forward-upgrade-fragments",
        evidence_reference: "cr-038 disposable forward-upgrade fixture",
        system_identifier: system_identifier.to_string(),
        database_oid,
        allocation_revision: fixture.allocation_revision,
        allocation_fence: fixture.allocation_fence,
        issued_at_unix_ms: now - 1000,
        hard_expires_at_unix_ms: fixture.expiry_ms,
        shared_units: 10_000,
        class_units: 1_000,
        list_units: 5,
        refill_interval_ms: 1_000,
        predecessor: None,
    };
    fn digest(label: &str, bytes: &[u8]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_derive_key(label);
        hasher.update(bytes);
        hasher.finalize()
    }
    let core = digest(
        "Commit0 local development budget core v1",
        &serde_json::to_vec(&config).unwrap(),
    );
    let disposition = digest(
        "Commit0 local development no-cache disposition v1",
        core.as_bytes(),
    );
    let envelope = digest(
        "Commit0 local development budget envelope v1",
        disposition.as_bytes(),
    );
    let disposition_id = Uuid::from_slice(&disposition.as_bytes()[..16]).unwrap();
    let dimensions = serde_json::json!([{"dimensionId":"local-policy-requests", "effectiveBound":config.shared_units,
        "measuredLoad":0, "targetDemand":0, "failureReserve":0, "preCacheHeadroom":config.shared_units, "finalBudget":config.shared_units}]).to_string();
    let vector = digest(
        "Commit0 local development budget vector v1",
        dimensions.as_bytes(),
    );
    let caps = serde_json::to_string(
        &(1..=7_i32)
            .map(|class| {
                let units = match class {
                    1 => config.shared_units,
                    7 => config.list_units,
                    _ => config.class_units,
                };
                serde_json::json!({"capClass":class,"capacityUnits":units,"refillUnits":units,"refillIntervalMs":config.refill_interval_ms})
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    admin
        .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance; BEGIN ISOLATION LEVEL SERIALIZABLE")
        .await
        .unwrap();
    let row = admin
        .query_one(
            BUDGET_PUBLISH_SQL,
            &[
                &config.provider_boundary_id,
                &config.allocation_revision,
                &"1",
                &config.hard_expires_at_unix_ms,
                &config.cell_id,
                &core.as_bytes().as_slice(),
                &disposition_id,
                &disposition.as_bytes().as_slice(),
                &Option::<Uuid>::None,
                &Option::<Vec<u8>>::None,
                &"0",
                &Option::<Vec<u8>>::None,
                &envelope.as_bytes().as_slice(),
                &vector.as_bytes().as_slice(),
                &dimensions,
                &caps,
            ],
        )
        .await
        .expect("publish budget configuration");
    let code: String = row.get("result_code");
    assert_eq!(code, "PUBLISHED", "fresh budget fixture must publish once");
    admin
        .batch_execute("COMMIT; RESET SESSION AUTHORIZATION")
        .await
        .unwrap();
    fixture
}

fn drain_policy(
    boundary: &str,
    cell: &str,
    service: &str,
    revision: &str,
    expiry_ms: u64,
    metadata_max_bytes: u64,
    metadata_max_rows: u64,
) -> DrainPolicy {
    DrainPolicy {
        boundary: boundary.into(),
        cell: cell.into(),
        service: service.into(),
        revision: revision.into(),
        quota_revision: 1,
        quotas: [[100_000_000, 100_000, 1000, 0, 0, 0]; 3],
        // Short on purpose: `drain_cleanup_claim_v1` refuses (`DRAIN_CLEANUP_TOO_EARLY`) until the
        // reservation's own expiry has passed, and `cleanup_not_before` is derived from it. This
        // fixture wants each synthetic reservation cleanable almost immediately, not after a
        // realistic multi-minute TTL, so `reserve_and_release` sleeps past this window before
        // claiming. The pool is warmed (see below) before this window starts being spent, so it
        // only needs to absorb per-call round-trip time, not a cold connect-and-attest.
        maximum_ttl_ms: 3_000,
        expires_at_ms: expiry_ms,
        metadata_max_rows,
        metadata_max_bytes,
        stage: DrainStagePolicy {
            max_bytes: 30_000_000,
            max_files: 3000,
            max_metadata_bytes: metadata_max_bytes,
            max_metadata_rows: metadata_max_rows,
            prepare_ttl_ms: 60_000,
        },
    }
}

async fn publish_drain_policy(admin: &tokio_postgres::Client, policy: &DrainPolicy) {
    let json = serde_json::to_string(policy).unwrap();
    let canonical = policy.canonical_bytes().unwrap();
    let digest = policy.digest().unwrap();
    admin
        .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance; BEGIN ISOLATION LEVEL SERIALIZABLE")
        .await
        .unwrap();
    admin
        .query_one(
            "SELECT object_store_retention.drain_policy_publish_v1($1::text::jsonb,$2,$3)",
            &[&json, &canonical, &&digest[..]],
        )
        .await
        .expect("publish drain policy");
    admin
        .batch_execute("COMMIT; RESET SESSION AUTHORIZATION")
        .await
        .unwrap();
}

/// One synthetic descriptor. `i` only needs to make the descriptor's identifiers and object key
/// distinct across a run; the underlying reservation semantics are otherwise identical every time.
fn synthetic_descriptor(
    i: u32,
    policy: &DrainPolicy,
    policy_digest: &[u8; 32],
    allocation: &BudgetFixture,
    now: i64,
) -> DrainDescriptor {
    let send_not_after = now + i64::try_from(policy.maximum_ttl_ms).unwrap() - 1000;
    DrainDescriptor {
        policy_revision: policy.revision.clone(),
        policy_digest: lore_object_dispatch::drain_policy::hex(policy_digest),
        boundary: policy.boundary.clone(),
        cell: policy.cell.clone(),
        service: policy.service.clone(),
        logical_request_id: Uuid::now_v7(),
        attempt_id: Uuid::now_v7(),
        upload_id: Uuid::now_v7(),
        spool_object_id: Uuid::now_v7(),
        upload_fence: 1,
        source_hash: "22".repeat(32),
        source_epoch: 1,
        source_manifest: "33".repeat(32),
        remote_epoch: 1,
        remote_fence: 1,
        object_key: format!("forward-upgrade-object-{i:08}"),
        body_digest: "44".repeat(32),
        body_size: 128,
        send_not_after_ms: u64::try_from(send_not_after).unwrap(),
        hard_not_after_ms: u64::try_from(send_not_after + 1000).unwrap(),
        prepared_ttl_ms: policy.maximum_ttl_ms,
        max_chunk_bytes: 262_144,
        allocation_revision: allocation.allocation_revision.into(),
        allocation_fence: allocation.allocation_fence,
        allocation_expiry_ms: u64::try_from(allocation.expiry_ms).unwrap(),
        boundary_digest: "55".repeat(32),
        boundary_token: "boundary-token".into(),
        observation_digest: "66".repeat(32),
    }
}

/// One full reserve -> claim -> release(+no-op compact) cycle, driven through the real
/// `DrainClient`. Compaction is a deliberate no-op here: the published policy's `expires_at_ms` is
/// far in the future, so every released row stays in state 3 holding its charge -- exactly the
/// "8192 released rows, zero spooled files" shape from the CR's slot-31 evidence.
async fn reserve_and_release(
    client: &DrainClient,
    descriptor: &DrainDescriptor,
    claimable_after: Duration,
) -> Result<(), DrainError> {
    client.reserve(descriptor).await?;
    // `drain_cleanup_claim_v1` refuses until the reservation's own expiry passes
    // (`DRAIN_CLEANUP_TOO_EARLY`); the fixture's policy pins that window short specifically so this
    // wait is bounded.
    tokio::time::sleep(claimable_after).await;
    let intent = client.claim_cleanup(descriptor.spool_object_id).await?;
    client.release_cleanup(&intent).await?;
    Ok(())
}

// -------------------------------------------------------------------------------------------
// CR-038 addendum (2026-09-23) fixture: admit one genuine `object_dispatch_spool_objects` row
// (state 1, RESERVED) through the real 0013 `ReservePut` procedure, via the typed runtime client
// -- not a hand-crafted INSERT. `payload_kind = 1` (chunked upload, the identity's `upload_id` and
// `upload_fence` both set) needs no pre-existing `object_dispatch_requests` row:
// `bound_request_logical_request_id` stays NULL, and a composite foreign key with a NULL column is
// not enforced. The blake3-shaped fields below are opaque 32-byte tokens the procedure stores and
// later re-derives its own ACK digest from; they are not required to be a real hash of anything,
// exactly as `tests/dispatch_client_live.rs`'s own fixture uses fixed byte patterns for the same
// fields.
// -------------------------------------------------------------------------------------------

async fn admit_one_reserved_spool_object(pool: Arc<DispatchRuntimePool>, boundary: &str) {
    let runtime = DispatchRuntimeClient::new(pool).expect("runtime client");
    let identity = PutStreamIdentity {
        provider_boundary_id: boundary.into(),
        authenticated_cell_id: "r25-refusal-cell".into(),
        authenticated_tenant_id: "r25-refusal-tenant".into(),
        logical_request_id: Uuid::now_v7(),
        attempt_id: Uuid::now_v7(),
        upload_id: Uuid::now_v7(),
        upload_fence: 1,
    };
    let quota = ReservePutQuotaScope {
        max_bytes: 100,
        max_rows: 10,
        max_concurrency: 10,
        low_water_bytes: 0,
        low_water_rows: 0,
        low_water_concurrency: 0,
    };
    let request = ReservePutRequest {
        protocol_revision: "protocol-1".into(),
        policy_revision: "policy-1".into(),
        identity,
        spool_object_id: Uuid::now_v7(),
        boundary_blake3: [0x41; 32],
        boundary_token: "boundary-token".into(),
        observation_binding_blake3: [0x51; 32],
        expected_size: 10,
        expected_blake3: [0x31; 32],
        put_reservation_fingerprint: [0x61; 32],
        allocation_revision: "allocation-1".into(),
        allocation_fence: 1,
        reservation_deadline_unix_ms: 4_000_000_000_000,
        allocation_hard_expiry_unix_ms: 4_000_000_000_000,
        prepared_ttl_ms: 60_000,
        max_chunk_bytes: 1_048_576,
        quota_revision: 1,
        global_quota: quota,
        cell_quota: quota,
        tenant_quota: quota,
        limits: DispatchRecordLimits {
            maximum_identity_bytes: 256,
            maximum_boundary_token_bytes: 256,
            maximum_record_bytes: 16_777_216,
        },
    };
    runtime
        .reserve_put(&request)
        .await
        .expect("admit one real reservation through 0013, leaving a spool_objects row behind");
}

// -------------------------------------------------------------------------------------------
// Test plan item 1 (the main one): an R27 cell wedges under the slot-31 load shape; the SAME
// cell, upgraded, absorbs the same load and more. The pre-upgrade wedge observation IS the
// negative control the CR asks for, colocated in one test rather than a second cell.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database with a real BLAKE3 provider"]
async fn live_upgraded_cell_survives_the_load_that_wedges_an_unupgraded_cell() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_WEDGE_PG_URL").await;
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");
    install_blake3_provider(&fixture.client).await;

    let (identity, system_identifier, database_oid) = database_identity(&fixture.client).await;
    let now = now_ms(&fixture.client).await;
    let boundary = "forward-upgrade-boundary";
    let cell = "forward-upgrade-cell";
    let service = "forward-upgrade-service";
    let allocation = publish_budget(
        &fixture.client,
        boundary,
        cell,
        &system_identifier,
        database_oid,
        now,
    )
    .await;

    // Scaled down from slot-31's 8,192 reservations / 134,217,728-byte cap by the same ratio: the
    // wedge mechanism (a flat 16,384-byte charge per row, never given back until compaction) does
    // not depend on the absolute count. WEDGE_AT reservations exhaust METADATA_MAX_BYTES exactly.
    const WEDGE_AT: u32 = 8;
    const METADATA_MAX_BYTES: u64 = 16384 * WEDGE_AT as u64;
    let policy = drain_policy(
        boundary,
        cell,
        service,
        "forward-upgrade-policy-v1",
        u64::try_from(now + 3_600_000).unwrap(),
        METADATA_MAX_BYTES,
        1_000_000,
    );
    publish_drain_policy(&fixture.client, &policy).await;
    let policy_digest = policy.digest().unwrap();

    let pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&fixture.base_url, identity))
            .expect("runtime pool"),
    );
    let client = DrainClient::new(pool);
    // Warm the pool (first connect + physical-identity attestation) before the timed loop below,
    // so reservation 0's `send_not_after_ms` window isn't spent on cold-connection latency.
    client
        .verify_schema_revision()
        .await
        .expect_err("an R27 cell has no marker yet; this call only warms the pool");

    // Slightly longer than the policy's own `maximum_ttl_ms` window used to build each
    // descriptor's `send_not_after_ms`/`hard_not_after_ms`, so `drain_cleanup_claim_v1` never
    // refuses with `DRAIN_CLEANUP_TOO_EARLY`.
    let claimable_after = Duration::from_millis(policy.maximum_ttl_ms + 500);

    // -- Negative control (still R27): drive exactly the wedging load and observe the wedge. --
    for i in 0..WEDGE_AT {
        // A fresh clock read per reservation: each descriptor's expiry window is short by design
        // (see the policy above), so a `now` captured once at the top of the test would already be
        // stale by the second or third iteration.
        let iteration_now = now_ms(&fixture.client).await;
        let descriptor =
            synthetic_descriptor(i, &policy, &policy_digest, &allocation, iteration_now);
        reserve_and_release(&client, &descriptor, claimable_after)
            .await
            .unwrap_or_else(|error| panic!("reservation {i} on the unupgraded cell: {error}"));
    }
    let wedged = client
        .observe(boundary, cell)
        .await
        .expect("observe wedged cell");
    assert!(
        wedged.metadata_full,
        "an R27 cell must wedge after {WEDGE_AT} released reservations at the flat charge, exactly \
         the slot-31 defect (ledger row 34)"
    );
    let extra_now = now_ms(&fixture.client).await;
    let extra = synthetic_descriptor(WEDGE_AT, &policy, &policy_digest, &allocation, extra_now);
    assert!(
        matches!(client.reserve(&extra).await, Err(DrainError::Refused)),
        "a wedged cell must refuse a further reservation, not silently accept it"
    );

    // -- Upgrade in place. D4 requires no other session connected: drop the admin connection and
    // the runtime pool (the sole owners of their respective sessions) before calling, and wait for
    // the server to actually observe them gone. --
    let base_url = fixture.base_url.clone();
    drop(client);
    drop(fixture);
    wait_until_exclusive(&migrator).await;
    let report = upgrade_cell_schema(&migrator)
        .await
        .expect("upgrade R27 to current");
    assert_eq!(
        report.disposition,
        CellUpgradeDisposition::Upgraded(CellSchemaRevision::R27)
    );
    assert_eq!(report.attestation.schema_revision, CELL_SCHEMA_CURRENT);
    let fixture = admin_at(base_url).await;
    let pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&fixture.base_url, identity))
            .expect("runtime pool"),
    );
    let client = DrainClient::new(pool);

    // -- Positive: the exact same cell, same policy, same load shape, no longer wedges. --
    let after_upgrade = client
        .observe(boundary, cell)
        .await
        .expect("observe upgraded cell");
    assert!(
        !after_upgrade.metadata_full,
        "the upgrade must true up every already-released row's charge and clear metadata_full"
    );

    // Drive past the byte count that wedged the unupgraded cell: 2x WEDGE_AT more reservations,
    // metadata_max_rows left generous so only the byte true-up is under test (CR-038 D7: R4's
    // criterion is the byte cap only; the row counter is a separate, deliberately unfixed gap).
    for i in WEDGE_AT..WEDGE_AT + WEDGE_AT * 2 {
        let iteration_now = now_ms(&fixture.client).await;
        let descriptor =
            synthetic_descriptor(i, &policy, &policy_digest, &allocation, iteration_now);
        reserve_and_release(&client, &descriptor, claimable_after)
            .await
            .unwrap_or_else(|error| panic!("reservation {i} on the upgraded cell: {error}"));
        let observation = client
            .observe(boundary, cell)
            .await
            .expect("observe during sustained load");
        assert!(
            !observation.metadata_full,
            "metadata_full must stay false through sustained load after the true-up (row {i})"
        );
    }

    // The counter must reflect the ACTUAL retained size, not merely "not full": every state-3 row
    // now costs its computed retained size, so the aggregate is far below the byte cap that a flat
    // 16,384-byte charge would have reached in WEDGE_AT * 3 reservations.
    let final_metadata_bytes: i64 = fixture
        .client
        .query_one(
            "SELECT metadata_bytes::bigint FROM object_store_retention.drain_policies WHERE boundary = $1 AND cell = $2",
            &[&boundary, &cell],
        )
        .await
        .expect("read trued-up policy counter")
        .get(0);
    assert!(
        u64::try_from(final_metadata_bytes).unwrap() < METADATA_MAX_BYTES,
        "trued-up aggregate ({final_metadata_bytes}) must be well under the cap ({METADATA_MAX_BYTES}) \
         after 3x the wedging row count"
    );
}

// -------------------------------------------------------------------------------------------
// Real scale: the flagship test above proves the mechanism at a scaled-down cap (network
// round-trips through real reserve/claim/release dominate its runtime). This test proves the
// absolute numbers instead: a cell bulk-seeded (SQL, like the implementer's own scratch proof) to
// the exact slot-31 shape -- 8,192 released rows, 134,217,728 bytes, the real dev policy's cap --
// wedges, and the same cell upgraded in place both clears `metadata_full` and accepts real new
// reservations through `DrainClient`.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database with a real BLAKE3 provider"]
async fn live_upgraded_cell_at_real_dev_cap_stays_writable() {
    const REAL_ROWS: i64 = 8192;
    const REAL_MAX_BYTES: u64 = 134_217_728; // 8192 * 16384, the real dev policy cap.
    const REAL_MAX_ROWS: u64 = 32_768; // the real dev policy's metadata_max_rows.

    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_REAL_CAP_PG_URL").await;
    let base_url = fixture.base_url.clone();
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");
    install_blake3_provider(&fixture.client).await;

    let (identity, system_identifier, database_oid) = database_identity(&fixture.client).await;
    let now = now_ms(&fixture.client).await;
    let boundary = "real-cap-boundary";
    let cell = "real-cap-cell";
    let service = "real-cap-service";
    let allocation = publish_budget(
        &fixture.client,
        boundary,
        cell,
        &system_identifier,
        database_oid,
        now,
    )
    .await;

    // A real, fully-valid published policy (not the minimal synthetic JSON the other seeded-row
    // tests use), because the writability check at the end drives REAL reservations against it.
    let policy = drain_policy(
        boundary,
        cell,
        service,
        "real-cap-policy-v1",
        u64::try_from(now + 3_600_000).unwrap(),
        REAL_MAX_BYTES,
        REAL_MAX_ROWS,
    );
    publish_drain_policy(&fixture.client, &policy).await;
    let policy_digest = policy.digest().unwrap();
    let policy_digest_hex = lore_object_dispatch::drain_policy::hex(&policy_digest);

    // Bulk-seed the exact slot-31 shape in one round trip: 8,192 released (state 3) rows, each
    // still holding the flat 16,384-byte pre-true-up charge, zero spooled files (nothing here
    // creates an `object_dispatch_spool_objects` row, matching the observed dump). `drain_spool_custody`
    // has no UUID-version CHECK of its own (unlike `object_dispatch_spool_objects`), so
    // `md5(...)::uuid` identities are sufficient here.
    fixture
        .client
        .execute(
            &format!(
                "INSERT INTO object_store_retention.drain_spool_custody
                   (spool_id, boundary, cell, service, logical_id, attempt_id, descriptor, canonical,
                    digest, cleanup_not_before, state, cleanup_fence, metadata_bytes, release_receipt,
                    release_digest)
                 SELECT md5('real-cap-spool'||i)::uuid, '{boundary}', '{cell}', '{service}',
                   md5('real-cap-logical'||i)::uuid, md5('real-cap-attempt'||i)::uuid,
                   jsonb_build_object('policy_revision', 'real-cap-policy-v1', 'policy_digest', '{policy_digest_hex}'),
                   decode('aa','hex'), decode(repeat('11',32),'hex'), 0, 3, 1, 16384,
                   decode(repeat('11',32),'hex'), decode(repeat('11',32),'hex')
                 FROM generate_series(1, {REAL_ROWS}) i"
            ),
            &[],
        )
        .await
        .expect("bulk-seed the real slot-31 shape (SQL, matching the implementer's own scratch proof)");
    fixture
        .client
        .execute(
            "UPDATE object_store_retention.drain_policies \
             SET metadata_rows = $1::text::object_store_retention.uint64, \
                 metadata_bytes = $2::text::object_store_retention.uint64 \
             WHERE boundary = $3 AND cell = $4",
            &[
                &REAL_ROWS.to_string(),
                &REAL_MAX_BYTES.to_string(),
                &boundary,
                &cell,
            ],
        )
        .await
        .expect("set the aggregate to the exact real cap");

    let pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&fixture.base_url, identity))
            .expect("runtime pool"),
    );
    let client = DrainClient::new(pool);
    client
        .verify_schema_revision()
        .await
        .expect_err("R27 cell, no marker yet; this call only warms the pool");

    let wedged = client
        .observe(boundary, cell)
        .await
        .expect("observe the bulk-seeded cell");
    assert!(
        wedged.metadata_full,
        "8,192 rows at the flat charge on the real {REAL_MAX_BYTES}-byte cap must read as wedged, \
         exactly the slot-31 condition"
    );

    drop(client);
    drop(fixture);
    wait_until_exclusive(&migrator).await;
    let report = upgrade_cell_schema(&migrator)
        .await
        .expect("upgrade the real-scale cell to current");
    assert_eq!(report.attestation.schema_revision, CELL_SCHEMA_CURRENT);

    let fixture = admin_at(base_url).await;
    let pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&fixture.base_url, identity))
            .expect("runtime pool"),
    );
    let client = DrainClient::new(pool);
    let after_upgrade = client
        .observe(boundary, cell)
        .await
        .expect("observe the upgraded real-scale cell");
    assert!(
        !after_upgrade.metadata_full,
        "trueing up all 8,192 rows must clear metadata_full at the real cap"
    );

    // Writable: drive a handful of real reservations through `DrainClient` against the SAME
    // published policy the bulk-seeded rows reference, proving the cell accepts new writes, not
    // merely that the counter reads as not-full.
    client
        .verify_schema_revision()
        .await
        .expect("the upgraded cell's marker must now be readable");
    let claimable_after = Duration::from_millis(policy.maximum_ttl_ms + 500);
    for i in 0..3u32 {
        let iteration_now = now_ms(&fixture.client).await;
        let descriptor =
            synthetic_descriptor(i, &policy, &policy_digest, &allocation, iteration_now);
        reserve_and_release(&client, &descriptor, claimable_after)
            .await
            .unwrap_or_else(|error| panic!("post-upgrade real reservation {i}: {error}"));
    }
    assert!(
        !client
            .observe(boundary, cell)
            .await
            .expect("observe after real writes")
            .metadata_full,
        "the cell must remain writable (not wedged) after real post-upgrade reservations"
    );
}

// -------------------------------------------------------------------------------------------
// CR-038 D5: write-behind refuses to start on a cell that predates the true-up, and accepts one
// that has it. No reservation traffic needed -- this is a pure marker readback.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_write_behind_refuses_an_unupgraded_cell_and_accepts_an_upgraded_one() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_D5_PG_URL").await;
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");

    let (identity, ..) = database_identity(&fixture.client).await;
    let pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&fixture.base_url, identity))
            .expect("runtime pool"),
    );
    let client = DrainClient::new(pool);
    assert_eq!(
        client.verify_schema_revision().await,
        Err(DrainError::SchemaUpgradeRequired),
        "an R27 cell has no cell_schema_revision_v1() marker; write-behind must refuse to start"
    );

    let base_url = fixture.base_url.clone();
    drop(client);
    drop(fixture);
    wait_until_exclusive(&migrator).await;
    upgrade_cell_schema(&migrator)
        .await
        .expect("upgrade to current");
    let pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&base_url, identity)).expect("runtime pool"),
    );
    let client = DrainClient::new(pool);
    assert_eq!(
        client.verify_schema_revision().await,
        Ok(()),
        "an upgraded cell's marker must match this build's CELL_SCHEMA_REVISION"
    );
}

// -------------------------------------------------------------------------------------------
// Test plan item 6: refusals. Catalog drift (an unknown manifest), a future marker, and a
// replica still connected all refuse without changing the cell's state.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_upgrade_refuses_unknown_states_future_markers_and_active_replicas() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_REFUSALS_PG_URL").await;
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");

    // An R27 cell with one function planted (drift, not a known older state) must refuse via
    // attestation classification -- CatalogDrift, not a guess at which state it might be.
    fixture
        .client
        .batch_execute(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             CREATE OR REPLACE FUNCTION object_store_retention.local_canonical_u8_v1(value integer)
             RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
             SET search_path = pg_catalog AS 'SELECT pg_catalog.decode(''00'', ''hex'')';
             COMMIT;",
        )
        .await
        .expect("plant drift");
    assert!(
        matches!(
            upgrade_cell_schema(&migrator).await,
            Err(CellSchemaError::CatalogDrift(_))
        ),
        "an unknown manifest must refuse as catalog drift, not as UpgradeRequired for a guessed state"
    );
    fixture
        .client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             {LOCAL_CANONICAL_U8_V1_ORIGINAL_BODY}
             COMMIT;"
        ))
        .await
        .expect("restore the original function body");
    // The cell is still R27 here (not yet upgraded): `attest_cell_schema` always requires the
    // CURRENT state, so a cell that fully attests as a known OLDER state is reported through
    // `UpgradeRequired`, not through `Ok`. That is itself the proof the plant is fully undone: a
    // real drift would still report `CatalogDrift`.
    assert_eq!(
        attest_cell_schema(&migrator).await,
        Err(CellSchemaError::UpgradeRequired(CellSchemaRevision::R27)),
        "attestation must fully hold at R27 once the plant is undone"
    );

    // Upgrade for real, then plant a future marker: the installer must refuse it outright.
    let base_url = fixture.base_url.clone();
    drop(fixture);
    wait_until_exclusive(&migrator).await;
    upgrade_cell_schema(&migrator)
        .await
        .expect("real upgrade to current");
    let fixture = admin_at(base_url).await;
    fixture
        .client
        .batch_execute(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             CREATE OR REPLACE FUNCTION object_store_retention.cell_schema_revision_v1() RETURNS integer
             LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT 29 $$;
             COMMIT;",
        )
        .await
        .expect("plant a future marker");
    assert_eq!(
        upgrade_cell_schema(&migrator).await,
        Err(CellSchemaError::FutureSchema)
    );
    assert_eq!(
        attest_cell_schema(&migrator).await,
        Err(CellSchemaError::FutureSchema)
    );
    fixture
        .client
        .batch_execute(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             CREATE OR REPLACE FUNCTION object_store_retention.cell_schema_revision_v1() RETURNS integer
             LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT 28 $$;
             COMMIT;",
        )
        .await
        .expect("restore the real marker");
    attest_cell_schema(&migrator)
        .await
        .expect("attestation holds again");

    // A second connection open against the cell database (any role) is enough to refuse a fresh
    // upgrade attempt on a rebuilt R27 cell, via the D4 replica-active check.
    let fresh = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_REFUSALS_REPLICA_PG_URL").await;
    let fresh_base_url = fresh.base_url.clone();
    let (fresh_migrator, _fresh_task) =
        connect_as(&fresh.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&fresh_migrator, CellSchemaRevision::R27)
        .await
        .expect("install a second real R27 cell");
    // Drop the admin connection first, so the ONLY other session below is the deliberate observer.
    drop(fresh);
    wait_until_exclusive(&fresh_migrator).await;
    let (_observer, _observer_task) =
        connect_as(&fresh_base_url, "object_dispatch_retention_runtime").await;
    assert_eq!(
        upgrade_cell_schema(&fresh_migrator).await,
        Err(CellSchemaError::ReplicasActive),
        "an active session on the cell database must refuse the offline upgrade"
    );
    drop(_observer);
    drop(_observer_task);
    // The refused attempt must not have moved the cell: it is still R27, upgradable.
    wait_until_exclusive(&fresh_migrator).await;
    upgrade_cell_schema(&fresh_migrator)
        .await
        .expect("upgrade proceeds once the other session is gone");
}

// -------------------------------------------------------------------------------------------
// Test plan item 5: the session advisory lock. Two upgrade attempts at once; exactly one
// proceeds, the other refuses without touching anything.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_two_concurrent_upgrades_exactly_one_proceeds() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_LOCK_PG_URL").await;
    let (migrator_a, _task_a) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator_a, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");

    // `acquire_cell_schema_lock` is what the second connection actually races against;
    // `upgrade_cell_schema` also needs no other session connected (D4), so exercise the lock via
    // the lock primitive directly rather than a second full `upgrade_cell_schema` call, which
    // would itself trip `ReplicasActive` before ever reaching the lock and would prove nothing
    // about the lock specifically.
    lore_object_dispatch::cell_schema_install::acquire_cell_schema_lock(&migrator_a)
        .await
        .expect("first session takes the lock");

    let (migrator_b, _task_b) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    assert_eq!(
        lore_object_dispatch::cell_schema_install::acquire_cell_schema_lock(&migrator_b).await,
        Err(CellSchemaError::SchemaOperationBusy),
        "a second session must refuse at once, never wait"
    );

    lore_object_dispatch::cell_schema_install::release_cell_schema_lock(&migrator_a)
        .await
        .expect("release the first session's lock");
    lore_object_dispatch::cell_schema_install::acquire_cell_schema_lock(&migrator_b)
        .await
        .expect("the lock is free once released");
    lore_object_dispatch::cell_schema_install::release_cell_schema_lock(&migrator_b)
        .await
        .expect("release the second session's lock");

    // Drop the first session and the admin connection, then prove `upgrade_cell_schema` itself is
    // unaffected: nothing was changed by the lock contention above.
    drop(migrator_a);
    drop(_task_a);
    drop(fixture);
    wait_until_exclusive(&migrator_b).await;
    upgrade_cell_schema(&migrator_b)
        .await
        .expect("upgrade proceeds cleanly");
}

// -------------------------------------------------------------------------------------------
// Test plan item 7: fresh-install parity. A fresh R28 install and an upgraded R27 cell must
// attest byte-identical manifests.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_fresh_install_and_upgraded_cell_attest_identical_manifests() {
    let fresh = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_PARITY_FRESH_PG_URL").await;
    let (fresh_migrator, _fresh_task) =
        connect_as(&fresh.base_url, "object_dispatch_retention_migrator").await;
    let fresh_report = install_cell_schema(&fresh_migrator)
        .await
        .expect("fresh install runs the forward step through the same wrapper as upgrade");
    assert_eq!(
        fresh_report.attestation.schema_revision,
        CELL_SCHEMA_CURRENT
    );

    let upgraded = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_PARITY_UPGRADED_PG_URL").await;
    let (upgraded_migrator, _upgraded_task) =
        connect_as(&upgraded.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&upgraded_migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");
    drop(upgraded);
    wait_until_exclusive(&upgraded_migrator).await;
    let upgrade_report = upgrade_cell_schema(&upgraded_migrator)
        .await
        .expect("upgrade to current");

    assert_eq!(
        fresh_report.attestation.catalog_blake3, upgrade_report.attestation.catalog_blake3,
        "a fresh R28 install and an upgraded R27 cell must produce byte-identical manifests"
    );
    assert_eq!(
        fresh_report.attestation.catalog_sections,
        upgrade_report.attestation.catalog_sections
    );
}

// -------------------------------------------------------------------------------------------
// Test plan item 3 (partial: the lost-COMMIT reply): kill the reply to the forward step's own
// `COMMIT` after the server has already committed. Recovery is classification, not replay: the
// next run must find R28 and never re-run the step. Proxy copied from the pattern established in
// `tests/dispatch_client_live.rs`'s `LostCommitProxy` (see that file for the full design note);
// duplicated here because the two proxies close over different clients and there is no shared
// `tests/common/` module either already depends on.
// -------------------------------------------------------------------------------------------

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
            "cell-schema-forward-upgrade-lost-commit-proxy",
            async move {
                let mut connections = Vec::new();
                while let Ok((downstream, _)) = listener.accept().await {
                    let upstream = upstream.clone();
                    let arm = Arc::clone(&task_arm);
                    let fired = Arc::clone(&task_fired);
                    connections.push(AbortOnDropHandle::new(lore_base::lore_spawn!(
                        "cell-schema-forward-upgrade-lost-commit-connection",
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

// ---------------------------------------------------------------------------------------------
// A second, generalized fault proxy: kill the connection outright (both directions) the moment a
// client->server frame's payload contains a fixed needle, WITHOUT forwarding that frame. This
// simulates the connection dying before the server ever receives a given statement -- the other
// two rows of the CR-038 crash table ("during attest" and "before COMMIT"), as distinct from the
// `LostCommitProxy` above (whose fault fires only after the server has already processed and
// replied to `COMMIT`). Matching on raw frame bytes works for both the simple query protocol
// (tag `Q`) and the extended protocol's `Parse` (tag `P`, used for every parameterless
// `Client::query`/`query_one` call this module makes), since in both cases the SQL text itself is
// carried inline in that one frame's payload.
// ---------------------------------------------------------------------------------------------

struct NeedleKillProxy {
    port: u16,
    fired: Arc<AtomicBool>,
    _task: AbortOnDropHandle<()>,
}

impl NeedleKillProxy {
    async fn start(upstream: String, needle: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind needle-kill proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let fired = Arc::new(AtomicBool::new(false));
        let task_fired = Arc::clone(&fired);
        let task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "cell-schema-forward-upgrade-needle-kill-proxy",
            async move {
                let mut connections = Vec::new();
                while let Ok((downstream, _)) = listener.accept().await {
                    let upstream = upstream.clone();
                    let fired = Arc::clone(&task_fired);
                    connections.push(AbortOnDropHandle::new(lore_base::lore_spawn!(
                        "cell-schema-forward-upgrade-needle-kill-connection",
                        async move {
                            if let Ok(server) = TcpStream::connect(&upstream).await {
                                relay_kill_before_forward(downstream, server, needle, fired).await;
                            }
                        }
                    )));
                }
            }
        ));
        Self {
            port,
            fired,
            _task: task,
        }
    }

    fn fault_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }
}

async fn relay_kill_before_forward(
    downstream: TcpStream,
    upstream: TcpStream,
    needle: &str,
    fired: Arc<AtomicBool>,
) {
    let (mut downstream_read, mut downstream_write) = downstream.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let needle = needle.as_bytes();
    let forward = async move {
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        // The client's very first message (the startup packet, and this proxy is only ever used
        // with `sslmode=disable` so no preceding `SSLRequest`) has NO leading tag byte -- unlike
        // every later message in the session, it is just a 4-byte big-endian length followed by
        // that many bytes of payload. Relay it byte-for-byte before switching to tagged-frame
        // parsing, or the tag-based loop below misreads its first payload byte as a tag and a
        // length that never resolves, hanging the connection.
        loop {
            let read = match downstream_read.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() < 4 {
                continue;
            }
            let Ok(length) = <[u8; 4]>::try_from(&buffer[0..4]) else {
                return;
            };
            let length = u32::from_be_bytes(length) as usize;
            if length < 4 || buffer.len() < length {
                continue;
            }
            if upstream_write.write_all(&buffer[..length]).await.is_err() {
                return;
            }
            if upstream_write.flush().await.is_err() {
                return;
            }
            buffer.drain(..length);
            break;
        }
        loop {
            let read = match downstream_read.read(&mut chunk).await {
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
                let frame = &buffer[offset..offset + total];
                let matches_needle = (tag == b'Q' || tag == b'P')
                    && frame.windows(needle.len()).any(|w| w == needle);
                if matches_needle {
                    // The server never receives this frame at all: close both directions now.
                    fired.store(true, Ordering::Release);
                    return;
                }
                if upstream_write.write_all(frame).await.is_err() {
                    return;
                }
                offset += total;
            }
            buffer.drain(..offset);
            if upstream_write.flush().await.is_err() {
                return;
            }
        }
    };
    let backward = async move {
        let _ = tokio::io::copy(&mut upstream_read, &mut downstream_write).await;
    };
    tokio::select! {
        () = forward => {}
        () = backward => {}
    }
}

/// Parse `<user>@<host:port>/<db>` out of a migrator URL for the proxy fixtures below.
fn host_port_and_path(base_url: &str) -> (String, String) {
    let upstream = url_as(base_url, "object_dispatch_retention_migrator");
    let without_scheme = upstream
        .split_once("://")
        .map(|(_, rest)| rest)
        .expect("scheme separator in the migrator URL");
    let after_userinfo = without_scheme
        .split_once('@')
        .map(|(_, rest)| rest)
        .expect("userinfo separator in the migrator URL");
    let (host_port, path) = after_userinfo
        .split_once('/')
        .expect("host:port/database in the migrator URL");
    (host_port.to_string(), path.to_string())
}

/// A single state-3 custody row, seeded directly (no reservation algebra needed): enough to prove
/// a forward-step crash/retry trues it exactly once, without the full reserve/release apparatus
/// the flagship wedge test needs. Unlike `seed_metadata_true_up_fixture` (test plan item 9), this
/// needs no matching `object_dispatch_spool_objects`/`object_dispatch_requests` rows: nothing here
/// calls `drain_cleanup_release_v1` (which is what reads `object_dispatch_spool_objects`) -- the
/// row starts life already in state 3, exactly as a previously-released, not-yet-trued row would.
async fn seed_one_untrued_row(
    admin: &tokio_postgres::Client,
    boundary: &str,
    cell: &str,
    spool: Uuid,
) {
    admin
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             INSERT INTO object_store_retention.drain_policies
               (boundary, cell, revision, digest, policy, canonical, metadata_rows, metadata_bytes)
             VALUES ('{boundary}', '{cell}', 'seed-policy-v1', decode(repeat('11',32),'hex'),
               '{{\"expires_at_ms\": 4102444800000}}'::jsonb, decode('aa','hex'), 1, 16384)
             ON CONFLICT (boundary, cell) DO NOTHING;
             INSERT INTO object_store_retention.drain_spool_custody
               (spool_id, boundary, cell, service, logical_id, attempt_id, descriptor, canonical,
                digest, cleanup_not_before, state, cleanup_fence, metadata_bytes, release_receipt,
                release_digest)
             VALUES ('{spool}', '{boundary}', '{cell}', 'seed-service', md5('logical'||'{spool}')::uuid,
               md5('attempt'||'{spool}')::uuid,
               jsonb_build_object('policy_revision', 'seed-policy-v1', 'policy_digest', repeat('11', 32)),
               decode('aa','hex'), decode(repeat('11',32),'hex'), 0, 3, 1, 16384,
               decode(repeat('11',32),'hex'), decode(repeat('11',32),'hex'));
             COMMIT;"
        ))
        .await
        .expect("seed one untrued state-3 custody row");
}

/// The exact true-up formula (mirrors `drain_retained_metadata_bytes_v1`), recomputed
/// independently so a test can assert the stored `metadata_bytes` was applied exactly once rather
/// than merely "less than the flat charge".
async fn read_retained_and_expected(admin: &tokio_postgres::Client, spool: Uuid) -> (i64, i64) {
    let row = admin
        .query_one(
            "SELECT metadata_bytes, octet_length(descriptor::text), octet_length(canonical), \
             octet_length(release_receipt), octet_length(release_digest) \
             FROM object_store_retention.drain_spool_custody WHERE spool_id = $1",
            &[&spool],
        )
        .await
        .expect("read custody row after recovery");
    let retained: i64 = row.get(0);
    let descriptor_len: i32 = row.get(1);
    let canonical_len: i32 = row.get(2);
    let receipt_len: i32 = row.get(3);
    let release_digest_len: i32 = row.get(4);
    let expected = (1024
        + i64::from(descriptor_len)
        + i64::from(canonical_len)
        + i64::from(receipt_len)
        + i64::from(release_digest_len))
    .max(1024);
    (retained, expected)
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_upgrade_recovers_from_a_kill_mid_attest() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_KILL_MID_ATTEST_PG_URL").await;
    let base_url = fixture.base_url.clone();
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");
    let spool = Uuid::now_v7();
    seed_one_untrued_row(
        &fixture.client,
        "kill-mid-attest-boundary",
        "kill-mid-attest-cell",
        spool,
    )
    .await;

    drop(migrator);
    drop(_migrator_task);
    drop(fixture);
    {
        let probe = admin_at(base_url.clone()).await;
        wait_until_exclusive(&probe.client).await;
    }

    let (host_port, path) = host_port_and_path(&base_url);
    // `rules_and_policies` names the last column of the catalog manifest query
    // (`CELL_CATALOG_MANIFEST_SQL`), read as part of the IN-TRANSACTION attest that follows the
    // forward step's body -- killing on it lands the fault mid-attest, before `COMMIT` is ever
    // sent, inside the step's own `SERIALIZABLE` transaction. Postgres rolls the whole thing back:
    // the row seeded above must still read as untrued (16384) after this attempt.
    let proxy = NeedleKillProxy::start(host_port, "rules_and_policies").await;
    let proxied_url = format!(
        "postgresql://object_dispatch_retention_migrator@127.0.0.1:{}/{path}?sslmode=disable",
        proxy.port
    );
    let (proxied_migrator, _proxied_task) = {
        let (client, connection) = tokio_postgres::connect(&proxied_url, tokio_postgres::NoTls)
            .await
            .expect("connect through the needle-kill proxy");
        (
            client,
            AbortOnDropHandle::new(lore_base::lore_spawn!(
                "cell-schema-forward-upgrade-mid-attest-proxied",
                async move {
                    let _ = connection.await;
                }
            )),
        )
    };
    let outcome = upgrade_cell_schema(&proxied_migrator).await;
    assert!(
        outcome.is_err(),
        "a connection killed mid-attest must surface as an error to this call"
    );
    assert!(
        proxy.fault_fired(),
        "the fault must actually have fired, or this proves nothing"
    );
    drop(proxied_migrator);
    drop(_proxied_task);

    // The whole in-progress transaction rolled back: the cell is still R27 (nothing committed),
    // and this fixture's own connections above are the only sessions, so a rerun performs the
    // real state transition again and needs the same D4 exclusivity as any first attempt.
    let (recovery_migrator, _recovery_task) =
        connect_as(&base_url, "object_dispatch_retention_migrator").await;
    wait_until_exclusive(&recovery_migrator).await;
    let report = upgrade_cell_schema(&recovery_migrator)
        .await
        .expect("recovery run reaches R28");
    assert_eq!(
        report.disposition,
        CellUpgradeDisposition::Upgraded(CellSchemaRevision::R27),
        "nothing committed on the killed attempt, so recovery must perform the real transition, \
         not find it already current"
    );
    assert_eq!(report.attestation.schema_revision, CELL_SCHEMA_CURRENT);

    // `drain_spool_custody` is not migrator-readable (only owner/runtime hold grants on it); read
    // the row back as the superuser fixture connection.
    let admin_conn = admin_at(base_url).await;
    let (retained, expected) = read_retained_and_expected(&admin_conn.client, spool).await;
    assert_eq!(
        retained, expected,
        "the seeded row must be trued to exactly the formula's output once, not left untrued or \
         double-processed"
    );
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_upgrade_recovers_from_a_kill_before_commit() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_KILL_BEFORE_COMMIT_PG_URL").await;
    let base_url = fixture.base_url.clone();
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");
    let spool = Uuid::now_v7();
    seed_one_untrued_row(
        &fixture.client,
        "kill-before-commit-boundary",
        "kill-before-commit-cell",
        spool,
    )
    .await;

    drop(migrator);
    drop(_migrator_task);
    drop(fixture);
    {
        let probe = admin_at(base_url.clone()).await;
        wait_until_exclusive(&probe.client).await;
    }

    let (host_port, path) = host_port_and_path(&base_url);
    // The only client->server frame containing this exact text on this code path is
    // `apply_forward_step`'s own final `client.batch_execute("COMMIT;")`, issued only after the
    // step body and its in-transaction attest have both already succeeded. Killing on it means the
    // server never receives `COMMIT` at all -- a strictly later crash point than the mid-attest
    // case above, and the one the CR's own crash table calls "inside step 5, before COMMIT".
    let proxy = NeedleKillProxy::start(host_port, "COMMIT").await;
    let proxied_url = format!(
        "postgresql://object_dispatch_retention_migrator@127.0.0.1:{}/{path}?sslmode=disable",
        proxy.port
    );
    let (proxied_migrator, _proxied_task) = {
        let (client, connection) = tokio_postgres::connect(&proxied_url, tokio_postgres::NoTls)
            .await
            .expect("connect through the needle-kill proxy");
        (
            client,
            AbortOnDropHandle::new(lore_base::lore_spawn!(
                "cell-schema-forward-upgrade-before-commit-proxied",
                async move {
                    let _ = connection.await;
                }
            )),
        )
    };
    let outcome = upgrade_cell_schema(&proxied_migrator).await;
    assert!(
        outcome.is_err(),
        "a connection killed before COMMIT must surface as an error to this call"
    );
    assert!(
        proxy.fault_fired(),
        "the fault must actually have fired, or this proves nothing"
    );
    drop(proxied_migrator);
    drop(_proxied_task);

    // The server never received COMMIT, so nothing committed: same recovery shape as the
    // mid-attest case above, a real (not no-op) state transition.
    let (recovery_migrator, _recovery_task) =
        connect_as(&base_url, "object_dispatch_retention_migrator").await;
    wait_until_exclusive(&recovery_migrator).await;
    let report = upgrade_cell_schema(&recovery_migrator)
        .await
        .expect("recovery run reaches R28");
    assert_eq!(
        report.disposition,
        CellUpgradeDisposition::Upgraded(CellSchemaRevision::R27),
        "nothing committed on the killed attempt, so recovery must perform the real transition"
    );
    assert_eq!(report.attestation.schema_revision, CELL_SCHEMA_CURRENT);

    let admin_conn = admin_at(base_url).await;
    let (retained, expected) = read_retained_and_expected(&admin_conn.client, spool).await;
    assert_eq!(
        retained, expected,
        "the seeded row must be trued to exactly the formula's output once, not left untrued or \
         double-processed"
    );
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_upgrade_recovers_from_a_lost_commit_reply() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_LOST_COMMIT_PG_URL").await;
    let base_url = fixture.base_url.clone();
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");
    let spool = Uuid::now_v7();
    seed_one_untrued_row(
        &fixture.client,
        "lost-commit-boundary",
        "lost-commit-cell",
        spool,
    )
    .await;

    // D4 needs an exclusive session at the moment the upgrade actually runs. Drop every handle
    // this test has opened so far and wait for the server to see them gone before the proxied
    // connection below becomes the sole session.
    drop(migrator);
    drop(_migrator_task);
    drop(fixture);
    {
        let probe = admin_at(base_url.clone()).await;
        wait_until_exclusive(&probe.client).await;
    }

    let (host_port, path) = host_port_and_path(&base_url);
    let proxy = LostCommitProxy::start(host_port).await;
    let proxied_url = format!(
        "postgresql://object_dispatch_retention_migrator@127.0.0.1:{}/{path}?sslmode=disable",
        proxy.port
    );
    let (proxied_migrator, _proxied_task) = {
        let (client, connection) = tokio_postgres::connect(&proxied_url, tokio_postgres::NoTls)
            .await
            .expect("connect through the lost-commit proxy");
        (
            client,
            AbortOnDropHandle::new(lore_base::lore_spawn!(
                "cell-schema-forward-upgrade-proxied",
                async move {
                    let _ = connection.await;
                }
            )),
        )
    };

    proxy.drop_next_commit_response();
    let outcome = upgrade_cell_schema(&proxied_migrator).await;
    assert!(
        outcome.is_err(),
        "the client must see an error when its own COMMIT reply never arrives, even though the \
         server committed"
    );
    assert!(
        proxy.fault_fired(),
        "the fault must actually have fired, or this proves nothing"
    );
    drop(proxied_migrator);
    drop(_proxied_task);

    // Recovery is classification, not replay: a fresh (unproxied) connection must find the cell
    // already at R28 and must not attempt the step again. `AlreadyCurrent` needs no exclusivity
    // check at all (D4 only gates the one state transition), so no wait is needed here.
    let (migrator, _migrator_task) =
        connect_as(&base_url, "object_dispatch_retention_migrator").await;
    let report = upgrade_cell_schema(&migrator).await.expect("recovery run");
    assert_eq!(report.disposition, CellUpgradeDisposition::AlreadyCurrent);
    assert_eq!(report.attestation.schema_revision, CELL_SCHEMA_CURRENT);

    // The server-side COMMIT that the client never saw a reply for already trued the seeded row
    // exactly once; recovery classifying as AlreadyCurrent (rather than re-running the step) is
    // what keeps it that way -- assert the stored value directly rather than only inferring it
    // from the disposition. `drain_spool_custody` is not migrator-readable; use the admin
    // (superuser) fixture connection instead.
    let admin_conn = admin_at(base_url).await;
    let (retained, expected) = read_retained_and_expected(&admin_conn.client, spool).await;
    assert_eq!(
        retained, expected,
        "the row the lost-commit attempt actually trued server-side must read as trued exactly \
         once, not doubled by any retry logic"
    );
}

// -------------------------------------------------------------------------------------------
// Test plan item 3 (fully): the backfill touches only state-3 rows. States 1, 2 and 4 must be
// byte-for-byte untouched.
//
// Test plan item 4: the backfill's own guard (`AND x.state=3 AND x.metadata_bytes=t.charged` on
// the APPLY step, added specifically because "the backfill UPDATE matches on spool_id only" was
// the original, unfixed shape of this defect) prevents a double give-back when a row a backfill
// snapshot already read gets compacted before the APPLY step's own re-check runs. The real 0028
// backfill runs as one atomic statement inside the upgrade's own LOCK TABLE-guarded transaction,
// which excludes genuine wall-clock concurrency with compaction by construction -- so the
// discrimination proof here is a deterministic, parameter-driven replay of exactly the APPLY
// step's WHERE clause (real vs the pre-fix shape), fed the SAME stale snapshot values a real race
// would produce, rather than a timing-dependent two-connection race.
// -------------------------------------------------------------------------------------------

/// Re-run just the backfill APPLY step's own guard, standalone, against caller-supplied
/// `charged`/`retained` values standing in for a snapshot read before some other change to the
/// row. `guarded = true` is 0028's real WHERE clause; `false` drops `AND x.state=3 AND
/// x.metadata_bytes=t.charged`, the exact pre-fix shape CR-038 names as the defect this guards
/// against. Returns the number of custody rows the UPDATE matched.
/// `Ok(rows_affected)` on success. The mutated (pre-fix) shape can also legitimately fail the
/// `object_store_retention.uint64` domain's own `>= 0` CHECK when the double give-back this test
/// forces would take the policy counter negative -- that failure is itself discriminating evidence
/// (the real guard's WHERE clause makes the statement that provokes it unreachable), so the caller
/// decides what a `Err` means rather than this helper treating it as a fixture bug.
async fn apply_parametrized_backfill_step(
    admin: &tokio_postgres::Client,
    guarded: bool,
    spool: Uuid,
    charged: i64,
    retained: i64,
) -> Result<i64, tokio_postgres::Error> {
    let guard_clause = if guarded {
        "AND x.state=3 AND x.metadata_bytes=$2"
    } else {
        ""
    };
    let update_sql = format!(
        "UPDATE object_store_retention.drain_spool_custody x SET metadata_bytes=$3
         WHERE x.spool_id=$1 {guard_clause} AND $3::bigint<$2::bigint"
    );
    admin
        .batch_execute("BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;")
        .await
        .expect("open owner transaction");
    let affected = admin
        .execute(&update_sql, &[&spool, &charged, &retained])
        .await;
    let result = match affected {
        Ok(affected) if affected > 0 => admin
            .execute(
                "UPDATE object_store_retention.drain_policies p
                 SET metadata_bytes=(p.metadata_bytes::numeric-($1::bigint::numeric-$2::bigint::numeric))::object_store_retention.uint64
                 FROM object_store_retention.drain_spool_custody x
                 WHERE x.spool_id=$3 AND p.boundary=x.boundary AND p.cell=x.cell",
                &[&charged, &retained, &spool],
            )
            .await
            .map(|_| affected),
        other => other,
    };
    admin
        .batch_execute(if result.is_ok() {
            "COMMIT;"
        } else {
            "ROLLBACK;"
        })
        .await
        .expect("close the owner transaction");
    result.map(|affected| i64::try_from(affected).unwrap())
}

async fn read_policy_metadata_bytes(
    admin: &tokio_postgres::Client,
    boundary: &str,
    cell: &str,
) -> i64 {
    admin
        .query_one(
            "SELECT metadata_bytes::bigint FROM object_store_retention.drain_policies WHERE boundary = $1 AND cell = $2",
            &[&boundary, &cell],
        )
        .await
        .expect("read policy counter")
        .get(0)
}

// This test (via `apply_parametrized_backfill_step`) proves a hand-copied reproduction of the
// backfill APPLY step's WHERE-clause predicate, not the shipped 0028 statement itself. Under the
// real, shipped 0028 migration the backfill runs inside the same transaction that takes
// `drain_policies` in `ACCESS EXCLUSIVE MODE NOWAIT` (see `migrations/0028_...sql`), which makes
// the race this test simulates unreachable in production: no concurrent compaction can interleave
// with a live backfill. The parametrized replay exists because that exclusivity makes the real
// race untestable by timing, so this discriminates the guard clause deterministically instead.
#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_backfill_leaves_other_states_untouched_and_the_guard_prevents_a_double_give_back() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_BACKFILL_STATES_PG_URL").await;
    let base_url = fixture.base_url.clone();
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");

    // -- Part 1 (item 3): seed one row per state 1, 2, 3, 4 and prove backfill only touches 3. --
    let boundary = "backfill-states-boundary";
    let cell = "backfill-states-cell";
    fixture
        .client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             INSERT INTO object_store_retention.drain_policies
               (boundary, cell, revision, digest, policy, canonical, metadata_rows, metadata_bytes)
             VALUES ('{boundary}', '{cell}', 'seed-policy-v1', decode(repeat('11',32),'hex'),
               '{{\"expires_at_ms\": 4102444800000}}'::jsonb, decode('aa','hex'), 4, 65536);
             COMMIT;"
        ))
        .await
        .expect("seed policy");

    let spool_state1 = Uuid::now_v7();
    let spool_state2 = Uuid::now_v7();
    let spool_state4 = Uuid::now_v7();
    let spool_state3 = Uuid::now_v7();
    for (spool, state) in [(spool_state1, 1), (spool_state2, 2)] {
        fixture
            .client
            .batch_execute(&format!(
                "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
                 INSERT INTO object_store_retention.drain_spool_custody
                   (spool_id, boundary, cell, service, logical_id, attempt_id, descriptor, canonical,
                    digest, cleanup_not_before, state, cleanup_fence, metadata_bytes)
                 VALUES ('{spool}', '{boundary}', '{cell}', 'seed-service',
                   md5('logical'||'{spool}')::uuid, md5('attempt'||'{spool}')::uuid,
                   jsonb_build_object('policy_revision','seed-policy-v1','policy_digest', repeat('11', 32)),
                   decode('aa','hex'), decode(repeat('11',32),'hex'), 0, {state}, 1, 16384);
                 COMMIT;"
            ))
            .await
            .unwrap_or_else(|error| panic!("seed state-{state} row: {error}"));
    }
    // State 4: already compacted (the shape `drain_cleanup_compact_v1` leaves: descriptor/canonical
    // NULL, metadata_bytes at the 1024 marker). Seeded as a state-3 row first, then moved with a
    // plain UPDATE: the `drain_custody_policy_expiry_v1` trigger is BEFORE INSERT only, and an
    // INSERT with a NULL descriptor straight away would trip its `SELECT ... INTO STRICT` lookup
    // (NULL matches no policy row).
    seed_one_untrued_row(&fixture.client, boundary, cell, spool_state4).await;
    fixture
        .client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             UPDATE object_store_retention.drain_spool_custody
             SET state = 4, descriptor = NULL, canonical = NULL, metadata_bytes = 1024
             WHERE spool_id = '{spool_state4}';
             COMMIT;"
        ))
        .await
        .expect("move the state-4 row to the already-compacted shape");
    // State 3: seed_one_untrued_row's own policy insert is `ON CONFLICT DO NOTHING`, so it will
    // not disturb the 65536 seeded above.
    seed_one_untrued_row(&fixture.client, boundary, cell, spool_state3).await;

    async fn snapshot(admin: &tokio_postgres::Client, spool: Uuid) -> Vec<Option<String>> {
        // Every column cast to text in SQL itself: a simple, order-preserving byte-for-byte
        // comparison with no client-side type dispatch to get wrong (`jsonb`'s `::text` cast is
        // its canonical serialization; `bytea`'s is `\x`-prefixed hex, which is exact).
        let row = admin
            .query_one(
                "SELECT state::text, metadata_bytes::text, descriptor::text, canonical::text, \
                 release_receipt::text, release_digest::text, cleanup_fence::text, \
                 cleanup_not_before::text FROM object_store_retention.drain_spool_custody \
                 WHERE spool_id = $1",
                &[&spool],
            )
            .await
            .expect("snapshot row");
        (0..8).map(|index| row.get(index)).collect()
    }
    let before_state1 = snapshot(&fixture.client, spool_state1).await;
    let before_state2 = snapshot(&fixture.client, spool_state2).await;
    let before_state4 = snapshot(&fixture.client, spool_state4).await;

    drop(migrator);
    drop(_migrator_task);
    drop(fixture);
    {
        let probe = admin_at(base_url.clone()).await;
        wait_until_exclusive(&probe.client).await;
    }
    let (recovery_migrator, _recovery_task) =
        connect_as(&base_url, "object_dispatch_retention_migrator").await;
    upgrade_cell_schema(&recovery_migrator)
        .await
        .expect("upgrade to current");

    let admin_conn = admin_at(base_url.clone()).await;
    let after_state1 = snapshot(&admin_conn.client, spool_state1).await;
    let after_state2 = snapshot(&admin_conn.client, spool_state2).await;
    let after_state4 = snapshot(&admin_conn.client, spool_state4).await;
    assert_eq!(
        before_state1, after_state1,
        "a state-1 row must be byte-for-byte untouched"
    );
    assert_eq!(
        before_state2, after_state2,
        "a state-2 row must be byte-for-byte untouched"
    );
    assert_eq!(
        before_state4, after_state4,
        "an already-compacted state-4 row must be byte-for-byte untouched -- never given back twice"
    );
    let (retained3, expected3) = read_retained_and_expected(&admin_conn.client, spool_state3).await;
    assert_eq!(
        retained3, expected3,
        "the state-3 row must still be trued normally alongside the untouched states"
    );

    // -- Part 2 (item 4): the guard itself, deterministically. --
    // Two isolated boundary/cell pairs, each with its own row compacted the moment BEFORE the
    // (simulated) backfill APPLY step runs against a stale pre-compaction snapshot.
    async fn compact_and_snapshot(
        admin: &tokio_postgres::Client,
        boundary: &str,
        cell: &str,
        spool: Uuid,
    ) -> (i64, i64) {
        // Unlike every other seeded policy in this file, `expires_at_ms` here is in the PAST: this
        // helper needs `drain_cleanup_compact_v1` to actually run (its early-return condition is
        // `greatest(s.expires_at_unix_ms, policy.expires_at_ms) > now`; with no matching
        // `object_dispatch_spool_objects` row, `s.expires_at_unix_ms` is NULL and `greatest` falls
        // through to the policy's own value alone).
        admin
            .batch_execute(&format!(
                "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
                 INSERT INTO object_store_retention.drain_policies
                   (boundary, cell, revision, digest, policy, canonical, metadata_rows, metadata_bytes)
                 VALUES ('{boundary}', '{cell}', 'seed-policy-v1', decode(repeat('11',32),'hex'),
                   '{{\"expires_at_ms\": 1000}}'::jsonb, decode('aa','hex'), 1, 16384);
                 COMMIT;"
            ))
            .await
            .expect("seed isolated policy");
        seed_one_untrued_row(admin, boundary, cell, spool).await;
        let charged: i64 = 16384;
        let retained: i64 = admin
            .query_one(
                "SELECT object_store_retention.drain_retained_metadata_bytes_v1(c) \
                 FROM object_store_retention.drain_spool_custody c WHERE c.spool_id = $1",
                &[&spool],
            )
            .await
            .expect("compute the retained size a snapshot would have captured")
            .get(0);
        // Compaction "races ahead": give the row's own custody charge back now, exactly like the
        // real 0027 `drain_cleanup_compact_v1`, before any backfill APPLY step re-checks it.
        admin
            .batch_execute(&format!(
                "SET SESSION AUTHORIZATION object_dispatch_retention_runtime;
                 BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;
                 SELECT object_store_retention.drain_cleanup_compact_v1('{spool}');
                 COMMIT;
                 RESET SESSION AUTHORIZATION;"
            ))
            .await
            .expect("real compaction on the row");
        (charged, retained)
    }

    let real_boundary = "backfill-race-real-boundary";
    let real_cell = "backfill-race-real-cell";
    let real_spool = Uuid::now_v7();
    let (real_charged, real_retained) =
        compact_and_snapshot(&admin_conn.client, real_boundary, real_cell, real_spool).await;
    let policy_after_compaction_only =
        read_policy_metadata_bytes(&admin_conn.client, real_boundary, real_cell).await;
    assert_eq!(
        policy_after_compaction_only, 1024,
        "compaction alone must already have given the row's charge back to 1024"
    );
    let real_affected = apply_parametrized_backfill_step(
        &admin_conn.client,
        true,
        real_spool,
        real_charged,
        real_retained,
    )
    .await
    .expect("the real guard's statement must succeed (as a correct no-op)");
    assert_eq!(
        real_affected, 0,
        "the real guard must refuse to touch a row compaction already moved to state 4"
    );
    assert_eq!(
        read_policy_metadata_bytes(&admin_conn.client, real_boundary, real_cell).await,
        1024,
        "the real guard must leave the policy exactly where compaction alone left it -- no double give-back"
    );

    let mutated_boundary = "backfill-race-mutated-boundary";
    let mutated_cell = "backfill-race-mutated-cell";
    let mutated_spool = Uuid::now_v7();
    let (mutated_charged, mutated_retained) = compact_and_snapshot(
        &admin_conn.client,
        mutated_boundary,
        mutated_cell,
        mutated_spool,
    )
    .await;
    let mutated_result = apply_parametrized_backfill_step(
        &admin_conn.client,
        false,
        mutated_spool,
        mutated_charged,
        mutated_retained,
    )
    .await;
    // The discrimination proof itself: dropping `AND x.state=3 AND x.metadata_bytes=t.charged`
    // (the exact pre-fix shape CR-038 names) makes the custody UPDATE incorrectly re-match a row
    // compaction already moved to state 4, attempting a second give-back for the same charge. That
    // attempt either succeeds and drives the policy counter below the 1024 compaction alone left
    // (a silent double give-back) or is caught by the `uint64` domain's own `>= 0` CHECK when the
    // second subtraction goes negative -- both outcomes are the guard's absence actually mattering;
    // a clean `Ok` leaving the counter at 1024 (indistinguishable from the real guard's own
    // behavior) would mean the mutation changed nothing and the proof failed.
    match mutated_result {
        Ok(affected) => {
            assert_eq!(
                affected, 1,
                "the pre-fix (spool_id-only) shape must incorrectly re-match an already-compacted \
                 row, or this proves nothing"
            );
            let mutated_policy_bytes =
                read_policy_metadata_bytes(&admin_conn.client, mutated_boundary, mutated_cell)
                    .await;
            assert!(
                mutated_policy_bytes < 1024,
                "the pre-fix shape must double-give-back: the policy counter must be reduced a \
                 SECOND time below what compaction alone left it (1024), landing at \
                 {mutated_policy_bytes}"
            );
        }
        Err(error) => {
            assert_eq!(
                error.as_db_error().and_then(|db| db.constraint()),
                Some("uint64_check"),
                "an error here must be the double give-back going negative through the uint64 \
                 domain's own CHECK, not some other failure: {error}"
            );
        }
    }
}

// -------------------------------------------------------------------------------------------
// Test plan item 9: the release true-up matches the row's actual retained size, and an underflow
// raises rather than clamps. Seeded directly at the SQL level (bypassing the full reservation
// algebra), because the true-up formula and the underflow guard are properties of
// `drain_cleanup_release_v1` alone and do not depend on how a row was reserved.
//
// Discrimination proof for the underflow guard: a hand-mutated in-memory copy of the SAME
// function body, with the underflow RAISE replaced by 0026's original GREATEST(...,0) clamp, is
// installed directly (CREATE OR REPLACE) against a disposable cell that is never the tracked
// migration file -- nothing here ever touches `migrations/0028_*.sql` on disk, so this needs no
// git worktree and leaves `git status` on implementation files unaffected by construction. The
// real function must raise; the mutated one must not, and must leave a clamped-away balance.
// -------------------------------------------------------------------------------------------

struct SeedIdentifiers {
    spool: Uuid,
    logical: Uuid,
    attempt: Uuid,
}

async fn seed_metadata_true_up_fixture(
    admin: &tokio_postgres::Client,
    boundary: &str,
    cell: &str,
    service: &str,
    ids: SeedIdentifiers,
    metadata_bytes: i64,
) {
    let SeedIdentifiers {
        spool,
        logical,
        attempt,
    } = ids;
    // A CHECK constraint pins `*_uuid_unix_ms` to the exact 48-bit big-endian millisecond
    // timestamp UUIDv7 embeds in its own first six bytes; a literal placeholder value only
    // happens to satisfy it for the fixed, hand-picked UUIDs `cell_retention_rows.sql` uses. Real
    // `Uuid::now_v7()` values need it computed.
    fn uuid_v7_unix_ms(id: Uuid) -> i64 {
        let bytes = id.as_bytes();
        i64::from(bytes[0]) * 1_099_511_627_776
            + i64::from(bytes[1]) * 4_294_967_296
            + i64::from(bytes[2]) * 16_777_216
            + i64::from(bytes[3]) * 65_536
            + i64::from(bytes[4]) * 256
            + i64::from(bytes[5])
    }
    let logical_unix_ms = uuid_v7_unix_ms(logical);
    let attempt_unix_ms = uuid_v7_unix_ms(attempt);

    // A minimal, schema-valid `drain_policies` row (bypassing publish's own validation, which this
    // fixture does not need to satisfy -- only the table's own CHECK constraints apply to a direct
    // INSERT). `policy` only needs `expires_at_ms` far in the future so compaction stays a no-op.
    admin
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             INSERT INTO object_store_retention.drain_policies
               (boundary, cell, revision, digest, policy, canonical, metadata_rows, metadata_bytes)
             VALUES ('{boundary}', '{cell}', 'seed-policy-v1', decode(repeat('11',32),'hex'),
               '{{\"expires_at_ms\": 4102444800000}}'::jsonb, decode('aa','hex'), 1, {metadata_bytes})
             -- This fixture is called once per case, all sharing one boundary/cell; the policy row
             -- itself is seeded only once, and later cases intentionally mutate its metadata_bytes
             -- by hand, so a re-seed here must never clobber that.
             ON CONFLICT (boundary, cell) DO NOTHING;
             COMMIT;"
        ))
        .await
        .expect("seed drain_policies row");

    // `object_dispatch_spool_objects` FK-references a request row when `payload_kind = 2`
    // (`bound_request_*` must be non-null and present). Schema-only, like
    // `tests/common/cell_retention_rows.sql`'s own fixture -- no Submit/ACK writer exists in the
    // installed cell procedure set, so this does not claim canonical lifecycle validity.
    admin
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             INSERT INTO object_store_retention.object_dispatch_requests (
               schema_revision, protocol_revision, policy_revision, provider_boundary_id,
               authenticated_cell_id, authenticated_tenant_id, logical_request_id, attempt_id,
               logical_request_uuid_unix_ms, attempt_uuid_unix_ms, canonical_descriptor_bytes,
               canonical_descriptor_fingerprint, operation_tag, consumer_context_tag, phase,
               allocation_revision, allocation_fence, admission_clock_unix_ms, deadline_unix_ms,
               allocation_hard_expiry_unix_ms, request_state_canonical_bytes, request_state_blake3,
               terminal_result_id, terminal_result_tag, terminal_result_canonical_bytes,
               terminal_result_blake3, terminal_result_size, terminal_retryability, result_disposition,
               put_payload_availability, result_payload_availability, dispatch_attempt_blake3,
               closure_committed_at_unix_ms, submit_receipt_canonical_bytes, submit_receipt_blake3,
               get_outcome_canonical_bytes, get_outcome_blake3, quota_revision, row_revision,
               state_committed_at_unix_ms, created_at_unix_ms, byte_result_handle, payload_size,
               payload_blake3, fetch_head_state, fetch_fence_generation, fetch_open_lease_count,
               fetch_head_revision, fetch_head_committed_at_unix_ms, fetch_head_canonical_bytes,
               fetch_head_blake3
             ) VALUES (
               'object-store-dispatch-authority-schema-v1', 'protocol-1', 'policy-1', '{boundary}',
               '{cell}', 'seed-tenant', '{logical}', '{attempt}', {logical_unix_ms}, {attempt_unix_ms}, decode('aa', 'hex'),
               decode(repeat('11', 32), 'hex'), 1, 1, 5, 'allocation-1', 1, 1000, 2000,
               4102444800000, decode('aa'||repeat('11', 32), 'hex'), decode(repeat('11', 32), 'hex'),
               'result-{spool}', 7, decode('aa'||repeat('11', 32), 'hex'), decode(repeat('11', 32), 'hex'),
               33, 1, 3, 1, 3, decode(repeat('11', 32), 'hex'), 1500,
               decode('aa'||repeat('11', 32), 'hex'), decode(repeat('11', 32), 'hex'),
               decode('aa'||repeat('11', 32), 'hex'), decode(repeat('11', 32), 'hex'), 1, 1, 1500, 1000,
               'result/body-{spool}', 33, decode(repeat('11', 32), 'hex'), 1, 1, 0, 1, 1500,
               decode('aa'||repeat('11', 32), 'hex'), decode(repeat('11', 32), 'hex')
             );
             COMMIT;"
        ))
        .await
        .expect("seed object_dispatch_requests row");

    admin
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             INSERT INTO object_store_retention.object_dispatch_spool_objects (
               schema_revision,spool_object_id,logical_request_id,attempt_id,provider_boundary_id,
               authenticated_cell_id,authenticated_tenant_id,bound_request_logical_request_id,
               bound_request_attempt_id,request_binding_state,payload_kind,lifecycle_state,
               terminal_result_id,boundary_blake3,boundary_token,observation_binding_blake3,
               expected_size,expected_blake3,quota_bytes,quota_rows,quota_concurrency,quota_revision,
               purge_state,canonical_record_bytes,record_blake3,spool_revision,created_at_unix_ms,
               committed_size,committed_blake3,durable_handle,ready_at_unix_ms
             ) VALUES ('object-store-dispatch-authority-schema-v1', '{spool}', '{logical}', '{attempt}',
               '{boundary}', '{cell}', 'seed-tenant', '{logical}', '{attempt}', 2, 2, 2, 'result-{spool}',
               decode(repeat('11',32),'hex'), 'boundary-token', decode(repeat('11',32),'hex'),
               33, decode(repeat('11',32),'hex'), 1, 1, 1, 1, 3, decode('aa'||repeat('11',32),'hex'),
               decode(repeat('11',32),'hex'), 1, 1500, 33, decode(repeat('11',32),'hex'),
               'result/body-{spool}', 1500);
             -- Shared across every case's spool row (same boundary/cell/service): top up rather
             -- than insert-once, so each case's own release has enough counted usage to give back.
             INSERT INTO object_store_retention.object_dispatch_quota_usage (
               schema_revision, provider_boundary_id, scope_kind, scope_id, quota_class, used_bytes,
               used_rows, used_concurrency, counter_revision, updated_at_unix_ms
             ) VALUES ('object-store-dispatch-authority-schema-v1', '{boundary}', 1, '{boundary}', 1, 1, 1, 1, 1, 1500),
               ('object-store-dispatch-authority-schema-v1', '{boundary}', 2, '{cell}', 1, 1, 1, 1, 1, 1500),
               ('object-store-dispatch-authority-schema-v1', '{boundary}', 3, '{service}', 1, 1, 1, 1, 1, 1500)
             ON CONFLICT (provider_boundary_id, scope_kind, scope_id, quota_class) DO UPDATE SET
               used_bytes = object_store_retention.object_dispatch_quota_usage.used_bytes + 1,
               used_rows = object_store_retention.object_dispatch_quota_usage.used_rows + 1,
               used_concurrency = object_store_retention.object_dispatch_quota_usage.used_concurrency + 1,
               counter_revision = object_store_retention.object_dispatch_quota_usage.counter_revision + 1;
             INSERT INTO object_store_retention.drain_spool_custody (
               spool_id, boundary, cell, service, logical_id, attempt_id, descriptor, canonical,
               digest, cleanup_not_before, state, cleanup_fence, metadata_bytes
             ) VALUES ('{spool}', '{boundary}', '{cell}', '{service}', '{logical}', '{attempt}',
               -- `drain_custody_policy_expiry_v1`'s BEFORE INSERT trigger requires the descriptor
               -- to name the exact policy row seeded above (revision and hex digest), or its
               -- `SELECT ... INTO STRICT` raises 'query returned no rows'.
               jsonb_build_object('policy_revision', 'seed-policy-v1', 'policy_digest', repeat('11', 32)),
               decode('aa','hex'), decode(repeat('11',32),'hex'), 0, 2, 1, 16384);
             COMMIT;"
        ))
        .await
        .expect("seed spool_objects, quota_usage and drain_spool_custody rows");
}

/// The real release function's body (0028's replacement of 0026's), reproduced verbatim as a
/// literal for the discrimination proof below. `local_blake3_v1` inside it requires a real BLAKE3
/// provider, so this test needs the same `plpython3u` image as the flagship wedge test.
const REAL_RELEASE_FUNCTION_BODY: &str = "(spool uuid,fence bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE q object_store_retention.object_dispatch_quota_usage%ROWTYPE; n integer:=0; receipt bytea; computed_release_digest bytea;
DECLARE retained bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF c.cleanup_fence IS DISTINCT FROM fence OR c.state=1 THEN RAISE EXCEPTION 'DRAIN_CLEANUP_FENCED'; END IF;
 IF c.state IN(3,4) THEN RETURN; END IF;
 IF s.spool_object_id IS NULL THEN RAISE EXCEPTION 'DRAIN_CLEANUP_MISSING_ACCOUNTING'; END IF;
 FOR q IN SELECT * FROM object_store_retention.object_dispatch_quota_usage x
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service))
 ORDER BY x.scope_kind FOR UPDATE LOOP
  IF q.used_bytes<s.quota_bytes OR q.used_rows<s.quota_rows OR q.used_concurrency<s.quota_concurrency THEN RAISE EXCEPTION 'DRAIN_COUNTER_UNDERFLOW'; END IF;
  n:=n+1;
 END LOOP;
 IF n<>3 THEN RAISE EXCEPTION 'DRAIN_COUNTER_MISSING'; END IF;
 UPDATE object_store_retention.object_dispatch_quota_usage x SET used_bytes=x.used_bytes-s.quota_bytes,
 used_rows=x.used_rows-s.quota_rows,used_concurrency=x.used_concurrency-s.quota_concurrency,counter_revision=x.counter_revision+1,
 updated_at_unix_ms=object_store_retention.clock_unix_ms_v1()
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service));
 receipt:=convert_to('fragment-drain-release-v1','UTF8')||uuid_send(spool)||c.digest
 ||object_store_retention.local_canonical_u64_v1(fence::object_store_retention.uint64)
 ||object_store_retention.local_canonical_u64_v1(s.quota_bytes)
 ||object_store_retention.local_canonical_u64_v1(s.quota_rows)
 ||object_store_retention.local_canonical_u64_v1(s.quota_concurrency);
 computed_release_digest:=object_store_retention.local_blake3_v1(receipt);
 UPDATE object_store_retention.drain_spool_custody x SET state=3,release_receipt=receipt||computed_release_digest,release_digest=computed_release_digest
 WHERE x.spool_id=spool RETURNING * INTO c;
 -- The true-up. The row is complete, so its worst-case allowance becomes its actual cost.
 -- Compaction later takes it to the 1024 marker and its decrement reads this same column, so
 -- nothing is released twice. An underflow is a bookkeeping error and fails closed.
 retained:=object_store_retention.drain_retained_metadata_bytes_v1(c);
 IF retained<c.metadata_bytes THEN
  UPDATE object_store_retention.drain_spool_custody x SET metadata_bytes=retained WHERE x.spool_id=spool;
  UPDATE object_store_retention.drain_policies x
  SET metadata_bytes=(x.metadata_bytes::numeric-(c.metadata_bytes-retained))::object_store_retention.uint64
  WHERE x.boundary=c.boundary AND x.cell=c.cell AND x.metadata_bytes::numeric>=(c.metadata_bytes-retained);
  IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_UNDERFLOW'; END IF;
 END IF;
END $$;";

/// The same body with 0026's original silent clamp in place of the underflow guard -- the exact
/// shape the CR's test plan asks the discrimination proof to revert.
const CLAMPING_RELEASE_FUNCTION_BODY: &str = "(spool uuid,fence bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE q object_store_retention.object_dispatch_quota_usage%ROWTYPE; n integer:=0; receipt bytea; computed_release_digest bytea;
DECLARE retained bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF c.cleanup_fence IS DISTINCT FROM fence OR c.state=1 THEN RAISE EXCEPTION 'DRAIN_CLEANUP_FENCED'; END IF;
 IF c.state IN(3,4) THEN RETURN; END IF;
 IF s.spool_object_id IS NULL THEN RAISE EXCEPTION 'DRAIN_CLEANUP_MISSING_ACCOUNTING'; END IF;
 FOR q IN SELECT * FROM object_store_retention.object_dispatch_quota_usage x
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service))
 ORDER BY x.scope_kind FOR UPDATE LOOP
  IF q.used_bytes<s.quota_bytes OR q.used_rows<s.quota_rows OR q.used_concurrency<s.quota_concurrency THEN RAISE EXCEPTION 'DRAIN_COUNTER_UNDERFLOW'; END IF;
  n:=n+1;
 END LOOP;
 IF n<>3 THEN RAISE EXCEPTION 'DRAIN_COUNTER_MISSING'; END IF;
 UPDATE object_store_retention.object_dispatch_quota_usage x SET used_bytes=x.used_bytes-s.quota_bytes,
 used_rows=x.used_rows-s.quota_rows,used_concurrency=x.used_concurrency-s.quota_concurrency,counter_revision=x.counter_revision+1,
 updated_at_unix_ms=object_store_retention.clock_unix_ms_v1()
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service));
 receipt:=convert_to('fragment-drain-release-v1','UTF8')||uuid_send(spool)||c.digest
 ||object_store_retention.local_canonical_u64_v1(fence::object_store_retention.uint64)
 ||object_store_retention.local_canonical_u64_v1(s.quota_bytes)
 ||object_store_retention.local_canonical_u64_v1(s.quota_rows)
 ||object_store_retention.local_canonical_u64_v1(s.quota_concurrency);
 computed_release_digest:=object_store_retention.local_blake3_v1(receipt);
 UPDATE object_store_retention.drain_spool_custody x SET state=3,release_receipt=receipt||computed_release_digest,release_digest=computed_release_digest
 WHERE x.spool_id=spool RETURNING * INTO c;
 retained:=object_store_retention.drain_retained_metadata_bytes_v1(c);
 IF retained<c.metadata_bytes THEN
  UPDATE object_store_retention.drain_spool_custody x SET metadata_bytes=retained WHERE x.spool_id=spool;
  UPDATE object_store_retention.drain_policies x
  SET metadata_bytes=greatest((x.metadata_bytes::numeric-(c.metadata_bytes-retained)),0)::object_store_retention.uint64
  WHERE x.boundary=c.boundary AND x.cell=c.cell;
 END IF;
END $$;";

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database with a real BLAKE3 provider"]
async fn live_release_true_up_matches_actual_size_and_underflow_raises() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_TRUE_UP_PG_URL").await;
    let base_url = fixture.base_url.clone();
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R27)
        .await
        .expect("install a real R27 cell");
    drop(fixture);
    wait_until_exclusive(&migrator).await;
    upgrade_cell_schema(&migrator)
        .await
        .expect("upgrade to current (real 0028)");
    let fixture = admin_at(base_url).await;
    install_blake3_provider(&fixture.client).await;

    let boundary = "true-up-boundary";
    let cell = "true-up-cell";
    let service = "true-up-service";

    // Case A: real 0028, correctness. The row's descriptor/canonical/release fields are all NULL
    // or tiny at this point (release has not run yet), so `drain_retained_metadata_bytes_v1`
    // computes the 1024 floor before release fills in the release receipt/digest; after release it
    // must equal 1024 + len(descriptor::text) + len(canonical) + len(release_receipt) +
    // len(release_digest), clamped to the charge and never below 1024. Assert against that formula
    // computed independently in Rust from what the row holds after release, not merely "less than
    // 16384", so a regression that changes the formula's shape (not just its magnitude) is caught.
    let spool = Uuid::now_v7();
    let logical = Uuid::now_v7();
    let attempt = Uuid::now_v7();
    seed_metadata_true_up_fixture(
        &fixture.client,
        boundary,
        cell,
        service,
        SeedIdentifiers {
            spool,
            logical,
            attempt,
        },
        16384,
    )
    .await;
    fixture
        .client
        .batch_execute(&format!(
            "SET SESSION AUTHORIZATION object_dispatch_retention_runtime;
             BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;
             SELECT object_store_retention.drain_cleanup_release_v1('{spool}', 1);
             COMMIT;
             RESET SESSION AUTHORIZATION;"
        ))
        .await
        .expect("real release must succeed and true up");
    let row = fixture
        .client
        .query_one(
            "SELECT metadata_bytes, octet_length(descriptor::text), octet_length(canonical), \
             octet_length(release_receipt), octet_length(release_digest) \
             FROM object_store_retention.drain_spool_custody WHERE spool_id = $1",
            &[&spool],
        )
        .await
        .expect("read released custody row");
    let retained: i64 = row.get(0);
    let descriptor_len: i32 = row.get(1);
    let canonical_len: i32 = row.get(2);
    let receipt_len: i32 = row.get(3);
    let release_digest_len: i32 = row.get(4);
    let expected = (1024
        + i64::from(descriptor_len)
        + i64::from(canonical_len)
        + i64::from(receipt_len)
        + i64::from(release_digest_len))
    .max(1024);
    assert_eq!(
        retained, expected,
        "the released row's metadata_bytes must equal the true-up formula's own output, not merely \
         be smaller than the flat charge"
    );
    let policy_bytes: i64 = fixture
        .client
        .query_one(
            "SELECT metadata_bytes::bigint FROM object_store_retention.drain_policies WHERE boundary = $1 AND cell = $2",
            &[&boundary, &cell],
        )
        .await
        .expect("read policy counter")
        .get(0);
    assert_eq!(
        policy_bytes,
        16384 - (16384 - retained),
        "the policy aggregate must have been reduced by exactly what the row gave back"
    );

    // Case B: real 0028, underflow. Corrupt the policy counter below what a true-up would
    // subtract, then force another true-up-eligible release on a second seeded row; the real
    // function must raise DRAIN_METADATA_UNDERFLOW, not silently clamp to zero.
    let spool_b = Uuid::now_v7();
    let logical_b = Uuid::now_v7();
    let attempt_b = Uuid::now_v7();
    seed_metadata_true_up_fixture(
        &fixture.client,
        boundary,
        cell,
        service,
        SeedIdentifiers {
            spool: spool_b,
            logical: logical_b,
            attempt: attempt_b,
        },
        16384,
    )
    .await;
    fixture
        .client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             UPDATE object_store_retention.drain_policies SET metadata_bytes = 1
             WHERE boundary = '{boundary}' AND cell = '{cell}';
             COMMIT;"
        ))
        .await
        .expect("corrupt the policy counter below the pending true-up");
    let underflow = fixture
        .client
        .batch_execute(&format!(
            "SET SESSION AUTHORIZATION object_dispatch_retention_runtime;
             BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;
             SELECT object_store_retention.drain_cleanup_release_v1('{spool_b}', 1);
             COMMIT;
             RESET SESSION AUTHORIZATION;"
        ))
        .await;
    let error = underflow.expect_err("the real true-up must raise on an impossible subtraction");
    assert_eq!(
        error.as_db_error().map(|db| db.message()),
        Some("DRAIN_METADATA_UNDERFLOW"),
        "the real function must raise this exact message, not clamp"
    );
    // The raise aborted the transaction before `COMMIT`/`RESET SESSION AUTHORIZATION` ran; clean up
    // this connection's session state before reusing it.
    fixture
        .client
        .batch_execute("ROLLBACK; RESET SESSION AUTHORIZATION;")
        .await
        .expect("roll back the aborted underflow transaction");

    // Discrimination proof: install a hand-mutated copy of the SAME release function, with the
    // underflow guard replaced by 0026's original silent clamp, directly on this disposable cell.
    // This never touches migrations/0028_*.sql on disk -- both bodies above are Rust string
    // literals compared against each other, not derived from the tracked file -- so no worktree is
    // needed and `git status` on implementation files is unaffected by construction.
    assert_ne!(
        CLAMPING_RELEASE_FUNCTION_BODY, REAL_RELEASE_FUNCTION_BODY,
        "the mutation must actually change the function body, or this proves nothing"
    );
    fixture
        .client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             CREATE OR REPLACE FUNCTION object_store_retention.drain_cleanup_release_v1{CLAMPING_RELEASE_FUNCTION_BODY}
             COMMIT;"
        ))
        .await
        .expect("install the mutated (clamping) release function");

    let spool_c = Uuid::now_v7();
    let logical_c = Uuid::now_v7();
    let attempt_c = Uuid::now_v7();
    seed_metadata_true_up_fixture(
        &fixture.client,
        boundary,
        cell,
        service,
        SeedIdentifiers {
            spool: spool_c,
            logical: logical_c,
            attempt: attempt_c,
        },
        16384,
    )
    .await;
    fixture
        .client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             UPDATE object_store_retention.drain_policies SET metadata_bytes = 1
             WHERE boundary = '{boundary}' AND cell = '{cell}';
             COMMIT;"
        ))
        .await
        .expect("corrupt the policy counter for the mutated case");
    fixture
        .client
        .batch_execute(&format!(
            "SET SESSION AUTHORIZATION object_dispatch_retention_runtime;
             BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;
             SELECT object_store_retention.drain_cleanup_release_v1('{spool_c}', 1);
             COMMIT;
             RESET SESSION AUTHORIZATION;"
        ))
        .await
        .expect(
            "the mutated (clamping) function must NOT raise on the same impossible subtraction",
        );
    let clamped_policy_bytes: i64 = fixture
        .client
        .query_one(
            "SELECT metadata_bytes::bigint FROM object_store_retention.drain_policies WHERE boundary = $1 AND cell = $2",
            &[&boundary, &cell],
        )
        .await
        .expect("read clamped policy counter")
        .get(0);
    assert_eq!(
        clamped_policy_bytes, 0,
        "the mutated (0026-shaped) function silently clamps to zero where the real 0028 raises: \
         this is the discrimination proof that the real function's guard is load-bearing"
    );

    // Restore the real function so a later call in this same connection is unaffected. Nothing on
    // disk was ever written by this test, so `git status` on `migrations/` is untouched.
    fixture
        .client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             CREATE OR REPLACE FUNCTION object_store_retention.drain_cleanup_release_v1{REAL_RELEASE_FUNCTION_BODY}
             COMMIT;"
        ))
        .await
        .expect("restore the real release function");
    attest_cell_schema(&migrator)
        .await
        .expect("attestation holds again once the real function is restored");
}

/// The three budget-row counts that make up slot 0's real published shape: one row in
/// `object_dispatch_budget_configurations`, one in `object_dispatch_current_budget_configuration`,
/// and one `object_dispatch_budget_bucket_state` row per published cap class (`publish_budget`
/// above always publishes caps 1..=7, so 7 here whenever a boundary has ever published).
async fn budget_row_counts(admin: &tokio_postgres::Client, boundary: &str) -> (i64, i64, i64) {
    let configurations: i64 = admin
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_budget_configurations \
             WHERE provider_boundary_id = $1",
            &[&boundary],
        )
        .await
        .expect("count budget configurations")
        .get(0);
    let current: i64 = admin
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_current_budget_configuration \
             WHERE provider_boundary_id = $1",
            &[&boundary],
        )
        .await
        .expect("count current budget configuration")
        .get(0);
    let bucket_state: i64 = admin
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_budget_bucket_state \
             WHERE provider_boundary_id = $1",
            &[&boundary],
        )
        .await
        .expect("count budget bucket state")
        .get(0);
    (configurations, current, bucket_state)
}

// -------------------------------------------------------------------------------------------
// CR-038 addendum (2026-09-23), test plan item 1: a cell installed at R25 -- slot 0's actual
// state -- with its drain budget PUBLISHED AT R25, matching slot 0's real shape (one
// configurations row, one current row, one bucket_state row per published cap class), upgrades
// through R26 and R27 to the current state, attests R28, leaves those budget rows completely
// unchanged by the upgrade, and then accepts real write-behind traffic: a genuine DrainClient
// reserve/claim/release cycle, and write-behind startup's own schema-revision check.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database with a real BLAKE3 provider"]
async fn live_install_at_r25_upgrades_to_current_and_drain_client_writes() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_CHAIN_PG_URL").await;
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R25)
        .await
        .expect("install a real R25 cell (slot 0's actual state)");
    assert_eq!(
        attest_cell_schema(&migrator).await,
        Err(CellSchemaError::UpgradeRequired(CellSchemaRevision::R25)),
        "a fresh R25 install must attest as R25, not as current"
    );

    let (identity, system_identifier, database_oid) = database_identity(&fixture.client).await;
    let now = now_ms(&fixture.client).await;
    let boundary = "r25-chain-boundary";
    let cell = "r25-chain-cell";
    let service = "r25-chain-service";

    // Publish the drain budget BEFORE the upgrade: R25 already carries migrations 0021/0022 (the
    // budget limiter schema), matching slot 0's actual pre-upgrade shape.
    install_blake3_provider(&fixture.client).await;
    let allocation = publish_budget(
        &fixture.client,
        boundary,
        cell,
        &system_identifier,
        database_oid,
        now,
    )
    .await;
    let before_upgrade_counts = budget_row_counts(&fixture.client, boundary).await;
    assert_eq!(
        before_upgrade_counts,
        (1, 1, 7),
        "a single published budget at R25 must read as exactly one configuration row, one \
         current-configuration row, and one bucket_state row per published cap class (1..=7) -- \
         slot 0's real pre-upgrade shape"
    );

    let base_url = fixture.base_url.clone();
    drop(fixture);
    wait_until_exclusive(&migrator).await;
    let report = upgrade_cell_schema(&migrator)
        .await
        .expect("upgrade an R25 cell all the way to current: R25 -> R26 -> R27 -> R28");
    assert_eq!(
        report.disposition,
        CellUpgradeDisposition::Upgraded(CellSchemaRevision::R25)
    );
    assert_eq!(report.attestation.schema_revision, CELL_SCHEMA_CURRENT);

    let fixture = admin_at(base_url).await;
    let after_upgrade_counts = budget_row_counts(&fixture.client, boundary).await;
    assert_eq!(
        after_upgrade_counts, before_upgrade_counts,
        "the R25 -> R28 upgrade must leave the pre-existing published budget rows completely \
         unchanged: no forward step here touches budget configuration/current/bucket_state"
    );
    let policy = drain_policy(
        boundary,
        cell,
        service,
        "r25-chain-policy-v1",
        u64::try_from(now + 3_600_000).unwrap(),
        16_384 * 8,
        1_000_000,
    );
    publish_drain_policy(&fixture.client, &policy).await;
    let policy_digest = policy.digest().unwrap();

    let pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&fixture.base_url, identity))
            .expect("runtime pool"),
    );
    let client = DrainClient::new(pool);
    // Write-behind startup's own gate: an upgraded cell's marker must now be readable.
    client
        .verify_schema_revision()
        .await
        .expect("write-behind startup must accept a cell upgraded from R25 to current");

    let descriptor_now = now_ms(&fixture.client).await;
    let descriptor = synthetic_descriptor(0, &policy, &policy_digest, &allocation, descriptor_now);
    let claimable_after = Duration::from_millis(policy.maximum_ttl_ms + 500);
    reserve_and_release(&client, &descriptor, claimable_after)
        .await
        .expect("a real reserve/claim/release cycle must succeed on the upgraded cell");
    assert!(
        !client
            .observe(boundary, cell)
            .await
            .expect("observe after a real write")
            .metadata_full,
        "one reservation on a fresh policy must not read as metadata_full"
    );
}

// -------------------------------------------------------------------------------------------
// CR-038 addendum (2026-09-23), test plan item 5: the R25 -> R26 step refuses a cell that still
// holds ANY spool object, or ANY nonzero quota usage -- proved as two independent triggers, each
// on its own fresh R25 cell -- and the refused cell is left exactly at R25, never partially
// advanced. The refusal message names the reason. `live_install_at_r25_upgrades_to_current_and_
// drain_client_writes` above is the positive control: the same upgrade call, on a cell with
// neither trigger present, succeeds -- so a refusal here is provably the guard firing on the
// condition it names, not some unrelated failure of the step itself.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database with a real BLAKE3 provider"]
async fn live_r25_upgrade_refuses_a_spool_object_or_charged_quota_and_leaves_the_cell_at_r25() {
    // -- Trigger 1: any row in object_dispatch_spool_objects, admitted through the real 0013
    // ReservePut procedure (not a hand-crafted INSERT). --
    let spool_fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_SPOOL_REFUSAL_PG_URL").await;
    let (spool_migrator, _spool_task) = connect_as(
        &spool_fixture.base_url,
        "object_dispatch_retention_migrator",
    )
    .await;
    install_cell_schema_at(&spool_migrator, CellSchemaRevision::R25)
        .await
        .expect("install a real R25 cell");
    // The shared canonical-record codec (0009) verifies the client-supplied digest against a real
    // BLAKE3 provider even for a plain reserve_put admission.
    install_blake3_provider(&spool_fixture.client).await;
    let (spool_identity, ..) = database_identity(&spool_fixture.client).await;
    let spool_pool = Arc::new(
        DispatchRuntimePool::new(runtime_pool_config(&spool_fixture.base_url, spool_identity))
            .expect("runtime pool"),
    );
    admit_one_reserved_spool_object(spool_pool, "r25-spool-refusal-boundary").await;

    drop(spool_fixture);
    wait_until_exclusive(&spool_migrator).await;
    let spool_reason = match upgrade_cell_schema(&spool_migrator).await {
        Err(CellSchemaError::Precondition(reason)) => {
            assert!(
                reason.contains("holds spool objects")
                    && reason.contains("cannot be carried forward"),
                "the spool-object refusal must name spool objects specifically, not a generic \
                 blocker: {reason}"
            );
            assert!(
                reason.contains("reinstall the cell") && reason.contains("owner decision"),
                "the refusal must name the remedy -- reinstall the cell or get an owner decision \
                 -- not just describe the blocker: {reason}"
            );
            assert!(
                !reason.to_lowercase().contains("retention"),
                "the cell cannot be carried forward at all here; the message must not suggest \
                 waiting for retention to clear it: {reason}"
            );
            reason
        }
        other => {
            panic!("expected a named Precondition refusal for a live spool object, got {other:?}")
        }
    };
    assert_eq!(
        attest_cell_schema(&spool_migrator).await,
        Err(CellSchemaError::UpgradeRequired(CellSchemaRevision::R25)),
        "a refused R25 -> R26 step must leave the cell exactly at R25, not partially advanced"
    );

    // -- Trigger 2: nonzero object_dispatch_quota_usage, with no spool object at all. Inserted
    // directly: unlike object_dispatch_spool_objects, this table has no foreign key into
    // object_dispatch_requests, so a minimal valid row needs no upstream admission call. --
    let quota_fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_QUOTA_REFUSAL_PG_URL").await;
    let (quota_migrator, _quota_task) = connect_as(
        &quota_fixture.base_url,
        "object_dispatch_retention_migrator",
    )
    .await;
    install_cell_schema_at(&quota_migrator, CellSchemaRevision::R25)
        .await
        .expect("install a second real R25 cell");
    let now = now_ms(&quota_fixture.client).await;
    quota_fixture
        .client
        .execute(
            "INSERT INTO object_store_retention.object_dispatch_quota_usage
               (schema_revision, provider_boundary_id, scope_kind, scope_id, quota_class,
                used_bytes, used_rows, used_concurrency, counter_revision, updated_at_unix_ms)
             VALUES ('object-store-dispatch-authority-schema-v1', 'r25-quota-refusal-boundary', 1,
                     'r25-quota-refusal-boundary', 1, 0, 1, 1, 1, $1)",
            &[&now],
        )
        .await
        .expect("seed a nonzero quota-usage row (no FK dependency, unlike a spool row)");

    drop(quota_fixture);
    wait_until_exclusive(&quota_migrator).await;
    let quota_reason = match upgrade_cell_schema(&quota_migrator).await {
        Err(CellSchemaError::Precondition(reason)) => {
            assert!(
                reason.contains("charged spool quota")
                    && reason.contains("cannot be carried forward"),
                "the quota refusal must name the quota charge specifically, not a generic \
                 blocker: {reason}"
            );
            assert!(
                reason.contains("reinstall the cell") && reason.contains("owner decision"),
                "the refusal must name the remedy -- reinstall the cell or get an owner decision \
                 -- not just describe the blocker: {reason}"
            );
            assert!(
                !reason.to_lowercase().contains("retention"),
                "the cell cannot be carried forward at all here; the message must not suggest \
                 waiting for retention to clear it: {reason}"
            );
            reason
        }
        other => panic!(
            "expected a named Precondition refusal for a nonzero quota charge, got {other:?}"
        ),
    };
    assert_eq!(
        attest_cell_schema(&quota_migrator).await,
        Err(CellSchemaError::UpgradeRequired(CellSchemaRevision::R25)),
        "a refused R25 -> R26 step must leave the cell exactly at R25, not partially advanced"
    );

    assert_ne!(
        spool_reason, quota_reason,
        "the two triggers must be distinguishable by their refusal reason, not collapsed into \
         one generic message"
    );
}

// -------------------------------------------------------------------------------------------
// CR-038 addendum (2026-09-23), test plan item 7: an R25 cell with one extra relation is a state
// outside the closed CELL_SCHEMA_STATES list. It must be refused as drift, never guessed at or
// silently walked forward as if it were a known state.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_r25_upgrade_refuses_a_state_outside_the_known_list() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_DRIFT_PG_URL").await;
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R25)
        .await
        .expect("install a real R25 cell");

    // One extra function: a state outside the closed CELL_SCHEMA_STATES list, neither R25 nor any
    // other known state. A function rather than a table: `DROP TABLE` triggers catalog activity
    // that can attract a stray autovacuum backend shortly afterward, which would flakily trip the
    // final upgrade's D4 exclusivity check below for a reason unrelated to what this test proves.
    fixture
        .client
        .batch_execute(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             CREATE FUNCTION object_store_retention.cr038_r25_drift_probe_v1() RETURNS integer
             LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$ SELECT 1 $$;
             COMMIT;",
        )
        .await
        .expect("plant one extra function");

    assert!(
        matches!(
            attest_cell_schema(&migrator).await,
            Err(CellSchemaError::CatalogDrift(_))
        ),
        "an R25 cell with an extra function must not classify as any known state"
    );
    // Classification runs before the D4 exclusivity check, so this refuses even with the admin
    // connection above still open.
    assert!(
        matches!(
            upgrade_cell_schema(&migrator).await,
            Err(CellSchemaError::CatalogDrift(_))
        ),
        "upgrade must refuse a state outside the known list, never walk it forward as a guess"
    );

    // Undo the plant and confirm the cell is provably back to exactly R25.
    fixture
        .client
        .batch_execute(
            "BEGIN; SET LOCAL ROLE object_dispatch_retention_owner;
             DROP FUNCTION object_store_retention.cr038_r25_drift_probe_v1();
             COMMIT;",
        )
        .await
        .expect("undo the plant");
    assert_eq!(
        attest_cell_schema(&migrator).await,
        Err(CellSchemaError::UpgradeRequired(CellSchemaRevision::R25)),
        "once the plant is undone the cell must fully attest as R25 again, proving the plant was \
         fully reversed rather than merely no longer triggering some unrelated check"
    );

    drop(fixture);
    wait_until_exclusive(&migrator).await;
    upgrade_cell_schema(&migrator)
        .await
        .expect("a genuinely R25 cell upgrades cleanly once the drift is gone");
}

// -------------------------------------------------------------------------------------------
// CR-038 addendum (2026-09-23), test plan item 3: kill the session right after the R25 -> R26
// step's own COMMIT is acknowledged by the server but never reaches the client, inside a CHAINED
// upgrade that must still walk R26 -> R27 -> R28 afterward. The chaining/reclassify loop that
// makes this possible is new code the R27-only crash tests above never exercise (they upgrade in
// exactly one hop): a fresh run must resume from R26, not replay the R25 -> R26 step.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_upgrade_recovers_from_a_lost_commit_after_the_r25_to_r26_step() {
    let fixture = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_LOST_COMMIT_PG_URL").await;
    let base_url = fixture.base_url.clone();
    let (migrator, _migrator_task) =
        connect_as(&fixture.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&migrator, CellSchemaRevision::R25)
        .await
        .expect("install a real R25 cell");

    drop(migrator);
    drop(_migrator_task);
    drop(fixture);
    {
        let probe = admin_at(base_url.clone()).await;
        wait_until_exclusive(&probe.client).await;
    }

    let (host_port, path) = host_port_and_path(&base_url);
    let proxy = LostCommitProxy::start(host_port).await;
    let proxied_url = format!(
        "postgresql://object_dispatch_retention_migrator@127.0.0.1:{}/{path}?sslmode=disable",
        proxy.port
    );
    let (proxied_migrator, _proxied_task) = {
        let (client, connection) = tokio_postgres::connect(&proxied_url, tokio_postgres::NoTls)
            .await
            .expect("connect through the lost-commit proxy");
        (
            client,
            AbortOnDropHandle::new(lore_base::lore_spawn!(
                "cell-schema-forward-upgrade-r25-proxied",
                async move {
                    let _ = connection.await;
                }
            )),
        )
    };

    // The R25 -> R26 step is the first `COMMIT` a chained upgrade from R25 issues, so the proxy's
    // single-shot arm targets it without needing to skip any earlier COMMIT.
    proxy.drop_next_commit_response();
    let outcome = upgrade_cell_schema(&proxied_migrator).await;
    assert!(
        outcome.is_err(),
        "the client must see an error when the R25 -> R26 step's own COMMIT reply never arrives, \
         even though the server committed it"
    );
    assert!(
        proxy.fault_fired(),
        "the fault must actually have fired, or this proves nothing"
    );
    drop(proxied_migrator);
    drop(_proxied_task);

    // The server-side R25 -> R26 COMMIT the client never saw already landed: a fresh connection
    // must classify the cell as R26, not R25, proving the chained loop's persisted step survives
    // the connection that ran it.
    let (migrator, _migrator_task) =
        connect_as(&base_url, "object_dispatch_retention_migrator").await;
    assert_eq!(
        attest_cell_schema(&migrator).await,
        Err(CellSchemaError::UpgradeRequired(CellSchemaRevision::R26)),
        "the cell must attest as R26 after the lost-commit crash, not R25 (the step silently \
         re-ran) and not current (the loop kept going past a dead connection)"
    );

    wait_until_exclusive(&migrator).await;
    let report = upgrade_cell_schema(&migrator)
        .await
        .expect("recovery must resume from R26 and reach current");
    assert_eq!(
        report.disposition,
        CellUpgradeDisposition::Upgraded(CellSchemaRevision::R26),
        "recovery must resume from R26 (the state actually reached), never redo the R25 -> R26 \
         step"
    );
    assert_eq!(report.attestation.schema_revision, CELL_SCHEMA_CURRENT);
}

// -------------------------------------------------------------------------------------------
// CR-038 addendum (2026-09-23), test plan item 4: three-way fresh-install parity. A fresh R28
// install, a cell upgraded all the way from R25, and a cell upgraded starting from R26 (the
// resume case) must all attest byte-identical manifests: every one of the twelve sections, plus
// the whole-manifest digest.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_fresh_r25_upgrade_and_r26_resume_attest_identical_manifests() {
    let fresh = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_PARITY_FRESH_PG_URL").await;
    let (fresh_migrator, _fresh_task) =
        connect_as(&fresh.base_url, "object_dispatch_retention_migrator").await;
    let fresh_report = install_cell_schema(&fresh_migrator)
        .await
        .expect("fresh install runs the forward steps through the same wrapper as upgrade");
    assert_eq!(
        fresh_report.attestation.schema_revision,
        CELL_SCHEMA_CURRENT
    );

    let from_r25 = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_PARITY_FROM_R25_PG_URL").await;
    let (from_r25_migrator, _from_r25_task) =
        connect_as(&from_r25.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&from_r25_migrator, CellSchemaRevision::R25)
        .await
        .expect("install a real R25 cell");
    drop(from_r25);
    wait_until_exclusive(&from_r25_migrator).await;
    let from_r25_report = upgrade_cell_schema(&from_r25_migrator)
        .await
        .expect("upgrade all the way from R25");
    assert_eq!(
        from_r25_report.disposition,
        CellUpgradeDisposition::Upgraded(CellSchemaRevision::R25)
    );

    let from_r26 = admin("LORE_TEST_CELL_SCHEMA_UPGRADE_R25_PARITY_FROM_R26_PG_URL").await;
    let (from_r26_migrator, _from_r26_task) =
        connect_as(&from_r26.base_url, "object_dispatch_retention_migrator").await;
    install_cell_schema_at(&from_r26_migrator, CellSchemaRevision::R26)
        .await
        .expect("install a real R26 cell");
    drop(from_r26);
    wait_until_exclusive(&from_r26_migrator).await;
    let from_r26_report = upgrade_cell_schema(&from_r26_migrator)
        .await
        .expect("upgrade starting from R26 (the resume case)");
    assert_eq!(
        from_r26_report.disposition,
        CellUpgradeDisposition::Upgraded(CellSchemaRevision::R26)
    );

    assert_eq!(
        fresh_report.attestation.catalog_sections, from_r25_report.attestation.catalog_sections,
        "a fresh install and a cell upgraded from R25 must match on every manifest section"
    );
    assert_eq!(
        fresh_report.attestation.catalog_sections, from_r26_report.attestation.catalog_sections,
        "a fresh install and a cell resumed from R26 must match on every manifest section"
    );
    assert_eq!(
        fresh_report.attestation.catalog_blake3, from_r25_report.attestation.catalog_blake3,
        "a fresh install and a cell upgraded from R25 must attest byte-identical manifests"
    );
    assert_eq!(
        fresh_report.attestation.catalog_blake3, from_r26_report.attestation.catalog_blake3,
        "a fresh install and a cell resumed from R26 must attest byte-identical manifests"
    );
}

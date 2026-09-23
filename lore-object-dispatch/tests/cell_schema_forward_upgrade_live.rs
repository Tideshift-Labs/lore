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
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;
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

    let upstream = url_as(&base_url, "object_dispatch_retention_migrator");
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
    let proxy = LostCommitProxy::start(host_port.to_string()).await;
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

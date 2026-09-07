// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! CD-8 retention over schema-valid seeded rows, plus grants minted by the real charge client.
//! Run only with run-cell-retention-live.ps1 (fresh PostgreSQL 16, supported installer, pinned CA).
//! Request/child records are relational fixtures, NOT proof of reserve -> submit -> ACK lifecycle:
//! the installed cell API has no Submit/ACK writer. No canonical success result is claimed here.
//! Request clocks are seeded in the past. Real grants/configurations are aged ONLY in explicit
//! fixture SQL after proving admission/replay; database clock and retention code remain unchanged.

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::BudgetPin;
use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::DispatchConnectionBudget;
use lore_object_dispatch::DispatchDatabaseIdentity;
use lore_object_dispatch::DispatchPoolConfig;
use lore_object_dispatch::DispatchPoolRole;
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::MeteredProviderAttemptRequest;
use lore_object_dispatch::PostgresProviderChargeAuthority;
use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderAttemptLedger;
use lore_object_dispatch::ProviderAttemptOutcome;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderAttemptRequest;
use lore_object_dispatch::ProviderCapabilities;
use lore_object_dispatch::ProviderRetryPolicy;
use lore_object_dispatch::ProviderTrafficClass;
use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;
use lore_object_dispatch::cell_retention::CellRetentionClient;
use lore_object_dispatch::cell_retention::CellRetentionReadiness;
use lore_object_dispatch::cell_retention::CellRetentionSettings;
use lore_object_dispatch::cell_retention::CellRetentionTask;
use lore_object_dispatch::cell_retention::REASON_BACKLOG_SATURATED;
use lore_object_dispatch::cell_retention::REASON_BLOCKED_BACKLOG;
use lore_object_dispatch::cell_schema_install::install_cell_schema;
use tokio_postgres::Client;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const BOUNDARY: &str = "cell.test.shared-budget";
const REVISION: &str = "Budget.Rev_1-a";
const FENCE: u64 = 1;
const INTERVAL_MS: u64 = 1_000_000_000;

struct Fixture {
    admin: Client,
    pool: Arc<DispatchRuntimePool>,
    _connection: AbortOnDropHandle<()>,
}

fn tls(pem: &str) -> MakeRustlsConnect {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes())) {
        roots.add(cert.expect("CA PEM")).expect("CA root");
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    MakeRustlsConnect::new(config)
}

async fn connect(url: &str, pem: &str) -> (Client, AbortOnDropHandle<()>) {
    let (client, connection) = tokio_postgres::connect(url, tls(pem))
        .await
        .expect("fixture TLS connection");
    let task = AbortOnDropHandle::new(lore_base::lore_spawn!("cell-retention-live", async move {
        connection.await.expect("fixture connection remains usable");
    }));
    (client, task)
}

impl Fixture {
    async fn new() -> Self {
        let base = std::env::var("LORE_TEST_CELL_RETENTION_PG_URL")
            .expect("runner supplies fresh database");
        let pem = std::fs::read_to_string(
            std::env::var("LORE_TEST_CELL_RETENTION_CA_PATH").expect("runner CA path"),
        )
        .expect("read CA");
        let (admin, connection) = connect(&base, &pem).await;
        let migrator_url = base.replace("postgres@", "object_dispatch_retention_migrator@");
        let (migrator, _migrator_connection) = connect(&migrator_url, &pem).await;
        install_cell_schema(&migrator)
            .await
            .expect("supported cell install and attestation");
        let row = admin.query_one("SELECT (SELECT system_identifier::text FROM pg_control_system()), (SELECT oid FROM pg_database WHERE datname=current_database())", &[]).await.expect("physical identity");
        let identity =
            DispatchDatabaseIdentity::new(row.get::<_, String>(0).parse().unwrap(), row.get(1))
                .unwrap();
        let pool = Arc::new(
            DispatchRuntimePool::new(DispatchPoolConfig {
                postgres_url: base.replace("postgres@", "object_dispatch_retention_runtime@"),
                role: DispatchPoolRole::Runtime,
                expected_database_identity: identity,
                pool_max: 1,
                connect_timeout: Duration::from_secs(5),
                acquire_timeout: Duration::from_secs(5),
                statement_timeout: Duration::from_secs(5),
                lock_timeout: Duration::from_secs(1),
                tls: DispatchTlsMode::PinnedRootCa(pem),
                budget: DispatchConnectionBudget::new(1, 1, 1, 1, 1).unwrap(),
            })
            .unwrap(),
        );
        let fixture = Self {
            admin,
            pool,
            _connection: connection,
        };
        let state = fixture
            .client()
            .read_state()
            .await
            .expect("real runtime layer readback");
        assert_eq!(state.install_revision, 1);
        fixture
    }

    fn client(&self) -> CellRetentionClient {
        CellRetentionClient::new(self.pool.clone()).unwrap()
    }

    async fn sql(&self, sql: &str) {
        self.admin
            .batch_execute(sql)
            .await
            .unwrap_or_else(|error| panic!("fixture SQL: {error:?}"));
    }

    async fn count(&self, table: &str) -> i64 {
        self.admin
            .query_one(
                &format!("SELECT count(*) FROM object_store_retention.{table}"),
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn seed(&self, id: u32, closure: i64, expiry: i64) {
        let sql = include_str!("common/cell_retention_rows.sql")
            .replace("$LOGICAL", &format!("00000000-03e8-7000-8000-{id:012x}"))
            .replace("$ATTEMPT", &format!("00000000-03e9-7000-8000-{id:012x}"))
            .replace("$SPOOL", &format!("00000000-05dc-7000-8000-{id:012x}"))
            .replace("$PURGE", &format!("00000000-05dd-7000-8000-{id:012x}"))
            .replace("$LEASE", &format!("00000000-05de-7000-8000-{id:012x}"))
            .replace("$ID", &id.to_string())
            .replace("$EXPIRY", &expiry.to_string())
            .replace("$CLOSURE", &closure.to_string())
            .replace("$DIGEST", "decode(repeat('11',32),'hex')")
            .replace("$RECORD", "decode('aa'||repeat('11',32),'hex')");
        self.sql(&sql).await;
    }
}

fn settings(batch: u32) -> CellRetentionSettings {
    CellRetentionSettings::new(Some(1000), Some(batch), Some(60_000), Some(2)).unwrap()
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 with TLS; use run-cell-retention-live.ps1"]
async fn live_cell_retention_removes_children_atomically_and_preserves_both_horizons() {
    let f = Fixture::new().await;
    f.seed(1, 1500, 3000).await;
    f.seed(2, 1500, i64::MAX).await;
    f.seed(3, i64::MAX, 3000).await;
    let client = f.client();
    let s = settings(10);
    let before = client.backlog(&s).await.unwrap();
    assert_eq!((before.prunable, before.blocked, before.grants), (1, 0, 0));
    // A parent-delete failure must roll the whole statement back, including its child deletes.
    f.sql("CREATE FUNCTION public.refuse_retention_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rollback' USING ERRCODE='23514'; END $$; CREATE TRIGGER refuse_retention_delete BEFORE DELETE ON object_store_retention.object_dispatch_requests FOR EACH ROW EXECUTE FUNCTION public.refuse_retention_delete();").await;
    assert_eq!(
        client.prune_once(&s).await,
        Err(lore_object_dispatch::DispatchAuthorityError::AuthorityUnavailable)
    );
    for table in [
        "requests",
        "attempts",
        "spool_objects",
        "payload_purges",
        "fetch_leases",
    ] {
        assert_eq!(
            f.count(&format!("object_dispatch_{table}")).await,
            3,
            "rollback {table}"
        );
    }
    f.sql("DROP TRIGGER refuse_retention_delete ON object_store_retention.object_dispatch_requests; DROP FUNCTION public.refuse_retention_delete();").await;
    let report = client.prune_once(&s).await.unwrap();
    assert_eq!(
        (
            report.examined,
            report.pruned_requests,
            report.pruned_attempts,
            report.pruned_spool_objects,
            report.pruned_payload_purges,
            report.pruned_fetch_leases
        ),
        (1, 1, 1, 1, 1, 1)
    );
    assert_eq!(report.database_now_unix_ms - report.horizon_unix_ms, 60_000);
    for table in [
        "requests",
        "attempts",
        "spool_objects",
        "payload_purges",
        "fetch_leases",
    ] {
        assert_eq!(
            f.count(&format!("object_dispatch_{table}")).await,
            2,
            "preserved {table}"
        );
    }
    let remaining: Vec<String> = f.admin.query("SELECT logical_request_id::text FROM object_store_retention.object_dispatch_requests ORDER BY logical_request_id", &[]).await.unwrap().iter().map(|r|r.get(0)).collect();
    assert_eq!(
        remaining,
        [
            "00000000-03e8-7000-8000-000000000002",
            "00000000-03e8-7000-8000-000000000003"
        ]
    );
    assert_eq!(client.prune_once(&s).await.unwrap().pruned_requests, 0);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 with TLS; use run-cell-retention-live.ps1"]
async fn live_cell_retention_blockers_fail_readiness_and_recover_after_drain() {
    let f = Fixture::new().await;
    let s = settings(1);
    let readiness = Arc::new(CellRetentionReadiness::new(&s));
    let task = CellRetentionTask::new(f.client(), s.clone(), readiness.clone());
    for (id, block, unblock) in [
        (
            1,
            "UPDATE object_store_retention.object_dispatch_spool_objects SET lifecycle_state=2,purged_at_unix_ms=NULL,release_reason=NULL,release_receipt_bytes=NULL,release_receipt_blake3=NULL",
            "UPDATE object_store_retention.object_dispatch_spool_objects SET lifecycle_state=3,purged_at_unix_ms=1600,release_reason=1,release_receipt_bytes=canonical_record_bytes,release_receipt_blake3=record_blake3",
        ),
        (
            2,
            "UPDATE object_store_retention.object_dispatch_payload_purges SET purge_state=1,receipt_canonical_bytes=NULL,receipt_blake3=NULL,released_bytes=NULL,released_rows=NULL,released_concurrency=NULL,quota_revision=NULL,purged_at_unix_ms=NULL",
            "UPDATE object_store_retention.object_dispatch_payload_purges SET purge_state=2,receipt_canonical_bytes=reservation_canonical_bytes,receipt_blake3=reservation_blake3,released_bytes=33,released_rows=1,released_concurrency=1,quota_revision=1,purged_at_unix_ms=1600",
        ),
        (
            3,
            "UPDATE object_store_retention.object_dispatch_fetch_leases SET state=1,terminal_reason=NULL,terminal_at_unix_ms=NULL,terminal_fingerprint=NULL",
            "UPDATE object_store_retention.object_dispatch_fetch_leases SET state=2,terminal_reason=1,terminal_at_unix_ms=1600,terminal_fingerprint=lease_blake3",
        ),
    ] {
        f.seed(id, 1500, 3000).await;
        f.sql(block).await;
        let backlog = f.client().backlog(&s).await.unwrap();
        assert_eq!(
            (backlog.prunable, backlog.blocked, backlog.grants),
            (0, 1, 0),
            "blocker {id}"
        );
        task.prune_once().await;
        assert!(readiness.retention_ready(), "stall tolerance {id}");
        task.prune_once().await;
        let snapshot = readiness.snapshot();
        assert_eq!(
            snapshot.retention_reason,
            Some(REASON_BLOCKED_BACKLOG),
            "blocker {id}"
        );
        assert_eq!(snapshot.last_blocked_backlog, 1);
        assert_eq!(f.count("object_dispatch_requests").await, 1);
        f.sql(unblock).await;
        task.prune_once().await;
        assert!(readiness.retention_ready());
        assert_eq!(readiness.snapshot().consecutive_stalls, 0);
        assert_eq!(f.count("object_dispatch_requests").await, 0);
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 with TLS; use run-cell-retention-live.ps1"]
async fn live_cell_retention_bounds_batch_probe_and_recovers_from_saturation() {
    let f = Fixture::new().await;
    for id in 1..=7 {
        f.seed(id, 1500, 3000).await;
    }
    let s = settings(1);
    let readiness = Arc::new(CellRetentionReadiness::new(&s));
    let task = CellRetentionTask::new(f.client(), s.clone(), readiness.clone());
    assert_eq!(
        f.client().backlog(&s).await.unwrap().prunable,
        2,
        "probe is batch + one"
    );
    for remaining in [6, 5] {
        task.prune_once().await;
        assert_eq!(f.count("object_dispatch_requests").await, remaining);
        assert_eq!(readiness.snapshot().last_pruned, 1);
        assert_eq!(readiness.snapshot().last_prunable_backlog, 2);
    }
    assert_eq!(
        readiness.snapshot().retention_reason,
        Some(REASON_BACKLOG_SATURATED)
    );
    for _ in 0..5 {
        task.prune_once().await;
    }
    assert!(readiness.retention_ready());
    assert_eq!(f.count("object_dispatch_requests").await, 0);
    task.prune_once().await;
    assert_eq!(readiness.snapshot().last_pruned, 0);
    assert!(readiness.retention_ready());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 with TLS; use run-cell-retention-live.ps1"]
async fn live_cell_retention_real_grants_use_budget_expiry_and_bounded_drain() {
    let f = Fixture::new().await;
    f.sql(&first_publication_sql(i64::MAX, FENCE)).await;
    let calls = Arc::new(AtomicU32::new(0));
    let boundary =
        CellProviderBoundary::new(BOUNDARY, "fixture-bucket", "test-1", "objects.test.invalid")
            .unwrap();
    let target = boundary.target().clone();
    let provider = GovernedProviderClient::new(
        boundary,
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        PostgresProviderChargeAuthority::new(f.pool.clone()).unwrap(),
        CountingTransport(calls.clone()),
    );
    let mut last_request = None;
    for _ in 0..7 {
        let logical = Uuid::now_v7().to_string();
        let request = MeteredProviderAttemptRequest::try_from(ProviderAttemptRequest {
            traffic_class: ProviderTrafficClass::Drain,
            attempt_class: ProviderAttemptClass::Readiness,
            target: target.clone(),
            logical_request_id: logical.clone(),
            attempt_id: Uuid::now_v7().to_string(),
            attempt_ordinal: 1,
            deadline_unix_ms: i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
                + 60_000,
            budget_pin: BudgetPin {
                revision: REVISION.into(),
                fence: FENCE,
            },
            put_body: None,
            put_part: None,
        })
        .unwrap();
        let mut ledger = ProviderAttemptLedger::new(BOUNDARY, &logical).unwrap();
        provider
            .execute(&mut ledger, &request, &())
            .await
            .expect("real charge commit before scripted transport");
        assert_eq!(ledger.committed_grant_count(), 1);
        last_request = Some((logical, request));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 7);
    assert_eq!(f.count("object_dispatch_provider_charge_grants").await, 7);
    assert_eq!(
        f.count("object_dispatch_requests").await,
        0,
        "direct charge creates no request row"
    );
    let s = settings(1);
    let client = f.client();
    assert_eq!(client.prune_once(&s).await.unwrap().pruned_charge_grants, 0);
    // Fixture-only aging: no live clock replacement, no fabricated grant or readiness outcome.
    f.sql("UPDATE object_store_retention.object_dispatch_provider_charge_grants SET grant_committed_at_unix_ms=1000").await;
    assert_eq!(
        client.backlog(&s).await.unwrap().grants,
        0,
        "live budget retains old grants"
    );
    assert_eq!(client.prune_once(&s).await.unwrap().pruned_charge_grants, 0);
    // An old grant retained under a live budget must still fence the exact same attempt.
    let (logical, request) = last_request.unwrap();
    let before: String = f.admin.query_one("SELECT jsonb_agg(to_jsonb(s) ORDER BY cap_class)::text FROM object_store_retention.object_dispatch_budget_bucket_state s", &[]).await.unwrap().get(0);
    let mut replay_ledger = ProviderAttemptLedger::new(BOUNDARY, &logical).unwrap();
    assert_eq!(
        provider
            .execute(&mut replay_ledger, &request, &())
            .await
            .map(|value| value.outcome),
        Err(lore_object_dispatch::ProviderClientError::ChargeRefused(
            lore_object_dispatch::ProviderChargeError::AttemptAlreadyCharged
        ))
    );
    assert_eq!(replay_ledger.committed_grant_count(), 0);
    assert_eq!(replay_ledger.attempt_count(), 0);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        7,
        "duplicate request issues no provider call"
    );
    assert_eq!(f.count("object_dispatch_provider_charge_grants").await, 7);
    let after: String = f.admin.query_one("SELECT jsonb_agg(to_jsonb(s) ORDER BY cap_class)::text FROM object_store_retention.object_dispatch_budget_bucket_state s", &[]).await.unwrap().get(0);
    assert_eq!(
        after, before,
        "duplicate grant lookup leaves every cap and its revision unchanged"
    );
    f.sql("UPDATE object_store_retention.object_dispatch_provider_charge_grants SET grant_committed_at_unix_ms=object_store_retention.clock_unix_ms_v1(); UPDATE object_store_retention.object_dispatch_budget_configurations SET hard_expires_at_unix_ms=2000").await;
    assert_eq!(
        client.prune_once(&s).await.unwrap().pruned_charge_grants,
        0,
        "fresh grants retain forensic window after budget expiry"
    );
    f.sql("UPDATE object_store_retention.object_dispatch_provider_charge_grants SET grant_committed_at_unix_ms=1000").await;
    assert_eq!(client.backlog(&s).await.unwrap().grants, 2);
    let readiness = Arc::new(CellRetentionReadiness::new(&s));
    let task = CellRetentionTask::new(f.client(), s, readiness.clone());
    for remaining in [6, 5] {
        task.prune_once().await;
        assert_eq!(
            f.count("object_dispatch_provider_charge_grants").await,
            remaining
        );
        assert_eq!(
            readiness.snapshot().last_pruned,
            0,
            "snapshot counts request rows only"
        );
        assert_eq!(readiness.snapshot().last_grant_backlog, 2);
    }
    assert_eq!(
        readiness.snapshot().retention_reason,
        Some(REASON_BACKLOG_SATURATED)
    );
    for _ in 0..5 {
        task.prune_once().await;
    }
    assert_eq!(f.count("object_dispatch_provider_charge_grants").await, 0);
    assert!(readiness.retention_ready());
    task.prune_once().await;
    assert_eq!(readiness.snapshot().last_pruned, 0);
    assert!(readiness.retention_ready());
}

struct CountingTransport(Arc<AtomicU32>);
impl ProviderTransport for CountingTransport {
    type Operation = ();
    type Response = ();
    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a (),
    ) -> Result<ProviderAttemptReport<()>, ProviderTransportRefusal> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    }
}
fn first_publication_sql(hard_expiry: i64, allocation_fence: u64) -> String {
    let caps = cap_json();
    format!(
        "SET SESSION AUTHORIZATION object_dispatch_retention_maintenance;\
         BEGIN ISOLATION LEVEL SERIALIZABLE;\
         SELECT object_store_retention.object_store_dispatch_publish_budget_configuration_v1(\
           'object-store-dispatch-budget-limiter-v1', '{BOUNDARY}', '{REVISION}',\
           {allocation_fence}::bigint::object_store_retention.uint64,\
           {hard_expiry}, 'object-store-frozen-capacity-budget-core-v1',\
           'object-store-exact-target-cache-disposition-v1',\
           'object-store-budget-frozen-envelope-v1', 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 'cell-test', 'cell-test', '{BOUNDARY}',\
           '{BOUNDARY}', 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, decode(repeat('11',32),'hex'),\
           '018f3e12-a456-7abc-8def-000000000001'::uuid, decode(repeat('22',32),'hex'),\
           decode(repeat('11',32),'hex'), 1::bigint::object_store_retention.uint64,\
           NULL::uuid, NULL::bytea, 0::bigint::object_store_retention.uint64, NULL::bytea,\
           decode(repeat('33',32),'hex'), decode(repeat('11',32),'hex'),\
           decode(repeat('22',32),'hex'), decode(repeat('44',32),'hex'),\
           1::bigint::object_store_retention.uint64, 1::smallint,\
           NULL::text, NULL::text, NULL::bytea, NULL::bytea, decode(repeat('44',32),'hex'),\
           '[{{\"dimensionId\":\"all\",\"effectiveBound\":10,\"measuredLoad\":1,\"targetDemand\":1,\"failureReserve\":1,\"preCacheHeadroom\":7,\"finalBudget\":7}}]'::jsonb,\
           '{caps}'::jsonb);\
         COMMIT; RESET SESSION AUTHORIZATION;"
    )
}

fn cap_json() -> String {
    let entries = (1..=7)
        .map(|class| {
            let capacity = if class == 1 { 8 } else if class == 7 { 1 } else { 7 };
            format!(
                "{{\"capClass\":{class},\"capacityUnits\":{capacity},\"refillUnits\":{capacity},\"refillIntervalMs\":{INTERVAL_MS}}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]")
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 with TLS; use run-cell-retention-live.ps1"]
async fn live_cell_retention_backlog_keeps_clock_and_horizon_coherent() {
    let f = Fixture::new().await;
    // Deliberately slow each clock invocation in this disposable database AFTER attestation.
    // nextval counters cannot be used: the real backlog client correctly opens READ ONLY.
    // Sleeping guarantees separate evaluations cross a millisecond boundary without changing
    // database time. No production source or readiness values are patched.
    f.sql("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE plpgsql VOLATILE AS $$ BEGIN PERFORM pg_sleep(0.01); RETURN floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint; END $$;").await;
    // Negative control executes the former query shape against the exact same fixture clock.
    f.sql("SET SESSION AUTHORIZATION object_dispatch_retention_runtime")
        .await;
    let old = f.admin.query_one("SELECT (r).horizon_unix_ms,(r).database_now_unix_ms FROM (SELECT object_store_retention.object_store_dispatch_cell_retention_backlog_v1('object-store-dispatch-cell-retention-v1',60000,2) AS r) q", &[]).await.unwrap();
    assert_ne!(
        old.get::<_, i64>(1) - old.get::<_, i64>(0),
        60_000,
        "old flattened query must be a discriminating negative control"
    );
    f.sql("RESET SESSION AUTHORIZATION").await;
    let report = f
        .client()
        .backlog(&settings(1))
        .await
        .expect("one coherent authoritative backlog report");
    assert_eq!(report.database_now_unix_ms - report.horizon_unix_ms, 60_000);
}

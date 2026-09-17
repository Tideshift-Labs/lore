// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Live PostgreSQL 16 evidence for CR-034's runtime budget pin re-read: migration 0025's
//! `SECURITY DEFINER` head-read function, and the refresh-and-retry the head read feeds in
//! `GovernedProviderClient::execute`.
//!
//! Pattern of `provider_charge_live.rs`, trimmed to what this delta needs: install through 0025,
//! publish a first revision, then drive the real `PostgresProviderChargeAuthority` (never a fake)
//! through a real renewal. Each test in this file runs against its own fresh, disposable
//! PostgreSQL 16 database -- never the owner's default stack, never slot 50's published budget.
//! See `lorehub/docs/lore-change-requests/cr-034-runtime-budget-pin-re-read.md`.

use std::env;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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
use lore_object_dispatch::ProviderChargeAuthority;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderChargeGrant;
use lore_object_dispatch::ProviderChargeRequest;
use lore_object_dispatch::ProviderClientError;
use lore_object_dispatch::ProviderRetryPolicy;
use lore_object_dispatch::ProviderTrafficClass;
use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;
use tokio_postgres::Client;
use tokio_postgres::NoTls;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const MIGRATION_0002: &str =
    include_str!("../migrations/0002_object_store_retention_authority.sql");
const MIGRATION_0003: &str =
    include_str!("../migrations/0003_object_store_retention_provisioning.sql");
const MIGRATION_0007: &str =
    include_str!("../migrations/0007_object_store_dispatch_authority_core.sql");
const MIGRATION_0008: &str =
    include_str!("../migrations/0008_object_store_dispatch_authority_provisioning.sql");
const MIGRATION_0009: &str =
    include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql");
const MIGRATION_0010: &str =
    include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql");
const MIGRATION_0011: &str =
    include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql");
const MIGRATION_0012: &str =
    include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql");
const MIGRATION_0013: &str =
    include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql");
const MIGRATION_0014: &str =
    include_str!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql");
const MIGRATION_0015: &str =
    include_str!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql");
const MIGRATION_0016: &str =
    include_str!("../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql");
const MIGRATION_0017: &str =
    include_str!("../migrations/0017_object_store_dispatch_put_spool_ready_mutation.sql");
const MIGRATION_0018: &str =
    include_str!("../migrations/0018_object_store_dispatch_dispatcher_identity_schema.sql");
const MIGRATION_0019: &str =
    include_str!("../migrations/0019_object_store_dispatch_dispatcher_identity_provisioning.sql");
const MIGRATION_0020: &str =
    include_str!("../migrations/0020_object_store_dispatch_dispatcher_registration.sql");
const MIGRATION_0021: &str =
    include_str!("../migrations/0021_object_store_dispatch_budget_limiter_schema.sql");
const MIGRATION_0022: &str =
    include_str!("../migrations/0022_object_store_dispatch_budget_limiter_provisioning.sql");
// CR-034: the runtime head-read function this file exists to prove. Not a `CellSchemaLayer` --
// see the plan's decision D2 and `cell_schema_install.rs`'s "not a layer" note for 0025.
const MIGRATION_0025: &str =
    include_str!("../migrations/0025_object_store_dispatch_budget_head_read.sql");

const API_REVISION: &str = "object-store-dispatch-budget-limiter-v1";
const BOUNDARY: &str = "cell.test.budget-pin-refresh";
const REVISION: &str = "Budget.Rev_1";
const FENCE: u64 = 1;
const INTERVAL_MS: u64 = 1_000_000_000;
const ENV_URL: &str = "LORE_TEST_BUDGET_PIN_REFRESH_PG_URL";

// ---------------------------------------------------------------------------------------------
// Case 9 + 10: the head-read function is the only door, and is least privilege.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_head_read_function_is_the_only_door_and_is_least_privilege() {
    let url = env::var(ENV_URL).expect("runner must set LORE_TEST_BUDGET_PIN_REFRESH_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;

    let head = head_read_as(&admin, "object_dispatch_retention_runtime", BOUNDARY)
        .await
        .expect("the runtime role must be able to call the head read");
    assert_eq!(head.0, "HEAD");
    assert_eq!(head.1.as_deref(), Some(REVISION));
    assert_eq!(head.2.as_deref(), Some(FENCE.to_string()).as_deref());

    for role in [
        "object_dispatch_retention_maintenance",
        "object_dispatch_retention_migrator",
    ] {
        let error = head_read_as(&admin, role, BOUNDARY)
            .await
            .expect_err(&format!("{role} must be refused"));
        assert_eq!(error, "42501", "case: {role}");
    }

    // The runtime role still cannot SELECT the head table directly (the 0022 REVOKE ALL block
    // stays intact) -- the function is the only door.
    let direct_select =
        direct_select_current_configuration_as(&admin, "object_dispatch_retention_runtime")
            .await
            .expect_err("a direct SELECT on the head table must still be refused");
    assert_eq!(direct_select, "42501");
}

// ---------------------------------------------------------------------------------------------
// Case 11: a writer pinned to N renews across a publish of N+1 and debits only the N+1 key.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_pinned_writer_renews_across_a_publish_and_debits_only_the_new_fence() {
    let url = env::var(ENV_URL).expect("runner must set LORE_TEST_BUDGET_PIN_REFRESH_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;
    set_available(&admin, 1, 10).await;
    set_available(&admin, 2, 10).await;
    let before_old = bucket_available_at(&admin, REVISION, FENCE, 1).await;

    let successor_revision = "Budget.Rev_2";
    let successor_fence = FENCE + 1;
    assert_eq!(
        publish_clean_successor(&admin, successor_revision, successor_fence).await,
        Ok("PUBLISHED".to_string())
    );
    let before_new = bucket_available_at(&admin, successor_revision, successor_fence, 1).await;

    let expected_database_identity = read_database_identity(&admin).await;
    let runtime_pool = Arc::new(
        DispatchRuntimePool::new(pool_config(
            &url,
            Duration::from_secs(5),
            expected_database_identity,
        ))
        .expect("construct shared runtime pool"),
    );
    let inner = PostgresProviderChargeAuthority::new(Arc::clone(&runtime_pool))
        .expect("construct real PostgreSQL charge authority");
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let authority = CountingRefreshAuthority {
        inner,
        refresh_calls: refresh_calls.clone(),
    };
    let transport_calls = Arc::new(AtomicU32::new(0));
    let client = GovernedProviderClient::new(
        live_boundary(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        authority,
        CountingTransport(transport_calls.clone()),
    );

    // The request itself is still bound to the ORIGINAL pin (N): it is a writer that has not
    // restarted since the publish.
    let request = live_request(Uuid::now_v7(), Uuid::now_v7());
    let metered = MeteredProviderAttemptRequest::try_from(request.clone())
        .expect("readiness must be metered");
    let mut ledger = ProviderAttemptLedger::new(BOUNDARY, &request.logical_request_id)
        .expect("construct ledger");

    let outcome = client.execute(&mut ledger, &metered, &()).await;

    assert_eq!(
        outcome.map(|execution| execution.outcome),
        Ok(ProviderAttemptOutcome::Decisive),
        "a writer pinned to N must renew and succeed against the published N+1 head"
    );
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        1,
        "exactly one refresh"
    );
    assert_eq!(transport_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.poisoned(), None);

    let logical_request_id =
        Uuid::parse_str(&request.logical_request_id).expect("fixture logical_request_id is a uuid");
    let attempt_id = Uuid::parse_str(&request.attempt_id).expect("fixture attempt_id is a uuid");
    assert_eq!(
        grant_count_for(&admin, logical_request_id, attempt_id).await,
        1,
        "exactly one grant row for this (attempt_id, attempt_ordinal)"
    );

    // The double-spend proof: the old fence's shared bucket is byte-for-byte untouched, and the
    // new fence's shared bucket was actually debited.
    let after_old = bucket_available_at(&admin, REVISION, FENCE, 1).await;
    assert_eq!(
        after_old, before_old,
        "the old fence's shared bucket must not be debited at all"
    );
    let after_new = bucket_available_at(&admin, successor_revision, successor_fence, 1).await;
    let before_new_units: i128 = before_new.parse().expect("scaled balance is numeric");
    let after_new_units: i128 = after_new.parse().expect("scaled balance is numeric");
    assert!(
        after_new_units < before_new_units,
        "the new fence's shared bucket must be debited by the granted attempt: before {before_new_units}, after {after_new_units}"
    );
}

// ---------------------------------------------------------------------------------------------
// Case 12: two generations of drift (N+1 and N+2 both published) refuses, decisively, no debit.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_two_generations_of_drift_refuses_the_attempt_and_debits_nothing() {
    let url = env::var(ENV_URL).expect("runner must set LORE_TEST_BUDGET_PIN_REFRESH_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;
    set_available(&admin, 1, 10).await;
    set_available(&admin, 2, 10).await;

    assert_eq!(
        publish_clean_successor(&admin, "Budget.Rev_2", FENCE + 1).await,
        Ok("PUBLISHED".to_string())
    );
    assert_eq!(
        publish_clean_successor(&admin, "Budget.Rev_3", FENCE + 2).await,
        Ok("PUBLISHED".to_string())
    );

    let before_old = bucket_available_at(&admin, REVISION, FENCE, 1).await;
    let before_first_successor = bucket_available_at(&admin, "Budget.Rev_2", FENCE + 1, 1).await;
    let before_second_successor = bucket_available_at(&admin, "Budget.Rev_3", FENCE + 2, 1).await;

    let expected_database_identity = read_database_identity(&admin).await;
    let runtime_pool = Arc::new(
        DispatchRuntimePool::new(pool_config(
            &url,
            Duration::from_secs(5),
            expected_database_identity,
        ))
        .expect("construct shared runtime pool"),
    );
    let inner = PostgresProviderChargeAuthority::new(Arc::clone(&runtime_pool))
        .expect("construct real PostgreSQL charge authority");
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let authority = CountingRefreshAuthority {
        inner,
        refresh_calls: refresh_calls.clone(),
    };
    let transport_calls = Arc::new(AtomicU32::new(0));
    let client = GovernedProviderClient::new(
        live_boundary(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        authority,
        CountingTransport(transport_calls.clone()),
    );

    let request = live_request(Uuid::now_v7(), Uuid::now_v7());
    let metered = MeteredProviderAttemptRequest::try_from(request.clone())
        .expect("readiness must be metered");
    let mut ledger = ProviderAttemptLedger::new(BOUNDARY, &request.logical_request_id)
        .expect("construct ledger");

    let outcome = client.execute(&mut ledger, &metered, &()).await;

    assert_eq!(
        outcome,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::BudgetPinRejected
        )),
        "N+2 drift is more than one generation and must stay a typed decisive refusal"
    );
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        1,
        "the head is read once, then refused as a non-successor fence"
    );
    assert_eq!(transport_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.poisoned(), None);

    let logical_request_id =
        Uuid::parse_str(&request.logical_request_id).expect("fixture logical_request_id is a uuid");
    let attempt_id = Uuid::parse_str(&request.attempt_id).expect("fixture attempt_id is a uuid");
    assert_eq!(
        grant_count_for(&admin, logical_request_id, attempt_id).await,
        0,
        "no grant row anywhere for this attempt"
    );
    assert_eq!(
        bucket_available_at(&admin, REVISION, FENCE, 1).await,
        before_old
    );
    assert_eq!(
        bucket_available_at(&admin, "Budget.Rev_2", FENCE + 1, 1).await,
        before_first_successor
    );
    assert_eq!(
        bucket_available_at(&admin, "Budget.Rev_3", FENCE + 2, 1).await,
        before_second_successor
    );
}

// ---------------------------------------------------------------------------------------------
// Case 13: expiry stays typed and never enters the refresh branch.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_expiry_refuses_typed_and_never_enters_the_refresh_branch() {
    let url = env::var(ENV_URL).expect("runner must set LORE_TEST_BUDGET_PIN_REFRESH_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    let database_now: i64 = admin
        .query_one("SELECT object_store_retention.clock_unix_ms_v1()", &[])
        .await
        .expect("read database clock")
        .get(0);
    seed_configuration_with_expiry(&admin, database_now + 100).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let expected_database_identity = read_database_identity(&admin).await;
    let runtime_pool = Arc::new(
        DispatchRuntimePool::new(pool_config(
            &url,
            Duration::from_secs(5),
            expected_database_identity,
        ))
        .expect("construct shared runtime pool"),
    );
    let inner = PostgresProviderChargeAuthority::new(Arc::clone(&runtime_pool))
        .expect("construct real PostgreSQL charge authority");
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let authority = CountingRefreshAuthority {
        inner,
        refresh_calls: refresh_calls.clone(),
    };
    let transport_calls = Arc::new(AtomicU32::new(0));
    let client = GovernedProviderClient::new(
        live_boundary(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        authority,
        CountingTransport(transport_calls.clone()),
    );

    let request = live_request(Uuid::now_v7(), Uuid::now_v7());
    let metered = MeteredProviderAttemptRequest::try_from(request.clone())
        .expect("readiness must be metered");
    let mut ledger = ProviderAttemptLedger::new(BOUNDARY, &request.logical_request_id)
        .expect("construct ledger");

    let outcome = client.execute(&mut ledger, &metered, &()).await;

    assert_eq!(
        outcome,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::ConfigurationUnresolved
        )),
        "expiry must stay CONFIGURATION_UNRESOLVED, never dressed up as a renewal"
    );
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        0,
        "expiry is not BudgetPinRejected and must never enter the refresh branch"
    );
    assert_eq!(transport_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(grant_count(&admin).await, 0);
}

// ---------------------------------------------------------------------------------------------
// Shared fixtures (pattern of provider_charge_live.rs; this file is deliberately self-contained)
// ---------------------------------------------------------------------------------------------

/// Wraps the real `PostgresProviderChargeAuthority` and counts calls to `refresh_budget_pin`
/// without changing its behavior, so a live test can prove exactly how many times the head was
/// actually read against real PostgreSQL -- zero on expiry, exactly one on a renewable rejection.
struct CountingRefreshAuthority {
    inner: PostgresProviderChargeAuthority,
    refresh_calls: Arc<AtomicU32>,
}

impl ProviderChargeAuthority for CountingRefreshAuthority {
    async fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        self.inner.charge(request).await
    }

    async fn refresh_budget_pin(
        &self,
        provider_boundary_id: &str,
    ) -> Result<BudgetPin, ProviderChargeError> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.refresh_budget_pin(provider_boundary_id).await
    }
}

struct CountingTransport(Arc<AtomicU32>);

impl ProviderTransport for CountingTransport {
    type Operation = ();
    type Response = ();

    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    }
}

fn pool_config(
    base_url: &str,
    statement_timeout: Duration,
    expected_database_identity: DispatchDatabaseIdentity,
) -> DispatchPoolConfig {
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
            DispatchPoolRole::Runtime.role_name()
        ),
        role: DispatchPoolRole::Runtime,
        expected_database_identity,
        pool_max: 1,
        connect_timeout: Duration::from_secs(10),
        acquire_timeout: Duration::from_secs(10),
        statement_timeout,
        lock_timeout: Duration::from_secs(1),
        tls: DispatchTlsMode::Disabled,
        budget: DispatchConnectionBudget::new(1, 1, 1, 1, 1, 0).expect("live process budget"),
    }
}

async fn read_database_identity(client: &Client) -> DispatchDatabaseIdentity {
    let row = client
        .query_one(
            "SELECT (SELECT system_identifier::text FROM pg_control_system()),
                    (SELECT oid FROM pg_database WHERE datname = current_database())",
            &[],
        )
        .await
        .expect("read physical database identity");
    let system_identifier = row
        .get::<_, String>(0)
        .parse()
        .expect("canonical PostgreSQL system identifier");
    DispatchDatabaseIdentity::new(system_identifier, row.get(1))
        .expect("nonzero physical database identity")
}

fn live_boundary() -> CellProviderBoundary {
    CellProviderBoundary::new(BOUNDARY, "fixture-bucket", "test-1", "objects.test.invalid")
        .expect("construct live provider boundary")
}

fn live_request(logical_request_id: Uuid, attempt_id: Uuid) -> ProviderAttemptRequest {
    ProviderAttemptRequest {
        traffic_class: ProviderTrafficClass::Drain,
        attempt_class: ProviderAttemptClass::Readiness,
        target: live_boundary().target().clone(),
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        attempt_ordinal: 1,
        deadline_unix_ms: future_deadline(),
        budget_pin: BudgetPin {
            revision: REVISION.to_string(),
            fence: FENCE,
        },
        put_body: None,
        put_part: None,
    }
}

struct LiveDatabase {
    client: Client,
    _connection: AbortOnDropHandle<()>,
}

impl Deref for LiveDatabase {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for LiveDatabase {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

async fn connect(url: &str) -> LiveDatabase {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let handle = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "budget-pin-refresh-live",
        async move {
            let _ = connection.await;
        }
    ));
    LiveDatabase {
        client,
        _connection: handle,
    }
}

async fn install(client: &Client) {
    client
        .batch_execute(
            "DO $$ BEGIN \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF; \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime NOLOGIN; END IF; \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance NOLOGIN; END IF; \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator NOLOGIN; END IF; \
             END $$;",
        )
        .await
        .expect("create fixture roles");
    client
        .batch_execute("ALTER ROLE object_dispatch_retention_runtime LOGIN")
        .await
        .expect("allow the runtime pool to connect as its own role");
    for migration in [
        MIGRATION_0002,
        MIGRATION_0003,
        MIGRATION_0007,
        MIGRATION_0008,
        MIGRATION_0009,
        MIGRATION_0010,
        MIGRATION_0011,
        MIGRATION_0012,
        MIGRATION_0013,
        MIGRATION_0014,
        MIGRATION_0015,
        MIGRATION_0016,
        MIGRATION_0017,
        MIGRATION_0018,
        MIGRATION_0019,
        MIGRATION_0020,
        MIGRATION_0021,
        MIGRATION_0022,
        MIGRATION_0025,
    ] {
        client
            .batch_execute(migration)
            .await
            .expect("install migration");
    }
}

async fn seed_configuration(client: &Client) {
    seed_configuration_with_expiry(client, i64::MAX).await;
}

async fn seed_configuration_with_expiry(client: &Client, hard_expiry: i64) {
    let sql = first_publication_sql(hard_expiry, FENCE);
    client
        .batch_execute(&sql)
        .await
        .expect("publish resolved configuration");
}

fn first_publication_sql(hard_expiry: i64, allocation_fence: u64) -> String {
    let caps = cap_json();
    format!(
        "SET SESSION AUTHORIZATION object_dispatch_retention_maintenance;\
         BEGIN ISOLATION LEVEL SERIALIZABLE;\
         SELECT object_store_retention.object_store_dispatch_publish_budget_configuration_v1(\
           '{API_REVISION}', '{BOUNDARY}', '{REVISION}',\
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
    let entries: Vec<String> = (1..=7)
        .map(|class| {
            let capacity = if class == 1 {
                3
            } else if class == 7 {
                1
            } else {
                2
            };
            format!(
                "{{\"capClass\":{class},\"capacityUnits\":{capacity},\"refillUnits\":{capacity},\"refillIntervalMs\":{INTERVAL_MS}}}"
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

/// A clean rotation to `revision`/`fence`, carrying every other field forward from the current
/// head unchanged. Trimmed from `provider_charge_live.rs`'s `publish_successor`: this file never
/// needs the mutation matrix that proves the publish function's own fail-closed checks -- that
/// coverage already lives there. This helper exists only to put a real N+1 (or N+2) head in place
/// so the refresh-and-retry contract can be proven against it.
async fn publish_clean_successor(
    client: &Client,
    revision: &str,
    fence: u64,
) -> Result<String, String> {
    let new_id = Uuid::now_v7();
    let sql = format!(
        "SELECT (object_store_retention.object_store_dispatch_publish_budget_configuration_v1(\
          '{API_REVISION}', c.provider_boundary_id, '{revision}',\
          {fence}::bigint::object_store_retention.uint64, c.hard_expires_at_unix_ms,\
          c.core_schema_revision, c.disposition_schema_revision, c.envelope_schema_revision,\
          c.target_kind, c.target_id, c.target_revision + 1,\
          c.target_kind, c.target_id, c.target_revision + 1,\
          c.target_kind, c.target_id, c.target_revision + 1,\
          c.cell_id, c.cell_id, c.provider_boundary_id,\
          c.provider_boundary_id, c.provider_allocation_set_revision,\
          c.provider_allocation_set_revision, c.provider_allocation_set_revision,\
          c.provider_allocation_set_fence, c.provider_allocation_set_fence,\
          c.provider_allocation_set_fence, c.core_record_digest, '{new_id}'::uuid,\
          decode(repeat('55',32),'hex'), c.core_record_digest, c.disposition_revision + 1,\
          c.disposition_id, c.disposition_record_digest, c.envelope_revision, c.envelope_record_digest,\
          decode(repeat('66',32),'hex'), c.core_record_digest, decode(repeat('55',32),'hex'),\
          c.final_budget_vector_digest, c.envelope_revision + 1, c.disposition,\
          c.cache_implementation_package_path, c.cache_implementation_revision,\
          c.cache_proof_digest, c.cache_effect_vector_digest, c.final_budget_vector_digest,\
          c.dimensions, c.cap_budgets)).result_code \
         FROM object_store_retention.object_dispatch_current_budget_configuration current_config \
         JOIN object_store_retention.object_dispatch_budget_configurations c \
           USING (provider_boundary_id, allocation_revision, allocation_fence) \
         WHERE current_config.provider_boundary_id = '{BOUNDARY}'"
    );
    client
        .batch_execute(
            "GRANT SELECT ON object_store_retention.object_dispatch_current_budget_configuration, \
             object_store_retention.object_dispatch_budget_configurations \
             TO object_dispatch_retention_maintenance",
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
    client
        .batch_execute(
            "SET SESSION AUTHORIZATION object_dispatch_retention_maintenance; \
             BEGIN ISOLATION LEVEL SERIALIZABLE",
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
    let outcome = match client.query_one(&sql, &[]).await {
        Ok(row) => {
            let result: String = row.get(0);
            client
                .batch_execute("COMMIT; RESET SESSION AUTHORIZATION")
                .await
                .map_err(|error| format!("{error:?}"))?;
            Ok(result)
        }
        Err(error) => {
            let _ = client
                .batch_execute("ROLLBACK; RESET SESSION AUTHORIZATION")
                .await;
            Err(format!("{error:?}; SQL: {sql}"))
        }
    };
    client
        .batch_execute(
            "REVOKE SELECT ON \
               object_store_retention.object_dispatch_current_budget_configuration, \
               object_store_retention.object_dispatch_budget_configurations \
             FROM object_dispatch_retention_maintenance",
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
    outcome
}

/// Calls the migration-0025 head-read function as `role`, returning `(result_code,
/// allocation_revision, allocation_fence-as-text)` on success, or the SQLSTATE (falling back to
/// the debug-formatted error) on refusal.
async fn head_read_as(
    client: &Client,
    role: &str,
    boundary: &str,
) -> Result<(String, Option<String>, Option<String>), String> {
    client
        .batch_execute(&format!("SET SESSION AUTHORIZATION {role}"))
        .await
        .map_err(|error| format!("{error:?}"))?;
    let sql = "SELECT (r).result_code, (r).allocation_revision, ((r).allocation_fence)::text \
        FROM (SELECT object_store_retention.object_store_dispatch_read_current_budget_pin_v1($1, $2) AS r) q";
    let outcome = match client.query_one(sql, &[&API_REVISION, &boundary]).await {
        Ok(row) => Ok((row.get(0), row.get(1), row.get(2))),
        Err(error) => Err(error
            .code()
            .map(|code| code.code().to_string())
            .unwrap_or_else(|| format!("{error:?}"))),
    };
    client
        .batch_execute("RESET SESSION AUTHORIZATION")
        .await
        .map_err(|error| format!("{error:?}"))?;
    outcome
}

/// Proves the head table itself is still unreachable outside the function (the 0022 `REVOKE ALL`
/// block), independent of whether the function grants a door in.
async fn direct_select_current_configuration_as(client: &Client, role: &str) -> Result<(), String> {
    client
        .batch_execute(&format!("SET SESSION AUTHORIZATION {role}"))
        .await
        .map_err(|error| format!("{error:?}"))?;
    let outcome = match client
        .query_opt(
            "SELECT 1 FROM object_store_retention.object_dispatch_current_budget_configuration LIMIT 1",
            &[],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => Err(error
            .code()
            .map(|code| code.code().to_string())
            .unwrap_or_else(|| format!("{error:?}"))),
    };
    client
        .batch_execute("RESET SESSION AUTHORIZATION")
        .await
        .map_err(|error| format!("{error:?}"))?;
    outcome
}

async fn set_available(client: &Client, cap_class: i16, units: u64) {
    // Bare integer literals multiply as int4 (`int4mul`) and overflow past ~2.1e9: this file uses
    // larger `units` than provider_charge_live.rs's fixture (1-2) to leave headroom for a real
    // debit, so both operands are cast to the uint64 domain's own underlying `numeric(20,0)`
    // before multiplying, not left to Postgres's default int4 literal type.
    client
        .batch_execute(&format!(
            "UPDATE object_store_retention.object_dispatch_budget_bucket_state SET \
             available_scaled = {units}::numeric(20,0) * {INTERVAL_MS}::numeric(20,0), \
             updated_at_unix_ms = object_store_retention.clock_unix_ms_v1(), \
             state_revision = state_revision + 1 \
             WHERE provider_boundary_id = '{BOUNDARY}' AND cap_class = {cap_class};"
        ))
        .await
        .expect("set bucket availability");
}

async fn bucket_available_at(
    client: &Client,
    revision: &str,
    fence: u64,
    cap_class: i16,
) -> String {
    client
        .query_one(
            "SELECT available_scaled::text FROM \
             object_store_retention.object_dispatch_budget_bucket_state \
             WHERE provider_boundary_id = $1 AND allocation_revision = $2 \
               AND allocation_fence = $3::bigint::object_store_retention.uint64 \
               AND cap_class = $4",
            &[
                &BOUNDARY,
                &revision,
                &i64::try_from(fence).expect("fixture fence fits i64"),
                &cap_class,
            ],
        )
        .await
        .expect("read exact rotated bucket state")
        .get(0)
}

async fn grant_count(client: &Client) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .expect("count grants")
        .get(0)
}

async fn grant_count_for(client: &Client, logical_request_id: Uuid, attempt_id: Uuid) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants \
             WHERE provider_boundary_id = $1 AND logical_request_id = $2 AND attempt_id = $3",
            &[&BOUNDARY, &logical_request_id, &attempt_id],
        )
        .await
        .expect("count grants for attempt")
        .get(0)
}

fn future_deadline() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_millis();
    i64::try_from(now).expect("current Unix milliseconds must fit i64") + 60_000
}

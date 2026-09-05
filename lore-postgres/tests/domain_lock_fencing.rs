// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Real-Postgres proof for WP-117's fenced lock coordinator.
//!
//! Every case is `#[ignore]` and is executed by `run-lock-fencing-live.ps1`,
//! which gives each exact case a fresh PostgreSQL 16 database.

use std::collections::BTreeMap;
use std::time::Duration;
use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::lock_order::LockClass;
use lore_postgres::domain::lock_order::LockSequence;
use lore_postgres::domain::lock_order::lock_branch;
use lore_postgres::domain::lock_order::lock_repository;
use lore_postgres::domain::locks::AcquireOrRenewInput;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::domain::locks::ForceReleaseInput;
use lore_postgres::domain::locks::LockRejection;
use lore_postgres::domain::locks::LockResourceInput;
use lore_postgres::domain::locks::PostgresLockCoordinator;
use lore_postgres::domain::locks::ReleaseInput;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_postgres::domain::locks::acquire_or_renew_binding;
use lore_postgres::domain::locks::force_release_binding;
use lore_postgres::domain::locks::lock_tenant_scope_key;
use lore_postgres::domain::locks::release_binding;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::domain::receipts::MARKER_SAFETY_EPSILON;
use lore_postgres::domain::receipts::NORMAL_FUTURE_SKEW;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::RECEIPT_BEARING_FUTURE_HORIZON;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::STALE_HORIZON;
use lore_postgres::domain::receipts::UUID_FUTURE_HORIZON_EXCEEDED_V1;
use lore_postgres::domain::receipts::UUID_TIME_OUT_OF_RANGE_V1;
use lore_postgres::domain::schema::FUTURE_REJECT_QUOTA_HOURLY_MAX;
use lore_postgres::domain::schema::FUTURE_REJECT_QUOTA_RETAINED_MAX;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn store(url: &str) -> PostgresDomainStore {
    let store = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
        .await
        .expect("connect domain store");
    store
        .lock_coordinator()
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-117 fixture");
    store
}

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

fn uuid_v7_at(time: SystemTime) -> Uuid {
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("test timestamp follows epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ))
}

fn owner(issuer: &str, subject: &str) -> VerifiedLockOwner {
    VerifiedLockOwner {
        verified_issuer: issuer.to_owned(),
        authenticated_subject: subject.to_owned(),
    }
}

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_owned(),
        scope: rand::random::<[u8; 16]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

async fn prepare_operation(
    store: &PostgresDomainStore,
    owner: &VerifiedLockOwner,
    repository_id: &[u8],
    branch_id: &[u8],
    method: &str,
) -> GovernedOperation {
    prepare_bound_operation(store, owner, repository_id, branch_id, binding(method)).await
}

async fn prepare_bound_operation(
    store: &PostgresDomainStore,
    owner: &VerifiedLockOwner,
    repository_id: &[u8],
    branch_id: &[u8],
    binding: OperationBinding,
) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read receipt database clock");
    let key = ReceiptKey {
        verified_issuer: owner.verified_issuer.clone(),
        authenticated_subject: owner.authenticated_subject.clone(),
        tenant_scope_key: lock_tenant_scope_key(repository_id, branch_id)
            .expect("canonical lock tenant scope"),
        operation_id: uuid_v7_at(clock),
    };
    let prepared = store
        .domain_operation_prepare(&key, &binding, None)
        .await
        .expect("prepare lock operation");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("admissible lock operation must prepare, got {prepared:?}");
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

async fn prepare_create_operation(store: &PostgresDomainStore) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read create receipt database clock");
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp117/create/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp117-test".to_owned(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id: uuid_v7_at(clock),
    };
    let binding = binding("repository_create");
    let prepared = store
        .domain_operation_prepare(&key, &binding, None)
        .await
        .expect("prepare repository create");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("repository create must prepare, got {prepared:?}");
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

async fn create_repository(store: &PostgresDomainStore) -> ([u8; 16], [u8; 16]) {
    let repository_id: [u8; 16] = rand::random();
    let branch_id: [u8; 16] = rand::random();
    let operation = prepare_create_operation(store).await;
    let input = RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name: format!("wp117-lock-{:016x}", rand::random::<u64>()),
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: branch_id.to_vec(),
        default_branch_name: "main".to_owned(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        events: Vec::new(),
    };
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("create repository fixture");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    (repository_id, branch_id)
}

fn resource(hash: [u8; 32], token: Option<[u8; 32]>) -> LockResourceInput {
    LockResourceInput {
        resource_hash: hash.to_vec(),
        description: format!("/Game/{:02x}.uasset", hash[0]),
        expected_ownership_token: token,
    }
}

fn acquire_input(
    repository_id: &[u8; 16],
    branch_id: &[u8; 16],
    owner: VerifiedLockOwner,
    resources: Vec<LockResourceInput>,
    lease_duration: Option<Duration>,
) -> AcquireOrRenewInput {
    AcquireOrRenewInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner,
        acting_owner: None,
        resources,
        lease_duration,
        outbox_cell_id: None,
    }
}

async fn acquire_one(
    store: &PostgresDomainStore,
    lock_owner: &VerifiedLockOwner,
    repository_id: &[u8; 16],
    branch_id: &[u8; 16],
    hash: [u8; 32],
    lease: Option<Duration>,
) -> lore_postgres::domain::locks::FencedLock {
    let input = acquire_input(
        repository_id,
        branch_id,
        lock_owner.clone(),
        vec![resource(hash, None)],
        lease,
    );
    let operation = prepare_bound_operation(
        store,
        lock_owner,
        repository_id,
        branch_id,
        acquire_or_renew_binding(&input).expect("valid acquire binding"),
    )
    .await;
    let result = store
        .lock_coordinator()
        .acquire_or_renew(&operation, &input)
        .await
        .expect("acquire lock");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    assert_eq!(result.locks.len(), 1);
    result.locks.into_iter().next().expect("one acquired lock")
}

fn assert_rejection(
    result: &lore_postgres::domain::locks::LockMutationResult,
    expected: LockRejection,
) {
    assert_eq!(result.rejection, Some(expected), "result={result:?}");
    assert!(matches!(result.outcome, DomainOutcome::NotApplied { .. }));
}

// ---------------------------------------------------------------------------
// CR-032 / WP-119 Part L: `lock_namespace` outbox producers.
//
// `PostgresLockCoordinator::acquire_or_renew`/`release`/`force_release` build
// and append their one classified event internally (`LockTransition`,
// `build_lock_event` in `lore-postgres/src/domain/locks/coordinator.rs`) when
// `outbox_cell_id` is supplied; the caller never constructs the event. These
// tests drive that classification end to end against real Postgres.

fn outbox_cell_id() -> String {
    format!("wp119-lock-{:08x}", rand::random::<u32>())
}

/// The pinned `lock_namespace` `aggregate_id`: lowercase hex of the 16
/// repository bytes immediately followed by lowercase hex of the 16 branch
/// bytes, per `lock_namespace_id` in the coordinator.
fn lock_namespace_aggregate_id(repository_id: &[u8; 16], branch_id: &[u8; 16]) -> Vec<u8> {
    let mut out = String::with_capacity(64);
    for byte in repository_id.iter().chain(branch_id.iter()) {
        out.push_str(&format!("{byte:02x}"));
    }
    out.into_bytes()
}

async fn outbox_row_count_for_repository(client: &Client, repository_id: &[u8]) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("count outbox rows for repository")
        .get(0)
}

struct LockOutboxRow {
    event_kind: String,
    aggregate_kind: String,
    aggregate_id: Vec<u8>,
    aggregate_version: Vec<u8>,
    cell_id: String,
}

async fn one_outbox_row_for_repository(client: &Client, repository_id: &[u8]) -> LockOutboxRow {
    let row = client
        .query_one(
            "SELECT event_kind, aggregate_kind, aggregate_id, aggregate_version, cell_id \
             FROM lore_outbox_events WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("exactly one outbox row for repository");
    LockOutboxRow {
        event_kind: row.get("event_kind"),
        aggregate_kind: row.get("aggregate_kind"),
        aggregate_id: row.get("aggregate_id"),
        aggregate_version: row.get("aggregate_version"),
        cell_id: row.get("cell_id"),
    }
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn a_fresh_acquire_commits_exactly_one_lock_acquired_row_with_the_fence_and_owner_token() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "wp119-acquire");
    let hash: [u8; 32] = rand::random();
    let cell_id = outbox_cell_id();

    let mut input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner.clone(),
        vec![resource(hash, None)],
        None,
    );
    input.outbox_cell_id = Some(cell_id.clone());
    let operation = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("valid acquire binding"),
    )
    .await;
    let result = coordinator
        .acquire_or_renew(&operation, &input)
        .await
        .expect("fresh acquire must succeed");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    assert_eq!(result.locks.len(), 1);
    let lock = &result.locks[0];

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "lock.acquired");
    assert_eq!(row.aggregate_kind, "lock_namespace");
    assert_eq!(row.cell_id, cell_id);
    assert_eq!(
        row.aggregate_id,
        lock_namespace_aggregate_id(&repository_id, &branch_id)
    );
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(
        decoded.ordinal,
        u64::try_from(lock.fence).expect("fence fits u64"),
        "ordinal must be the fence read back from the committed lock row, not a caller value"
    );
    assert_eq!(
        decoded.identity, lock.ownership_token,
        "identity must be the owner token minted inside the transaction"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn a_same_owner_renewal_commits_exactly_one_lock_renewed_row_with_the_new_fence_and_token() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "wp119-renew");
    let hash: [u8; 32] = rand::random();

    // First acquire with no cell id supplied: proves an unclassified batch
    // leaves no row, and gives the renewal something real to renew.
    let held = acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0,
        "an acquire with no outbox_cell_id must append nothing"
    );

    let cell_id = outbox_cell_id();
    let mut input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner.clone(),
        vec![resource(hash, Some(held.ownership_token))],
        None,
    );
    input.outbox_cell_id = Some(cell_id.clone());
    let operation = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("valid renew binding"),
    )
    .await;
    let result = coordinator
        .acquire_or_renew(&operation, &input)
        .await
        .expect("renewal by the same owner must succeed");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    let renewed = &result.locks[0];
    assert_ne!(
        renewed.ownership_token, held.ownership_token,
        "test fixture sanity: every committed row mints a fresh token, including a renewal"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "lock.renewed");
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(
        decoded.ordinal,
        u64::try_from(renewed.fence).expect("fence fits u64")
    );
    assert_eq!(decoded.identity, renewed.ownership_token);
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn an_expiry_takeover_by_a_different_owner_commits_exactly_one_lock_taken_over_row_with_the_successors_fence()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    coordinator
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("empty backfill");
    coordinator
        .enable_fencing_for_component_fixture(true)
        .await
        .expect("enable finite leases in test fixture");
    let owner_a = owner("https://issuer.example", "wp119-predecessor");
    let owner_b = owner("https://issuer.example", "wp119-successor");
    let hash: [u8; 32] = rand::random();

    let predecessor = acquire_one(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        hash,
        Some(Duration::from_millis(40)),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(90)).await;

    let cell_id = outbox_cell_id();
    let mut input = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(hash, None)],
        Some(Duration::from_secs(2)),
    );
    input.outbox_cell_id = Some(cell_id.clone());
    let operation = prepare_bound_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("valid takeover binding"),
    )
    .await;
    let result = coordinator
        .acquire_or_renew(&operation, &input)
        .await
        .expect("takeover of an expired lock must succeed");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    let successor = &result.locks[0];
    assert_ne!(successor.fence, predecessor.fence);

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "lock.taken_over");
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(
        decoded.ordinal,
        u64::try_from(successor.fence).expect("fence fits u64"),
        "ordinal must be the successor's committed fence, not the predecessor's"
    );
    assert_eq!(decoded.identity, successor.ownership_token);
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn owner_release_and_admin_force_release_each_commit_their_pinned_kind() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();

    // -- normal, owner-initiated release --
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "wp119-release");
    let hash: [u8; 32] = rand::random();
    let held = acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;

    let cell_id = outbox_cell_id();
    let release_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: lock_owner.clone(),
        resources: vec![resource(hash, Some(held.ownership_token))],
        outbox_cell_id: Some(cell_id.clone()),
    };
    let release_op = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        release_binding(&release_input).expect("valid release binding"),
    )
    .await;
    let released = coordinator
        .release(&release_op, &release_input)
        .await
        .expect("owner release must succeed");
    assert_eq!(released.outcome, DomainOutcome::Applied);
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "lock.released");
    assert_eq!(row.cell_id, cell_id);
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(decoded.identity, held.ownership_token);

    // -- dark administrative force release, a fresh repository/lock --
    let (repository_id, branch_id) = create_repository(&store).await;
    let target = owner("https://issuer.example", "wp119-force-target");
    let admin = owner("https://issuer.example", "wp119-force-admin");
    let hash: [u8; 32] = rand::random();
    let held = acquire_one(&store, &target, &repository_id, &branch_id, hash, None).await;

    let force_cell_id = outbox_cell_id();
    let force_input = ForceReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        target_owner: target,
        acting_owner: admin.clone(),
        resources: vec![resource(hash, Some(held.ownership_token))],
        outbox_cell_id: Some(force_cell_id.clone()),
    };
    let force_op = prepare_bound_operation(
        &store,
        &admin,
        &repository_id,
        &branch_id,
        force_release_binding(&force_input).expect("valid force-release binding"),
    )
    .await;
    let forced = coordinator
        .force_release(&force_op, &force_input)
        .await
        .expect("admin force release must succeed");
    assert_eq!(forced.outcome, DomainOutcome::Applied);
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );
    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(row.event_kind, "lock.force_released");
    assert_eq!(row.cell_id, force_cell_id);
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(decoded.identity, held.ownership_token);
}

/// CR-032 classifies "Expired-row cleanup that changes no logical ownership"
/// as emitting no row, and neither `cleanup_exact` nor the lease/backfill
/// bootstrap calls that arm finite leases accept an `outbox_cell_id` at all --
/// there is no caller-reachable way to make either append one.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn cleanup_and_lease_bootstrap_paths_never_append_an_outbox_row() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;

    // Lease/backfill bootstrap: arms finite leases and reconciles legacy rows,
    // touching schema-state and backfill bookkeeping only, never `lore_locks`
    // through the fenced batch path.
    coordinator
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("empty backfill");
    coordinator
        .enable_fencing_for_component_fixture(true)
        .await
        .expect("enable finite leases in test fixture");
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0,
        "lease/backfill bootstrap must not touch the outbox"
    );

    // An expired row, cleaned up: no ownership change, no event.
    let lock_owner = owner("https://issuer.example", "wp119-cleanup");
    let hash: [u8; 32] = rand::random();
    let expired = acquire_one(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        hash,
        Some(Duration::from_millis(40)),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(90)).await;
    let cleaned = coordinator
        .cleanup_exact(
            &repository_id,
            &branch_id,
            &hash,
            expired.repository_lock_generation,
            expired.branch_lock_generation,
            expired.fence,
        )
        .await
        .expect("cleanup of the expired row");
    assert!(
        cleaned,
        "the expired row must be logically absent and cleaned up"
    );

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0,
        "cleanup_exact changes no logical ownership and must append nothing"
    );
}

/// A decisive rejection commits a receipt and returns before any lock
/// mutation, structurally through `commit_rejection`, which never sees the
/// caller's `outbox_cell_id` at all. Every case below supplies one anyway, so
/// a future regression that threaded it through would still be caught.
/// Covers all four `LockRejection` variants a rejection can carry (not
/// `AdmissionRejected`, which never reaches `commit_rejection`).
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn every_lock_rejection_kind_leaves_the_outbox_empty() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let owner_a = owner("https://issuer.example", "wp119-rej-a");
    let owner_b = owner("https://issuer.example", "wp119-rej-b");
    let hash: [u8; 32] = rand::random();
    // Held for the resource's side effect (a currently owned row for the
    // ForeignOwner/AuthorityMismatch cases below), not for its own fields.
    let _held = acquire_one(&store, &owner_a, &repository_id, &branch_id, hash, None).await;

    // ForeignOwner: a different owner tries to acquire/renew a currently held
    // resource.
    let mut foreign_input = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(hash, None)],
        None,
    );
    foreign_input.outbox_cell_id = Some(outbox_cell_id());
    let foreign_op = prepare_bound_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&foreign_input).expect("valid binding"),
    )
    .await;
    let foreign_result = coordinator
        .acquire_or_renew(&foreign_op, &foreign_input)
        .await
        .expect("foreign acquire result");
    assert_rejection(&foreign_result, LockRejection::ForeignOwner);

    // AuthorityMismatch: the true owner renews with the wrong token.
    let mut mismatch_input = acquire_input(
        &repository_id,
        &branch_id,
        owner_a.clone(),
        vec![resource(hash, Some(rand::random()))],
        None,
    );
    mismatch_input.outbox_cell_id = Some(outbox_cell_id());
    let mismatch_op = prepare_bound_operation(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&mismatch_input).expect("valid binding"),
    )
    .await;
    let mismatch_result = coordinator
        .acquire_or_renew(&mismatch_op, &mismatch_input)
        .await
        .expect("wrong-token renew result");
    assert_rejection(&mismatch_result, LockRejection::AuthorityMismatch);

    // NotFound: releasing a resource with no current row.
    let missing_hash: [u8; 32] = rand::random();
    let not_found_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: owner_a.clone(),
        resources: vec![resource(missing_hash, Some(rand::random()))],
        outbox_cell_id: Some(outbox_cell_id()),
    };
    let not_found_op = prepare_bound_operation(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        release_binding(&not_found_input).expect("valid binding"),
    )
    .await;
    let not_found_result = coordinator
        .release(&not_found_op, &not_found_input)
        .await
        .expect("release of an absent resource");
    assert_rejection(&not_found_result, LockRejection::NotFound);

    // NamespaceMismatch: a repository that was never created.
    let absent_repository_id: [u8; 16] = rand::random();
    let absent_branch_id: [u8; 16] = rand::random();
    let mut namespace_input = acquire_input(
        &absent_repository_id,
        &absent_branch_id,
        owner_a.clone(),
        vec![resource(rand::random(), None)],
        None,
    );
    namespace_input.outbox_cell_id = Some(outbox_cell_id());
    let namespace_op = prepare_bound_operation(
        &store,
        &owner_a,
        &absent_repository_id,
        &absent_branch_id,
        acquire_or_renew_binding(&namespace_input).expect("valid binding"),
    )
    .await;
    let namespace_result = coordinator
        .acquire_or_renew(&namespace_op, &namespace_input)
        .await
        .expect("acquire against an absent repository");
    assert_rejection(&namespace_result, LockRejection::NamespaceMismatch);

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0,
        "no rejection above may leave a row on the held resource's repository"
    );
    assert_eq!(
        outbox_row_count_for_repository(&db, &absent_repository_id).await,
        0,
        "the NamespaceMismatch case must not leave a row keyed on the absent repository either"
    );
}

/// A receipt replay (an exact retry of an already-committed operation)
/// returns the original result without re-running the mutation, so it must
/// not append a second event even when the retry supplies its own
/// `outbox_cell_id`.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn a_replayed_receipt_appends_no_second_row() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "wp119-replay");
    let hash: [u8; 32] = rand::random();
    let cell_id = outbox_cell_id();

    let mut input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner.clone(),
        vec![resource(hash, None)],
        None,
    );
    input.outbox_cell_id = Some(cell_id.clone());
    let operation = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("valid binding"),
    )
    .await;
    let first = coordinator
        .acquire_or_renew(&operation, &input)
        .await
        .expect("first acquire must succeed");
    assert_eq!(first.outcome, DomainOutcome::Applied);
    assert!(!first.replayed);
    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1
    );

    // The exact same prepared operation (same receipt key/binding/token),
    // resubmitted with the same input, must replay rather than re-mutate.
    let second = coordinator
        .acquire_or_renew(&operation, &input)
        .await
        .expect("replayed acquire must succeed");
    assert!(
        second.replayed,
        "an exact retry must be reported as replayed"
    );
    assert_eq!(second.outcome, first.outcome);

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        1,
        "a replayed receipt must not append a second event"
    );
}

/// An empty-resource release commits `empty-release-v1` and returns before
/// any fence is drawn or any resource examined, so it must append nothing
/// even with an `outbox_cell_id` supplied.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn an_empty_resource_release_appends_no_row() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "wp119-empty-release");

    let input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: lock_owner.clone(),
        resources: Vec::new(),
        outbox_cell_id: Some(outbox_cell_id()),
    };
    let operation = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        release_binding(&input).expect("valid empty-release binding"),
    )
    .await;
    let result = coordinator
        .release(&operation, &input)
        .await
        .expect("empty release must succeed");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    assert_eq!(result.locks.len(), 0);

    assert_eq!(
        outbox_row_count_for_repository(&db, &repository_id).await,
        0,
        "an empty-resource release must append nothing"
    );
}

/// A token-bearing batch where at least one resource is still current and
/// owned by the caller, and another of the caller's OWN resources has fallen
/// out of currency (here, via a namespace generation bump, not lease
/// expiry -- leases are off in production, so the generation path is the
/// realistic one), classifies as `lock.renewed`, not `lock.acquired`. Only a
/// row current and owned by somebody else drives `lock.taken_over`.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn a_mixed_batch_of_the_callers_own_current_and_stale_generation_rows_is_a_renewal() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "wp119-mixed-batch");
    let stays_current_hash: [u8; 32] = rand::random();
    let goes_stale_hash: [u8; 32] = rand::random();

    // Both resources acquired by the same owner, before the generation bump.
    let goes_stale = acquire_one(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        goes_stale_hash,
        None,
    )
    .await;

    // Bump the repository's lock generation through a real production write
    // (begin_obliterate), making every row acquired before it logically
    // stale without touching any row's `expires_at`.
    let obliterate_operation = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "begin_obliterate",
    )
    .await;
    let obliterate = store
        .begin_obliterate(&obliterate_operation, &repository_id, None)
        .await
        .expect("begin real repository obliteration");
    assert_eq!(obliterate.outcome, DomainOutcome::Applied);

    // A fresh acquire of the still-current-generation resource, after the
    // bump, by the same owner: this row is current at request time.
    let stays_current = acquire_one(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        stays_current_hash,
        None,
    )
    .await;

    let cell_id = outbox_cell_id();
    let mut input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner.clone(),
        vec![
            resource(stays_current_hash, Some(stays_current.ownership_token)),
            resource(goes_stale_hash, Some(goes_stale.ownership_token)),
        ],
        None,
    );
    input.outbox_cell_id = Some(cell_id.clone());
    let operation = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("valid mixed-batch binding"),
    )
    .await;
    let result = coordinator
        .acquire_or_renew(&operation, &input)
        .await
        .expect("mixed-currency batch by the same owner must succeed");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    assert_eq!(result.locks.len(), 2);

    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(
        row.event_kind, "lock.renewed",
        "a batch with at least one current row and no foreign row is a renewal, even when \
         another of the caller's own rows went stale from a generation bump"
    );
}

/// `lock.taken_over` fires when the existing row is not current because the
/// namespace's lock generation moved past it (a real `begin_obliterate`
/// bump), not only because a lease expired. This is the production-relevant
/// path, since finite leases stay off until WP-120.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn a_stale_generation_row_held_by_a_different_owner_is_a_takeover() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let db = client(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let owner_a = owner("https://issuer.example", "wp119-gen-predecessor");
    let owner_b = owner("https://issuer.example", "wp119-gen-successor");
    let hash: [u8; 32] = rand::random();

    let predecessor = acquire_one(&store, &owner_a, &repository_id, &branch_id, hash, None).await;

    let obliterate_operation = prepare_operation(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        "begin_obliterate",
    )
    .await;
    let obliterate = store
        .begin_obliterate(&obliterate_operation, &repository_id, None)
        .await
        .expect("begin real repository obliteration");
    assert_eq!(obliterate.outcome, DomainOutcome::Applied);

    let cell_id = outbox_cell_id();
    let mut input = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(hash, None)],
        None,
    );
    input.outbox_cell_id = Some(cell_id.clone());
    let operation = prepare_bound_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("valid generation-takeover binding"),
    )
    .await;
    let result = coordinator
        .acquire_or_renew(&operation, &input)
        .await
        .expect("takeover of a stale-generation foreign row must succeed");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    let successor = &result.locks[0];
    assert_ne!(successor.fence, predecessor.fence);
    assert!(
        successor.repository_lock_generation > predecessor.repository_lock_generation,
        "test fixture sanity: the successor must actually observe the bumped generation"
    );

    let row = one_outbox_row_for_repository(&db, &repository_id).await;
    assert_eq!(
        row.event_kind, "lock.taken_over",
        "a foreign row made non-current by a generation bump is a takeover, not an acquire"
    );
    let decoded = AggregateVersion::decode(&row.aggregate_version).expect("decode");
    assert_eq!(decoded.identity, successor.ownership_token);
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn two_coordinators_racing_one_resource_choose_exactly_one_owner_pair() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store_a = store(&url).await;
    let store_b = store(&url).await;
    let (repository_id, branch_id) = create_repository(&store_a).await;
    let owner_a = owner("https://issuer-a.example", "shared-subject");
    let owner_b = owner("https://issuer-b.example", "shared-subject");
    let hash: [u8; 32] = rand::random();
    let input_a = acquire_input(
        &repository_id,
        &branch_id,
        owner_a.clone(),
        vec![resource(hash, None)],
        None,
    );
    let input_b = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(hash, None)],
        None,
    );
    let operation_a = prepare_bound_operation(
        &store_a,
        &owner_a,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input_a).expect("race A binding"),
    )
    .await;
    let operation_b = prepare_bound_operation(
        &store_b,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input_b).expect("race B binding"),
    )
    .await;
    let coordinator_a = store_a.lock_coordinator();
    let coordinator_b = store_b.lock_coordinator();

    let (a, b) = tokio::join!(
        coordinator_a.acquire_or_renew(&operation_a, &input_a),
        coordinator_b.acquire_or_renew(&operation_b, &input_b),
    );
    let a = a.expect("first race result");
    let b = b.expect("second race result");
    assert!(
        matches!(
            (a.rejection, b.rejection),
            (None, Some(LockRejection::ForeignOwner)) | (Some(LockRejection::ForeignOwner), None)
        ),
        "exactly one contender must apply: a={a:?}, b={b:?}"
    );
    let rows = store_a
        .lock_coordinator()
        .query(&repository_id, Some(&branch_id), None)
        .await
        .expect("query race winner");
    assert_eq!(rows.len(), 1);
    assert!(rows[0].owner == owner_a || rows[0].owner == owner_b);
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn racing_batches_are_all_or_nothing() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store_a = store(&url).await;
    let store_b = store(&url).await;
    let (repository_id, branch_id) = create_repository(&store_a).await;
    let owner_a = owner("https://issuer-a.example", "batch-a");
    let owner_b = owner("https://issuer-b.example", "batch-b");
    let common: [u8; 32] = rand::random();
    let only_a: [u8; 32] = rand::random();
    let only_b: [u8; 32] = rand::random();
    let input_a = acquire_input(
        &repository_id,
        &branch_id,
        owner_a.clone(),
        vec![resource(only_a, None), resource(common, None)],
        None,
    );
    let input_b = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(common, None), resource(only_b, None)],
        None,
    );
    let operation_a = prepare_bound_operation(
        &store_a,
        &owner_a,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input_a).expect("batch A binding"),
    )
    .await;
    let operation_b = prepare_bound_operation(
        &store_b,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input_b).expect("batch B binding"),
    )
    .await;
    let coordinator_a = store_a.lock_coordinator();
    let coordinator_b = store_b.lock_coordinator();

    let (a, b) = tokio::join!(
        coordinator_a.acquire_or_renew(&operation_a, &input_a),
        coordinator_b.acquire_or_renew(&operation_b, &input_b),
    );
    let a = a.expect("batch A result");
    let b = b.expect("batch B result");
    assert_eq!(
        usize::from(a.rejection.is_none()) + usize::from(b.rejection.is_none()),
        1
    );
    let rows = store_a
        .lock_coordinator()
        .query(&repository_id, Some(&branch_id), None)
        .await
        .expect("query batch result");
    assert_eq!(
        rows.len(),
        2,
        "a losing batch must publish zero rows: {rows:?}"
    );
    let hashes = rows
        .iter()
        .map(|row| row.resource_hash.as_slice())
        .collect::<Vec<_>>();
    assert!(
        (hashes.contains(&common.as_slice())
            && hashes.contains(&only_a.as_slice())
            && rows.iter().all(|row| row.owner == owner_a))
            || (hashes.contains(&common.as_slice())
                && hashes.contains(&only_b.as_slice())
                && rows.iter().all(|row| row.owner == owner_b)),
        "rows must be one whole winning batch: {rows:?}"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn same_subject_under_different_issuers_is_foreign_for_every_owner_operation() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let owner_a = owner("https://issuer-a.example", "same-subject");
    let owner_b = owner("https://issuer-b.example", "same-subject");
    let hash: [u8; 32] = rand::random();
    let held = acquire_one(&store, &owner_a, &repository_id, &branch_id, hash, None).await;

    let foreign_acquire_input = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(hash, None)],
        None,
    );
    let acquire_op = prepare_bound_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&foreign_acquire_input).expect("foreign acquire binding"),
    )
    .await;
    let acquire = coordinator
        .acquire_or_renew(&acquire_op, &foreign_acquire_input)
        .await
        .expect("foreign acquire result");
    assert_rejection(&acquire, LockRejection::ForeignOwner);

    let renew_input = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(hash, Some(held.ownership_token))],
        None,
    );
    let renew_op = prepare_bound_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&renew_input).expect("foreign renew binding"),
    )
    .await;
    let renew = coordinator
        .acquire_or_renew(&renew_op, &renew_input)
        .await
        .expect("foreign renew result");
    assert_rejection(&renew, LockRejection::ForeignOwner);

    let release_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: owner_b.clone(),
        resources: vec![resource(hash, Some(held.ownership_token))],
        outbox_cell_id: None,
    };
    let release_op = prepare_bound_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        release_binding(&release_input).expect("foreign release binding"),
    )
    .await;
    let release = coordinator
        .release(&release_op, &release_input)
        .await
        .expect("foreign release result");
    assert_rejection(&release, LockRejection::AuthorityMismatch);

    let visible_a = coordinator
        .query(&repository_id, Some(&branch_id), Some(&owner_a))
        .await
        .expect("query owner A");
    let visible_b = coordinator
        .query(&repository_id, Some(&branch_id), Some(&owner_b))
        .await
        .expect("query owner B");
    assert_eq!((visible_a.len(), visible_b.len()), (1, 0));
    let push_foreign = coordinator
        .query(&repository_id, Some(&branch_id), None)
        .await
        .expect("query push authority")
        .into_iter()
        .any(|lock| lock.owner != owner_b);
    assert!(
        push_foreign,
        "same subject under a different issuer must remain foreign at push preflight"
    );
    assert_eq!(
        coordinator
            .status(&repository_id, &branch_id, &hash)
            .await
            .expect("status")
            .expect("lock remains")
            .owner,
        owner_a
    );

    let replay_hash: [u8; 32] = rand::random();
    let replay_input = acquire_input(
        &repository_id,
        &branch_id,
        owner_b.clone(),
        vec![resource(replay_hash, None)],
        None,
    );
    let replay_operation = prepare_bound_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&replay_input).expect("replay binding"),
    )
    .await;
    let first = coordinator
        .acquire_or_renew(&replay_operation, &replay_input)
        .await
        .expect("first replay-shaped acquire");
    let replay = coordinator
        .acquire_or_renew(&replay_operation, &replay_input)
        .await
        .expect("exact acquire replay");
    assert!(replay.replayed);
    assert_eq!(replay.outcome, first.outcome);
    assert_eq!(
        replay.locks, first.locks,
        "replay must retain token and fence"
    );

    let mut mismatched_input = replay_input.clone();
    mismatched_input.resources[0]
        .description
        .push_str("-changed");
    let mismatch = coordinator
        .acquire_or_renew(&replay_operation, &mismatched_input)
        .await;
    assert!(matches!(mismatch, Err(DomainError::InvalidInput(_))));
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn acquire_result_boundary_is_rejected_before_lock_mutation() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let direct = client(&url).await;
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "receipt-boundary");

    let mut last_valid = None;
    let first_oversized = (1..=512)
        .find_map(|count| {
            let resources = (0..count)
                .map(|index| {
                    let mut hash = [0u8; 32];
                    hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    resource(hash, None)
                })
                .collect();
            let input = acquire_input(
                &repository_id,
                &branch_id,
                lock_owner.clone(),
                resources,
                None,
            );
            match acquire_or_renew_binding(&input) {
                Ok(_) => {
                    last_valid = Some(input);
                    None
                }
                Err(DomainError::InvalidInput(message))
                    if message.contains("public-result limit") =>
                {
                    Some(input)
                }
                Err(error) => panic!("unexpected boundary validation error: {error}"),
            }
        })
        .expect("the frozen 4096-byte receipt limit must bound a batch below 512 resources");
    let last_valid = last_valid.expect("at least one lock result must fit");

    let operation = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&last_valid).expect("boundary-sized valid binding"),
    )
    .await;
    let committed = coordinator
        .acquire_or_renew(&operation, &last_valid)
        .await
        .expect("largest discovered valid batch commits");
    assert_eq!(committed.locks.len(), last_valid.resources.len());
    let replay = coordinator
        .acquire_or_renew(&operation, &last_valid)
        .await
        .expect("boundary-sized result replays");
    assert!(replay.replayed);
    assert_eq!(replay.locks, committed.locks);

    let before: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_locks WHERE repository = $1 AND branch = $2",
            &[&repository_id.as_slice(), &branch_id.as_slice()],
        )
        .await
        .expect("count boundary locks")
        .get(0);
    let oversized = coordinator
        .acquire_or_renew(&operation, &first_oversized)
        .await;
    assert!(
        matches!(oversized, Err(DomainError::InvalidInput(message)) if message.contains("public-result limit"))
    );
    let after: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_locks WHERE repository = $1 AND branch = $2",
            &[&repository_id.as_slice(), &branch_id.as_slice()],
        )
        .await
        .expect("recount boundary locks")
        .get(0);
    assert_eq!(after, before, "oversized intent must not mutate lock rows");

    let sub_millisecond = AcquireOrRenewInput {
        lease_duration: Some(Duration::from_nanos(999_999)),
        resources: vec![resource(rand::random(), None)],
        ..last_valid.clone()
    };
    assert!(matches!(
        acquire_or_renew_binding(&sub_millisecond),
        Err(DomainError::InvalidInput(message)) if message.contains("1ms")
    ));

    let whole_millisecond = AcquireOrRenewInput {
        lease_duration: Some(Duration::from_millis(1)),
        resources: vec![resource(rand::random(), None)],
        ..last_valid.clone()
    };
    acquire_or_renew_binding(&whole_millisecond)
        .expect("whole-millisecond lease has an exact binding");
    let fractional_millisecond = AcquireOrRenewInput {
        lease_duration: Some(Duration::from_millis(1) + Duration::from_nanos(1)),
        resources: vec![resource(rand::random(), None)],
        ..last_valid
    };
    assert!(matches!(
        acquire_or_renew_binding(&fractional_millisecond),
        Err(DomainError::InvalidInput(message)) if message.contains("whole milliseconds")
    ));
    let fractional_result = coordinator
        .acquire_or_renew(&operation, &fractional_millisecond)
        .await;
    assert!(matches!(
        fractional_result,
        Err(DomainError::InvalidInput(message)) if message.contains("whole milliseconds")
    ));
    let after_fractional: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_locks WHERE repository = $1 AND branch = $2",
            &[&repository_id.as_slice(), &branch_id.as_slice()],
        )
        .await
        .expect("recount after fractional lease rejection")
        .get(0);
    assert_eq!(
        after_fractional, before,
        "fractional-millisecond lease must be rejected before lock mutation"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn stale_release_renew_force_and_cleanup_cannot_touch_a_successor() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    coordinator
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("empty backfill");
    coordinator
        .enable_fencing_for_component_fixture(true)
        .await
        .expect("enable finite leases in test fixture");
    let owner_a = owner("https://issuer.example", "lease-a");
    let owner_b = owner("https://issuer.example", "lease-b");
    let admin = owner("https://issuer.example", "admin");
    let hash: [u8; 32] = rand::random();
    let predecessor = acquire_one(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        hash,
        Some(Duration::from_millis(40)),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(90)).await;
    let successor = acquire_one(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        hash,
        Some(Duration::from_secs(2)),
    )
    .await;

    let stale_release_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: owner_a.clone(),
        resources: vec![resource(hash, Some(predecessor.ownership_token))],
        outbox_cell_id: None,
    };
    let stale_release_op = prepare_bound_operation(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        release_binding(&stale_release_input).expect("stale release binding"),
    )
    .await;
    let stale_release = coordinator
        .release(&stale_release_op, &stale_release_input)
        .await
        .expect("stale release result");
    assert_rejection(&stale_release, LockRejection::AuthorityMismatch);

    let stale_renew_input = acquire_input(
        &repository_id,
        &branch_id,
        owner_a.clone(),
        vec![resource(hash, Some(predecessor.ownership_token))],
        Some(Duration::from_secs(2)),
    );
    let stale_renew_op = prepare_bound_operation(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&stale_renew_input).expect("stale renew binding"),
    )
    .await;
    let stale_renew = coordinator
        .acquire_or_renew(&stale_renew_op, &stale_renew_input)
        .await
        .expect("stale renew result");
    assert_rejection(&stale_renew, LockRejection::ForeignOwner);

    let stale_force_input = ForceReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        target_owner: owner_a,
        acting_owner: admin.clone(),
        resources: vec![resource(hash, Some(predecessor.ownership_token))],
        outbox_cell_id: None,
    };
    let stale_force_op = prepare_bound_operation(
        &store,
        &admin,
        &repository_id,
        &branch_id,
        force_release_binding(&stale_force_input).expect("stale force binding"),
    )
    .await;
    let stale_force = coordinator
        .force_release(&stale_force_op, &stale_force_input)
        .await
        .expect("stale force result");
    assert_rejection(&stale_force, LockRejection::AuthorityMismatch);

    assert!(
        !coordinator
            .cleanup_exact(
                &repository_id,
                &branch_id,
                &hash,
                predecessor.repository_lock_generation,
                predecessor.branch_lock_generation,
                predecessor.fence
            )
            .await
            .expect("stale cleanup")
    );
    assert_eq!(
        coordinator
            .status(&repository_id, &branch_id, &hash)
            .await
            .expect("status")
            .expect("successor remains"),
        successor
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn obsolete_repository_and_branch_generations_make_rows_logically_absent() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "generation-owner");
    let hash: [u8; 32] = rand::random();
    let old = acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;
    let initial_witness = coordinator
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("initial lock witness");

    let obliterate_operation = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "begin_obliterate",
    )
    .await;
    let obliterate = store
        .begin_obliterate(&obliterate_operation, &repository_id, None)
        .await
        .expect("begin real repository obliteration");
    assert_eq!(obliterate.outcome, DomainOutcome::Applied);
    let obliterate_witness = coordinator
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("post-obliteration lock witness");
    assert!(
        obliterate_witness.repository_lock_generation > initial_witness.repository_lock_generation,
        "the real begin_obliterate generation update must propagate to the namespace"
    );
    assert!(
        coordinator
            .status(&repository_id, &branch_id, &hash)
            .await
            .expect("status after repository invalidation")
            .is_none()
    );
    let replacement =
        acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;
    assert!(replacement.fence > old.fence);

    let delete_operation = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "repository_delete",
    )
    .await;
    let deleted = store
        .repository_delete(
            &delete_operation,
            &RepositoryDeleteInput {
                repository_id: repository_id.to_vec(),
                expected_generation: obliterate.repository_generation,
                delete_proof: rand::random::<[u8; 32]>().to_vec(),
                projection: Vec::new(),
                events: Vec::new(),
            },
        )
        .await
        .expect("tombstone real repository and branch rows");
    assert_eq!(deleted.outcome, DomainOutcome::Applied);
    let tombstone_witness = coordinator
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("post-tombstone lock witness");
    assert!(
        tombstone_witness.repository_lock_generation
            > obliterate_witness.repository_lock_generation,
        "the real repository tombstone must propagate its lock generation"
    );
    assert!(
        tombstone_witness.branch_lock_generation > obliterate_witness.branch_lock_generation,
        "the branch tombstone written by repository_delete must propagate its lock generation"
    );
    assert!(
        coordinator
            .status(&repository_id, &branch_id, &hash)
            .await
            .expect("status after branch invalidation")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn lease_clock_is_captured_after_the_namespace_lock_wait() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    coordinator
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("empty backfill");
    coordinator
        .enable_fencing_for_component_fixture(true)
        .await
        .expect("enable finite leases");
    let lock_owner = owner("https://issuer.example", "wait-owner");
    let hash: [u8; 32] = rand::random();
    let input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner,
        vec![resource(hash, None)],
        Some(Duration::from_millis(250)),
    );
    let operation = prepare_bound_operation(
        &store,
        &input.owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("wait binding"),
    )
    .await;

    let mut blocker = client(&url).await;
    let blocker_tx = blocker
        .transaction()
        .await
        .expect("begin namespace blocker");
    blocker_tx.query_one("SELECT 1 FROM lore_domain_lock_namespaces WHERE repository_id=$1 AND branch_id=$2 FOR UPDATE", &[&repository_id.as_slice(), &branch_id.as_slice()]).await.expect("lock namespace row");
    let acquire = coordinator.acquire_or_renew(&operation, &input);
    let release = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let released_at = SystemTime::now();
        blocker_tx
            .commit()
            .await
            .expect("release namespace blocker");
        released_at
    };
    let (result, released_at) = tokio::join!(acquire, release);
    let lock = result
        .expect("acquire after wait")
        .locks
        .into_iter()
        .next()
        .expect("acquired row");
    let expires_at = lock.expires_at.expect("finite expiry");
    assert!(
        expires_at
            .duration_since(released_at)
            .expect("expiry follows release")
            >= Duration::from_millis(180),
        "queue time shortened the lease: released={released_at:?}, expires={expires_at:?}"
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn lock_operations_reuse_cr029_receipt_bands_markers_and_quota() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "receipt-owner");
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("receipt clock");
    assert_eq!(NORMAL_FUTURE_SKEW, Duration::from_secs(300));
    assert_eq!(RECEIPT_BEARING_FUTURE_HORIZON, Duration::from_secs(86_400));
    assert_eq!(STALE_HORIZON, Duration::from_secs(31_536_000));
    assert_eq!(MARKER_SAFETY_EPSILON, Duration::from_secs(86_400));
    assert_eq!(
        (
            FUTURE_REJECT_QUOTA_RETAINED_MAX,
            FUTURE_REJECT_QUOTA_HOURLY_MAX
        ),
        (1_024, 64)
    );

    let scope = lock_tenant_scope_key(&repository_id, &branch_id).expect("lock scope");
    let future_key = ReceiptKey {
        verified_issuer: lock_owner.verified_issuer.clone(),
        authenticated_subject: lock_owner.authenticated_subject.clone(),
        tenant_scope_key: scope.clone(),
        operation_id: uuid_v7_at(
            clock
                .checked_add(NORMAL_FUTURE_SKEW + Duration::from_secs(1))
                .expect("future time"),
        ),
    };
    let future = store
        .domain_operation_prepare(&future_key, &binding("lock.future.receipt"), None)
        .await
        .expect("receipt-bearing future");
    assert!(
        matches!(future, PrepareResult::Committed(DomainOutcome::NotApplied { ref reason, .. }) if reason == UUID_TIME_OUT_OF_RANGE_V1)
    );

    let marker_key = ReceiptKey {
        verified_issuer: lock_owner.verified_issuer,
        authenticated_subject: lock_owner.authenticated_subject,
        tenant_scope_key: scope,
        operation_id: uuid_v7_at(
            clock
                .checked_add(RECEIPT_BEARING_FUTURE_HORIZON + Duration::from_secs(1))
                .expect("beyond horizon"),
        ),
    };
    let marker_binding = binding("lock.future.marker");
    let marker = store
        .domain_operation_prepare(&marker_key, &marker_binding, None)
        .await
        .expect("future marker");
    assert!(
        matches!(marker, PrepareResult::Committed(DomainOutcome::NotApplied { ref reason, .. }) if reason == UUID_FUTURE_HORIZON_EXCEEDED_V1)
    );
    let counts = direct.query_one("SELECT (SELECT count(*)::bigint FROM lore_domain_operation_future_rejections WHERE tenant_scope_key=$1), (SELECT count(*)::bigint FROM lore_domain_operation_future_reject_quotas WHERE tenant_scope_key=$1)", &[&marker_key.tenant_scope_key]).await.expect("shared marker/quota counts");
    assert_eq!((counts.get::<_, i64>(0), counts.get::<_, i64>(1)), (1, 1));
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn lock_mutations_take_the_receipt_before_domain_and_namespace_rows() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "order-owner");
    let hash: [u8; 32] = rand::random();
    let input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner,
        vec![resource(hash, None)],
        None,
    );
    let operation = prepare_bound_operation(
        &store,
        &input.owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input).expect("lock-order binding"),
    )
    .await;

    let mut blocker = client(&url).await;
    let blocker_tx = blocker
        .transaction()
        .await
        .expect("begin repository blocker");
    blocker_tx
        .query_one(
            "SELECT 1 FROM lore_domain_repositories WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id.as_slice()],
        )
        .await
        .expect("lock repository row");
    let receipt_key = operation.key.clone();
    let coordinator_task =
        lore_base::lore_spawn!(
            async move { coordinator.acquire_or_renew(&operation, &input).await }
        );
    let probe = client(&url).await;
    let mut observed_receipt_lock = false;
    for _ in 0..100 {
        let result = probe.execute("SELECT 1 FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE NOWAIT", &[&receipt_key.verified_issuer, &receipt_key.authenticated_subject, &receipt_key.tenant_scope_key, &receipt_key.operation_id.as_bytes().as_slice()]).await;
        if result
            .as_ref()
            .err()
            .and_then(tokio_postgres::Error::as_db_error)
            .is_some_and(|error| error.code().code() == "55P03")
        {
            observed_receipt_lock = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        observed_receipt_lock,
        "the receipt row must be locked while the mutation waits on repository"
    );
    blocker_tx
        .commit()
        .await
        .expect("release repository blocker");
    let applied = coordinator_task
        .await
        .expect("join acquire")
        .expect("ordered acquire");
    assert_eq!(applied.outcome, DomainOutcome::Applied);
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn missing_and_repeated_release_are_not_found_and_empty_list_is_ok() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "release-owner");
    let missing_hash: [u8; 32] = rand::random();
    let missing_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: lock_owner.clone(),
        resources: vec![resource(missing_hash, Some(rand::random()))],
        outbox_cell_id: None,
    };
    let missing_op = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        release_binding(&missing_input).expect("missing release binding"),
    )
    .await;
    let missing = coordinator
        .release(&missing_op, &missing_input)
        .await
        .expect("missing release");
    assert_rejection(&missing, LockRejection::NotFound);

    let hash: [u8; 32] = rand::random();
    let held = acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;
    let release_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: lock_owner.clone(),
        resources: vec![resource(hash, Some(held.ownership_token))],
        outbox_cell_id: None,
    };
    let release_op = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        release_binding(&release_input).expect("first release binding"),
    )
    .await;
    let released = coordinator
        .release(&release_op, &release_input)
        .await
        .expect("first release");
    assert_eq!(released.outcome, DomainOutcome::Applied);
    let repeat_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: lock_owner.clone(),
        resources: vec![resource(hash, Some(held.ownership_token))],
        outbox_cell_id: None,
    };
    let repeat_op = prepare_bound_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        release_binding(&repeat_input).expect("repeat release binding"),
    )
    .await;
    let repeated = coordinator
        .release(&repeat_op, &repeat_input)
        .await
        .expect("repeated release");
    assert_rejection(&repeated, LockRejection::NotFound);

    let empty_owner = owner("https://issuer.example", "empty");
    let empty_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: empty_owner.clone(),
        resources: Vec::new(),
        outbox_cell_id: None,
    };
    let empty_operation = prepare_bound_operation(
        &store,
        &empty_owner,
        &repository_id,
        &branch_id,
        release_binding(&empty_input).expect("empty release binding"),
    )
    .await;
    let empty_result = coordinator
        .release(&empty_operation, &empty_input)
        .await
        .expect("empty release");
    assert_eq!(empty_result.outcome, DomainOutcome::Applied);
    assert!(empty_result.locks.is_empty());
    assert_eq!(empty_result.rejection, None);
}

/// The batched fenced Status path, at the batch size it exists for.
///
/// `status_many` replaced a per-resource loop that took one pool checkout per
/// entry off the shared CR-029 domain pool (INV-EE P1-8). One query for the
/// whole batch only pays off at N > 1, and only that size exercises the
/// `unnest` join's ordering and duplicate semantics — the two things its
/// contract actually promises.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn batched_status_orders_by_stored_key_and_repeats_a_duplicate_request() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "status-batch");

    // Sorted so the expected order is a property of the stored key rather than
    // of whichever random hash happened to come out larger.
    let mut hashes: [[u8; 32]; 2] = [rand::random(), rand::random()];
    hashes.sort();
    let [lower, higher] = hashes;
    let absent: [u8; 32] = rand::random();
    // Acquired HIGH first, so insertion order is the reverse of key order and
    // the expected result below cannot be satisfied by insertion order alone.
    for hash in [higher, lower] {
        acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;
    }

    // Requested high-first, with `lower` twice and one resource that was never
    // locked: the result must be key-ordered, must repeat the duplicate, and
    // must simply omit the absent one.
    let requested: Vec<(&[u8], &[u8])> = vec![
        (&branch_id, &higher),
        (&branch_id, &lower),
        (&branch_id, &absent),
        (&branch_id, &lower),
    ];
    let found = coordinator
        .status_many(&repository_id, &requested)
        .await
        .expect("batched status");
    assert_eq!(
        found
            .iter()
            .map(|lock| lock.resource_hash.as_slice())
            .collect::<Vec<_>>(),
        vec![lower.as_slice(), lower.as_slice(), higher.as_slice()],
        "the batch must be ordered by stored key, and a duplicate request must repeat"
    );
    assert!(found.iter().all(|lock| lock.owner == lock_owner));

    // A resource on a branch of a different repository must not leak in.
    let (other_repository, other_branch) = create_repository(&store).await;
    let other_hash: [u8; 32] = rand::random();
    acquire_one(
        &store,
        &lock_owner,
        &other_repository,
        &other_branch,
        other_hash,
        None,
    )
    .await;
    let cross: Vec<(&[u8], &[u8])> = vec![(&other_branch, &other_hash)];
    assert!(
        coordinator
            .status_many(&repository_id, &cross)
            .await
            .expect("cross-repository batched status")
            .is_empty(),
        "a batch is scoped to its repository, not to the branch alone"
    );

    // `status` is now a thin wrapper over the batch path.
    assert_eq!(
        coordinator
            .status(&repository_id, &branch_id, &higher)
            .await
            .expect("single status")
            .expect("the lock is current")
            .resource_hash,
        higher.to_vec()
    );
    assert!(
        coordinator
            .status(&repository_id, &branch_id, &absent)
            .await
            .expect("single status for an absent resource")
            .is_none()
    );
}

/// Absent SCHEMA-117 is a routing answer; half-present SCHEMA-117 is damage.
///
/// A cell the migration never reached must boot on the legacy route (INV-EE
/// P0-1). But a *partially* installed schema is a state no migration and no
/// permitted rollback produces, so routing around it would silently return an
/// armed cell to the subject-only legacy comparison. The two must not answer
/// the same.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn an_absent_schema_routes_legacy_but_a_partial_one_is_refused() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    // Deliberately not the bootstrapping `store()` helper: this case needs the
    // state a booting cell actually finds before any migration has run.
    let bare = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store without SCHEMA-117");
    let readiness = bare
        .lock_coordinator()
        .readiness()
        .await
        .expect("an unmigrated database must answer, not error");
    assert!(!readiness.provisioned && !readiness.fencing_enabled);

    bare.lock_coordinator()
        .bootstrap()
        .await
        .expect("install SCHEMA-117");
    let direct = client(&url).await;

    // One relation missing: partially installed.
    direct
        .execute("DROP TABLE lore_domain_lock_backfill_quarantine", &[])
        .await
        .expect("drop one fenced relation");
    assert!(
        matches!(
            bare.lock_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a half-installed SCHEMA-117 must be refused, never reported as unprovisioned"
    );

    // All relations present, singleton state row gone: also incomplete.
    bare.lock_coordinator()
        .bootstrap()
        .await
        .expect("reinstall SCHEMA-117");
    direct
        .execute(
            "DELETE FROM lore_domain_lock_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("remove the singleton schema-state row");
    assert!(
        matches!(
            bare.lock_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a missing singleton schema-state row must be refused, not reported as unprovisioned"
    );

    // `lore_locks` is part of SCHEMA-117, not something the legacy plugin adds
    // later, so a provisioned schema without it is damage too. Reading around
    // it would count zero unfenced rows and prove headroom from the namespaces
    // alone, arming a cell whose first lock read takes 42P01 (INV-EE R2-P2-1).
    bare.lock_coordinator()
        .bootstrap()
        .await
        .expect("reinstall SCHEMA-117 and its schema-state row");
    bare.lock_coordinator()
        .readiness()
        .await
        .expect("a fully installed schema must answer");
    direct
        .execute("DROP TABLE lore_locks CASCADE", &[])
        .await
        .expect("drop the lock table");
    assert!(
        matches!(
            bare.lock_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a provisioned schema missing lore_locks must be refused, never reported as ready"
    );
}

/// The cutover entry point must refuse while the state it produces is
/// unserviceable.
///
/// This case is a tripwire on `PUBLIC_MUTATION_CONTRACT_AVAILABLE`: it fails
/// the day a follow-on lane flips that constant, which is when its first
/// assertion stops describing the contract and must be rewritten rather than
/// deleted.
///
/// WP-120 (`9a6d5e0`) built the whole SERVER half: fenced `Lock`/`Unlock`/
/// `AdminLock`/`ForceUnlock` are served (`lore-server/src/grpc/lock_service.rs`)
/// and issue/consume a per-resource ownership token. But `lore/src` cannot
/// yet keep or present that token, so arming today would still strand every
/// fenced lock unreleasable by its owner (INV-EE P0-2) -- a follow-on lane
/// builds the client half and flips the constant in that change
/// (`PUBLIC_MUTATION_CONTRACT_AVAILABLE` stays `false` in
/// `lore-postgres/src/domain/locks/schema.rs` until then). The refusal is
/// the WP-120 gate and nothing else: the same evidence arms successfully
/// through the fixture path.
#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn arming_is_refused_until_the_public_mutation_contract_exists() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let (_repository_id, _branch_id) = create_repository(&store).await;
    coordinator
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("complete empty backfill");

    let refused = coordinator.enable_fencing(false).await;
    match refused {
        Err(DomainError::NotReady(reason)) => assert_eq!(
            reason,
            lore_postgres::domain::locks::schema::PUBLIC_MUTATION_CONTRACT_MISSING,
            "the refusal must name the missing WP-120 contract, not an evidence gap"
        ),
        other => panic!("arming must be refused before WP-120, got {other:?}"),
    }
    assert!(
        !coordinator
            .readiness()
            .await
            .expect("readiness after a refused arming")
            .fencing_enabled,
        "a refused arming must leave the cell on the legacy route"
    );

    // Every evidence check passed; only the contract gate refused.
    coordinator
        .enable_fencing_for_component_fixture(false)
        .await
        .expect("the same evidence must arm through the fixture path");
    assert!(
        coordinator
            .readiness()
            .await
            .expect("readiness after fixture arming")
            .fencing_enabled
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn readiness_rejects_each_missing_fenced_precondition() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let direct = client(&url).await;
    let (repository_id, branch_id) = create_repository(&store).await;
    let initial = coordinator.readiness().await.expect("initial readiness");
    assert!(!initial.fencing_enabled && !initial.sequence_headroom && initial.backfill_state == 0);
    coordinator
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("complete empty backfill");
    coordinator
        .enable_fencing_for_component_fixture(false)
        .await
        .expect("enable fencing");
    let ready = coordinator.readiness().await.expect("ready projection");
    assert!(
        ready.fencing_enabled
            && ready.same_database
            && ready.sequence_headroom
            && ready.quarantined_rows == 0
            && ready.unfenced_rows == 0
    );

    let late_legacy_hash: [u8; 32] = rand::random();
    direct.execute("INSERT INTO lore_locks(repository,branch,hash,owner,description,locked_at) VALUES($1,$2,$3,'legacy-late','late legacy row',0)", &[&repository_id.as_slice(), &branch_id.as_slice(), &late_legacy_hash.as_slice()]).await.expect("insert late legacy row");
    assert_eq!(
        coordinator
            .readiness()
            .await
            .expect("late legacy readiness")
            .unfenced_rows,
        1
    );
    assert!(
        coordinator
            .status(&repository_id, &branch_id, &late_legacy_hash)
            .await
            .expect("late legacy status must not panic")
            .is_none()
    );
    assert!(matches!(
        coordinator
            .enable_fencing_for_component_fixture(false)
            .await,
        Err(DomainError::NotReady(_))
    ));
    direct
        .execute(
            "DELETE FROM lore_locks WHERE repository=$1 AND branch=$2 AND hash=$3",
            &[
                &repository_id.as_slice(),
                &branch_id.as_slice(),
                &late_legacy_hash.as_slice(),
            ],
        )
        .await
        .expect("remove late legacy row");

    let identity: String = direct
        .query_one(
            "SELECT database_identity FROM lore_domain_lock_schema_state WHERE id=1",
            &[],
        )
        .await
        .expect("read identity")
        .get(0);
    direct.execute("UPDATE lore_domain_lock_schema_state SET database_identity='wrong-database' WHERE id=1", &[]).await.expect("poison identity");
    assert!(
        !coordinator
            .readiness()
            .await
            .expect("identity mismatch readiness")
            .same_database
    );
    direct
        .execute(
            "UPDATE lore_domain_lock_schema_state SET database_identity=$1 WHERE id=1",
            &[&identity],
        )
        .await
        .expect("restore identity");
    direct.execute("INSERT INTO lore_domain_lock_backfill_quarantine(repository_id,branch_id,resource_hash,legacy_subject,reason) VALUES($1,$2,$3,'ambiguous','test')", &[&repository_id.as_slice(), &branch_id.as_slice(), &rand::random::<[u8;32]>().as_slice()]).await.expect("insert quarantine");
    assert_eq!(
        coordinator
            .readiness()
            .await
            .expect("quarantine readiness")
            .quarantined_rows,
        1
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn same_database_identity_accepts_only_the_domain_authority_database() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    create_repository(&store).await;
    store
        .lock_coordinator()
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("complete fresh-cell backfill");
    let state_marker: String = direct
        .query_one(
            "SELECT database_identity FROM lore_domain_lock_schema_state WHERE id=1",
            &[],
        )
        .await
        .expect("read lock database identity")
        .get(0);
    assert_eq!(state_marker, store.identity().as_marker());
    direct
        .execute(
            "UPDATE lore_domain_lock_schema_state SET database_identity=$1 WHERE id=1",
            &[&format!("{}:other", store.identity().as_marker())],
        )
        .await
        .expect("poison lock database identity");
    let readiness = store
        .lock_coordinator()
        .readiness()
        .await
        .expect("read mismatched identity");
    assert!(!readiness.same_database);
    let enabled = store
        .lock_coordinator()
        .enable_fencing_for_component_fixture(false)
        .await;
    assert!(matches!(enabled, Err(DomainError::NotReady(_))));
}

async fn insert_legacy_lock(
    direct: &Client,
    repository_id: &[u8; 16],
    branch_id: &[u8; 16],
    hash: &[u8; 32],
    subject: &str,
) {
    direct.execute("INSERT INTO lore_locks(repository,branch,hash,owner,description,locked_at) VALUES($1,$2,$3,$4,'legacy',extract(epoch FROM clock_timestamp())::bigint*1000)", &[&repository_id.as_slice(), &branch_id.as_slice(), &hash.as_slice(), &subject]).await.expect("insert legacy lock");
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn lock_backfill_is_restartable_and_quarantines_ambiguous_legacy_owners() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let direct = client(&url).await;
    let (repository_id, branch_id) = create_repository(&store).await;
    let mapped_hash: [u8; 32] = rand::random();
    let unresolved_hash: [u8; 32] = rand::random();
    insert_legacy_lock(
        &direct,
        &repository_id,
        &branch_id,
        &mapped_hash,
        "mapped-subject",
    )
    .await;
    insert_legacy_lock(
        &direct,
        &repository_id,
        &branch_id,
        &unresolved_hash,
        "unresolved-subject",
    )
    .await;
    let mut mapping = BTreeMap::from([(
        "mapped-subject".to_owned(),
        "https://issuer.example".to_owned(),
    )]);
    let first = coordinator
        .backfill(&mapping)
        .await
        .expect("first backfill pass");
    assert_eq!(
        (first.converted, first.quarantined, first.complete),
        (1, 1, false)
    );
    mapping.insert(
        "unresolved-subject".to_owned(),
        "https://issuer.example".to_owned(),
    );
    let resumed = coordinator
        .backfill(&mapping)
        .await
        .expect("resumed backfill");
    assert_eq!(
        (resumed.converted, resumed.quarantined, resumed.complete),
        (1, 0, true)
    );
    let replay = coordinator
        .backfill(&mapping)
        .await
        .expect("backfill replay");
    assert_eq!(
        (replay.converted, replay.quarantined, replay.complete),
        (0, 0, true)
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn backfill_proves_fence_sequence_headroom_before_cutover() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let direct = client(&url).await;
    let (repository_id, branch_id) = create_repository(&store).await;
    let hash: [u8; 32] = rand::random();
    insert_legacy_lock(&direct, &repository_id, &branch_id, &hash, "legacy-owner").await;
    direct
        .execute("SELECT setval('lore_domain_lock_fence_seq', 1, true)", &[])
        .await
        .expect("rewind disposable sequence");
    let mapping = BTreeMap::from([(
        "legacy-owner".to_owned(),
        "https://issuer.example".to_owned(),
    )]);
    let report = coordinator
        .backfill(&mapping)
        .await
        .expect("backfill with headroom");
    assert!(report.complete);
    let row = direct.query_one("SELECT sequence_headroom_fence, (SELECT max(fence) FROM lore_locks), nextval('lore_domain_lock_fence_seq') FROM lore_domain_lock_schema_state WHERE id=1", &[]).await.expect("read headroom evidence");
    let evidence: i64 = row.get(0);
    let max_fence: i64 = row.get(1);
    let next: i64 = row.get(2);
    assert!(
        evidence > max_fence && next > max_fence,
        "evidence={evidence}, max={max_fence}, next={next}"
    );
    assert!(
        coordinator
            .readiness()
            .await
            .expect("headroom readiness")
            .sequence_headroom
    );
}

#[tokio::test]
#[ignore = "run with tests/run-lock-fencing-live.ps1"]
async fn push_witness_capture_and_transaction_local_revalidation_detect_change() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.lock_coordinator();
    let mut direct = client(&url).await;
    let (repository_id, branch_id) = create_repository(&store).await;
    let before = coordinator
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("capture witness without CR-019");
    let lock_owner = owner("https://issuer.example", "witness-owner");
    acquire_one(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        rand::random(),
        None,
    )
    .await;
    let after = coordinator
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("capture changed witness");
    assert_ne!(before, after);

    let tx = direct
        .transaction()
        .await
        .expect("begin final-push-shaped transaction");
    let mut sequence = LockSequence::new();
    sequence
        .enter(LockClass::OperationReceipt)
        .expect("receipt position");
    lock_repository(&tx, &mut sequence, &repository_id)
        .await
        .expect("lock repository")
        .expect("repository row");
    lock_branch(&tx, &mut sequence, &repository_id, &branch_id)
        .await
        .expect("lock branch")
        .expect("branch row");
    let stale = PostgresLockCoordinator::revalidate_push_witness(
        &tx,
        &mut sequence,
        &repository_id,
        &branch_id,
        &before,
    )
    .await;
    assert!(matches!(stale, Err(DomainError::Contention(_))));
    tx.rollback().await.expect("rollback stale final push");

    let tx = direct
        .transaction()
        .await
        .expect("begin matching final push");
    let mut sequence = LockSequence::new();
    sequence
        .enter(LockClass::OperationReceipt)
        .expect("receipt position");
    lock_repository(&tx, &mut sequence, &repository_id)
        .await
        .expect("lock repository")
        .expect("repository row");
    lock_branch(&tx, &mut sequence, &repository_id, &branch_id)
        .await
        .expect("lock branch")
        .expect("branch row");
    PostgresLockCoordinator::revalidate_push_witness(
        &tx,
        &mut sequence,
        &repository_id,
        &branch_id,
        &after,
    )
    .await
    .expect("matching witness");
    tx.rollback().await.expect("rollback matching final push");
}

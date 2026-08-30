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
use lore_postgres::domain::locks::lock_tenant_scope_key;
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
    let binding = binding(method);
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
        event: None,
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
        event: None,
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
    let operation = prepare_operation(
        store,
        lock_owner,
        repository_id,
        branch_id,
        "lock.acquire_or_renew",
    )
    .await;
    let result = store
        .lock_coordinator()
        .acquire_or_renew(
            &operation,
            &acquire_input(
                repository_id,
                branch_id,
                lock_owner.clone(),
                vec![resource(hash, None)],
                lease,
            ),
        )
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
    let operation_a = prepare_operation(
        &store_a,
        &owner_a,
        &repository_id,
        &branch_id,
        "lock.race.a",
    )
    .await;
    let operation_b = prepare_operation(
        &store_b,
        &owner_b,
        &repository_id,
        &branch_id,
        "lock.race.b",
    )
    .await;
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
    let operation_a = prepare_operation(
        &store_a,
        &owner_a,
        &repository_id,
        &branch_id,
        "lock.batch.a",
    )
    .await;
    let operation_b = prepare_operation(
        &store_b,
        &owner_b,
        &repository_id,
        &branch_id,
        "lock.batch.b",
    )
    .await;
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

    let acquire_op = prepare_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        "lock.foreign.acquire",
    )
    .await;
    let acquire = coordinator
        .acquire_or_renew(
            &acquire_op,
            &acquire_input(
                &repository_id,
                &branch_id,
                owner_b.clone(),
                vec![resource(hash, None)],
                None,
            ),
        )
        .await
        .expect("foreign acquire result");
    assert_rejection(&acquire, LockRejection::ForeignOwner);

    let renew_op = prepare_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        "lock.foreign.renew",
    )
    .await;
    let renew = coordinator
        .acquire_or_renew(
            &renew_op,
            &acquire_input(
                &repository_id,
                &branch_id,
                owner_b.clone(),
                vec![resource(hash, Some(held.ownership_token))],
                None,
            ),
        )
        .await
        .expect("foreign renew result");
    assert_rejection(&renew, LockRejection::ForeignOwner);

    let release_op = prepare_operation(
        &store,
        &owner_b,
        &repository_id,
        &branch_id,
        "lock.foreign.release",
    )
    .await;
    let release = coordinator
        .release(
            &release_op,
            &ReleaseInput {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                owner: owner_b.clone(),
                resources: vec![resource(hash, Some(held.ownership_token))],
                event: None,
            },
        )
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
        .enable_fencing(true)
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

    let stale_release_op = prepare_operation(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        "lock.stale.release",
    )
    .await;
    let stale_release = coordinator
        .release(
            &stale_release_op,
            &ReleaseInput {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                owner: owner_a.clone(),
                resources: vec![resource(hash, Some(predecessor.ownership_token))],
                event: None,
            },
        )
        .await
        .expect("stale release result");
    assert_rejection(&stale_release, LockRejection::AuthorityMismatch);

    let stale_renew_op = prepare_operation(
        &store,
        &owner_a,
        &repository_id,
        &branch_id,
        "lock.stale.renew",
    )
    .await;
    let stale_renew = coordinator
        .acquire_or_renew(
            &stale_renew_op,
            &acquire_input(
                &repository_id,
                &branch_id,
                owner_a.clone(),
                vec![resource(hash, Some(predecessor.ownership_token))],
                Some(Duration::from_secs(2)),
            ),
        )
        .await
        .expect("stale renew result");
    assert_rejection(&stale_renew, LockRejection::ForeignOwner);

    let stale_force_op = prepare_operation(
        &store,
        &admin,
        &repository_id,
        &branch_id,
        "lock.stale.force",
    )
    .await;
    let stale_force = coordinator
        .force_release(
            &stale_force_op,
            &ForceReleaseInput {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                target_owner: owner_a,
                acting_owner: admin,
                resources: vec![resource(hash, Some(predecessor.ownership_token))],
                event: None,
            },
        )
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
    let direct = client(&url).await;
    let (repository_id, branch_id) = create_repository(&store).await;
    let lock_owner = owner("https://issuer.example", "generation-owner");
    let hash: [u8; 32] = rand::random();
    let old = acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;

    direct.execute("UPDATE lore_domain_repositories SET lock_generation = lock_generation + 1 WHERE repository_id = $1", &[&repository_id.as_slice()]).await.expect("invalidate repository lock generation");
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

    direct.execute("UPDATE lore_domain_branches SET lock_generation = lock_generation + 1 WHERE repository_id = $1 AND branch_id = $2", &[&repository_id.as_slice(), &branch_id.as_slice()]).await.expect("invalidate branch lock generation");
    assert!(
        coordinator
            .status(&repository_id, &branch_id, &hash)
            .await
            .expect("status after branch invalidation")
            .is_none()
    );
    let newest = acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;
    assert!(newest.fence > replacement.fence);
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
        .enable_fencing(true)
        .await
        .expect("enable finite leases");
    let lock_owner = owner("https://issuer.example", "wait-owner");
    let hash: [u8; 32] = rand::random();
    let operation = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "lock.wait.clock",
    )
    .await;
    let input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner,
        vec![resource(hash, None)],
        Some(Duration::from_millis(250)),
    );

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
    let operation = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "lock.order",
    )
    .await;
    let input = acquire_input(
        &repository_id,
        &branch_id,
        lock_owner,
        vec![resource(hash, None)],
        None,
    );

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
    let missing_op = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "lock.release.missing",
    )
    .await;
    let missing = coordinator
        .release(
            &missing_op,
            &ReleaseInput {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                owner: lock_owner.clone(),
                resources: vec![resource(missing_hash, Some(rand::random()))],
                event: None,
            },
        )
        .await
        .expect("missing release");
    assert_rejection(&missing, LockRejection::NotFound);

    let hash: [u8; 32] = rand::random();
    let held = acquire_one(&store, &lock_owner, &repository_id, &branch_id, hash, None).await;
    let release_op = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "lock.release.first",
    )
    .await;
    let released = coordinator
        .release(
            &release_op,
            &ReleaseInput {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                owner: lock_owner.clone(),
                resources: vec![resource(hash, Some(held.ownership_token))],
                event: None,
            },
        )
        .await
        .expect("first release");
    assert_eq!(released.outcome, DomainOutcome::Applied);
    let repeat_op = prepare_operation(
        &store,
        &lock_owner,
        &repository_id,
        &branch_id,
        "lock.release.repeat",
    )
    .await;
    let repeated = coordinator
        .release(
            &repeat_op,
            &ReleaseInput {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                owner: lock_owner,
                resources: vec![resource(hash, Some(held.ownership_token))],
                event: None,
            },
        )
        .await
        .expect("repeated release");
    assert_rejection(&repeated, LockRejection::NotFound);

    let empty_result = coordinator
        .release(
            &prepare_operation(
                &store,
                &owner("https://issuer.example", "empty"),
                &repository_id,
                &branch_id,
                "lock.release.empty",
            )
            .await,
            &ReleaseInput {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                owner: owner("https://issuer.example", "empty"),
                resources: Vec::new(),
                event: None,
            },
        )
        .await
        .expect("empty release");
    assert_eq!(empty_result.outcome, DomainOutcome::Applied);
    assert!(empty_result.locks.is_empty());
    assert_eq!(empty_result.rejection, None);
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
        .enable_fencing(false)
        .await
        .expect("enable fencing");
    let ready = coordinator.readiness().await.expect("ready projection");
    assert!(
        ready.fencing_enabled
            && ready.same_database
            && ready.sequence_headroom
            && ready.quarantined_rows == 0
    );

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
    let enabled = store.lock_coordinator().enable_fencing(false).await;
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

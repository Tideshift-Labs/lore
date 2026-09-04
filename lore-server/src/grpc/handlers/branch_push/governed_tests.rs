// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! INV-EE P1-5: `enforce_fenced_locks`, `GovernedPushCommit::publish`, and both
//! governed branches of `push_with_governance` had zero direct coverage.
//! CR-030's required-test list names the push leg explicitly; this module
//! closes that gap.
//!
//! Section A/C (`#[ignore]`, live Postgres): `enforce_fenced_locks`'s owner-pair
//! comparison and rename-aware path mapping, plus P1-7's missing-namespace-row
//! fail-closed regression. Section B (no Postgres): `GovernedPushCommit::publish`
//! and P1-10's CAS-retry-suppression change, driven through a scriptable
//! [`crate::domain::test_support::ScriptedDomainStore`].

use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::CAS_MISMATCH_V1;
use lore_postgres::domain::coordinator::CommittedOrdinal;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MutationResult;
use lore_postgres::domain::coordinator::NOT_FOUND_V1;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::TOMBSTONED_V1;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::locks::AcquireOrRenewInput;
use lore_postgres::domain::locks::LockResourceInput;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_postgres::domain::locks::acquire_or_renew_binding;
use lore_postgres::domain::locks::lock_tenant_scope_key;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_revision::branch;
use lore_revision::lock::util::assemble_resource_for_path;
use lore_revision::node::Node;
use lore_revision::node::NodeFlags;
use lore_revision::node::ROOT_NODE;
use lore_revision::state;
use lore_storage::hash::hash_string;
use rand::random;
use tokio_postgres::Client;
use tonic::Code;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

use super::*;
use crate::domain::DomainContext;
use crate::domain::test_support::ScriptedDomainStore;
use crate::grpc::get_write_token;
use crate::grpc::server::RevisionListAcceleration;

// ---------------------------------------------------------------------------
// Shared fixtures — live Postgres (Section A/C)
// ---------------------------------------------------------------------------

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

fn uuid_v7_at(time: std::time::SystemTime) -> Uuid {
    let elapsed = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
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

async fn direct_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
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
            "https://issuer.example/p1-5/create/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:p1-5-governed-test".to_owned(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id: uuid_v7_at(clock),
    };
    let binding = OperationBinding {
        method: "repository_create".to_owned(),
        scope: rand::random::<[u8; 16]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    };
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
        name: format!("p1-5-governed-{:016x}", rand::random::<u64>()),
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

/// Connects, bootstraps SCHEMA-117, and creates one repository/branch/lock
/// namespace fixture through the real domain rail.
async fn fenced_fixture(url: &str) -> (PostgresDomainStore, [u8; 16], [u8; 16]) {
    let store = PostgresDomainStore::connect(url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store");
    store
        .lock_coordinator()
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-117 fixture");
    let (repository_id, branch_id) = create_repository(&store).await;
    (store, repository_id, branch_id)
}

async fn acquire_lock_on_path(
    store: &PostgresDomainStore,
    lock_owner: &VerifiedLockOwner,
    repository_id: &[u8; 16],
    branch_id_bytes: &[u8; 16],
    branch: BranchId,
    path: &str,
) {
    let hash = assemble_resource_for_path(path, branch).hash;
    let input = AcquireOrRenewInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id_bytes.to_vec(),
        owner: lock_owner.clone(),
        acting_owner: None,
        resources: vec![LockResourceInput {
            resource_hash: hash.as_ref().to_vec(),
            description: path.to_owned(),
            expected_ownership_token: None,
        }],
        lease_duration: None,
        event: None,
    };
    let operation = prepare_bound_operation(
        store,
        lock_owner,
        repository_id,
        branch_id_bytes,
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
}

// ---------------------------------------------------------------------------
// Shared fixtures — local Lore-revision content (both sections)
// ---------------------------------------------------------------------------

async fn create_root_branch_with_id(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    name: &str,
) {
    let write_token = get_write_token();
    branch::create(
        repository.clone(),
        &write_token,
        branch,
        name,
        branch::default_category(),
        "test-creator",
        1,
        vec![],
        false,
        false,
    )
    .await
    .expect("create root branch with an explicit id");
}

/// Serializes a revision with a single root-level File node at `file_name`.
/// Does NOT push/advance the branch tip.
async fn serialize_file_revision(
    repository: &Arc<RepositoryContext>,
    parent: Hash,
    revision_number: u64,
    file_name: &str,
) -> Hash {
    serialize_file_revision_with_context(
        repository,
        parent,
        revision_number,
        file_name,
        Context::default(),
    )
    .await
}

/// Like `serialize_file_revision`, but lets the caller pin the file's
/// `address.context` — the node identity `detect_and_coalesce_moves` matches
/// on to fold an add/delete pair into a rename (mirrors
/// `push_lock_guard.rs`'s `rename_counts_both_endpoints_as_changed` fixture).
async fn serialize_file_revision_with_context(
    repository: &Arc<RepositoryContext>,
    parent: Hash,
    revision_number: u64,
    file_name: &str,
    context: Context,
) -> Hash {
    let write_token = get_write_token();
    let state = state::State::new();
    state.set_parent_self(parent);
    state.set_revision_number(revision_number);
    let node = Node {
        flags: NodeFlags::File.bits(),
        name_hash: hash_string(file_name),
        address: Address {
            hash: Hash::default(),
            context,
        },
        ..Default::default()
    };
    state
        .node_add(repository.clone(), ROOT_NODE, node, file_name)
        .await
        .expect("node_add");
    state
        .serialize(repository.clone(), &write_token)
        .await
        .expect("serialize state")
}

async fn serialize_empty_revision(
    repository: &Arc<RepositoryContext>,
    parent: Hash,
    revision_number: u64,
) -> Hash {
    let write_token = get_write_token();
    let state = state::State::new();
    state.set_parent_self(parent);
    state.set_revision_number(revision_number);
    state
        .serialize(repository.clone(), &write_token)
        .await
        .expect("serialize state")
}

/// Pushes `revision` to `branch`, actually advancing the branch tip.
async fn push_revision(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    revision: Hash,
) -> Hash {
    super::push(
        repository.clone(),
        branch,
        revision,
        true,
        true,
        false,
        branch::DEFAULT_HISTORY_STEP_SIZE,
        RevisionListAcceleration::default(),
    )
    .await
    .expect("push")
    .revision
}

/// Builds a fresh in-memory repository, creates `branch` with the given id,
/// and pushes an empty root revision so `load_latest` resolves to a real
/// prior tip. Returns the repository context, the pushed root hash, and the
/// execution the caller must keep scoping further local-store work under.
async fn local_repository_with_root(
    repository: RepositoryId,
    branch: BranchId,
) -> (
    Arc<RepositoryContext>,
    Hash,
    Arc<lore_revision::interface::ExecutionContext>,
) {
    let (immutable_store, mutable_store, execution) = crate::store::test_store_create()
        .await
        .expect("create local test stores");
    let repository_ctx = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository,
    ));
    let root = Box::pin(LORE_CONTEXT.scope(execution.clone(), {
        let repository_ctx = repository_ctx.clone();
        async move {
            create_root_branch_with_id(&repository_ctx, branch, "main").await;
            let root = serialize_empty_revision(&repository_ctx, Hash::default(), 1).await;
            push_revision(&repository_ctx, branch, root).await
        }
    }))
    .await;
    (repository_ctx, root, execution)
}

// ---------------------------------------------------------------------------
// Section A — `enforce_fenced_locks` (live Postgres, `#[ignore]`)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn enforce_fenced_locks_blocks_a_push_from_a_foreign_owner_pair() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let (store, repository_id, branch_id) = fenced_fixture(&url).await;
    let coordinator = store.lock_coordinator();
    let repository = RepositoryId::from(repository_id);
    let branch = BranchId::from(branch_id);
    let path = "hero.uasset";

    // Held by (issuer-A, mallory); pushed by (issuer-A, alice) — different
    // subject under the same issuer, the ordinary foreign-owner case.
    let holder = owner("https://issuer-a.example", "mallory");
    let pusher = owner("https://issuer-a.example", "alice");
    acquire_lock_on_path(&store, &holder, &repository_id, &branch_id, branch, path).await;

    let (repository_ctx, root, execution) = local_repository_with_root(repository, branch).await;

    let error = Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let new_revision = serialize_file_revision(&repository_ctx, root, 2, path).await;
            super::enforce_fenced_locks(&coordinator, repository_ctx, branch, new_revision, &pusher)
                .await
        }
    }))
    .await
    .expect_err("a foreign owner pair must block the push");

    assert_eq!(error.code(), Code::PermissionDenied);
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn enforce_fenced_locks_does_not_block_the_lock_holders_own_push() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let (store, repository_id, branch_id) = fenced_fixture(&url).await;
    let coordinator = store.lock_coordinator();
    let repository = RepositoryId::from(repository_id);
    let branch = BranchId::from(branch_id);
    let path = "hero.uasset";

    let holder = owner("https://issuer-a.example", "mallory");
    acquire_lock_on_path(&store, &holder, &repository_id, &branch_id, branch, path).await;

    let (repository_ctx, root, execution) = local_repository_with_root(repository, branch).await;

    Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let new_revision = serialize_file_revision(&repository_ctx, root, 2, path).await;
            super::enforce_fenced_locks(
                &coordinator,
                repository_ctx,
                branch,
                new_revision,
                &holder,
            )
            .await
            .expect("the lock holder's own push must not be blocked by their own lock");
        }
    }))
    .await;
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn enforce_fenced_locks_treats_same_subject_under_a_different_issuer_as_foreign() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let (store, repository_id, branch_id) = fenced_fixture(&url).await;
    let coordinator = store.lock_coordinator();
    let repository = RepositoryId::from(repository_id);
    let branch = BranchId::from(branch_id);
    let path = "hero.uasset";

    // CR-030's named discriminating case: the SAME subject under a
    // DIFFERENT issuer must still be foreign — this is the whole point of
    // comparing the (issuer, subject) pair rather than the subject alone
    // (the fail-open regression `push_lock_guard.rs` still carries).
    let holder = owner("https://issuer-a.example", "same-subject");
    let pusher = owner("https://issuer-b.example", "same-subject");
    acquire_lock_on_path(&store, &holder, &repository_id, &branch_id, branch, path).await;

    let (repository_ctx, root, execution) = local_repository_with_root(repository, branch).await;

    let error = Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let new_revision = serialize_file_revision(&repository_ctx, root, 2, path).await;
            super::enforce_fenced_locks(&coordinator, repository_ctx, branch, new_revision, &pusher)
                .await
        }
    }))
    .await
    .expect_err("the same subject under a different issuer must remain foreign at push preflight");

    assert_eq!(error.code(), Code::PermissionDenied);
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn enforce_fenced_locks_blocks_a_push_touching_the_locked_old_path_of_a_rename() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let (store, repository_id, branch_id) = fenced_fixture(&url).await;
    let coordinator = store.lock_coordinator();
    let repository = RepositoryId::from(repository_id);
    let branch = BranchId::from(branch_id);
    let old_path = "old.uasset";
    let new_path = "new.uasset";

    let holder = owner("https://issuer-a.example", "mallory");
    let pusher = owner("https://issuer-a.example", "alice");

    let (immutable_store, mutable_store, execution) = crate::store::test_store_create()
        .await
        .expect("create local test stores");
    let repository_ctx = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository,
    ));

    // Same non-zero node context at both paths is what folds an add+delete
    // pair into a rename (`NodeChange::from_path`).
    let file_context: Context = random();
    let root = Box::pin(LORE_CONTEXT.scope(execution.clone(), {
        let repository_ctx = repository_ctx.clone();
        async move {
            create_root_branch_with_id(&repository_ctx, branch, "main").await;
            let root = serialize_file_revision_with_context(
                &repository_ctx,
                Hash::default(),
                1,
                old_path,
                file_context,
            )
            .await;
            push_revision(&repository_ctx, branch, root).await
        }
    }))
    .await;

    // Lock is on the OLD path — the file that "disappears" from the tree but
    // must still be recognized as touched by the rename.
    acquire_lock_on_path(
        &store,
        &holder,
        &repository_id,
        &branch_id,
        branch,
        old_path,
    )
    .await;

    let error = Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let renamed = serialize_file_revision_with_context(
                &repository_ctx,
                root,
                2,
                new_path,
                file_context,
            )
            .await;
            super::enforce_fenced_locks(&coordinator, repository_ctx, branch, renamed, &pusher)
                .await
        }
    }))
    .await
    .expect_err("a lock on the rename's old path must still block the push");

    assert_eq!(error.code(), Code::PermissionDenied);
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn enforce_fenced_locks_does_not_block_a_foreign_lock_on_an_untouched_path() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let (store, repository_id, branch_id) = fenced_fixture(&url).await;
    let coordinator = store.lock_coordinator();
    let repository = RepositoryId::from(repository_id);
    let branch = BranchId::from(branch_id);

    let holder = owner("https://issuer-a.example", "mallory");
    let pusher = owner("https://issuer-a.example", "alice");
    acquire_lock_on_path(
        &store,
        &holder,
        &repository_id,
        &branch_id,
        branch,
        "unrelated.uasset",
    )
    .await;

    let (repository_ctx, root, execution) = local_repository_with_root(repository, branch).await;

    Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let new_revision =
                serialize_file_revision(&repository_ctx, root, 2, "hero.uasset").await;
            super::enforce_fenced_locks(
                &coordinator,
                repository_ctx,
                branch,
                new_revision,
                &pusher,
            )
            .await
            .expect("a foreign lock on an untouched path must not block the push");
        }
    }))
    .await;
}

// ---------------------------------------------------------------------------
// Section C — P1-7, missing lock namespace row (live Postgres, `#[ignore]`)
// ---------------------------------------------------------------------------

/// Pins the permanent-unpushability regression from INV-EE P1-7: a branch
/// whose `lore_domain_lock_namespaces` row is missing makes the push leg fail
/// closed forever, because `capture_push_witness` reports
/// `DomainError::NotReady` and there is no coordinator-side repair path (owed
/// to WP-120 or a dedicated maintenance slice — not built here).
///
/// The row is removed directly rather than by reproducing the exact
/// insert-order race that can also leave it absent (the after-insert trigger
/// silently inserting nothing when the repository row is unresolvable): the
/// assertion this test pins is about the *consequence* of the row being
/// absent, not about every way it can become absent.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn missing_lock_namespace_row_leaves_the_branch_permanently_unpushable() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let (store, repository_id, branch_id) = fenced_fixture(&url).await;
    let coordinator = store.lock_coordinator();

    let direct = direct_client(&url).await;
    direct
        .execute(
            "DELETE FROM lore_domain_lock_namespaces WHERE repository_id=$1 AND branch_id=$2",
            &[&repository_id.as_slice(), &branch_id.as_slice()],
        )
        .await
        .expect("remove the namespace row to simulate the unresolvable-repository race");

    let error = coordinator
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect_err("a missing namespace row must fail the push leg closed");
    assert!(
        matches!(error, DomainError::NotReady(_)),
        "expected DomainError::NotReady, got {error:?}"
    );

    let status = crate::grpc::map_domain_error_to_status(&error);
    assert_eq!(status.code(), Code::FailedPrecondition);
}

// ---------------------------------------------------------------------------
// Section B — `GovernedPushCommit::publish` and P1-10 (no Postgres)
// ---------------------------------------------------------------------------

fn dummy_operation() -> GovernedOperation {
    GovernedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "scripted-pusher".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id: Uuid::now_v7(),
        },
        binding: OperationBinding {
            method: "branch_push_commit".to_owned(),
            scope: vec![7; 16],
            fingerprint_version: 1,
            fingerprint: vec![8; 32],
            canonical_intent_digest: vec![9; 32],
        },
        prepare_token: [0u8; 32],
    }
}

fn build_governed(
    domain: Arc<DomainContext>,
    expected_latest_hash: Vec<u8>,
    lock_witness: PushLockWitness,
    owner: VerifiedLockOwner,
    repository_generation: i64,
    branch_generation: i64,
) -> GovernedPushCommit {
    GovernedPushCommit {
        domain,
        operation: dummy_operation(),
        repository_generation,
        branch_generation,
        expected_latest_hash,
        lock_witness,
        owner,
        branch_name: "main".to_owned(),
    }
}

fn scripted_witness() -> PushLockWitness {
    PushLockWitness {
        repository_lock_generation: 1,
        branch_lock_generation: 1,
        branch_lock_namespace_last_applied_fence: 0,
    }
}

fn scripted_owner() -> VerifiedLockOwner {
    owner("https://issuer.example", "pusher")
}

async fn local_repository_context() -> RepositoryContext {
    let (immutable_store, mutable_store, _execution) = crate::store::test_store_create()
        .await
        .expect("create local test stores");
    RepositoryContext::new_server_context(immutable_store, mutable_store, random::<RepositoryId>())
}

#[tokio::test]
async fn publish_returns_aborted_and_never_calls_the_store_when_preflight_changed() {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult {
        outcome: DomainOutcome::Applied,
        repository_generation: Some(1),
        branch_generation: Some(1),
        observed_pointer: None,
    }));
    let domain = Arc::new(DomainContext::new(script.clone(), false));
    let governed = build_governed(
        domain,
        vec![0xAAu8; 32],
        scripted_witness(),
        scripted_owner(),
        1,
        1,
    );

    let repository = local_repository_context().await;
    let branch = random::<BranchId>();
    let actual_current_head = Hash::hash_buffer(b"preflight-changed-actual-current-head");
    let new_head = Hash::hash_buffer(b"preflight-changed-new-head");

    let error = governed
        .publish(&repository, branch, actual_current_head, new_head)
        .await
        .expect_err("a mismatched preflight must abort rather than reach the store");

    assert_eq!(error.code(), Code::Aborted);
    assert!(
        script.recorded_branch_push_commit_calls().is_empty(),
        "the store must never be called when the preflight guard rejects"
    );
}

#[tokio::test]
async fn publish_carries_the_witness_generations_and_hashes_into_the_commit_input() {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult {
        outcome: DomainOutcome::Applied,
        repository_generation: Some(9),
        branch_generation: Some(9),
        observed_pointer: None,
    }));
    let domain = Arc::new(DomainContext::new(script.clone(), false));
    let current_head = Hash::hash_buffer(b"witness-carriage-current-head");
    let new_head = Hash::hash_buffer(b"witness-carriage-new-head");
    let witness = PushLockWitness {
        repository_lock_generation: 11,
        branch_lock_generation: 13,
        branch_lock_namespace_last_applied_fence: 17,
    };
    let governed = build_governed(
        domain,
        current_head.as_ref().to_vec(),
        witness,
        scripted_owner(),
        3,
        5,
    );

    let repository = local_repository_context().await;
    let branch = random::<BranchId>();

    let applied = governed
        .publish(&repository, branch, current_head, new_head)
        .await
        .expect("an Applied outcome must succeed");
    assert_eq!(applied, new_head);

    let calls = script.recorded_branch_push_commit_calls();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.expected_repository_generation, 3);
    assert_eq!(call.expected_branch_generation, 5);
    assert_eq!(call.expected_repository_lock_generation, 11);
    assert_eq!(call.expected_branch_lock_generation, 13);
    assert_eq!(call.expected_branch_lock_namespace_last_applied_fence, 17);
    assert_eq!(call.expected_latest_hash, current_head.as_ref().to_vec());
    assert_eq!(call.new_latest_hash, new_head.as_ref().to_vec());
}

/// WP-116 review finding (blocking): every test above builds its `DomainContext`
/// via the two-argument `DomainContext::new`, which leaves `cell_id: None` --
/// so `publish`'s `event` match always took the `(None, _) => None` arm and the
/// entire outbox-producer wiring in this handler went unexecuted by any test,
/// including every test above this one. This is the first test in the tree
/// that configures a cell id and actually reaches the `(Some(cell_id), false)`
/// arm.
#[tokio::test]
async fn publish_with_a_configured_cell_id_and_an_advancing_head_builds_the_branch_pushed_event() {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult {
        outcome: DomainOutcome::Applied,
        repository_generation: Some(4),
        branch_generation: Some(6),
        observed_pointer: None,
    }));
    let domain =
        Arc::new(DomainContext::new(script.clone(), false).with_cell_id(Some("cell-a".to_owned())));
    let current_head = Hash::hash_buffer(b"cell-id-configured-current-head");
    let new_head = Hash::hash_buffer(b"cell-id-configured-new-head");
    let governed = build_governed(
        domain,
        current_head.as_ref().to_vec(),
        scripted_witness(),
        scripted_owner(),
        4,
        6,
    );

    let repository = local_repository_context().await;
    let branch = random::<BranchId>();

    let applied = governed
        .publish(&repository, branch, current_head, new_head)
        .await
        .expect("an Applied outcome must succeed");
    assert_eq!(applied, new_head);

    let calls = script.recorded_branch_push_commit_calls();
    assert_eq!(calls.len(), 1);
    let event = calls[0]
        .event
        .as_ref()
        .expect("a configured cell_id and an advancing head must build Some(event)");
    assert_eq!(event.cell_id, "cell-a");
    assert_eq!(event.event_kind, outbox_builders::BRANCH_PUSHED);
    assert_eq!(event.aggregate_kind, outbox_builders::AGGREGATE_BRANCH);
    assert_eq!(
        event.aggregate_id,
        branch.as_ref().to_vec(),
        "aggregate_id is the 16 raw branch-id bytes, per CR-032's second PIN-4 amendment \
         (2026-09-03) -- the branch name travels in the payload instead"
    );
    assert_eq!(event.aggregate_ordinal, CommittedOrdinal::BranchGeneration);
    assert_eq!(event.aggregate_identity, new_head.as_ref().to_vec());
    // The branch name (build_governed hardcodes "main") still travels, just
    // in the payload rather than aggregate_id.
    let payload_text = String::from_utf8(event.payload.clone()).expect("payload is UTF-8 JSON-ish");
    assert!(payload_text.contains("main"));
}

/// The second half of the C1 rule: a configured cell_id does not by itself
/// build an event on a current-head no-op. `publish`'s own match skips the
/// build in this case (`(Some(_), true) => None`) rather than building one and
/// relying on the coordinator to drop it -- the coordinator's
/// `branch.latest_hash == input.new_latest_hash` arm remains the only
/// suppression *authority* (proven at the coordinator level in
/// `lore-postgres/tests/domain_outbox_producers.rs`), but this proves the
/// handler-level build skip specifically, which that coordinator-level test
/// cannot: a `ScriptedDomainStore` never runs real coordinator logic, so this
/// is the only place `publish`'s own match arm is exercised.
#[tokio::test]
async fn publish_with_a_configured_cell_id_and_the_current_head_builds_no_event() {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult {
        outcome: DomainOutcome::Applied,
        repository_generation: Some(4),
        branch_generation: Some(6),
        observed_pointer: None,
    }));
    let domain =
        Arc::new(DomainContext::new(script.clone(), false).with_cell_id(Some("cell-a".to_owned())));
    let current_head = Hash::hash_buffer(b"cell-id-configured-noop-head");
    let governed = build_governed(
        domain,
        current_head.as_ref().to_vec(),
        scripted_witness(),
        scripted_owner(),
        4,
        6,
    );

    let repository = local_repository_context().await;
    let branch = random::<BranchId>();

    let applied = governed
        .publish(&repository, branch, current_head, current_head)
        .await
        .expect("a current-head push must still succeed");
    assert_eq!(applied, current_head);

    let calls = script.recorded_branch_push_commit_calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].event.is_none(),
        "a current-head push must build no event even with a configured cell_id"
    );
}

/// Runs `publish` once against a fresh scripted store that always returns
/// `NotApplied { reason, .. }`, with a matching preflight so the call reaches
/// the store.
async fn run_publish_with_reason(reason: &str) -> Result<Hash, Status> {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult::rejected(reason)));
    let domain = Arc::new(DomainContext::new(script, false));
    let current_head = Hash::hash_buffer(b"reason-mapping-current-head");
    let new_head = Hash::hash_buffer(b"reason-mapping-new-head");
    let governed = build_governed(
        domain,
        current_head.as_ref().to_vec(),
        scripted_witness(),
        scripted_owner(),
        1,
        1,
    );

    let repository = local_repository_context().await;
    let branch = random::<BranchId>();
    governed
        .publish(&repository, branch, current_head, new_head)
        .await
}

#[tokio::test]
async fn publish_maps_tombstoned_v1_to_not_found() {
    let status = run_publish_with_reason(TOMBSTONED_V1)
        .await
        .expect_err("TOMBSTONED_V1 must map to an error status");
    assert_eq!(status.code(), Code::NotFound);
}

#[tokio::test]
async fn publish_maps_not_found_v1_to_not_found() {
    let status = run_publish_with_reason(NOT_FOUND_V1)
        .await
        .expect_err("NOT_FOUND_V1 must map to an error status");
    assert_eq!(status.code(), Code::NotFound);
}

#[tokio::test]
async fn publish_maps_generation_mismatch_v1_to_aborted() {
    let status = run_publish_with_reason(GENERATION_MISMATCH_V1)
        .await
        .expect_err("GENERATION_MISMATCH_V1 must map to an error status");
    assert_eq!(status.code(), Code::Aborted);
}

#[tokio::test]
async fn publish_maps_cas_mismatch_v1_to_aborted() {
    let status = run_publish_with_reason(CAS_MISMATCH_V1)
        .await
        .expect_err("CAS_MISMATCH_V1 must map to an error status");
    assert_eq!(status.code(), Code::Aborted);
}

#[tokio::test]
async fn publish_maps_any_other_not_applied_reason_to_failed_precondition_carrying_the_reason() {
    let reason = "SOME_OTHER_REASON_V1";
    let status = run_publish_with_reason(reason)
        .await
        .expect_err("an unrecognized reason must still map to an error status");
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), reason);
}

// --- P1-10: governance disables the CAS retry loop ------------------------

#[tokio::test]
async fn idempotent_no_op_branch_surfaces_a_lost_cas_as_aborted_with_no_retry() {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult::rejected(
        CAS_MISMATCH_V1,
    )));
    let domain = Arc::new(DomainContext::new(script.clone(), false));

    let repository_id = random::<RepositoryId>();
    let branch_id = random::<BranchId>();
    let (repository_ctx, tip, execution) =
        local_repository_with_root(repository_id, branch_id).await;

    let error = Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let governed = build_governed(
                domain,
                tip.as_ref().to_vec(),
                scripted_witness(),
                scripted_owner(),
                1,
                1,
            );
            // `latest == current tip` drives the idempotent no-op branch,
            // which calls `publish(current_head, current_head)`.
            super::push_with_governance(
                repository_ctx,
                branch_id,
                tip,
                true,
                true,
                false,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                Some(&governed),
            )
            .await
        }
    }))
    .await
    .expect_err("a lost CAS under governance must surface as Aborted, not a transparent retry");

    assert_eq!(error.code(), Code::Aborted);
    assert_eq!(
        script.recorded_branch_push_commit_calls().len(),
        1,
        "governance must not retry a lost CAS"
    );
}

#[tokio::test]
async fn advancing_branch_surfaces_a_lost_cas_as_aborted_with_no_retry() {
    let script = Arc::new(ScriptedDomainStore::new(MutationResult::rejected(
        CAS_MISMATCH_V1,
    )));
    let domain = Arc::new(DomainContext::new(script.clone(), false));

    let repository_id = random::<RepositoryId>();
    let branch_id = random::<BranchId>();
    let (repository_ctx, tip, execution) =
        local_repository_with_root(repository_id, branch_id).await;

    let error = Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let next = serialize_file_revision(&repository_ctx, tip, 2, "hero.uasset").await;
            let governed = build_governed(
                domain,
                tip.as_ref().to_vec(),
                scripted_witness(),
                scripted_owner(),
                1,
                1,
            );
            // `latest != current tip`, a valid fast-forward: drives the main
            // loop, which calls `publish` at the publication boundary.
            super::push_with_governance(
                repository_ctx,
                branch_id,
                next,
                true,
                true,
                false,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                Some(&governed),
            )
            .await
        }
    }))
    .await
    .expect_err("a lost CAS under governance must surface as Aborted, not a transparent retry");

    assert_eq!(error.code(), Code::Aborted);
    assert_eq!(
        script.recorded_branch_push_commit_calls().len(),
        1,
        "governance must not retry a lost CAS"
    );
}

#[tokio::test]
async fn ungoverned_push_is_unchanged_by_governance() {
    let repository_id = random::<RepositoryId>();
    let branch_id = random::<BranchId>();
    let (repository_ctx, tip, execution) =
        local_repository_with_root(repository_id, branch_id).await;

    let (no_op, advancing) = Box::pin(LORE_CONTEXT.scope(execution, {
        let repository_ctx = repository_ctx.clone();
        async move {
            let no_op = super::push_with_governance(
                repository_ctx.clone(),
                branch_id,
                tip,
                true,
                true,
                false,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                None,
            )
            .await;

            let next = serialize_file_revision(&repository_ctx, tip, 2, "hero.uasset").await;
            let advancing = super::push_with_governance(
                repository_ctx,
                branch_id,
                next,
                true,
                true,
                false,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                None,
            )
            .await;
            (no_op, advancing)
        }
    }))
    .await;

    assert!(
        no_op
            .expect("an ungoverned no-op push must still succeed")
            .success,
        "governance must not change the ungoverned no-op branch"
    );
    assert!(
        advancing
            .expect("an ungoverned advancing push must still succeed")
            .success,
        "governance must not change the ungoverned advancing branch"
    );
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! CR-032 / WP-119 Part L2 / WP-120: `LoreLockService`'s fenced-routing gate.
//!
//! `PostgresLockCoordinator::acquire_or_renew`/`release`/`force_release` build
//! and append their pinned `lock_namespace` outbox event once a caller
//! supplies `outbox_cell_id` (proved against real Postgres in
//! `lore-postgres/tests/domain_lock_fencing.rs`). Nothing in this file
//! repeats that. This file proves the two states of the gate a step further
//! out, at the gRPC entry point that decides whether the coordinator is ever
//! reached at all:
//!
//! - a server built with an ARMED `fenced_coordinator` **serves** `Lock`/
//!   `Unlock` for a released client (a verified human JWT, no carriage)
//!   through `DomainContext::prepare_direct_lock_operation`, issuing a
//!   per-resource ownership token on acquire and requiring it on release.
//!   WP-120 (`9a6d5e0`) built this whole gRPC path, but
//!   `PUBLIC_MUTATION_CONTRACT_AVAILABLE` stays `false` in production
//!   (`lore-postgres/src/domain/locks/schema.rs`) until a follow-on lane
//!   ships the client half that keeps and presents that token -- see
//!   `lore-postgres/tests/domain_lock_fencing.rs`'s
//!   `arming_is_refused_until_the_public_mutation_contract_exists` for the
//!   coordinator-level half of that gate. `armed_service` below arms the
//!   coordinator through the test-only
//!   `PostgresLockCoordinator::enable_fencing_for_component_fixture` bypass
//!   so the served path can be exercised deterministically ahead of that
//!   lane, exactly as `enable_fencing_for_component_fixture`'s own doc
//!   comment intends; and
//! - a server built with no `fenced_coordinator` (the legacy default) routes
//!   through `store::lock_store::PostgresLockStore`, which succeeds and
//!   appends no CR-032 outbox row, because that store has no fence, no
//!   generation, and no domain transaction to append inside
//!   (`lock_store.rs`'s own `BLOCKED(WP-117)` comment).
//!
//! Real Postgres end to end for both arms, rather than a mock, so the
//! zero-vs-nonzero row counts are checked against `lore_outbox_events`
//! itself, not inferred from a mock never being asked to record one.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::lock_store::PostgresLockStore;
use lore_proto::LockService;
use lore_proto::lock::AdminLockRequest;
use lore_proto::lock::ForceUnlockRequest;
use lore_proto::lock::LockRequest;
use lore_proto::lock::QueryRequest;
use lore_proto::lock::Resource;
use lore_proto::lock::StatusRequest;
use lore_proto::lock::UnlockRequest;
use lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest;
use lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse;
use lore_proto::rebac::DomainOperationMaintenanceVerificationRequest;
use lore_proto::rebac::DomainOperationMaintenanceVerificationResponse;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::authnz::rebac::RepositoryOperationAuthorizationVerifier;
use lore_server::domain::DomainContext;
use lore_server::domain::PLATFORM_METHOD_REPOSITORY_CREATE;
use lore_server::grpc::lock_service::LoreLockService;
use lore_server::hooks::HookDispatcher;
use lore_server::notification::local::NotificationSender;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use tokio_postgres::Client;
use tonic::Code;
use tonic::Request;
use tonic::Status;
use tonic::metadata::BinaryMetadataValue;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
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

fn one_resource() -> Resource {
    Resource {
        branch: rand::random::<[u8; 16]>().to_vec().into(),
        hash: rand::random::<[u8; 32]>().to_vec().into(),
        description: "/Game/wp119-lock-service.uasset".to_owned(),
        expected_ownership_token: Default::default(),
    }
}

fn request_with_repository<T>(body: T, repository_id: &[u8; 16]) -> Request<T> {
    let mut request = Request::new(body);
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        BinaryMetadataValue::from_bytes(repository_id),
    );
    request
}

/// A request carrying both a verified human [`AuthorizationToken`] extension
/// (what `get_authorization` reads) and the raw bearer metadata header (what
/// WP-120's internal prepare forwards to the direct-authorization verifier).
fn authenticated_request<T>(
    body: T,
    repository_id: &[u8; 16],
    token: &AuthorizationToken,
) -> Request<T> {
    let mut request = request_with_repository(body, repository_id);
    request.metadata_mut().insert(
        "authorization",
        "Bearer wp120-test-bearer".parse().expect("ascii header"),
    );
    request.extensions_mut().insert(token.clone());
    request
}

async fn outbox_row_count(client: &Client, repository_id: &[u8]) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM lore_outbox_events WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("count outbox rows for repository")
        .get(0)
}

/// A test double for the direct-authorization rail. Every method but
/// `authorize_direct_repository_operation` is unreachable in this file --
/// only the fenced-lock path is exercised here, never the mediated create
/// rail those other methods serve.
struct DirectEchoVerifier {
    calls: AtomicUsize,
}

impl DirectEchoVerifier {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl RepositoryOperationAuthorizationVerifier for DirectEchoVerifier {
    async fn verify_repository_operation_authorization(
        &self,
        _request: Request<VerifyRepositoryOperationAuthorizationRequest>,
    ) -> Result<VerifyRepositoryOperationAuthorizationResponse, Status> {
        unreachable!("this file exercises only the direct fenced-lock rail")
    }

    async fn claim_repository_operation_stale_finalize_permit(
        &self,
        _request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("this file exercises only the direct fenced-lock rail")
    }

    async fn verify_repository_operation_terminal_status_attach(
        &self,
        _request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("this file exercises only the direct fenced-lock rail")
    }

    async fn verify_repository_operation_proof_namespace_materialize(
        &self,
        _request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("this file exercises only the direct fenced-lock rail")
    }

    async fn verify_repository_operation_proof_namespace_retire(
        &self,
        _request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        unreachable!("this file exercises only the direct fenced-lock rail")
    }

    async fn authorize_direct_repository_operation(
        &self,
        request: Request<AuthorizeDirectRepositoryOperationRequest>,
    ) -> Result<AuthorizeDirectRepositoryOperationResponse, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        assert_eq!(
            bearer,
            Some("Bearer wp120-test-bearer"),
            "the internal prepare must forward the caller's own bearer token"
        );
        let request = request.into_inner();
        Ok(AuthorizeDirectRepositoryOperationResponse {
            verified_issuer: request.verified_issuer,
            authenticated_subject: request.authenticated_subject,
            operation_id: request.operation_id.clone(),
            method: request.method,
            scope: request.scope,
            fingerprint_version: request.fingerprint_version,
            fingerprint: request.fingerprint,
            canonical_intent_digest: request.canonical_intent_digest,
            // Any 16 bytes satisfy the width check; reusing the operation id
            // keeps this fake trivially deterministic.
            authorization_id: request.operation_id,
            authorization_revision: 1,
            verification_nonce: bytes::Bytes::from_static(&[0x11; 32]),
            bound_fields_digest: bytes::Bytes::from_static(&[0x22; 32]),
            org_uuid: bytes::Bytes::new(),
        })
    }
}

/// A server wired with an armed `fenced_coordinator` and a configured
/// operation verifier serves `Lock` and `Unlock` for a released client (a
/// verified human JWT, no carriage): `Lock` issues a per-resource ownership
/// token, `Unlock` without it is refused, `Unlock` with it succeeds, and each
/// served mutation appends its own CR-032 outbox row.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn armed_fenced_coordinator_serves_lock_and_unlock_with_ownership_tokens() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let (service, _coordinator, verifier, repository_id, branch_id) = armed_service(&url).await;
    let db = client(&url).await;
    let token = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: "wp120-released-client".to_owned(),
        ..Default::default()
    };

    let locked = service
        .lock(authenticated_request(
            LockRequest {
                resources: vec![resource_for_branch(&branch_id)],
            },
            &repository_id,
            &token,
        ))
        .await
        .expect("a released client with a configured verifier must be served, not refused")
        .into_inner();
    assert_eq!(
        locked.locks.len(),
        1,
        "one resource requested, one lock returned"
    );
    let acquired = locked.locks[0].clone();
    assert_ne!(
        acquired.ownership_token.as_ref(),
        [0u8; 32].as_slice(),
        "Lock must issue a real per-resource ownership token, not a zero placeholder"
    );
    let resource = acquired
        .resource
        .clone()
        .expect("an acquired lock names its resource");

    let tokenless_unlock = service
        .unlock(authenticated_request(
            UnlockRequest {
                resources: vec![resource.clone()],
            },
            &repository_id,
            &token,
        ))
        .await
        .expect_err("release without the issued ownership token must be refused");
    assert_eq!(tokenless_unlock.code(), Code::InvalidArgument);

    let unlocked = service
        .unlock(authenticated_request(
            UnlockRequest {
                resources: vec![Resource {
                    expected_ownership_token: acquired.ownership_token.clone(),
                    ..resource
                }],
            },
            &repository_id,
            &token,
        ))
        .await
        .expect("release with the issued ownership token must succeed")
        .into_inner();
    assert_eq!(unlocked.resources.len(), 1);

    assert!(
        outbox_row_count(&db, &repository_id).await >= 2,
        "a served acquire and a served release must each append a CR-032 outbox row"
    );
    assert_eq!(
        verifier.calls.load(Ordering::SeqCst),
        2,
        "the direct verifier must be called once for the acquire and once for the release"
    );
}

/// Create a fixture repository and its default branch through the domain
/// coordinator directly (a plain direct create; the identity of the operation
/// that created it is irrelevant to the lock tests below).
///
/// The fenced lock coordinator requires a real `lore_domain_lock_namespaces`
/// row before it will acquire anything: `resolve_lock_fencing`'s
/// after-insert trigger on `lore_domain_branches` is what creates that row,
/// so a lock request against a repository/branch that was never created
/// through the domain layer is refused `FAILED_PRECONDITION`
/// ("the repository or branch lock state is absent or stale") -- fail-closed
/// behaviour, not a bug, and every served-path test below needs a real
/// fixture rather than a bare random id.
async fn create_repository_and_branch(store: &PostgresDomainStore) -> ([u8; 16], [u8; 16]) {
    let repository_id: [u8; 16] = rand::random();
    let branch_id: [u8; 16] = rand::random();
    let key = ReceiptKey {
        verified_issuer: "https://issuer.example/wp120-lock-fixture".to_owned(),
        authenticated_subject: "wp120-lock-fixture".to_owned(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id: Uuid::now_v7(),
    };
    let digest = rand::random::<[u8; 32]>().to_vec();
    let binding = OperationBinding {
        method: PLATFORM_METHOD_REPOSITORY_CREATE.to_owned(),
        scope: key.tenant_scope_key.clone(),
        fingerprint_version: 1,
        fingerprint: digest.clone(),
        canonical_intent_digest: digest.clone(),
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, None)
        .await
        .expect("prepare the fixture repository create")
    else {
        panic!("fixture repository create must prepare");
    };
    let input = RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name: format!("wp120-lock-{:016x}", rand::random::<u64>()),
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: branch_id.to_vec(),
        default_branch_name: "main".to_owned(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint: digest,
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        events: Vec::new(),
    };
    store
        .repository_create(
            &GovernedOperation {
                key,
                binding,
                prepare_token: token,
            },
            &input,
        )
        .await
        .expect("create the fixture repository and default branch");
    (repository_id, branch_id)
}

/// Build an armed, fully wired fenced `LoreLockService`, a fixture repository
/// its coordinator can actually serve locks against, and the supporting
/// coordinator/domain/verifier every served-path test below needs.
async fn armed_service(
    url: &str,
) -> (
    LoreLockService,
    Arc<lore_postgres::domain::locks::PostgresLockCoordinator>,
    Arc<DirectEchoVerifier>,
    [u8; 16],
    [u8; 16],
) {
    let domain_store = PostgresDomainStore::connect(url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store");
    let coordinator = Arc::new(domain_store.lock_coordinator());
    coordinator
        .bootstrap()
        .await
        .expect("install fenced lock schema");
    coordinator
        .backfill(&BackfillIssuerMap::new())
        .await
        .expect("complete empty backfill");
    coordinator
        .enable_fencing_for_component_fixture(false)
        .await
        .expect("arm fenced routing through the test-only fixture bypass");
    let (repository_id, branch_id) = create_repository_and_branch(&domain_store).await;

    let verifier = Arc::new(DirectEchoVerifier::new());
    let domain = Arc::new(
        DomainContext::new_with_lock_coordinator(
            Arc::new(domain_store) as Arc<dyn DomainTransactionStore>,
            true,
            coordinator.clone(),
        )
        .with_operation_verifier(Some(verifier.clone()))
        // A cell with no configured identity produces no outbox rows at all
        // (`DomainContext::cell_id`'s own doc comment) -- every served-path
        // test below asserts on `lore_outbox_events`, so this must be set.
        .with_cell_id(Some("wp120-lock-service-test".to_owned())),
    );
    let lock_store = PostgresLockStore::connect(url, 4, &TlsConfig::default())
        .await
        .expect("connect legacy lock store");
    let service = LoreLockService::new(
        Arc::new(lock_store),
        Arc::new(NotificationSender::default()),
        Arc::new(HookDispatcher::empty()),
        Duration::from_secs(60),
        false,
    )
    .with_fenced_coordinator(Some(coordinator.clone()), Some(domain));

    (service, coordinator, verifier, repository_id, branch_id)
}

/// A resource naming a real branch a fenced coordinator can serve locks
/// against, unlike [`one_resource`]'s fully random branch (fine for the
/// legacy-store test, which has no namespace to match).
fn resource_for_branch(branch_id: &[u8; 16]) -> Resource {
    Resource {
        branch: branch_id.to_vec().into(),
        ..one_resource()
    }
}

fn admin_token(subject: &str) -> AuthorizationToken {
    AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: subject.to_owned(),
        resources: Some(vec![ResourcePermission {
            resource_id: "urc-*".to_owned(),
            permission: vec!["migrate".to_owned()],
        }]),
        ..Default::default()
    }
}

/// THE security assertion: `Query` and `Status` never expose an ownership
/// token, including on the caller's own lock. The token is the bearer secret
/// that authorizes releasing a row; these two RPCs read OTHER people's locks
/// too, so `fenced_lock_to_wire` (not `..._with_token`) backs both, and this
/// is the test that a regression swapping the two would fail.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn queried_and_status_locks_never_expose_an_ownership_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let (service, _coordinator, _verifier, repository_id, branch_id) = armed_service(&url).await;
    let token = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: "wp120-query-status-owner".to_owned(),
        ..Default::default()
    };
    let resource = resource_for_branch(&branch_id);

    let locked = service
        .lock(authenticated_request(
            LockRequest {
                resources: vec![resource.clone()],
            },
            &repository_id,
            &token,
        ))
        .await
        .expect("acquire must succeed")
        .into_inner();
    let acquired = locked.locks[0].clone();
    assert!(
        !acquired.ownership_token.is_empty(),
        "sanity: Lock itself must return a real token"
    );

    let queried = service
        .query(authenticated_request(
            QueryRequest {
                branch: Some(resource.branch.clone()),
                owner: None,
                description: None,
            },
            &repository_id,
            &token,
        ))
        .await
        .expect("query must succeed")
        .into_inner();
    assert_eq!(queried.result.len(), 1);
    assert!(
        queried.result[0].ownership_token.is_empty(),
        "Query must never expose an ownership token, even the caller's own"
    );

    let status = service
        .status(authenticated_request(
            StatusRequest {
                resources: vec![resource],
            },
            &repository_id,
            &token,
        ))
        .await
        .expect("status must succeed")
        .into_inner();
    assert_eq!(status.locks.len(), 1);
    assert!(
        status.locks[0].ownership_token.is_empty(),
        "Status must never expose an ownership token, even the caller's own"
    );
}

/// `ForceUnlock` is the only way to take someone else's fenced lock, and it is
/// a genuinely different transition from `Unlock`: it needs the `migrate`
/// permission (same bar as `AdminLock`), it names the owner being released
/// explicitly, and -- unlike an ordinary release -- it does NOT require the
/// resource's ownership token, because an administrator legitimately holds
/// none (`ForceUnlockRequest`'s own doc comment; `fenced_batch(resources,
/// false)` in `fenced_force_release`).
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn admin_force_unlock_releases_another_owners_lock_without_a_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let (service, _coordinator, _verifier, repository_id, branch_id) = armed_service(&url).await;
    let db = client(&url).await;
    let owner_token = AuthorizationToken {
        issuer: "https://issuer.example".to_owned(),
        user_id: "wp120-force-unlock-owner".to_owned(),
        ..Default::default()
    };
    let admin = admin_token("wp120-force-unlock-admin");
    let resource = resource_for_branch(&branch_id);

    service
        .lock(authenticated_request(
            LockRequest {
                resources: vec![resource.clone()],
            },
            &repository_id,
            &owner_token,
        ))
        .await
        .expect("owner's acquire must succeed");

    // Deliberately no `expected_ownership_token` on the resource: the admin
    // holds none, and force-release must not require one.
    let forced = service
        .force_unlock(authenticated_request(
            ForceUnlockRequest {
                resources: vec![resource],
                owner: owner_token.user_id.clone(),
            },
            &repository_id,
            &admin,
        ))
        .await
        .expect("an administrator with migrate permission must force-release without a token")
        .into_inner();
    assert_eq!(forced.resources.len(), 1);

    assert!(
        outbox_row_count(&db, &repository_id).await >= 2,
        "both the acquire and the force-release must each append a CR-032 outbox row"
    );
}

/// `ForceUnlock` has no legacy fallback: a cell with no fenced coordinator
/// refuses it outright rather than reaching for the old admin-unlock
/// behaviour the legacy `PostgresLockStore` path never implemented as a
/// distinct transition.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn force_unlock_with_no_fenced_coordinator_is_refused() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let lock_store = PostgresLockStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect legacy lock store");
    let repository_id: [u8; 16] = rand::random();
    let admin = admin_token("wp120-unarmed-admin");

    let service = LoreLockService::new(
        Arc::new(lock_store),
        Arc::new(NotificationSender::default()),
        Arc::new(HookDispatcher::empty()),
        Duration::from_secs(60),
        false,
    );

    let error = service
        .force_unlock(authenticated_request(
            ForceUnlockRequest {
                resources: vec![one_resource()],
                owner: "someone".to_owned(),
            },
            &repository_id,
            &admin,
        ))
        .await
        .expect_err("an unarmed cell must refuse ForceUnlock, never fall back to a legacy path");

    assert_eq!(error.code(), Code::FailedPrecondition);
}

/// `AdminLock` is the mirror positive case to `ForceUnlock`'s refusal above:
/// with a fenced coordinator armed and the caller holding `migrate`
/// permission, an administrator can lock a resource on another subject's
/// behalf and the wire still returns that subject's real ownership token.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn admin_lock_on_behalf_of_another_subject_issues_that_subjects_ownership_token() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let (service, _coordinator, _verifier, repository_id, branch_id) = armed_service(&url).await;
    let admin = admin_token("wp120-admin-lock-admin");
    let target_owner = "wp120-admin-lock-target";

    let admin_locked = service
        .admin_lock(authenticated_request(
            AdminLockRequest {
                resources: vec![resource_for_branch(&branch_id)],
                owner: target_owner.to_owned(),
            },
            &repository_id,
            &admin,
        ))
        .await
        .expect("an administrator with migrate permission must be served")
        .into_inner();
    assert_eq!(admin_locked.locks.len(), 1);
    assert!(
        !admin_locked.locks[0].ownership_token.is_empty(),
        "AdminLock must still issue a real ownership token, owned by the target subject"
    );
    assert_eq!(admin_locked.locks[0].owner, target_owner);
}

/// A server with no `fenced_coordinator` (the legacy default) routes through
/// `PostgresLockStore` end to end: `Lock` succeeds and appends no CR-032
/// outbox row, because that store has no fence, no generation, and no domain
/// transaction to append inside.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn unarmed_legacy_route_succeeds_and_appends_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    // Only `lore_outbox_events` needs to exist for the assertion below; the
    // domain store itself plays no part in this test's Lock/Unlock flow,
    // which routes through the separate legacy `PostgresLockStore`.
    PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("install outbox schema for the zero-row assertion");
    let lock_store = PostgresLockStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect legacy lock store");
    let db = client(&url).await;
    let repository_id: [u8; 16] = rand::random();

    let service = LoreLockService::new(
        Arc::new(lock_store),
        Arc::new(NotificationSender::default()),
        Arc::new(HookDispatcher::empty()),
        Duration::from_secs(60),
        false,
    );

    let response = service
        .lock(request_with_repository(
            LockRequest {
                resources: vec![one_resource()],
            },
            &repository_id,
        ))
        .await
        .expect("an unarmed server must route Lock through the legacy store");
    assert_eq!(response.into_inner().locks.len(), 1);

    assert_eq!(
        outbox_row_count(&db, &repository_id).await,
        0,
        "the legacy lock_store path has no fence, no generation, and no domain transaction \
         to append an outbox row inside"
    );
}

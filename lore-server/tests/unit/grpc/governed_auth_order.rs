// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, CR-029): on the four metadata CAS handlers the
//! authorization checks run after admission and BEFORE the governed prepare,
//! so a refused caller leaves no receipt.
//!
//! The governed prepare that writes a receipt is the internal (released
//! client) admission: it asks the auth-grpc verifier, then calls
//! `domain_operation_prepare_direct`. Here the verifier panics on every port
//! and the coordinator is `UnreachableDomainStore`, whose prepare methods
//! panic too. A refused caller that returns its refusal without a panic is the
//! proof that no verifier call and no receipt write happened. A carried
//! (control-plane) admission writes nothing in the handler: its receipt was
//! prepared by the platform before the call.
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::metadata::Metadata;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_revision::state::allow_all_repositories;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::repository_authorizer::Action;
use lore_server::authnz::repository_authorizer::RawToken;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedToken;
use lore_server::domain::DomainContext;
use lore_server::grpc::domain_operation_metadata::AUTHN_BEARER_KEY;
use lore_server::grpc::get_write_token;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::Code;
use tonic::Request;
use tonic::Status;
use tonic::metadata::BinaryMetadataValue;

use crate::store::test_support::test_store_create;

/// Panics on every port: any verifier call means the governed prepare ran.
struct PrepareMustNotRun;

#[async_trait]
impl lore_server::authnz::rebac::RepositoryOperationAuthorizationVerifier for PrepareMustNotRun {
    async fn verify_repository_operation_authorization(
        &self,
        _: Request<lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest>,
    ) -> Result<lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse, Status> {
        panic!("a refused caller must not reach the governed prepare")
    }
    async fn claim_repository_operation_stale_finalize_permit(
        &self,
        _: Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        panic!("a refused caller must not reach the governed prepare")
    }
    async fn verify_repository_operation_terminal_status_attach(
        &self,
        _: Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        panic!("a refused caller must not reach the governed prepare")
    }
    async fn verify_repository_operation_proof_namespace_materialize(
        &self,
        _: Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        panic!("a refused caller must not reach the governed prepare")
    }
    async fn verify_repository_operation_proof_namespace_retire(
        &self,
        _: Request<lore_proto::rebac::DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status> {
        panic!("a refused caller must not reach the governed prepare")
    }
    async fn authorize_direct_repository_operation(
        &self,
        _: Request<lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest>,
    ) -> Result<lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse, Status> {
        panic!("a refused caller must not reach the governed prepare")
    }
}

/// An enforcing cell with internal admission open, whose prepare panics.
fn internal_admission_domain() -> Arc<DomainContext> {
    Arc::new(
        lore_server::domain::test_support::context(true)
            .with_operation_verifier(Some(Arc::new(PrepareMustNotRun))),
    )
}

const USER: &str = "released-desktop-user";

/// A released desktop client: verified human token, its `authorization`
/// header and a distinct `lore-authn-bearer`, no domain carriage. Every
/// internal-admission gate is open for it.
fn as_released_client<T>(request: &mut Request<T>) {
    let metadata = request.metadata_mut();
    metadata.insert(
        "authorization",
        "Bearer released-desktop-jwt".parse().unwrap(),
    );
    metadata.insert(
        AUTHN_BEARER_KEY,
        "Bearer released-desktop-authn-jwt".parse().unwrap(),
    );
    request
        .extensions_mut()
        .insert(RawToken("released-desktop-jwt".to_string()));
    request.extensions_mut().insert(AuthorizationToken {
        issuer: "https://issuer.example".to_string(),
        user_id: USER.to_string(),
        ..Default::default()
    });
}

fn with_repository_header<T>(request: &mut Request<T>, repository: RepositoryId) {
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        BinaryMetadataValue::from_bytes(repository.data()),
    );
}

/// Denies everything.
struct DenyAll;

#[async_trait]
impl RepositoryAuthorizer for DenyAll {
    async fn check_repository_access(
        &self,
        _token: Option<&VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        _action: Action,
    ) -> Result<(), Status> {
        Err(Status::permission_denied("denied"))
    }
}

/// Grants `read` and `write` only: past the write check, refused at the
/// protection-change check (not `set-protected`, not `admin`/`owner`, and
/// not the recorded creator).
struct ReadWriteOnly;

#[async_trait]
impl RepositoryAuthorizer for ReadWriteOnly {
    async fn check_repository_access(
        &self,
        _token: Option<&VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        action: Action,
    ) -> Result<(), Status> {
        match action {
            Action::Read | Action::Write => Ok(()),
            _ => Err(Status::permission_denied("denied")),
        }
    }
}

#[tokio::test]
async fn v0_repository_metadata_set_refuses_before_the_governed_prepare() {
    let repository = random::<RepositoryId>();
    let (immutable, mutable, _) = test_store_create().await.unwrap();
    let domain = internal_admission_domain();
    let mut request = Request::new(lore_proto::RepositoryMetadataSetRequest {
        repository_id: repository.data().to_vec().into(),
        expected_hash: vec![0u8; 32].into(),
        new_hash: vec![1u8; 32].into(),
    });
    as_released_client(&mut request);
    let err = lore_server::grpc::handlers::repository_metadata_set::handler(
        request,
        Arc::new(DenyAll),
        immutable,
        mutable,
        Some(&domain),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

#[tokio::test]
async fn v1_repository_metadata_set_refuses_before_the_governed_prepare() {
    let repository = random::<RepositoryId>();
    let (immutable, mutable, _) = test_store_create().await.unwrap();
    let domain = internal_admission_domain();
    let mut request = Request::new(
        lore_proto::lore::repository::v1::RepositoryMetadataSetRequest {
            id: repository.data().to_vec().into(),
            expected: vec![0u8; 32].into(),
            updated: vec![1u8; 32].into(),
        },
    );
    as_released_client(&mut request);
    let err = lore_server::grpc::repository::v1::repository_metadata_set::handler(
        request,
        Arc::new(DenyAll),
        immutable,
        mutable,
        Some(&domain),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
}

/// Seeds a repository record created by someone else, and a branch, and
/// answers `(current, proposed)` metadata hashes where `proposed` sets PROTECT.
async fn branch_with_protect_toggle(
    immutable: Arc<dyn lore_storage::ImmutableStore>,
    mutable: Arc<dyn lore_storage::MutableStore>,
    repository_id: RepositoryId,
    branch_id: BranchId,
) -> (Hash, Hash) {
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable,
        mutable,
        repository_id,
        allow_all_repositories(),
    ));
    let record = lore_revision::repository::metadata_store(
        repository.clone(),
        RepositoryMetadata {
            name: "repo".to_string(),
            creator: "someone-else".to_string(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    lore_revision::repository::metadata_store_hash(repository.clone(), record)
        .await
        .unwrap();
    branch::create(
        repository.clone(),
        &get_write_token(),
        branch_id,
        "test-branch",
        branch::default_category(),
        "creator",
        1,
        vec![],
        false,
        false,
    )
    .await
    .unwrap();
    let current = branch::metadata_hash(repository.clone(), branch_id)
        .await
        .unwrap();
    let mut proposed = Metadata::deserialize(repository.clone(), current)
        .await
        .unwrap();
    proposed.set_bool(branch::PROTECT, true).unwrap();
    let proposed = proposed.serialize(repository).await.unwrap();
    (current, proposed)
}

#[tokio::test]
async fn v0_branch_protection_change_refuses_before_the_governed_prepare() {
    let repository_id = random::<RepositoryId>();
    let branch_id = BranchId::from(Context::from(*uuid::Uuid::now_v7().as_bytes()));
    let (immutable, mutable, execution) = test_store_create().await.unwrap();
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let (current, proposed) = branch_with_protect_toggle(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            branch_id,
        )
        .await;
        let domain = internal_admission_domain();
        let mut request = Request::new(lore_proto::BranchMetadataSetRequest {
            branch_id: branch_id.into(),
            expected_hash: current.into(),
            new_hash: proposed.into(),
        });
        with_repository_header(&mut request, repository_id);
        as_released_client(&mut request);
        let authorizer: Arc<dyn RepositoryAuthorizer> = Arc::new(ReadWriteOnly);
        let err = lore_server::grpc::handlers::branch_metadata_set::handler(
            request,
            &authorizer,
            immutable,
            mutable,
            false,
            Some(&domain),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
        assert_eq!(err.message(), "Not permitted to change branch protection");
    }))
    .await;
}

#[tokio::test]
async fn v1_branch_protection_change_refuses_before_the_governed_prepare() {
    let repository_id = random::<RepositoryId>();
    let branch_id = BranchId::from(Context::from(*uuid::Uuid::now_v7().as_bytes()));
    let (immutable, mutable, execution) = test_store_create().await.unwrap();
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let (current, proposed) = branch_with_protect_toggle(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            branch_id,
        )
        .await;
        let domain = internal_admission_domain();
        let mut request = Request::new(lore_proto::lore::revision::v1::BranchMetadataSetRequest {
            id: branch_id.into(),
            expected: current.into(),
            updated: proposed.into(),
        });
        with_repository_header(&mut request, repository_id);
        as_released_client(&mut request);
        let authorizer: Arc<dyn RepositoryAuthorizer> = Arc::new(ReadWriteOnly);
        let err = lore_server::grpc::revision::v1::branch_metadata_set::handler(
            request,
            &authorizer,
            immutable,
            mutable,
            false,
            Some(&domain),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");
        assert_eq!(err.message(), "Not permitted to change branch protection");
    }))
    .await;
}

/// An auth-service outage, as the two kinds a check meets in production:
/// the real `AuthClientAuthorizer` against a port nothing listens on (a
/// fast dial failure, `RESOURCE_EXHAUSTED`), and the fork's timeout / outage
/// hold status (`INTERNAL` with the auth-unavailable marker).
fn outages() -> Vec<(Arc<dyn RepositoryAuthorizer>, Code)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    vec![
        (
            Arc::new(lore_server::authnz::repository_authorizer::AuthClientAuthorizer::new(closed)),
            Code::ResourceExhausted,
        ),
        (
            Arc::new(crate::authnz::repository_authorizer::RefusingAuthorizer(
                lore_server::authnz::auth::auth_unavailable_status(
                    "lore auth service did not answer check_user_permission within 8s".to_string(),
                ),
            )),
            Code::Internal,
        ),
    ]
}

/// v0 gRPC write path: an auth outage answers before the governed prepare
/// (no verifier call, no receipt), so `RESOURCE_EXHAUSTED` is safe to retry;
/// the fork's timeout / hold stays `INTERNAL`.
#[tokio::test]
async fn v0_auth_outage_answers_before_the_governed_prepare() {
    for (authorizer, code) in outages() {
        let repository = random::<RepositoryId>();
        let (immutable, mutable, _) = test_store_create().await.unwrap();
        let domain = internal_admission_domain();
        let mut request = Request::new(lore_proto::RepositoryMetadataSetRequest {
            repository_id: repository.data().to_vec().into(),
            expected_hash: vec![0u8; 32].into(),
            new_hash: vec![1u8; 32].into(),
        });
        as_released_client(&mut request);
        let err = lore_server::grpc::handlers::repository_metadata_set::handler(
            request,
            authorizer,
            immutable,
            mutable,
            Some(&domain),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), code, "{err:?}");
    }
}

/// v1 gRPC write path: as v0.
#[tokio::test]
async fn v1_auth_outage_answers_before_the_governed_prepare() {
    for (authorizer, code) in outages() {
        let repository = random::<RepositoryId>();
        let (immutable, mutable, _) = test_store_create().await.unwrap();
        let domain = internal_admission_domain();
        let mut request = Request::new(
            lore_proto::lore::repository::v1::RepositoryMetadataSetRequest {
                id: repository.data().to_vec().into(),
                expected: vec![0u8; 32].into(),
                updated: vec![1u8; 32].into(),
            },
        );
        as_released_client(&mut request);
        let err = lore_server::grpc::repository::v1::repository_metadata_set::handler(
            request,
            authorizer,
            immutable,
            mutable,
            Some(&domain),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), code, "{err:?}");
    }
}

/// v0 admin `Obliterate`: the `obliterate` check, and so any auth outage,
/// answers before `complete_governed` (an internal admission's receipt write).
#[tokio::test]
async fn obliterate_refuses_before_the_governed_prepare() {
    let mut cases: Vec<(Arc<dyn RepositoryAuthorizer>, Code)> =
        vec![(Arc::new(DenyAll), Code::PermissionDenied)];
    cases.extend(outages());
    for (authorizer, code) in cases {
        let repository = random::<RepositoryId>();
        let (immutable, mutable, _) = test_store_create().await.unwrap();
        let domain = internal_admission_domain();
        let mut request = Request::new(lore_proto::ObliterateRequest::default());
        with_repository_header(&mut request, repository);
        as_released_client(&mut request);
        let err = lore_server::grpc::handlers::obliterate::handler(
            request,
            &authorizer,
            immutable,
            mutable,
            Arc::new(crate::notification::testing::MockNotificationSender::new()),
            &lore_server::hooks::HookDispatcher::empty(),
            &Arc::new(None),
            Some(&domain),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), code, "{err:?}");
    }
}

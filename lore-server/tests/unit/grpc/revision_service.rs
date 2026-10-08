// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::grpc::revision_service::*;
use lore_server::hooks::HookDispatcher;
use lore_server::legacy::rpc::revision_service_server::RevisionService;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::Code;
use tonic::Request;

use crate::notification::testing::MockNotificationSender;
use crate::store::test_support::test_store_create;

fn service_with(
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    enforce: bool,
) -> LoreRevisionService {
    LoreRevisionService::new(
        immutable_store,
        mutable_store,
        Arc::new(MockNotificationSender::new()),
        Arc::new(HookDispatcher::empty()),
        Arc::new(AllowAllRepositoryAuthorizer),
        DEFAULT_HISTORY_STEP_SIZE,
        lore_server::grpc::server::RevisionListAcceleration::default(),
        Duration::from_secs(60),
        enforce,
        None,
        None,
    )
}

fn insert_token<T>(request: &mut Request<T>, repository: RepositoryId, perms: &[&str]) {
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    request.extensions_mut().insert(AuthorizationToken {
        user_id: "test-user".into(),
        resources: Some(vec![ResourcePermission {
            resource_id: format!("urc-{repository}"),
            permission: perms.iter().map(|p| p.to_string()).collect(),
        }]),
        ..Default::default()
    });
}

fn protect_request(
    repository: RepositoryId,
    perms: &[&str],
) -> Request<lore_proto::BranchProtectRequest> {
    let mut request = Request::new(lore_proto::BranchProtectRequest {
        branch: BranchId::from(uuid::Uuid::now_v7()).into(),
    });
    insert_token(&mut request, repository, perms);
    request
}

fn unprotect_request(
    repository: RepositoryId,
    perms: &[&str],
) -> Request<lore_proto::BranchUnprotectRequest> {
    let mut request = Request::new(lore_proto::BranchUnprotectRequest {
        branch: BranchId::from(uuid::Uuid::now_v7()).into(),
    });
    insert_token(&mut request, repository, perms);
    request
}

#[tokio::test]
async fn read_only_token_protect_is_denied() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    let err = service
        .branch_protect(protect_request(repository, &["read"]))
        .await
        .expect_err("read-only protect must be denied");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn write_token_protect_is_denied_without_admin() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    // Protecting a branch needs `admin`, not merely `write`.
    let err = service
        .branch_protect(protect_request(repository, &["read", "write"]))
        .await
        .expect_err("protect requires admin, not write");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn admin_token_protect_passes_gate() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    // An admin token clears the gate; protecting a non-existent
    // branch then fails downstream with NotFound — proving the
    // permission check passed.
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        // The admin token clears the gate; the protect then fails
        // downstream (non-existent branch) with something other than
        // PermissionDenied — proving the permission check passed.
        let err = service
            .branch_protect(protect_request(repository, &["read", "write", "admin"]))
            .await
            .expect_err("non-existent branch should fail downstream");
        assert_ne!(err.code(), Code::PermissionDenied);
    }))
    .await;
}

#[tokio::test]
async fn read_only_token_unprotect_is_denied() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    let err = service
        .branch_unprotect(unprotect_request(repository, &["read"]))
        .await
        .expect_err("read-only unprotect must be denied");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn write_token_unprotect_is_denied_without_admin() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    // The "anyone can unprotect" hole: a developer (write, no admin)
    // must NOT be able to clear branch protection.
    let err = service
        .branch_unprotect(unprotect_request(repository, &["read", "write"]))
        .await
        .expect_err("unprotect requires admin, not write");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn admin_token_unprotect_passes_gate() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        // The admin token clears the gate; unprotect then fails
        // downstream (non-existent branch) with something other than
        // PermissionDenied — proving the permission check passed.
        let err = service
            .branch_unprotect(unprotect_request(repository, &["read", "write", "admin"]))
            .await
            .expect_err("non-existent branch should fail downstream");
        assert_ne!(err.code(), Code::PermissionDenied);
    }))
    .await;
}

#[tokio::test]
async fn read_only_token_legacy_push_is_denied() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    let mut request = Request::new(lore_proto::BranchPushRequest {
        branch: BranchId::from(uuid::Uuid::now_v7()).into(),
        revision: Hash::from([1u8; 32].as_slice()).into(),
        force: false,
        fast_forward_merge: false,
    });
    insert_token(&mut request, repository, &["read"]);

    let err = service
        .branch_push(request)
        .await
        .expect_err("read-only legacy push must be denied");
    assert_eq!(err.code(), Code::PermissionDenied);
}

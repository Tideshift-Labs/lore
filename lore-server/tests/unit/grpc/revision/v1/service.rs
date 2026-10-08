// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_proto::lore::revision::v1::BranchCreateRequest;
use lore_proto::lore::revision::v1::BranchDeleteRequest;
use lore_proto::lore::revision::v1::BranchPushRequest;
use lore_proto::lore::revision::v1::revision_service_server::RevisionService;
use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::grpc::revision::v1::service::*;
use lore_server::hooks::HookDispatcher;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::Code;
use tonic::Request;

use crate::notification::testing::MockNotificationSender;
use crate::store::test_support::test_store_create;

/// Compile-time check that `LoreRevisionV1Service` fully implements
/// the generated `RevisionService` trait — wrapping it in
/// `RevisionServiceServer` requires the trait bound to hold.
#[allow(dead_code)]
fn assert_implements_trait(
    service: LoreRevisionV1Service,
) -> RevisionServiceServer<LoreRevisionV1Service> {
    RevisionServiceServer::new(service)
}

fn service_with(
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    enforce: bool,
) -> LoreRevisionV1Service {
    LoreRevisionV1Service::new(
        immutable_store,
        mutable_store,
        Arc::new(MockNotificationSender::new()),
        Arc::new(HookDispatcher::empty()),
        DEFAULT_HISTORY_STEP_SIZE,
        lore_server::grpc::server::RevisionListAcceleration::default(),
        None,
        Duration::from_secs(60),
        enforce,
        None,
        None,
    )
}

/// Insert an `AuthorizationToken` carrying a single `urc-<repo>`
/// resource with `perms`, optionally flagged as a service account.
fn insert_token<T>(
    request: &mut Request<T>,
    repository: RepositoryId,
    perms: &[&str],
    service_account: bool,
) {
    request.extensions_mut().insert(AuthorizationToken {
        user_id: "test-user".into(),
        is_service_account: Some(service_account),
        resources: Some(vec![ResourcePermission {
            resource_id: format!("urc-{repository}"),
            permission: perms.iter().map(|p| p.to_string()).collect(),
        }]),
        ..Default::default()
    });
}

fn push_request(
    repository: RepositoryId,
    perms: &[&str],
    service_account: bool,
) -> Request<BranchPushRequest> {
    let mut request = Request::new(BranchPushRequest {
        id: BranchId::from(uuid::Uuid::now_v7()).into(),
        revision_signature: Hash::from([1u8; 32].as_slice()).into(),
        force: false,
        fast_forward_merge: false,
    });
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    insert_token(&mut request, repository, perms, service_account);
    request
}

#[tokio::test]
async fn read_only_token_push_is_denied() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    let err = service
        .branch_push(push_request(repository, &["read"], false))
        .await
        .expect_err("read-only push must be denied");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn write_token_push_passes_permission_check() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    // A write token clears the gate; the push then fails downstream
    // because the branch doesn't exist — proving the check passed.
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let err = service
            .branch_push(push_request(repository, &["read", "write"], false))
            .await
            .expect_err("non-existent branch should be NotFound");
        assert_eq!(err.code(), Code::NotFound);
    }))
    .await;
}

#[tokio::test]
async fn enforcement_disabled_allows_read_only_push() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, false);

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let err = service
            .branch_push(push_request(repository, &["read"], false))
            .await
            .expect_err("non-existent branch should be NotFound");
        // Not PermissionDenied — the flag is off.
        assert_eq!(err.code(), Code::NotFound);
    }))
    .await;
}

#[tokio::test]
async fn read_only_service_account_push_is_denied() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    // Service accounts are NOT exempt from write enforcement.
    let err = service
        .branch_push(push_request(repository, &["read"], true))
        .await
        .expect_err("read-only service account must not write");
    assert_eq!(err.code(), Code::PermissionDenied);
}

/// Every unary write RPC on the v1 revision service must reject a
/// read-only token, so a newly added write RPC can't silently bypass.
#[tokio::test]
async fn all_write_rpcs_reject_read_only_token() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = service_with(immutable_store, mutable_store, true);

    // branch_push
    let err = service
        .branch_push(push_request(repository, &["read"], false))
        .await
        .expect_err("push denied");
    assert_eq!(err.code(), Code::PermissionDenied, "branch_push");

    // branch_create
    let mut create = Request::new(BranchCreateRequest {
        id: BranchId::from(uuid::Uuid::now_v7()).into(),
        name: "main".into(),
        creator: Some("alice".into()),
        category: "default".into(),
        stack: vec![],
    });
    create.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    insert_token(&mut create, repository, &["read"], false);
    let err = service
        .branch_create(create)
        .await
        .expect_err("create denied");
    assert_eq!(err.code(), Code::PermissionDenied, "branch_create");

    // branch_delete
    let mut delete = Request::new(BranchDeleteRequest {
        id: BranchId::from(uuid::Uuid::now_v7()).into(),
    });
    delete.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    insert_token(&mut delete, repository, &["read"], false);
    let err = service
        .branch_delete(delete)
        .await
        .expect_err("delete denied");
    assert_eq!(err.code(), Code::PermissionDenied, "branch_delete");
}

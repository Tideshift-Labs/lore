// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::grpc::storage_service::LoreStorageService;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::Code;
use tonic::Request;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

/// Compile-time check that `LoreStorageService` fully implements the generated
/// `StorageService` trait — wrapping it in `StorageServiceServer` requires the
/// trait bound to hold. Per-handler behavior is tested in each handler module.
#[allow(dead_code)]
fn assert_implements_trait(
    service: LoreStorageService,
) -> StorageServiceServer<LoreStorageService> {
    StorageServiceServer::new(service)
}

fn insert_repo_and_token<T>(request: &mut Request<T>, repository: RepositoryId, perms: &[&str]) {
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

fn mutable_store_request(
    repository: RepositoryId,
    perms: &[&str],
) -> Request<storage_v1::MutableStoreRequest> {
    let key = random::<Hash>();
    let value = random::<Hash>();
    let mut request = Request::new(storage_v1::MutableStoreRequest {
        key: bytes::Bytes::copy_from_slice(key.as_bytes()),
        value: bytes::Bytes::copy_from_slice(value.as_bytes()),
        key_type: 0,
    });
    insert_repo_and_token(&mut request, repository, perms);
    request
}

#[tokio::test]
async fn read_only_token_mutable_store_is_denied() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = LoreStorageService::new(
        immutable_store.clone(),
        immutable_store,
        mutable_store,
        Arc::new(AllowAllRepositoryAuthorizer),
        true,
    );

    let err =
        StorageServiceV1::mutable_store(&service, mutable_store_request(repository, &["read"]))
            .await
            .expect_err("read-only mutable_store must be denied");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn read_only_token_mutable_cas_is_denied() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _execution) = test_store_create().await.expect("stores");
    let service = LoreStorageService::new(
        immutable_store.clone(),
        immutable_store,
        mutable_store,
        Arc::new(AllowAllRepositoryAuthorizer),
        true,
    );

    let key = random::<Hash>();
    let mut request = Request::new(storage_v1::MutableCompareAndSwapRequest {
        key: bytes::Bytes::copy_from_slice(key.as_bytes()),
        expected: bytes::Bytes::new(),
        value: bytes::Bytes::copy_from_slice(random::<Hash>().as_bytes()),
        key_type: 0,
    });
    insert_repo_and_token(&mut request, repository, &["read"]);

    let err = StorageServiceV1::mutable_compare_and_swap(&service, request)
        .await
        .expect_err("read-only mutable_cas must be denied");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn write_token_mutable_store_passes_permission_check() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) = test_store_create().await.expect("stores");
    let service = LoreStorageService::new(
        immutable_store.clone(),
        immutable_store,
        mutable_store,
        Arc::new(AllowAllRepositoryAuthorizer),
        true,
    );

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        StorageServiceV1::mutable_store(
            &service,
            mutable_store_request(repository, &["read", "write"]),
        )
        .await
        .expect("a write token may store mutable data");
    }))
    .await;
}

#[tokio::test]
async fn enforcement_disabled_allows_read_only_mutable_store() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) = test_store_create().await.expect("stores");
    let service = LoreStorageService::new(
        immutable_store.clone(),
        immutable_store,
        mutable_store,
        Arc::new(AllowAllRepositoryAuthorizer),
        false,
    );

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        StorageServiceV1::mutable_store(&service, mutable_store_request(repository, &["read"]))
            .await
            .expect("enforcement disabled lets a read-only token through");
    }))
    .await;
}

fn verify_request(
    repository: RepositoryId,
    address: lore_base::types::Address,
) -> Request<storage_v1::VerifyRequest> {
    let mut request = Request::new(storage_v1::VerifyRequest {
        address: Some(address.into()),
        heal: false,
    });
    insert_repo_and_token(&mut request, repository, &["read"]);
    request
}

/// Row 72. A server with no local store hands its main store to the public
/// services in the local store's place. Verify is the one operation that
/// reads that slot, and it is local-only, so it is refused with a status
/// that names it rather than answered as a generic store failure.
#[tokio::test]
async fn verify_without_a_local_store_is_refused_as_not_supported() {
    use lore_server::store::grpc_replica::GrpcReplica;
    use lore_server::store::grpc_replica::ReplicationClient;

    let repository = random::<RepositoryId>();
    let (_immutable_store, mutable_store, execution) = test_store_create().await.expect("stores");
    let non_local: Arc<dyn lore_storage::ImmutableStore> =
        Arc::new(GrpcReplica::new(ReplicationClient::default()));
    let service = LoreStorageService::new(
        non_local.clone(),
        non_local,
        mutable_store,
        Arc::new(AllowAllRepositoryAuthorizer),
        true,
    );

    let address = lore_base::types::Address {
        hash: random(),
        context: random(),
    };
    let err = Box::pin(LORE_CONTEXT.scope(execution, async move {
        StorageServiceV1::verify(&service, verify_request(repository, address)).await
    }))
    .await
    .expect_err("verify needs a local store");
    assert_eq!(err.code(), Code::Unimplemented);
    assert!(
        err.message().contains("Verify") && err.message().contains("no local store"),
        "the status names the operation and the reason: {}",
        err.message()
    );
}

/// A local store still answers Verify; the refusal is only for its absence.
#[tokio::test]
async fn verify_with_a_local_store_still_reaches_it() {
    let repository = random::<RepositoryId>();
    let (_in_memory, mutable_store, execution) = test_store_create().await.expect("stores");
    // Verify reads pack files, so this store needs a directory.
    let dir = tempfile::tempdir().expect("tempdir");

    let response = Box::pin(LORE_CONTEXT.scope(execution, async move {
        let immutable_store: Arc<dyn lore_storage::ImmutableStore> =
            lore_storage::LocalImmutableStore::new(
                Some(dir.path().to_path_buf()),
                lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
            )
            .await
            .expect("local store");
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store.clone(),
            mutable_store,
            Arc::new(AllowAllRepositoryAuthorizer),
            true,
        );
        let (fragment, address, payload) = lore_revision::fragment::generate_random();
        immutable_store
            .clone()
            .put(repository, address, fragment, Some(payload), false)
            .await
            .expect("put a fragment");
        immutable_store.flush(true).await.expect("flush");
        StorageServiceV1::verify(&service, verify_request(repository, address)).await
    }))
    .await
    .expect("a local store verifies a fragment it holds");
    assert!(!response.into_inner().corrupted);
}

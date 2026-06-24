// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

use super::copy;
use super::copy::CopyResponseStream;
use super::get;
use super::get::GetResponseStream;
use super::get_metadata;
use super::mutable_compare_and_swap;
use super::mutable_load;
use super::mutable_store;
use super::put;
use super::put::PutResponseStream;
use super::query;
use super::verify;
use crate::grpc::get_repository;
use crate::grpc::require_permission;
use crate::grpc::storage_service::LoreStorageService;

#[tonic::async_trait]
impl StorageServiceV1 for LoreStorageService {
    type GetStream = GetResponseStream;

    async fn get(
        &self,
        request: Request<Streaming<lore_proto::lore::model::v1::Address>>,
    ) -> Result<Response<Self::GetStream>, Status> {
        get::handler(request, self.immutable_store().clone(), self).await
    }

    type GetMetadataStream = GetResponseStream;

    async fn get_metadata(
        &self,
        request: Request<Streaming<lore_proto::lore::model::v1::Address>>,
    ) -> Result<Response<Self::GetMetadataStream>, Status> {
        get_metadata::handler(request, self.immutable_store().clone(), self).await
    }

    type PutStream = PutResponseStream;

    async fn put(
        &self,
        request: Request<Streaming<storage_v1::PutRequest>>,
    ) -> Result<Response<Self::PutStream>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission(),
        )?;
        put::handler(request, self.immutable_store().clone(), self).await
    }

    async fn query(
        &self,
        request: Request<storage_v1::QueryRequest>,
    ) -> Result<Response<storage_v1::QueryResponse>, Status> {
        query::handler(request, self.immutable_store().clone()).await
    }

    type CopyStream = CopyResponseStream;

    async fn copy(
        &self,
        request: Request<Streaming<storage_v1::CopyRequest>>,
    ) -> Result<Response<Self::CopyStream>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission(),
        )?;
        copy::handler(request, self.immutable_store().clone(), self).await
    }

    async fn verify(
        &self,
        request: Request<storage_v1::VerifyRequest>,
    ) -> Result<Response<storage_v1::VerifyResponse>, Status> {
        verify::handler(request, self.local_immutable_store().clone()).await
    }

    async fn mutable_load(
        &self,
        request: Request<storage_v1::MutableLoadRequest>,
    ) -> Result<Response<storage_v1::MutableLoadResponse>, Status> {
        mutable_load::handler(request, self.mutable_store().clone()).await
    }

    async fn mutable_store(
        &self,
        request: Request<storage_v1::MutableStoreRequest>,
    ) -> Result<Response<storage_v1::MutableStoreResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission(),
        )?;
        mutable_store::handler(request, self.mutable_store().clone()).await
    }

    async fn mutable_compare_and_swap(
        &self,
        request: Request<storage_v1::MutableCompareAndSwapRequest>,
    ) -> Result<Response<storage_v1::MutableCompareAndSwapResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission(),
        )?;
        mutable_compare_and_swap::handler(request, self.mutable_store().clone()).await
    }
}

#[cfg(test)]
mod tests {
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Hash;
    use lore_proto::lore::storage::v1 as storage_v1;
    use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
    use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
    use lore_revision::lore::RepositoryId;
    use lore_transport::grpc::REPOSITORY_ID_KEY;
    use rand::random;
    use tonic::Code;
    use tonic::Request;
    use zerocopy::IntoBytes;

    use crate::auth::jwt::AuthorizationToken;
    use crate::auth::jwt::ResourcePermission;
    use crate::grpc::storage_service::LoreStorageService;
    use crate::store::test_store_create;

    /// Compile-time check that `LoreStorageService` fully implements the generated
    /// `StorageService` trait — wrapping it in `StorageServiceServer` requires the
    /// trait bound to hold. Per-handler behavior is tested in each handler module.
    #[allow(dead_code)]
    fn assert_implements_trait(
        service: LoreStorageService,
    ) -> StorageServiceServer<LoreStorageService> {
        StorageServiceServer::new(service)
    }

    fn insert_repo_and_token<T>(
        request: &mut Request<T>,
        repository: RepositoryId,
        perms: &[&str],
    ) {
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
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("stores");
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
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
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("stores");
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
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
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("stores");
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
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
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("stores");
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
            false,
        );

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            StorageServiceV1::mutable_store(&service, mutable_store_request(repository, &["read"]))
                .await
                .expect("enforcement disabled lets a read-only token through");
        }))
        .await;
    }
}

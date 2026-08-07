// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::types::Context;
use lore_base::types::Partition;
use lore_proto::lore::repository::v1::RepositoryStorageStatsRequest;
use lore_proto::lore::repository::v1::RepositoryStorageStatsResponse;
use lore_storage::StoreError;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::grpc::handlers::repository_query::check_repository_query_authorization;

/// `lore.repository.v1.RepositoryService.RepositoryStorageStats` handler.
///
/// Read-only aggregate of what the repository's fragments occupy in the store,
/// answered straight from the store's own fragment-metadata index. An unknown
/// repository has no associations and so reports zeroes rather than NOT_FOUND.
///
/// Backend-dependent: a store with no repository-keyed access path over its
/// fragment index reports `NotSupported`, which surfaces as UNIMPLEMENTED. That
/// is deliberate — the alternative is a full scan of every fragment the store
/// holds, billed to a caller who asked for one repository's number. A *wrapped*
/// store (composite / replicated / remote) reports UNIMPLEMENTED too; see
/// [`lore_storage::ImmutableStore::repository_stats`].
///
/// Unlike its sibling v1 handlers this one sets up no `LORE_CONTEXT` scope: it
/// makes a single store call and touches nothing that reads the execution
/// context. The trade is that its spans carry no correlation id.
#[tracing::instrument(name = "RepositoryStorageStats::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryStorageStatsRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
) -> Result<Response<RepositoryStorageStatsResponse>, Status> {
    let authorization = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());
    let req = request.into_inner();

    let repository_id: Context = req.id.into();
    if repository_id == Context::default() {
        return Err(Status::invalid_argument("Missing repository id"));
    }

    // Scope the read to the caller's repository. RepositoryService rides the
    // authn-only interceptor (UCS-13506), so the body repository id is not
    // authorized upstream; re-check it via the same ReBAC callback the sibling
    // read RPCs use. Auth-OFF (no auth_url) leaves behavior unchanged.
    if let Some(auth_url) = auth_url {
        check_repository_query_authorization(auth_url, authorization, repository_id.into()).await?;
    }

    let stats = immutable_store
        .repository_stats(Partition::from(repository_id))
        .await
        .map_err(|err| match err {
            StoreError::NotSupported(_) => Status::unimplemented(err.to_string()),
            StoreError::SlowDown(_) => Status::resource_exhausted(err.to_string()),
            _ => Status::internal(err.to_string()),
        })?;

    Ok(Response::new(RepositoryStorageStatsResponse {
        fragment_count: stats.fragment_count,
        payload_bytes: stats.payload_bytes,
        content_bytes: stats.content_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use bytes::Bytes;
    use lore_proto::lore::repository::v1::RepositoryStorageStatsRequest;
    use lore_revision::lore::RepositoryId;
    use lore_storage::ImmutableStore;
    use lore_storage::StoreMatch;
    use lore_storage::StoreObliterateStats;
    use lore_storage::StoreQueryResult;
    use lore_storage::errors::NotFound;
    use lore_storage::errors::NotSupported;
    use lore_storage::errors::SlowDown;
    use tonic::Request;

    use super::handler;
    use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
    use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server;

    fn request_for(repository_id: RepositoryId) -> Request<RepositoryStorageStatsRequest> {
        let mut request = Request::new(RepositoryStorageStatsRequest {
            id: repository_id.into(),
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer test-token".parse().unwrap());
        request
    }

    /// Same request shape, no `authorization` metadata — used with `auth_url =
    /// None` where the header would otherwise be unused.
    fn request_no_auth(repository_id: RepositoryId) -> Request<RepositoryStorageStatsRequest> {
        Request::new(RepositoryStorageStatsRequest {
            id: repository_id.into(),
        })
    }

    #[tokio::test]
    async fn denies_storage_stats_for_a_repository_the_caller_is_not_authorized_for() {
        let caller_authorized_repo = RepositoryId::from([21u8; 16]);
        let target_repo = RepositoryId::from([22u8; 16]);
        let (immutable, _mutable) = new_test_stores().await;
        let auth_url = start_stub_auth_server(caller_authorized_repo).await;

        let result = handler(request_for(target_repo), Some(auth_url), immutable).await;

        // This is the headline case: the gate must run BEFORE the store is
        // ever touched. A handler that compiles and looks plausible but
        // forgets the authz check would instead return whatever the (empty)
        // local store reports for the target repository.
        let err = result.expect_err("caller is not authorized for the target repository");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn accepts_the_callers_own_repository_but_the_local_store_has_no_stats_support() {
        let repository_id = RepositoryId::from([23u8; 16]);
        let (immutable, _mutable) = new_test_stores().await;
        let auth_url = start_stub_auth_server(repository_id).await;

        let result = handler(request_for(repository_id), Some(auth_url), immutable).await;

        // The authz check passes for a legitimate caller reading its own
        // repository; `LocalImmutableStore` has no `repository_stats`
        // override, so it falls through to the trait default
        // (`StoreError::NotSupported`), which this handler maps to
        // `Unimplemented`. Asserting `Unimplemented` here (not
        // `PermissionDenied`) is the proof that the gate let this caller
        // through.
        let err = result.expect_err("local store has no repository_stats support");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn auth_off_reaches_the_store_without_an_authorization_check() {
        let repository_id = RepositoryId::from([24u8; 16]);
        let (immutable, _mutable) = new_test_stores().await;

        let result = handler(request_for(repository_id), None, immutable).await;

        // Same Unimplemented outcome as the auth-ON own-repository case above
        // (no stub auth server involved at all here) — proves auth-OFF
        // behavior is unchanged by this handler.
        let err = result.expect_err("local store has no repository_stats support");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn missing_repository_id_is_invalid_argument() {
        let (immutable, _mutable) = new_test_stores().await;
        let request = Request::new(RepositoryStorageStatsRequest {
            id: Default::default(),
        });

        let result = handler(request, None, immutable).await;

        let err = result.expect_err("default repository id must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// Minimal `ImmutableStore` stand-in whose `repository_stats` returns a
    /// canned result. Every other trait method is unreachable from these
    /// tests (the handler under test only ever calls `repository_stats`) and
    /// panics if called, so an accidental extra call fails loudly.
    struct StatsStubStore {
        result: Result<lore_storage::StoreRepositoryStats, lore_storage::StoreError>,
    }

    #[async_trait]
    impl ImmutableStore for StatsStubStore {
        async fn exist(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
            _address: lore_storage::Address,
            _match_requested: StoreMatch,
        ) -> Result<StoreMatch, lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn exist_batch(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
            _addresses: &[lore_storage::Address],
            _match_requested: StoreMatch,
        ) -> Result<Vec<StoreMatch>, lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn query(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
            _address: lore_storage::Address,
            _match_requested: StoreMatch,
        ) -> Result<StoreQueryResult, lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn get_metadata(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
            _address: lore_storage::Address,
        ) -> Result<StoreQueryResult, lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn get(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
            _address: lore_storage::Address,
            _match_required: StoreMatch,
        ) -> Result<(lore_storage::Fragment, Bytes), lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn put(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
            _address: lore_storage::Address,
            _fragment: lore_storage::Fragment,
            _payload: Option<Bytes>,
            _force: bool,
        ) -> Result<(), lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn obliterate(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
            _address: lore_storage::Address,
            _stats: Arc<StoreObliterateStats>,
        ) -> Result<(), lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn evict(
            self: Arc<Self>,
            _max_capacity: usize,
            _sync_data: bool,
            _sink: Option<lore_storage::gc_event::GcEventSinkRef>,
        ) -> Result<usize, lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn compact(
            self: Arc<Self>,
            _max_size: usize,
            _at: Option<usize>,
            _sync_data: bool,
            _sink: Option<lore_storage::gc_event::GcEventSinkRef>,
        ) -> Result<Option<usize>, lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn compact_stop(self: Arc<Self>) {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        fn max_query_batch(&self) -> Option<usize> {
            None
        }

        async fn flush(self: Arc<Self>, _sync_data: bool) -> Result<(), lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn verify(self: Arc<Self>, _heal: bool) -> Result<(), lore_storage::StoreError> {
            unimplemented!("not exercised by repository_storage_stats tests")
        }

        async fn repository_stats(
            self: Arc<Self>,
            _partition: lore_storage::Partition,
        ) -> Result<lore_storage::StoreRepositoryStats, lore_storage::StoreError> {
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn success_copies_the_three_fields_through_without_transposing_them() {
        let repository_id = RepositoryId::from([25u8; 16]);
        let store: Arc<dyn ImmutableStore> = Arc::new(StatsStubStore {
            result: Ok(lore_storage::StoreRepositoryStats {
                fragment_count: 3,
                payload_bytes: 111,
                content_bytes: 222,
            }),
        });

        let response = handler(request_no_auth(repository_id), None, store)
            .await
            .expect("stub store reports success")
            .into_inner();

        assert_eq!(response.fragment_count, 3);
        assert_eq!(
            response.payload_bytes, 111,
            "payload_bytes must not be swapped with content_bytes"
        );
        assert_eq!(
            response.content_bytes, 222,
            "content_bytes must not be swapped with payload_bytes"
        );
    }

    #[tokio::test]
    async fn slow_down_maps_to_resource_exhausted() {
        let repository_id = RepositoryId::from([26u8; 16]);
        let store: Arc<dyn ImmutableStore> = Arc::new(StatsStubStore {
            result: Err(lore_storage::StoreError::from(SlowDown)),
        });

        let result = handler(request_no_auth(repository_id), None, store).await;

        let err = result.expect_err("SlowDown must surface as an error");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn not_supported_maps_to_unimplemented() {
        let repository_id = RepositoryId::from([27u8; 16]);
        let store: Arc<dyn ImmutableStore> = Arc::new(StatsStubStore {
            result: Err(lore_storage::StoreError::from(NotSupported {
                operation: "repository_stats".to_string(),
            })),
        });

        let result = handler(request_no_auth(repository_id), None, store).await;

        let err = result.expect_err("NotSupported must surface as an error");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn other_store_errors_map_to_internal() {
        let repository_id = RepositoryId::from([28u8; 16]);
        let store: Arc<dyn ImmutableStore> = Arc::new(StatsStubStore {
            result: Err(lore_storage::StoreError::from(NotFound)),
        });

        let result = handler(request_no_auth(repository_id), None, store).await;

        let err = result.expect_err("an unmapped store error must still surface as an error");
        assert_eq!(err.code(), tonic::Code::Internal);
    }
}

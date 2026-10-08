// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use lore_proto::lore::repository::v1::RepositoryStorageStatsRequest;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
use lore_server::authnz::repository_authorizer::RawToken;
use lore_server::grpc::repository::v1::repository_storage_stats::handler;
use lore_storage::ImmutableStore;
use lore_storage::StoreGetData;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;
use lore_storage::errors::NotFound;
use lore_storage::errors::NotSupported;
use lore_storage::errors::SlowDown;
use tonic::Request;

use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server;

/// Auth OFF: the selection a config with no `[server.auth]` gets.
fn allow_all() -> Arc<dyn lore_server::authnz::repository_authorizer::RepositoryAuthorizer> {
    Arc::new(AllowAllRepositoryAuthorizer)
}

fn request_for(repository_id: RepositoryId) -> Request<RepositoryStorageStatsRequest> {
    let mut request = Request::new(RepositoryStorageStatsRequest {
        id: repository_id.into(),
    });
    request
        .metadata_mut()
        .insert("authorization", "Bearer test-token".parse().unwrap());
    // The verified halves the interceptor inserts: an identity token (no
    // `resources` claim), so the online check is asked.
    request
        .extensions_mut()
        .insert(AuthorizationToken::default());
    request
        .extensions_mut()
        .insert(RawToken("test-token".into()));
    request
}

/// Same request shape, no `authorization` metadata or token — used with
/// `AllowAllRepositoryAuthorizer` (auth OFF).
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

    let result = handler(
        request_for(target_repo),
        Arc::new(AuthClientAuthorizer::new(auth_url)),
        immutable,
    )
    .await;

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

    let result = handler(
        request_for(repository_id),
        Arc::new(AuthClientAuthorizer::new(auth_url)),
        immutable,
    )
    .await;

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

    let result = handler(request_for(repository_id), allow_all(), immutable).await;

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

    let result = handler(request, allow_all(), immutable).await;

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

// Reason: every method but `repository_stats` is deliberately unreachable from these tests
// (see the doc comment above) and panics loudly via `unimplemented!()` if the handler ever
// calls one by accident - that is this stub's whole reason to exist, not a missing feature.
#[allow(clippy::unimplemented)]
#[async_trait]
impl ImmutableStore for StatsStubStore {
    async fn query(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _addresses: &[lore_storage::Address],
        _results: &mut [StoreMatchResult],
    ) -> Result<(), lore_storage::StoreError> {
        unimplemented!("not exercised by repository_storage_stats tests")
    }

    async fn get_metadata(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _address: lore_storage::Address,
    ) -> Result<StoreGetData, lore_storage::StoreError> {
        unimplemented!("not exercised by repository_storage_stats tests")
    }

    async fn get(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _address: lore_storage::Address,
    ) -> Result<StoreGetData, lore_storage::StoreError> {
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

    async fn stop_gc(self: Arc<Self>, _terminate: bool) {
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

    async fn copy(
        self: Arc<Self>,
        _source_partition: lore_storage::Partition,
        _source_address: lore_storage::Address,
        _destination_partition: lore_storage::Partition,
        _destination_context: lore_storage::Context,
        _behavior: lore_storage::immutable_store::CopyBehavior,
    ) -> Result<(), lore_storage::StoreError> {
        unimplemented!("not exercised by repository_storage_stats tests")
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

    let response = handler(request_no_auth(repository_id), allow_all(), store)
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

    let result = handler(request_no_auth(repository_id), allow_all(), store).await;

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

    let result = handler(request_no_auth(repository_id), allow_all(), store).await;

    let err = result.expect_err("NotSupported must surface as an error");
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn other_store_errors_map_to_internal() {
    let repository_id = RepositoryId::from([28u8; 16]);
    let store: Arc<dyn ImmutableStore> = Arc::new(StatsStubStore {
        result: Err(lore_storage::StoreError::from(NotFound)),
    });

    let result = handler(request_no_auth(repository_id), allow_all(), store).await;

    let err = result.expect_err("an unmapped store error must still surface as an error");
    assert_eq!(err.code(), tonic::Code::Internal);
}

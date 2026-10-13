// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::lore::repository::v1::RepositoryGetRequest;
use lore_proto::lore::repository::v1::RepositoryGetResponse;
use lore_proto::lore::repository::v1::repository_get_request::Query;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedToken;
use lore_server::grpc::forwarded_requests::ForwardedRequests;
use lore_server::grpc::repository::v1::repository_get::*;
use lore_storage::KeyValueStream;
use lore_storage::MutableStore;
use lore_storage::Partition;
use lore_storage::StoreError;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;

/// Wraps a real `MutableStore`, delegating every method except `store()`,
/// which always fails once wrapped. Mirrors the self-heal write's actual
/// failure mode under CR-029 enforcement (the domain-key bypass guard
/// rejects a `RepositoryId`-typed write on the generic mutable path —
/// see `lore-postgres/tests/domain_bypass.rs`) without depending on a
/// live Postgres store.
struct FailStoreWritesMutableStore {
    inner: Arc<dyn MutableStore>,
}

#[async_trait::async_trait]
impl MutableStore for FailStoreWritesMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: lore_base::types::KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        _partition: Partition,
        _key: Hash,
        _value: Hash,
        _key_type: lore_base::types::KeyType,
    ) -> Result<(), StoreError> {
        Err(StoreError::internal(
            "simulated domain-key bypass guard rejection",
        ))
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: lore_base::types::KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        partition: Partition,
        key_type: lore_base::types::KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}

// CR-029, self-heal writer pin (companion to `lore-postgres/tests/
// domain_bypass.rs`, which proves the guard itself rejects the write —
// this proves the call site at line 147 swallows that rejection rather
// than propagating it). The reviewer's defence for leaving this handler
// ungated is that a missing name -> ID mapping is repaired best-effort;
// if a future cleanup ever turns the `let _ = ...` into a `?`, this test
// must go red.
#[tokio::test]
async fn missing_name_mapping_repair_failure_does_not_fail_the_get() {
    let (immutable, mutable) = new_test_stores().await;
    let repository_id: RepositoryId = Context::from([9u8; 16]).into();
    let metadata_hash = seed_repository_metadata(
        immutable.clone(),
        mutable.clone(),
        repository_id,
        "my-repo",
        "a description",
    )
    .await;

    let faulty_mutable: Arc<dyn MutableStore> =
        Arc::new(FailStoreWritesMutableStore { inner: mutable });
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable,
        faulty_mutable,
        repository_id,
    ));

    let (metadata, hash) = repository_load_id(repository, repository_id, None, None)
        .await
        .expect("a failed name-mapping repair must not fail the get");

    assert_eq!(metadata.name, "my-repo");
    assert_eq!(hash, metadata_hash);
}

mod forwarded_request {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use lore_proto::lore::repository::v1::RepositoryCreateRequest;
    use lore_proto::lore::repository::v1::RepositoryCreateResponse;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::grpc::forwarded_requests::ForwardedRequestResult;
    use lore_server::grpc::forwarded_requests::InternalClientError;
    use lore_server::grpc::forwarded_requests::RpcFlags;
    use lore_server::grpc::forwarded_requests::repository_service::ForwardedRepositoryServiceClient;
    use lore_server::grpc::forwarded_requests::revision_service::ForwardedRevisionServiceClient;
    use lore_server::grpc::repository::v1::repository_get::*;
    use rand::random;

    use super::*;
    use crate::store::test_support::test_store_create;

    /// Single-use client that returns a pre-configured result on its one call.
    struct SingleShotClient {
        response: Arc<Mutex<Option<ForwardedRequestResult<RepositoryGetResponse>>>>,
    }

    #[async_trait]
    impl ForwardedRepositoryServiceClient for SingleShotClient {
        async fn repository_create(
            &mut self,
            _request: Request<RepositoryCreateRequest>,
        ) -> ForwardedRequestResult<RepositoryCreateResponse> {
            unreachable!("repository_create should not be called in repository_get tests")
        }

        async fn repository_get(
            &mut self,
            _request: Request<RepositoryGetRequest>,
        ) -> ForwardedRequestResult<RepositoryGetResponse> {
            self.response
                .lock()
                .unwrap()
                .take()
                .expect("repository_get called more than once")
        }
    }

    struct StubForwardedRequests {
        flags: RpcFlags,
        response: Arc<Mutex<Option<ForwardedRequestResult<RepositoryGetResponse>>>>,
    }

    impl StubForwardedRequests {
        fn new(
            repository_get: bool,
            response: ForwardedRequestResult<RepositoryGetResponse>,
        ) -> Arc<Self> {
            Arc::new(Self {
                flags: RpcFlags {
                    repository_get,
                    ..Default::default()
                },
                response: Arc::new(Mutex::new(Some(response))),
            })
        }

        fn forwarding_enabled(
            response: ForwardedRequestResult<RepositoryGetResponse>,
        ) -> Arc<Self> {
            Self::new(true, response)
        }

        fn forwarding_disabled(
            response: ForwardedRequestResult<RepositoryGetResponse>,
        ) -> Arc<Self> {
            Self::new(false, response)
        }
    }

    impl ForwardedRequests for StubForwardedRequests {
        fn rpc_flags(&self) -> &RpcFlags {
            &self.flags
        }

        fn forwarded_revision_service(&self) -> Box<dyn ForwardedRevisionServiceClient> {
            unreachable!("forwarded_revision_service should not be called in repository_get tests")
        }

        fn forwarded_repository_service(&self) -> Box<dyn ForwardedRepositoryServiceClient> {
            Box::new(SingleShotClient {
                response: Arc::clone(&self.response),
            })
        }
    }

    fn make_request(name: &str) -> Request<RepositoryGetRequest> {
        Request::new(RepositoryGetRequest {
            query: Some(Query::Name(name.into())),
        })
    }

    /// Writes the metadata blob, its pointer and the name → id mapping so a
    /// local lookup of `name` resolves.
    async fn seed_repository(
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
        id: RepositoryId,
        name: &str,
    ) {
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable_store,
            mutable_store,
            id,
        ));
        let metadata_hash = repository::metadata_store(
            repository.clone(),
            RepositoryMetadata {
                name: name.to_string(),
                creator: "alice".into(),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to store repository metadata");
        repository::metadata_store_hash(repository.clone(), metadata_hash)
            .await
            .expect("Failed to store repository metadata hash");
        repository::store_name_to_id(repository, name, id)
            .await
            .expect("Failed to store repository name to id mapping");
    }

    #[tokio::test]
    async fn delegates_to_remote_and_returns_response() {
        // When the flag is enabled the other server's response is returned directly;
        // repository_get_implementation is NOT called so the local store is not read.
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let repo_record = lore_proto::lore::model::v1::Repository {
            name: "test-repo".into(),
            ..Default::default()
        };
        let repo_response = Ok(Ok(Response::new(RepositoryGetResponse {
            repository: Some(repo_record),
            repository_generation: Some(42),
        })));
        let forwarded_requests = StubForwardedRequests::forwarding_enabled(repo_response);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let response = handler(
                make_request("test-repo"),
                Arc::new(AllowAllRepositoryAuthorizer),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                None, // no domain context
            )
            .await
            .expect("should succeed")
            .into_inner();

            // A forwarded response carries the remote server's generation through untouched.
            assert_eq!(response.repository_generation, Some(42));
            let repository = response
                .repository
                .expect("response should include Repository");
            assert_eq!(repository.name, "test-repo");
        }))
        .await;
    }

    #[tokio::test]
    async fn error_status_returned_to_caller() {
        // An error status from the forwarded server is forwarded directly to the original caller.
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let forwarded_request_result = Ok(Err(Status::not_found("test error forwarded")));
        let forwarded_requests =
            StubForwardedRequests::forwarding_enabled(forwarded_request_result);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let err = handler(
                make_request("test-repo"),
                Arc::new(AllowAllRepositoryAuthorizer),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                None, // no domain context
            )
            .await
            .expect_err("forwarded error should propagate");

            assert_eq!(err.code(), tonic::Code::NotFound);
            assert!(err.message().contains("test error forwarded"));
        }))
        .await;
    }

    #[tokio::test]
    async fn internal_client_error_maps_to_internal_status() {
        // A transport-level failure (InternalClientError) is mapped to Status::internal.
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let forwarded_requests =
            StubForwardedRequests::forwarding_enabled(Err(InternalClientError::internal("oops")));

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let err = handler(
                make_request("test-repo"),
                Arc::new(AllowAllRepositoryAuthorizer),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                None, // no domain context
            )
            .await
            .expect_err("transport error should become internal status");

            assert_eq!(err.code(), tonic::Code::Internal);
            assert!(err.message().contains("Error making forwarded request"));
        }))
        .await;
    }

    #[tokio::test]
    async fn flag_disabled_falls_through_to_local_execution() {
        // When repository_get is false the local path runs, even if a
        // ForwardedRequests is present. The stub client is not called.
        let id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        // response is irrelevant — client must never be called
        let forwarded_result = Ok(Err(Status::internal("should not be called")));
        let forwarded_requests = StubForwardedRequests::forwarding_disabled(forwarded_result);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed_repository(
                immutable_store.clone(),
                mutable_store.clone(),
                id,
                "my-repo",
            )
            .await;

            let response = handler(
                make_request("my-repo"),
                Arc::new(AllowAllRepositoryAuthorizer),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                None, // no domain context
            )
            .await
            .expect("local execution should succeed");

            let repository = response
                .into_inner()
                .repository
                .expect("response should include Repository");
            assert_eq!(repository.name, "my-repo");
            assert_eq!(repository.id, bytes::Bytes::from(id));
        }))
        .await;
    }

    /// Denial answers `RepositoryNotFound`, not `permission_denied`: a
    /// distinct status would let an unauthorized caller distinguish a
    /// partition that exists from one that does not.
    #[tokio::test]
    async fn denied_get_answers_not_found_for_an_existing_repository() {
        struct DenyAllRepositoryAuthorizer;

        #[async_trait]
        impl RepositoryAuthorizer for DenyAllRepositoryAuthorizer {
            async fn check_repository_access(
                &self,
                _token: Option<&VerifiedToken<'_>>,
                _repository_id: lore_base::types::RepositoryId,
                _action: Option<&str>,
            ) -> Result<(), Status> {
                Err(Status::permission_denied("denied"))
            }
        }

        let id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed_repository(
                immutable_store.clone(),
                mutable_store.clone(),
                id,
                "my-repo",
            )
            .await;

            let err = handler(
                make_request("my-repo"),
                Arc::new(DenyAllRepositoryAuthorizer),
                immutable_store,
                mutable_store,
                &None,
                None, // no domain context
            )
            .await
            .expect_err("denied get must fail");

            assert_eq!(err.code(), tonic::Code::NotFound, "{err:?}");
        }))
        .await;
    }
}

/// WP-120: `repository_generation` on `RepositoryGetResponse`.
mod refresh_generation {
    use std::sync::atomic::Ordering;

    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use rand::random;

    use super::*;
    use crate::grpc::generation_store::GenerationStore;
    use crate::grpc::generation_store::ReadHook;
    use crate::grpc::generation_store::RecordingMutableStore;
    use crate::grpc::generation_store::SequenceLog;
    use crate::store::test_support::test_store_create;

    async fn seed(
        immutable: Arc<dyn lore_storage::ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        id: RepositoryId,
    ) {
        seed_repository_metadata(immutable.clone(), mutable.clone(), id, "my-repo", "desc").await;
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable, mutable, id,
        ));
        repository::store_name_to_id(repository, "my-repo", id)
            .await
            .expect("store name to id mapping");
    }

    fn by_id(id: RepositoryId) -> Request<RepositoryGetRequest> {
        Request::new(RepositoryGetRequest {
            query: Some(Query::Id(id.into())),
        })
    }

    fn by_name() -> Request<RepositoryGetRequest> {
        Request::new(RepositoryGetRequest {
            query: Some(Query::Name("my-repo".into())),
        })
    }

    async fn get(
        request: Request<RepositoryGetRequest>,
        immutable: Arc<dyn lore_storage::ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        domain: Option<&Arc<lore_server::domain::DomainContext>>,
    ) -> Result<RepositoryGetResponse, Status> {
        get_as(
            request,
            Arc::new(AllowAllRepositoryAuthorizer),
            immutable,
            mutable,
            domain,
        )
        .await
    }

    async fn get_as(
        request: Request<RepositoryGetRequest>,
        authorizer: Arc<dyn RepositoryAuthorizer>,
        immutable: Arc<dyn lore_storage::ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        domain: Option<&Arc<lore_server::domain::DomainContext>>,
    ) -> Result<RepositoryGetResponse, Status> {
        handler(request, authorizer, immutable, mutable, &None, domain)
            .await
            .map(Response::into_inner)
    }

    #[tokio::test]
    async fn generation_is_absent_without_a_domain_context() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            for request in [by_id(id), by_name()] {
                let response = get(request, immutable.clone(), mutable.clone(), None)
                    .await
                    .expect("get succeeds without a domain context");
                assert!(response.repository.is_some());
                assert_eq!(response.repository_generation, None);
            }
        }))
        .await;
    }

    #[tokio::test]
    async fn generation_is_passed_through_by_id_and_by_name() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(Some(7), None);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            for request in [by_id(id), by_name()] {
                let response = get(request, immutable.clone(), mutable.clone(), Some(&domain))
                    .await
                    .expect("get succeeds");
                assert_eq!(response.repository_generation, Some(7));
                let repository = response.repository.expect("record still returned");
                assert_eq!(repository.name, "my-repo");
            }
            assert_eq!(store.repository_reads.load(Ordering::SeqCst), 2);
        }))
        .await;
    }

    /// Zero is a real generation. Dropping it as "unset" would let a client
    /// holding 0 mistake absence for "unchanged".
    #[tokio::test]
    async fn generation_zero_is_present_not_dropped() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(Some(0), None);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            let response = get(by_id(id), immutable, mutable, Some(&domain))
                .await
                .expect("get succeeds");
            assert_eq!(response.repository_generation, Some(0));
        }))
        .await;
    }

    /// A context whose enforcement is off has no authoritative rows: the field
    /// is absent and the store is never asked.
    #[tokio::test]
    async fn generation_is_absent_when_enforcement_is_off() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(Some(7), None);
        let domain = store.context(false);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            let response = get(by_id(id), immutable, mutable, Some(&domain))
                .await
                .expect("get succeeds");
            assert_eq!(response.repository_generation, None);
            assert_eq!(store.repository_reads.load(Ordering::SeqCst), 0);
        }))
        .await;
    }

    #[tokio::test]
    async fn generation_is_absent_when_the_domain_row_is_missing() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(None, None);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            let response = get(by_id(id), immutable, mutable, Some(&domain))
                .await
                .expect("get succeeds");
            assert!(response.repository.is_some());
            assert_eq!(response.repository_generation, None);
            assert_eq!(store.repository_reads.load(Ordering::SeqCst), 1);
        }))
        .await;
    }

    /// A negative stored value is not a generation a client can compare.
    #[tokio::test]
    async fn a_negative_stored_generation_reads_as_absent() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(Some(-1), None);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            let response = get(by_id(id), immutable, mutable, Some(&domain))
                .await
                .expect("get succeeds");
            assert_eq!(response.repository_generation, None);
        }))
        .await;
    }

    /// A repository the record read cannot find answers `NotFound`, never a
    /// response carrying a generation.
    #[tokio::test]
    async fn an_unknown_repository_is_not_found_even_with_a_generation_available() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(Some(7), None);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let error = get(by_id(id), immutable, mutable, Some(&domain))
                .await
                .expect_err("unknown repository");
            assert_eq!(error.code(), tonic::Code::NotFound, "{error:?}");
        }))
        .await;
    }

    struct DenyAllRepositoryAuthorizer;

    #[async_trait::async_trait]
    impl RepositoryAuthorizer for DenyAllRepositoryAuthorizer {
        async fn check_repository_access(
            &self,
            _token: Option<&VerifiedToken<'_>>,
            _repository_id: lore_base::types::RepositoryId,
            _action: Option<&str>,
        ) -> Result<(), Status> {
            Err(Status::permission_denied("denied"))
        }
    }

    /// The generation is read BEFORE the projection: a mutation landing
    /// between the two reads then costs the client one extra refresh, while
    /// the reverse order could pair a fresh generation with stale data and
    /// hide a change. A shared sequence stamps the generation read and every
    /// projection (mutable-store) load.
    #[tokio::test]
    async fn the_generation_is_read_before_the_projection_by_id_and_by_name() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let log = SequenceLog::new();
        let store = GenerationStore::recording(Some(7), None, log.clone());
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            let recording = RecordingMutableStore::wrap(mutable.clone(), log.clone());
            for (label, request, by_id) in [("id", by_id(id), true), ("name", by_name(), false)] {
                log.clear();
                let response = get(request, immutable.clone(), recording.clone(), Some(&domain))
                    .await
                    .expect("get succeeds");
                assert_eq!(response.repository_generation, Some(7), "by {label}");
                let generation_reads = log.generation_reads();
                let loads = log.projection_loads();
                assert_eq!(generation_reads.len(), 1, "by {label}: one generation read");
                assert!(!loads.is_empty(), "by {label}: the record read must be observed");
                let generation = generation_reads[0];
                let last_load = *loads.last().expect("non-empty");
                assert!(
                    generation < last_load,
                    "by {label}: generation read ({generation}) must precede the record read ({last_load}); loads {loads:?}"
                );
                if by_id {
                    assert!(
                        generation < loads[0],
                        "by id: no projection load may precede the generation read; loads {loads:?}"
                    );
                }
            }
        }))
        .await;
    }

    /// A denied caller learns nothing the unarmed path would not tell it: the
    /// status is identical to the unarmed denied status and the generation
    /// store is never read.
    #[tokio::test]
    async fn an_armed_denied_get_matches_the_unarmed_status_and_never_reads_the_generation() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(Some(7), Some(9));
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            for (label, make) in [
                (
                    "id",
                    Box::new(move || by_id(id)) as Box<dyn Fn() -> Request<RepositoryGetRequest>>,
                ),
                ("name", Box::new(by_name)),
            ] {
                let unarmed = get_as(
                    make(),
                    Arc::new(DenyAllRepositoryAuthorizer),
                    immutable.clone(),
                    mutable.clone(),
                    None,
                )
                .await
                .expect_err("unarmed denied get must fail");
                let armed = get_as(
                    make(),
                    Arc::new(DenyAllRepositoryAuthorizer),
                    immutable.clone(),
                    mutable.clone(),
                    Some(&domain),
                )
                .await
                .expect_err("armed denied get must fail");
                assert_eq!(armed.code(), unarmed.code(), "by {label}: {armed:?}");
                assert_eq!(armed.message(), unarmed.message(), "by {label}");
                assert_eq!(
                    store.repository_reads.load(Ordering::SeqCst),
                    0,
                    "by {label}: a denied caller must not cause a generation read"
                );
            }
        }))
        .await;
    }

    /// A failing generation read must not fail the record read.
    #[tokio::test]
    async fn a_generation_read_error_leaves_the_generation_absent_and_the_get_succeeds() {
        let id = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::failing();
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            for (label, request) in [("id", by_id(id)), ("name", by_name())] {
                let before = store.repository_reads.load(Ordering::SeqCst);
                let response = get(request, immutable.clone(), mutable.clone(), Some(&domain))
                    .await
                    .unwrap_or_else(|error| panic!("by {label}: get must succeed: {error:?}"));
                assert!(
                    store.repository_reads.load(Ordering::SeqCst) > before,
                    "by {label}: the failing read must actually have been attempted"
                );
                assert_eq!(response.repository_generation, None, "by {label}");
                assert_eq!(
                    response.repository.expect("record still returned").name,
                    "my-repo",
                    "by {label}"
                );
            }
        }))
        .await;
    }

    /// A name resolves twice (once for the generation, once for the record).
    /// If the mapping moved in between, the generation belongs to the other
    /// repository and must be dropped, while the record read still answers
    /// for the repository the name now points at.
    #[tokio::test]
    async fn a_name_that_moves_between_resolves_drops_the_generation() {
        let id = random::<RepositoryId>();
        let moved_to = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let other = Arc::new(RepositoryContext::new_server_context(
            immutable.clone(),
            mutable.clone(),
            moved_to,
        ));
        let hook: ReadHook = Arc::new(move || {
            let other = other.clone();
            Box::pin(async move {
                repository::store_name_to_id(other, "my-repo", moved_to)
                    .await
                    .expect("re-point the name between the two resolves");
            })
        });
        let store = GenerationStore::with_read_hook(Some(7), None, hook);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            // The record the name will point at carries the same name (the
            // record read refuses a mapping whose metadata disagrees) and a
            // distinguishing description.
            seed_repository_metadata(
                immutable.clone(),
                mutable.clone(),
                moved_to,
                "my-repo",
                "moved",
            )
            .await;
            let response = get(by_name(), immutable, mutable, Some(&domain))
                .await
                .expect("get succeeds");
            assert_eq!(store.repository_reads.load(Ordering::SeqCst), 1);
            let repository = response.repository.expect("record returned");
            assert_eq!(
                repository.description, "moved",
                "sanity: the second resolve saw the moved mapping"
            );
            assert_eq!(
                response.repository_generation, None,
                "the generation read for the first id must not ride along with the other repository"
            );
        }))
        .await;
    }

    struct AllowOnlyRepositoryAuthorizer(RepositoryId);

    #[async_trait::async_trait]
    impl RepositoryAuthorizer for AllowOnlyRepositoryAuthorizer {
        async fn check_repository_access(
            &self,
            _token: Option<&VerifiedToken<'_>>,
            repository_id: lore_base::types::RepositoryId,
            _action: Option<&str>,
        ) -> Result<(), Status> {
            if repository_id == self.0 {
                Ok(())
            } else {
                Err(Status::permission_denied("denied"))
            }
        }
    }

    /// The authorization already done for the first resolve covers that id
    /// only. If the name moves to a different id before the record read, the
    /// new id is authorized afresh; a denial answers the same `NotFound` as a
    /// denied caller and returns no record data.
    #[tokio::test]
    async fn a_name_that_moves_to_a_denied_id_between_resolves_is_not_found() {
        let id = random::<RepositoryId>();
        let moved_to = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let other = Arc::new(RepositoryContext::new_server_context(
            immutable.clone(),
            mutable.clone(),
            moved_to,
        ));
        let hook: ReadHook = Arc::new(move || {
            let other = other.clone();
            Box::pin(async move {
                repository::store_name_to_id(other, "my-repo", moved_to)
                    .await
                    .expect("re-point the name between the two resolves");
            })
        });
        let store = GenerationStore::with_read_hook(Some(7), None, hook);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            seed(immutable.clone(), mutable.clone(), id).await;
            seed_repository_metadata(
                immutable.clone(),
                mutable.clone(),
                moved_to,
                "my-repo",
                "secret",
            )
            .await;
            let denied_baseline = get_as(
                by_name(),
                Arc::new(DenyAllRepositoryAuthorizer),
                immutable.clone(),
                mutable.clone(),
                None,
            )
            .await
            .expect_err("a denied caller gets NotFound");
            let error = get_as(
                by_name(),
                Arc::new(AllowOnlyRepositoryAuthorizer(id)),
                immutable,
                mutable,
                Some(&domain),
            )
            .await
            .expect_err("the moved-to id is denied");
            assert_eq!(
                store.repository_reads.load(Ordering::SeqCst),
                1,
                "sanity: the mapping moved after the first id was authorized"
            );
            assert_eq!(error.code(), denied_baseline.code(), "{error:?}");
            assert_eq!(error.message(), denied_baseline.message());
        }))
        .await;
    }
}

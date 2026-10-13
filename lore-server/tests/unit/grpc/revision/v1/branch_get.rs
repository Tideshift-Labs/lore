// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::BranchPoint;
use lore_base::types::Hash;
use lore_proto::lore::revision::v1::BranchGetRequest;
use lore_proto::lore::revision::v1::BranchGetResponse;
use lore_proto::lore::revision::v1::branch_get_request::Query as BranchGetQuery;
use lore_revision::branch;
use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::repository::RepositoryContext;
use lore_revision::state;
use lore_server::grpc::get_write_token;
use lore_server::grpc::handlers::branch_push;
use lore_server::grpc::revision::v1::branch_get::*;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::Request;

use crate::store::test_support::test_store_create;

/// Returns the latest revision the test branch was forked at.
async fn create_test_branch(repository_context: Arc<RepositoryContext>, branch: BranchId) -> Hash {
    let write_token = get_write_token();
    let main = lore_revision::branch::create(
        repository_context.clone(),
        &write_token,
        BranchId::from(uuid::Uuid::now_v7()),
        branch::DEFAULT_DEFAULT_NAME,
        branch::default_category(),
        "test-creator",
        1,
        vec![],
        false,
        false,
    )
    .await
    .expect("Could not create main branch");

    let state = state::State::new();
    state.set_parent_self(Hash::default());
    state.set_revision_number(1);
    let state_hash = state
        .serialize(repository_context.clone(), &write_token)
        .await
        .expect("Failed to serialize state");

    let latest = branch_push::push(
        repository_context.clone(),
        main,
        state_hash,
        true,
        true,
        false,
        DEFAULT_HISTORY_STEP_SIZE,
        lore_server::grpc::server::RevisionListAcceleration::default(),
    )
    .await
    .expect("Failed to push latest revision")
    .revision;

    lore_revision::branch::create(
        repository_context.clone(),
        &write_token,
        branch,
        "test-name",
        branch::personal_category(),
        "BranchCreator",
        12345,
        vec![BranchPoint {
            branch: main,
            revision: latest,
        }],
        false,
        false,
    )
    .await
    .expect("Could not create test branch");

    latest
}

fn make_request_id(repository: RepositoryId, branch: BranchId) -> Request<BranchGetRequest> {
    let mut request = Request::new(BranchGetRequest {
        query: Some(BranchGetQuery::Id(branch.into())),
    });
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    request
}

fn make_request_name(repository: RepositoryId, name: &str) -> Request<BranchGetRequest> {
    let mut request = Request::new(BranchGetRequest {
        query: Some(BranchGetQuery::Name(name.into())),
    });
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    request
}

mod direct_handling {
    use super::*;

    #[tokio::test]
    async fn get_by_id_returns_branch_record() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let latest = create_test_branch(repository_context, branch_id).await;

            let response = handler(
                make_request_id(repository, branch_id),
                immutable_store.clone(),
                mutable_store.clone(),
                &None, /* no forwarded requests */
                None,  // no domain context
            )
            .await
            .expect("Request failed");

            let branch = response
                .into_inner()
                .branch
                .expect("response should include Branch");
            assert!(!branch.deleted);
            assert_eq!(branch.name, "test-name");
            assert_eq!(branch.creator, "BranchCreator");
            assert_eq!(branch.category, branch::personal_category());
            assert_eq!(branch.created, 12345);
            assert_eq!(branch.latest, bytes::Bytes::from(latest));
            assert!(!branch.metadata.is_empty());
            assert_eq!(branch.stack.len(), 1);
        }))
        .await;
    }

    #[tokio::test]
    async fn get_by_name_returns_branch_record() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let latest = create_test_branch(repository_context, branch_id).await;

            let response = handler(
                make_request_name(repository, "test-name"),
                immutable_store.clone(),
                mutable_store.clone(),
                &None, /* no forwarded requests */
                None,  // no domain context
            )
            .await
            .expect("Request failed");

            let branch = response
                .into_inner()
                .branch
                .expect("response should include Branch");
            assert!(!branch.deleted);
            assert_eq!(branch.name, "test-name");
            assert_eq!(branch.latest, bytes::Bytes::from(latest));
        }))
        .await;
    }

    #[tokio::test]
    async fn get_by_id_returns_deleted_record_after_delete() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            create_test_branch(repository_context.clone(), branch_id).await;
            branch::delete(repository_context, branch_id)
                .await
                .expect("delete should succeed");

            let response = handler(
                make_request_id(repository, branch_id),
                immutable_store.clone(),
                mutable_store.clone(),
                &None, /* no forwarded requests */
                None,  // no domain context
            )
            .await
            .expect("Request failed");

            let branch = response.into_inner().branch.expect("Branch present");
            assert!(branch.deleted);
            assert_eq!(branch.name, "test-name");
        }))
        .await;
    }

    #[tokio::test]
    async fn get_by_name_after_delete_returns_not_found() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            create_test_branch(repository_context.clone(), branch_id).await;
            branch::delete(repository_context, branch_id)
                .await
                .expect("delete should succeed");

            let err = handler(
                make_request_name(repository, "test-name"),
                immutable_store.clone(),
                mutable_store.clone(),
                &None, /* no forwarded requests */
                None,  // no domain context
            )
            .await
            .expect_err("name lookup of deleted branch should fail");
            assert_eq!(err.code(), tonic::Code::NotFound);
        }))
        .await;
    }

    #[tokio::test]
    async fn get_unknown_id_returns_not_found() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let unknown = BranchId::from(uuid::Uuid::now_v7());
            let err = handler(
                make_request_id(repository, unknown),
                immutable_store.clone(),
                mutable_store.clone(),
                &None, /* no forwarded requests */
                None,  // no domain context
            )
            .await
            .expect_err("unknown id should fail");
            assert_eq!(err.code(), tonic::Code::NotFound);
        }))
        .await;
    }

    #[tokio::test]
    async fn get_unknown_name_returns_not_found() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let err = handler(
                make_request_name(repository, "no-such-branch"),
                immutable_store.clone(),
                mutable_store.clone(),
                &None, /* no forwarded requests */
                None,  // no domain context
            )
            .await
            .expect_err("unknown name should fail");
            assert_eq!(err.code(), tonic::Code::NotFound);
        }))
        .await;
    }

    #[tokio::test]
    async fn get_with_unset_query_returns_invalid_argument() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let mut request = Request::new(BranchGetRequest { query: None });
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let err = handler(
                request,
                immutable_store.clone(),
                mutable_store.clone(),
                &None, /* no forwarded requests */
                None,  // no domain context
            )
            .await
            .expect_err("unset query should fail");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
        }))
        .await;
    }
}

mod forwarded_request {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use lore_server::grpc::forwarded_requests::ForwardedRequestResult;
    use lore_server::grpc::forwarded_requests::ForwardedRequests;
    use lore_server::grpc::forwarded_requests::InternalClientError;
    use lore_server::grpc::forwarded_requests::RpcFlags;
    use lore_server::grpc::forwarded_requests::revision_service::ForwardedRevisionServiceClient;
    use tonic::Response;
    use tonic::Status;

    use super::*;

    /// Single-use client that returns a pre-configured result on its one call.
    struct SingleShotClient {
        response: Arc<Mutex<Option<ForwardedRequestResult<BranchGetResponse>>>>,
    }

    #[async_trait]
    impl ForwardedRevisionServiceClient for SingleShotClient {
        async fn branch_create(
            &mut self,
            _request: Request<lore_proto::lore::revision::v1::BranchCreateRequest>,
        ) -> ForwardedRequestResult<lore_proto::lore::revision::v1::BranchCreateResponse> {
            unreachable!("branch_create should not be called in branch_get tests")
        }

        async fn branch_delete(
            &mut self,
            _request: Request<lore_proto::lore::revision::v1::BranchDeleteRequest>,
        ) -> ForwardedRequestResult<lore_proto::lore::revision::v1::BranchDeleteResponse> {
            unreachable!("branch_delete should not be called in branch_get tests")
        }

        async fn branch_get(
            &mut self,
            _request: Request<BranchGetRequest>,
        ) -> ForwardedRequestResult<BranchGetResponse> {
            self.response
                .lock()
                .unwrap()
                .take()
                .expect("branch_get called more than once")
        }

        async fn branch_list(
            &mut self,
            _request: Request<lore_proto::lore::revision::v1::BranchListRequest>,
        ) -> ForwardedRequestResult<lore_server::grpc::revision::v1::branch_list::BranchListStream>
        {
            unreachable!("branch_list should not be called in branch_get tests")
        }
    }

    struct StubForwardedRequests {
        flags: RpcFlags,
        response: Arc<Mutex<Option<ForwardedRequestResult<BranchGetResponse>>>>,
    }

    impl StubForwardedRequests {
        fn forwarding_enabled(response: ForwardedRequestResult<BranchGetResponse>) -> Arc<Self> {
            Arc::new(Self {
                flags: RpcFlags {
                    revision_branch_get: true,
                    ..Default::default()
                },
                response: Arc::new(Mutex::new(Some(response))),
            })
        }

        fn forwarding_disabled(response: ForwardedRequestResult<BranchGetResponse>) -> Arc<Self> {
            Arc::new(Self {
                flags: RpcFlags {
                    revision_branch_get: false,
                    ..Default::default()
                },
                response: Arc::new(Mutex::new(Some(response))),
            })
        }
    }

    impl ForwardedRequests for StubForwardedRequests {
        fn rpc_flags(&self) -> &RpcFlags {
            &self.flags
        }

        fn forwarded_revision_service(&self) -> Box<dyn ForwardedRevisionServiceClient> {
            Box::new(SingleShotClient {
                response: Arc::clone(&self.response),
            })
        }

        fn forwarded_repository_service(
            &self,
        ) -> Box<dyn lore_server::grpc::forwarded_requests::repository_service::ForwardedRepositoryServiceClient>
{
            unreachable!("forwarded_repository_service should not be called in branch_create tests")
        }
    }

    fn make_request(repository: RepositoryId, branch_id: BranchId) -> Request<BranchGetRequest> {
        let mut request = Request::new(BranchGetRequest {
            query: Some(BranchGetQuery::Id(branch_id.into())),
        });
        request.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );
        request
    }

    #[tokio::test]
    async fn delegates_to_remote_and_returns_response() {
        // When the flag is enabled the other server's response is returned directly;
        // branch_get_implementation is NOT called so the local store is not read.
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let branch = lore_proto::lore::model::v1::Branch {
            name: "test-name".into(),
            ..Default::default()
        };
        let branch_response = Ok(Ok(Response::new(BranchGetResponse {
            branch: Some(branch),
            branch_generation: Some(42),
        })));
        let forwarded_requests = StubForwardedRequests::forwarding_enabled(branch_response);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let branch_id = BranchId::from(uuid::Uuid::now_v7());

            let response = handler(
                make_request(repository, branch_id),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                None, // no domain context
            )
            .await
            .expect("should succeed")
            .into_inner();

            // A forwarded response carries the remote server's generation through untouched.
            assert_eq!(response.branch_generation, Some(42));
            let branch = response.branch.expect("response should include Branch");
            assert_eq!(branch.name, "test-name");
        }))
        .await;
    }

    #[tokio::test]
    async fn error_status_returned_to_caller() {
        // An error status from the forwarded server is forwarded directly to the original caller.
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let forwarded_request_result = Ok(Err(Status::not_found("test error forwarded")));
        let forwarded_requests =
            StubForwardedRequests::forwarding_enabled(forwarded_request_result);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let branch_id = BranchId::from(uuid::Uuid::now_v7());

            let err = handler(
                make_request(repository, branch_id),
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
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let forwarded_requests =
            StubForwardedRequests::forwarding_enabled(Err(InternalClientError::internal("oops")));

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let branch_id = BranchId::from(uuid::Uuid::now_v7());

            let err = handler(
                make_request(repository, branch_id),
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
        // When revision_branch_get is false the local path runs, even if a
        // ForwardedRequests is present. The stub client is not called.
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        // response is irrelevant — client must never be called
        let forwarded_result = Ok(Err(Status::internal("should not be called")));
        let forwarded_requests = StubForwardedRequests::forwarding_disabled(forwarded_result);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            create_test_branch(repository_context, branch_id).await;

            let response = handler(
                make_request(repository, branch_id),
                immutable_store,
                mutable_store,
                &Some(forwarded_requests as Arc<dyn ForwardedRequests>),
                None, // no domain context
            )
            .await
            .expect("local execution should succeed");

            let branch = response
                .into_inner()
                .branch
                .expect("response should include Branch");
            assert_eq!(branch.name, "test-name");
            assert!(!branch.deleted);
        }))
        .await;
    }
}

#[tokio::test]
async fn get_by_id_fresh_branch_reports_protected_false() {
    let repository = random::<RepositoryId>();
    let branch_id = BranchId::from(uuid::Uuid::now_v7());
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
        let repository_context = Arc::new(RepositoryContext::new_server_context(
            immutable_store.clone(),
            mutable_store.clone(),
            repository,
        ));
        create_test_branch(repository_context, branch_id).await;

        let response = handler(
            make_request_id(repository, branch_id),
            immutable_store.clone(),
            mutable_store.clone(),
            &None,
            None, // no domain context
        )
        .await
        .expect("Request failed");

        let branch = response.into_inner().branch.expect("Branch present");
        assert!(
            !branch.protected,
            "fresh branch should report protected=false"
        );
    }))
    .await;
}

#[tokio::test]
async fn get_by_id_protected_branch_reports_protected_true() {
    let repository = random::<RepositoryId>();
    let branch_id = BranchId::from(uuid::Uuid::now_v7());
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
        let repository_context = Arc::new(RepositoryContext::new_server_context(
            immutable_store.clone(),
            mutable_store.clone(),
            repository,
        ));
        create_test_branch(repository_context.clone(), branch_id).await;
        branch::protect(repository_context, branch_id)
            .await
            .expect("protect should succeed");

        let response = handler(
            make_request_id(repository, branch_id),
            immutable_store.clone(),
            mutable_store.clone(),
            &None,
            None, // no domain context
        )
        .await
        .expect("Request failed");

        let branch = response.into_inner().branch.expect("Branch present");
        assert!(
            branch.protected,
            "protected branch should report protected=true"
        );
    }))
    .await;
}

#[tokio::test]
async fn get_by_id_branch_after_protect_then_unprotect_reports_protected_false() {
    let repository = random::<RepositoryId>();
    let branch_id = BranchId::from(uuid::Uuid::now_v7());
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
        let repository_context = Arc::new(RepositoryContext::new_server_context(
            immutable_store.clone(),
            mutable_store.clone(),
            repository,
        ));
        create_test_branch(repository_context.clone(), branch_id).await;
        branch::protect(repository_context.clone(), branch_id)
            .await
            .expect("protect should succeed");
        branch::unprotect(repository_context, branch_id)
            .await
            .expect("unprotect should succeed");

        let response = handler(
            make_request_id(repository, branch_id),
            immutable_store.clone(),
            mutable_store.clone(),
            &None,
            None, // no domain context
        )
        .await
        .expect("Request failed");

        let branch = response.into_inner().branch.expect("Branch present");
        assert!(
            !branch.protected,
            "branch after protect+unprotect should report protected=false"
        );
    }))
    .await;
}

/// WP-120: `branch_generation` on `BranchGetResponse`.
mod refresh_generation {
    use std::sync::atomic::Ordering;

    use lore_server::domain::DomainContext;

    use super::*;
    use crate::grpc::generation_store::GenerationStore;
    use crate::grpc::generation_store::ReadHook;
    use crate::grpc::generation_store::RecordingMutableStore;
    use crate::grpc::generation_store::SequenceLog;

    async fn get(
        request: Request<BranchGetRequest>,
        immutable: Arc<dyn lore_storage::ImmutableStore>,
        mutable: Arc<dyn lore_storage::MutableStore>,
        domain: Option<&Arc<DomainContext>>,
    ) -> Result<BranchGetResponse, tonic::Status> {
        handler(request, immutable, mutable, &None, domain)
            .await
            .map(tonic::Response::into_inner)
    }

    #[tokio::test]
    async fn generation_is_absent_without_a_domain_context() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            for request in [
                make_request_id(repository, branch_id),
                make_request_name(repository, "test-name"),
            ] {
                let response = get(request, immutable.clone(), mutable.clone(), None)
                    .await
                    .expect("get succeeds without a domain context");
                assert!(response.branch.is_some());
                assert_eq!(response.branch_generation, None);
            }
        }))
        .await;
    }

    #[tokio::test]
    async fn generation_is_passed_through_by_id_and_by_name() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(None, Some(9));
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            for request in [
                make_request_id(repository, branch_id),
                make_request_name(repository, "test-name"),
            ] {
                let response = get(request, immutable.clone(), mutable.clone(), Some(&domain))
                    .await
                    .expect("get succeeds");
                assert_eq!(response.branch_generation, Some(9));
                assert_eq!(response.branch.expect("record").name, "test-name");
            }
            assert_eq!(store.branch_reads.load(Ordering::SeqCst), 2);
        }))
        .await;
    }

    /// Zero is a real generation, not an unset field.
    #[tokio::test]
    async fn generation_zero_is_present_not_dropped() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(None, Some(0));
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            let response = get(
                make_request_id(repository, branch_id),
                immutable,
                mutable,
                Some(&domain),
            )
            .await
            .expect("get succeeds");
            assert_eq!(response.branch_generation, Some(0));
        }))
        .await;
    }

    #[tokio::test]
    async fn generation_is_absent_when_enforcement_is_off() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(None, Some(9));
        let domain = store.context(false);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            for request in [
                make_request_id(repository, branch_id),
                make_request_name(repository, "test-name"),
            ] {
                let response = get(request, immutable.clone(), mutable.clone(), Some(&domain))
                    .await
                    .expect("get succeeds");
                assert_eq!(response.branch_generation, None);
            }
            assert_eq!(store.branch_reads.load(Ordering::SeqCst), 0);
        }))
        .await;
    }

    #[tokio::test]
    async fn generation_is_absent_when_the_domain_row_is_missing() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(None, None);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            let response = get(
                make_request_id(repository, branch_id),
                immutable,
                mutable,
                Some(&domain),
            )
            .await
            .expect("get succeeds");
            assert!(response.branch.is_some());
            assert_eq!(response.branch_generation, None);
            assert_eq!(store.branch_reads.load(Ordering::SeqCst), 1);
        }))
        .await;
    }

    #[tokio::test]
    async fn a_negative_stored_generation_reads_as_absent() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(None, Some(-3));
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            let response = get(
                make_request_id(repository, branch_id),
                immutable,
                mutable,
                Some(&domain),
            )
            .await
            .expect("get succeeds");
            assert_eq!(response.branch_generation, None);
        }))
        .await;
    }

    /// An unknown branch by name answers `NotFound` and never a generation.
    #[tokio::test]
    async fn an_unknown_branch_name_is_not_found_with_a_generation_available() {
        let repository = random::<RepositoryId>();
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::new(None, Some(9));
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let error = get(
                make_request_name(repository, "no-such-branch"),
                immutable,
                mutable,
                Some(&domain),
            )
            .await
            .expect_err("unknown branch");
            assert_eq!(error.code(), tonic::Code::NotFound, "{error:?}");
        }))
        .await;
    }

    /// The generation is read BEFORE the projection (see
    /// `domain::read_generation`): a shared sequence stamps the generation
    /// read and every projection (mutable-store) load.
    #[tokio::test]
    async fn the_generation_is_read_before_the_projection_by_id_and_by_name() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let log = SequenceLog::new();
        let store = GenerationStore::recording(None, Some(9), log.clone());
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            let recording = RecordingMutableStore::wrap(mutable.clone(), log.clone());
            for (label, request, by_id) in [
                ("id", make_request_id(repository, branch_id), true),
                ("name", make_request_name(repository, "test-name"), false),
            ] {
                log.clear();
                let response = get(request, immutable.clone(), recording.clone(), Some(&domain))
                    .await
                    .expect("get succeeds");
                assert_eq!(response.branch_generation, Some(9), "by {label}");
                let generation_reads = log.generation_reads();
                let loads = log.projection_loads();
                assert!(!generation_reads.is_empty(), "by {label}: generation read");
                assert!(!loads.is_empty(), "by {label}: the record read must be observed");
                let generation = generation_reads[0];
                let last_load = *loads.last().expect("non-empty");
                assert!(
                    generation < last_load,
                    "by {label}: generation read ({generation}) must precede the record read ({last_load}); loads {loads:?}"
                );
                if by_id {
                    assert_eq!(generation_reads.len(), 1, "by id: one generation read");
                    assert!(
                        generation < loads[0],
                        "by id: no projection load may precede the generation read; loads {loads:?}"
                    );
                }
            }
        }))
        .await;
    }

    /// A failing generation read must not fail the record read.
    #[tokio::test]
    async fn a_generation_read_error_leaves_the_generation_absent_and_the_get_succeeds() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let store = GenerationStore::failing();
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let context = Arc::new(RepositoryContext::new_server_context(
                immutable.clone(),
                mutable.clone(),
                repository,
            ));
            create_test_branch(context, branch_id).await;
            for (label, request) in [
                ("id", make_request_id(repository, branch_id)),
                ("name", make_request_name(repository, "test-name")),
            ] {
                let before = store.branch_reads.load(Ordering::SeqCst);
                let response = get(request, immutable.clone(), mutable.clone(), Some(&domain))
                    .await
                    .unwrap_or_else(|error| panic!("by {label}: get must succeed: {error:?}"));
                assert!(
                    store.branch_reads.load(Ordering::SeqCst) > before,
                    "by {label}: the failing read must actually have been attempted"
                );
                assert_eq!(response.branch_generation, None, "by {label}");
                assert_eq!(response.branch.expect("record").name, "test-name");
            }
        }))
        .await;
    }

    /// A name resolves twice (once for the generation, once for the record).
    /// If the mapping moved in between, the generation belongs to the other
    /// branch and must be dropped, while the record read still answers for the
    /// branch the name now points at.
    #[tokio::test]
    async fn a_name_that_moves_between_resolves_drops_the_generation() {
        let repository = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());
        let moved_to = BranchId::from(uuid::Uuid::now_v7());
        let (immutable, mutable, execution) = test_store_create().await.expect("stores");
        let context = Arc::new(RepositoryContext::new_server_context(
            immutable.clone(),
            mutable.clone(),
            repository,
        ));
        let hook_context = context.clone();
        let hook: ReadHook = Arc::new(move || {
            let context = hook_context.clone();
            Box::pin(async move {
                branch::store_name_to_id(context, moved_to, "test-name")
                    .await
                    .expect("re-point the name between the two resolves");
            })
        });
        let store = GenerationStore::with_read_hook(None, Some(9), hook);
        let domain = store.context(true);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            create_test_branch(context.clone(), branch_id).await;
            lore_revision::branch::create(
                context.clone(),
                &get_write_token(),
                moved_to,
                "other-name",
                branch::personal_category(),
                "BranchCreator",
                12345,
                vec![],
                false,
                false,
            )
            .await
            .expect("create the branch the name moves to");
            let response = get(
                make_request_name(repository, "test-name"),
                immutable,
                mutable,
                Some(&domain),
            )
            .await
            .expect("get succeeds");
            assert!(store.branch_reads.load(Ordering::SeqCst) >= 1);
            assert_eq!(
                response.branch.expect("record").name,
                "other-name",
                "sanity: the second resolve saw the moved mapping"
            );
            assert_eq!(
                response.branch_generation, None,
                "the generation read for the first id must not ride along with the other branch"
            );
        }))
        .await;
    }
}

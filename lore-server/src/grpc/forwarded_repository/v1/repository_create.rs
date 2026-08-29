// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_proto::lore::repository::v1::RepositoryCreateRequest;
use lore_proto::lore::repository::v1::RepositoryCreateResponse;
use lore_telemetry::InstrumentProvider;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::domain::DomainContext;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::domain::reject_unwired_governed_operation;
use crate::grpc::forwarded_requests::CallerContext;
use crate::grpc::get_authorization_optional;
use crate::grpc::repository::v1::repository_create::repository_create_implementation;
use crate::hooks::HookDispatcher;

/// Handler that takes a `RepositoryCreate` request forwarded on from peer's `RepositoryService`
/// and executes it, returning the result to the other server for forwarding on to its
/// client
#[tracing::instrument(name = "ForwardedRepository::v1::RepositoryCreate::Handler", skip_all)]
pub async fn handler(
    request: Request<RepositoryCreateRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    hook_dispatcher: &HookDispatcher,
    instrument_provider: &impl InstrumentProvider,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<RepositoryCreateResponse>, Status> {
    let caller_context = CallerContext::from_forwarded_request(&request)?;
    // Captured before `into_inner` consumes the request.
    let request_metadata = request.metadata().clone();
    let request_authorization = get_authorization_optional(request.extensions());
    let req = request.into_inner();

    // CR-029 R-BLOCK-2, at this entry point specifically. This handler
    // delegates to the same `repository_create_implementation` the front-door
    // v1 handler uses, so gating only the front door would leave this path
    // ungoverned — the exact "wired into the front-door service only" failure
    // CR-029's expected-source-scope correction #5 names. Note also that this
    // service runs behind no interceptor at all, so `request_authorization` is
    // `None` here and any carriage is refused as unauthenticated.
    if let Some(admitted) = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::RepositoryCreate {
            repository_id: &req.id,
        },
    )? {
        return Err(reject_unwired_governed_operation(
            &admitted,
            "lore.forwarded_repository.v1.ForwardedRepositoryService/RepositoryCreate",
        ));
    }

    repository_create_implementation(
        req,
        caller_context,
        auth_url,
        immutable_store,
        mutable_store,
        hook_dispatcher,
        instrument_provider,
    )
    .await
}

#[cfg(test)]
mod test {
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Context;
    use lore_revision::lore::RepositoryId;
    use lore_telemetry::InstrumentProvider;
    use rand::random;
    use tonic::Request;

    use super::*;
    use crate::hooks::HookDispatcher;
    use crate::store::test_store_create;

    struct TestInstrumentProvider;

    impl InstrumentProvider for TestInstrumentProvider {
        fn namespace(&self) -> &'static str {
            "test"
        }
    }

    fn make_body(repository_id: RepositoryId, name: &str) -> RepositoryCreateRequest {
        let id_bytes: Context = repository_id.into();
        RepositoryCreateRequest {
            id: bytes::Bytes::from(id_bytes),
            name: name.into(),
            description: String::new(),
            default_branch_id: bytes::Bytes::from(Context::from(uuid::Uuid::now_v7())),
            default_branch_name: "main".into(),
            creator: Some("alice".into()),
        }
    }

    fn make_forwarded_request(
        repository_id: RepositoryId,
        name: &str,
    ) -> Request<RepositoryCreateRequest> {
        CallerContext {
            repository_id,
            user_id: "alice".into(),
            correlation_id: String::new(),
            authorization: None,
        }
        .to_forwarded_request(make_body(repository_id, name))
        .expect("CallerContext::to_forwarded_request failed in test")
    }

    #[tokio::test]
    async fn missing_user_id_returns_internal_error() {
        let repository_id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            // Deliberately omit on-behalf-of-user-id to test the missing-field error
            let request = Request::new(make_body(repository_id, "my-repo"));

            let hook_dispatcher = HookDispatcher::empty();
            let err = handler(
                request,
                None,
                immutable_store,
                mutable_store,
                &hook_dispatcher,
                &TestInstrumentProvider,
                None, /* no domain coordinator */
            )
            .await
            .expect_err("missing user id should fail");

            assert_eq!(err.code(), tonic::Code::Internal);
            assert!(err.message().contains("on-behalf-of-user-id"));
        }))
        .await;
    }

    // Happy and unhappy paths verify that whatever the underlying
    // `repository_create_implementation` returns is forwarded on correctly.
    mod base_repository_create_handler {
        use super::*;

        #[tokio::test]
        async fn create_returns_full_repository_record() {
            let repository_id = random::<RepositoryId>();
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let hook_dispatcher = HookDispatcher::empty();

                let response = handler(
                    make_forwarded_request(repository_id, "my-repo"),
                    None, /* no auth */
                    immutable_store,
                    mutable_store,
                    &hook_dispatcher,
                    &TestInstrumentProvider,
                    None, /* no domain coordinator */
                )
                .await
                .expect("Request failed");

                let repo = response
                    .into_inner()
                    .repository
                    .expect("response should include Repository");
                assert_eq!(repo.name, "my-repo");
                assert_eq!(repo.creator, "alice");
                assert!(repo.created > 0);
                assert!(!repo.id.is_empty());
            }))
            .await;
        }

        #[tokio::test]
        async fn duplicate_id_returns_already_exists() {
            let repository_id = random::<RepositoryId>();
            let (immutable_store, mutable_store, execution) =
                test_store_create().await.expect("Failed to create stores");

            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let hook_dispatcher = HookDispatcher::empty();

                handler(
                    make_forwarded_request(repository_id, "my-repo"),
                    None,
                    immutable_store.clone(),
                    mutable_store.clone(),
                    &hook_dispatcher,
                    &TestInstrumentProvider,
                    None, /* no domain coordinator */
                )
                .await
                .expect("first create should succeed");

                // Same id, different name — should be AlreadyExists
                let err = handler(
                    make_forwarded_request(repository_id, "other-name"),
                    None,
                    immutable_store,
                    mutable_store,
                    &hook_dispatcher,
                    &TestInstrumentProvider,
                    None, /* no domain coordinator */
                )
                .await
                .expect_err("duplicate id with different name should fail");
                assert_eq!(err.code(), tonic::Code::AlreadyExists);
            }))
            .await;
        }
    }
}

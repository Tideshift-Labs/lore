// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::rebac::CreateResourceRequest;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::rebac::RebacApiClient;
use lore_server::grpc::handlers::repository_create::*;
use tonic::Code;
use tonic::Request;
use tonic::Status;

mod input_length_validation {
    use lore_revision::repository;

    use super::*;

    #[test]
    fn accepts_valid_input() {
        validate_create_input("my-repo", "a description", "main", "alice")
            .expect("valid input should pass");
    }

    #[test]
    fn accepts_name_at_max_length() {
        let name = "a".repeat(repository::MAX_NAME_LEN);
        validate_create_input(&name, "desc", "main", "alice")
            .expect("name at exactly MAX_NAME_LEN should pass");
    }

    #[test]
    fn rejects_oversized_repository_name() {
        let long_name = "a".repeat(repository::MAX_NAME_LEN + 1);
        let err = validate_create_input(&long_name, "desc", "main", "alice")
            .expect_err("should reject oversized name");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message()
                .contains("Repository name exceeds maximum length")
        );
    }

    #[test]
    fn rejects_oversized_description() {
        let long_desc = "a".repeat(repository::MAX_DESCRIPTION_LEN + 1);
        let err = validate_create_input("my-repo", &long_desc, "main", "alice")
            .expect_err("should reject oversized description");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("description exceeds maximum length"));
    }

    #[test]
    fn rejects_oversized_branch_name() {
        let long_branch = "a".repeat(repository::MAX_NAME_LEN + 1);
        let err = validate_create_input("my-repo", "desc", &long_branch, "alice")
            .expect_err("should reject oversized branch name");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("Branch name exceeds maximum length"));
    }

    #[test]
    fn rejects_oversized_creator() {
        let long_creator = "a".repeat(repository::MAX_NAME_LEN + 1);
        let err = validate_create_input("my-repo", "desc", "main", &long_creator)
            .expect_err("should reject oversized creator");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("Creator exceeds maximum length"));
    }
}

mod repository_create_auth_resource_tests {
    use lore_proto::rebac::CreateResourceResponse;
    use lore_proto::rebac::DeleteResourceRequest;
    use lore_proto::rebac::DeleteResourceResponse;
    use lore_server::authnz::rebac::RebacApiResult;

    use super::*;

    mockall::mock! {

        pub MockRebacApiClient {}

        #[async_trait::async_trait]
        impl RebacApiClient for MockRebacApiClient {
            async fn create_resource(
                &mut self,
                request: Request<CreateResourceRequest>,
            ) -> RebacApiResult<CreateResourceResponse>;

            async fn delete_resource(
                &mut self,
                request: Request<DeleteResourceRequest>,
            ) -> RebacApiResult<DeleteResourceResponse>;
        }
    }

    #[tokio::test]
    async fn permission_denied_propagated_to_client() {
        let repo_name = "2fc8bf934117e250152eba9a1fc78e71";
        let repository: RepositoryId = Context::from_str(repo_name)
            .expect("Failed to create repository")
            .into();

        let mut client = MockMockRebacApiClient::new();
        client
            .expect_create_resource()
            .return_once(|_| Err(Status::permission_denied("")));

        let error =
            repository_create_auth_resource(Box::new(client), None, repository, repo_name, None)
                .await
                .expect_err("Should have errored");
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(
            error.message(),
            "Failed to create repository, permission denied"
        );
    }

    #[tokio::test]
    async fn missing_auth_dependencies_returns_failed_precondition() {
        let repo_name = "2fc8bf934117e250152eba9a1fc78e71";
        let repository: RepositoryId = Context::from_str(repo_name)
            .expect("Failed to create repository")
            .into();

        let mut client = MockMockRebacApiClient::new();
        client
            .expect_create_resource()
            .return_once(|_| Err(Status::not_found("")));

        let error =
            repository_create_auth_resource(Box::new(client), None, repository, repo_name, None)
                .await
                .expect_err("Should have errored");
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(error.message(), "A required Auth entity was not found");
    }

    #[tokio::test]
    async fn invalid_repository_name_returns_invalid_argument() {
        let repo_name = "2fc8bf934117e250152eba9a1fc78e71";
        let repository: RepositoryId = Context::from_str(repo_name)
            .expect("Failed to create repository")
            .into();

        let mut client = MockMockRebacApiClient::new();
        client.expect_create_resource().return_once(|_| {
            Err(Status::invalid_argument(
                "Missing resource context in resourceName",
            ))
        });

        let error =
            repository_create_auth_resource(Box::new(client), None, repository, repo_name, None)
                .await
                .expect_err("Should have errored");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(
            error.message(),
            "Invalid repository name - missing Organization context"
        );
    }

    #[tokio::test]
    async fn already_exists_treated_as_success() {
        let repo_name = "2fc8bf934117e250152eba9a1fc78e71";
        let repository: RepositoryId = Context::from_str(repo_name)
            .expect("Failed to create repository")
            .into();

        let mut client = MockMockRebacApiClient::new();
        client
            .expect_create_resource()
            .return_once(|_| Err(Status::already_exists("")));

        repository_create_auth_resource(Box::new(client), None, repository, repo_name, None)
            .await
            .expect("AlreadyExists should be treated as success");
    }

    // the default case for errors that aren't specially handled
    #[tokio::test]
    async fn other_errors_return_internal_error() {
        let repo_name = "2fc8bf934117e250152eba9a1fc78e71";
        let repository: RepositoryId = Context::from_str(repo_name)
            .expect("Failed to create repository")
            .into();

        let mut client = MockMockRebacApiClient::new();
        client
            .expect_create_resource()
            .return_once(|_| Err(Status::invalid_argument("You used my api wrong!")));

        let error =
            repository_create_auth_resource(Box::new(client), None, repository, repo_name, None)
                .await
                .expect_err("Should have errored");
        assert_eq!(error.code(), Code::Internal);
        assert!(
            error
                .message()
                .contains("Failed to call auth create_resource"),
        );
        assert!(error.message().contains("You used my api wrong!"),);
    }
}

// TEST 3 (WP-116 guarded stop): confirms the ungoverned/legacy path at
// this fenced governed-mutation call site is unchanged. Every other test
// in this file exercises a sub-helper directly; none call the top-level
// `handler` at all, so nothing here previously proved that a cell with no
// domain coordinator (the ordinary pre-CR-029 configuration) still runs
// the full create handler to completion rather than tripping over the
// `admit_at_entry` gate this module's `if let Some(admitted) = ...`
// inserted. `admit_at_entry`'s own `Ok(None)` behavior is already pinned
// generically in `domain.rs`; this is the handler-specific companion.
mod legacy_path_regression {
    use lore_proto::RepositoryCreateRequest;
    use lore_server::hooks::HookDispatcher;
    use rand::random;

    use super::*;
    use crate::store::test_support::test_store_create;

    struct TestInstrumentProvider;

    impl lore_telemetry::InstrumentProvider for TestInstrumentProvider {
        fn namespace(&self) -> &'static str {
            "test"
        }
    }

    fn make_request(repository_id: RepositoryId, name: &str) -> Request<RepositoryCreateRequest> {
        let id_bytes: lore_base::types::Context = repository_id.into();
        Request::new(RepositoryCreateRequest {
            id: bytes::Bytes::from(id_bytes),
            name: name.into(),
            description: String::new(),
            default_branch_id: bytes::Bytes::from(lore_base::types::Context::from(
                uuid::Uuid::now_v7(),
            )),
            default_branch_name: "main".into(),
            creator: "alice".into(),
            created: 0,
        })
    }

    #[tokio::test]
    async fn no_domain_coordinator_runs_the_full_legacy_create_path() {
        let repository_id = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("test stores");
        let hook_dispatcher = HookDispatcher::empty();

        let response = LORE_CONTEXT
            .scope(execution, async move {
                handler(
                    make_request(repository_id, "wp116-legacy-path"),
                    None, /* no auth_url */
                    immutable_store,
                    mutable_store,
                    &hook_dispatcher,
                    &TestInstrumentProvider,
                    None, /* no domain coordinator */
                )
                .await
            })
            .await
            .expect("legacy path (no domain coordinator) must still succeed");

        let repo = response
            .into_inner()
            .repository
            .expect("response must include the created repository");
        assert_eq!(repo.name, "wp116-legacy-path");
    }
}

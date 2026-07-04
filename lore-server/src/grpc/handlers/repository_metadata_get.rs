// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::RepositoryMetadataGetRequest;
use lore_proto::RepositoryMetadataGetResponse;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::warn;

use crate::grpc::extract_correlation_id;
use crate::grpc::get_user_id;
use crate::grpc::handlers::repository_query::check_repository_query_authorization;
use crate::util::setup_execution;

#[tracing::instrument(name = "RepositoryMetadataGet::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryMetadataGetRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<RepositoryMetadataGetResponse>, Status> {
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());
    let req = request.into_inner();

    let repository_id: Context = req.repository_id.into();
    if repository_id == Context::default() {
        return Err(Status::invalid_argument("Missing repository ID"));
    }

    // Scope the read to the caller's repository. RepositoryService rides the
    // authn-only interceptor (UCS-13506), so the body repository id is not
    // authorized upstream; re-check it here via the same ReBAC callback the
    // sibling read RPCs use. When no auth_url is configured (auth-OFF), there
    // is nothing to enforce.
    if let Some(auth_url) = auth_url {
        check_repository_query_authorization(auth_url, authorization, repository_id.into()).await?;
    }

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id.into(),
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            let metadata_hash = repository::metadata_hash(repository).await.map_err(|err| {
                warn!(%err, "Failed to load repository metadata hash");
                Status::not_found(err.to_string())
            })?;

            Ok(Response::new(RepositoryMetadataGetResponse {
                metadata_hash: metadata_hash.into(),
            }))
        })
        .await
}

#[cfg(test)]
mod tests {
    use lore_base::types::Hash;
    use lore_proto::RepositoryMetadataGetRequest;
    use lore_revision::lore::RepositoryId;
    use tonic::Request;

    use super::handler;
    use crate::grpc::handlers::repository_query::authz_test_support::new_test_stores;
    use crate::grpc::handlers::repository_query::authz_test_support::seed_repository_metadata;
    use crate::grpc::handlers::repository_query::authz_test_support::start_stub_auth_server;

    fn request_for(repository_id: RepositoryId) -> Request<RepositoryMetadataGetRequest> {
        let mut request = Request::new(RepositoryMetadataGetRequest {
            repository_id: repository_id.into(),
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer test-token".parse().unwrap());
        request
    }

    #[tokio::test]
    async fn denies_metadata_get_for_a_repository_the_caller_is_not_authorized_for() {
        let caller_authorized_repo = RepositoryId::from([1u8; 16]);
        let target_repo = RepositoryId::from([2u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        // Seed real metadata on the target: if the handler mistakenly
        // skipped the authz check, it would succeed here instead of
        // returning PermissionDenied.
        seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            target_repo,
            "victim",
            "",
        )
        .await;
        let auth_url = start_stub_auth_server(caller_authorized_repo).await;

        let result = handler(request_for(target_repo), Some(auth_url), immutable, mutable).await;

        let err = result.expect_err("caller is not authorized for the target repository");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn accepts_metadata_get_for_the_callers_own_repository() {
        let repository_id = RepositoryId::from([3u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let seeded_hash = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "",
        )
        .await;
        let auth_url = start_stub_auth_server(repository_id).await;

        let response = handler(
            request_for(repository_id),
            Some(auth_url),
            immutable,
            mutable,
        )
        .await
        .expect("a legitimate client reading its own repository must be unaffected");

        assert_eq!(Hash::from(response.into_inner().metadata_hash), seeded_hash);
    }

    #[tokio::test]
    async fn auth_off_serves_metadata_without_an_authorization_check() {
        let repository_id = RepositoryId::from([4u8; 16]);
        let (immutable, mutable) = new_test_stores().await;
        let seeded_hash = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "acme",
            "",
        )
        .await;

        // No stub auth server is started at all: if the handler tried to
        // reach one with auth_url = None, this would fail to connect.
        let response = handler(request_for(repository_id), None, immutable, mutable)
            .await
            .expect("auth-off must leave behavior unchanged");

        assert_eq!(Hash::from(response.into_inner().metadata_hash), seeded_hash);
    }
}

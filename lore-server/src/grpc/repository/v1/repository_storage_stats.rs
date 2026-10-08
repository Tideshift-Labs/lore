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

use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::grpc::get_verified_token;
use crate::grpc::handlers::repository_query::check_repository_query_authorization;

/// `lore.repository.v1.RepositoryService.RepositoryStorageStats` handler.
///
/// Read-only aggregate of what the repository's fragments occupy in the store,
/// answered straight from the store's own fragment-metadata index. An unknown
/// repository has no associations and so reports zeroes rather than `NOT_FOUND`.
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
    authorizer: Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
) -> Result<Response<RepositoryStorageStatsResponse>, Status> {
    let (_, extensions, req) = request.into_parts();

    let repository_id: Context = req.id.into();
    if repository_id == Context::default() {
        return Err(Status::invalid_argument("Missing repository id"));
    }

    // Scope the read to the caller's repository. RepositoryService rides the
    // authn-only interceptor, so the body repository id is not authorized
    // before the handler; re-check it through the configured authorizer the
    // sibling read RPCs use. Auth-OFF selects AllowAll, so behavior there is
    // unchanged. The denial status propagates as-is (CR-016).
    check_repository_query_authorization(
        authorizer.as_ref(),
        get_verified_token(&extensions).as_ref(),
        repository_id.into(),
    )
    .await?;

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

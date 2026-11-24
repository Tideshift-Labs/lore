// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_proto::RepositoryDeleteRequest;
use lore_proto::RepositoryDeleteResponse;
use lore_revision::branch;
use lore_revision::lore::RepositoryId;
use lore_revision::lore::execution_context;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::no_link_traversal;
use lore_telemetry::InstrumentProvider;
use tonic::Extensions;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;
use tracing::warn;

use super::repository_query::repository_query_id;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::authnz::repository_registry::RepositoryRegistry;
use crate::domain::DomainContext;
use crate::domain::GovernedRepositoryDelete;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::RepositoryAdministration;
use crate::grpc::ServerResultExt;
use crate::grpc::extract_authorization_header;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_user_id;
use crate::grpc::repository_administration;
use crate::grpc::requested_repository_id;
use crate::util::setup_execution;

#[tracing::instrument(name = "RepositoryDelete::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryDeleteRequest>,
    registry: &RepositoryRegistry,
    authorizer: &Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    instrument_provider: &impl InstrumentProvider,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<RepositoryDeleteResponse>, Status> {
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = extract_authorization_header(&request);
    // Captured before `into_parts` consumes the request: the domain-operation
    // headers and the verified principal both live outside the message body.
    let request_authorization = get_authorization_optional(request.extensions());
    let (request_metadata, extensions, req) = request.into_parts();

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or authorization side effect.
    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: &req.id,
        },
    )?;
    // Upstream v0.13 (efda7650) refuses the all-zero id; do it before the governed prepare write.
    let id = requested_repository_id(&req.id)?;
    let governed = if admitted.is_some() {
        let digest = canonical_intent_digest(&CanonicalIntent::RepositoryDelete {
            repository_id: &req.id,
        })
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        GovernedRepositoryDelete::prepare(domain_context, admitted, digest).await?
    } else {
        None
    };

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
        no_link_traversal(),
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            repository_delete(
                repository,
                registry,
                authorizer,
                &extensions,
                authorization,
                governed,
            )
            .await
            .inspect_err(|err| warn!("Repository delete failed: {err}"))?;

            let num_repositories_deleted = instrument_provider.counter("num_repositories_deleted");
            num_repositories_deleted.add(1, &[]);

            Ok(Response::new(RepositoryDeleteResponse {}))
        })
        .await
}

async fn repository_delete(
    repository: Arc<RepositoryContext>,
    registry: &RepositoryRegistry,
    authorizer: &Arc<dyn RepositoryAuthorizer>,
    extensions: &Extensions,
    authorization: Option<String>,
    governed: Option<GovernedRepositoryDelete>,
) -> Result<(), Status> {
    // Fork (CR-029, ruling D-1): an admitted governed delete is authorized by
    // its domain admission (verified control-plane service identity, claim and
    // witness). Upstream's creator-or-owner/admin check, and its be2f3914
    // unreachable-as-missing answer, guard the ungoverned path only.
    //
    // Asked before the load, so a repository the caller's grants do not reach
    // is answered as a missing one.
    let administration = if governed.is_none() {
        let administration =
            repository_administration(authorizer, extensions, repository.id).await?;
        if administration == RepositoryAdministration::Unreachable {
            return Err(Status::not_found("Repository does not exist"));
        }
        Some(administration)
    } else {
        None
    };

    let Ok(data) = repository_query_id(
        repository.clone(),
        repository.id,
        None, /* skip authz */
        None, /* token */
    )
    .await
    .filter_slow_down()?
    else {
        return Err(Status::not_found("Repository does not exist"));
    };

    let metadata = repository::metadata(repository.clone(), data.metadata)
        .await
        .filter_slow_down()?
        .map_err(|_err| Status::not_found("Repository metadata not found"))?;

    let user_id = execution_context().user_id().await;

    if let Some(administration) = administration
        && !administration.permits(&metadata.creator, &user_id)
    {
        info!(
            "Repository delete refused for user {user_id}, creator {}",
            metadata.creator
        );
        return Err(Status::permission_denied("Not repository owner"));
    }
    registry.remove(authorization, repository.id).await?;

    if let Some(governed) = governed {
        governed
            .commit_repository(repository.clone(), &metadata.name, data.metadata)
            .await?;
        return Ok(());
    }
    repository::store_name_to_id(
        repository.clone(),
        metadata.name.as_str(),
        RepositoryId::default(),
    )
    .await
    .filter_slow_down()?
    .warn_map_err(|err| {
        Status::internal(format!("Failed to delete repository name mapping: {err}"))
    })?;

    repository::metadata_store_hash(repository.clone(), Hash::default())
        .await
        .filter_slow_down()?
        .warn_map_err(|err| {
            Status::internal(format!("Failed to delete repository metadata: {err}"))
        })?;

    // no filter_slow_down()? usage here: the repository record is already
    // torn down above, so this purge is past the point of no return. A
    // retryable status would invite a retry that only finds the repository
    // gone, leaving these keys orphaned.
    branch::purge_mapped_branches(repository.clone()).await;

    info!(
        "Deleted repository {} with ID {}",
        metadata.name, repository.id
    );

    Ok(())
}

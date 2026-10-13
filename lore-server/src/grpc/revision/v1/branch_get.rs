// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_proto::lore::revision::v1::BranchGetRequest;
use lore_proto::lore::revision::v1::BranchGetResponse;
use lore_proto::lore::revision::v1::branch_get_request::Query as BranchGetQuery;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::tracing::fields::BRANCH_ID;
use lore_telemetry::tracing::fields::METADATA;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;

use super::branch_record::build_branch;
use crate::domain::DomainContext;
use crate::domain::read_generation;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::ServerResultExt;
use crate::grpc::forwarded_requests::CallerContext;
use crate::grpc::forwarded_requests::ForwardedRequests;
use crate::util::setup_execution;

/// `lore.revision.v1.RevisionService.BranchGet` handler.
///
/// Lookup by id resolves live or deleted branches; lookup by name
/// resolves live branches only — deleted-branch names are erased
/// and may have been recycled.
///
/// Depending on server configuration, this request may get completely delegated to another server
/// via `ForwardedRevisionService`
#[tracing::instrument(name = "BranchGet::v1::handle", skip_all)]
pub async fn handler(
    request: Request<BranchGetRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    forwarded_requests: &Option<Arc<dyn ForwardedRequests>>,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchGetResponse>, Status> {
    let caller_context = CallerContext::from_original_request(&request)?;
    let req = request.into_inner();
    if let Some(forwarded_requests) = forwarded_requests
        && forwarded_requests.rpc_flags().revision_branch_get
    {
        forward_branch_get(req, caller_context, forwarded_requests).await
    } else {
        branch_get_implementation(
            req,
            caller_context,
            immutable_store,
            mutable_store,
            domain_context,
        )
        .await
    }
}

/// This `BranchGetRequest` should be handled by another server
/// and the response forwarded on to the client
async fn forward_branch_get(
    req: BranchGetRequest,
    context: CallerContext,
    forwarded_requests: &Arc<dyn ForwardedRequests>,
) -> Result<Response<BranchGetResponse>, Status> {
    let mut client = forwarded_requests.forwarded_revision_service();
    let request = context.to_forwarded_request(req)?;

    let branch_get_result = client
        .branch_get(request)
        .await
        .warn_map_err(|_err| Status::internal("Error making forwarded request"))?;

    // the Error arm of this result is for the client
    let response = branch_get_result?;
    Ok(response)
}

/// This `BranchGetRequest` should be fulfilled by this server.
pub async fn branch_get_implementation(
    req: BranchGetRequest,
    caller_context: CallerContext,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchGetResponse>, Status> {
    let Some(query) = req.query else {
        return Err(Status::invalid_argument(
            "BranchGetRequest.query must be set (id or name)",
        ));
    };

    let execution = setup_execution(
        module_path!(),
        caller_context.correlation_id,
        caller_context.user_id,
    );
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        caller_context.repository_id,
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            match query {
                BranchGetQuery::Id(id) => {
                    let branch_id = BranchId::from(id);
                    debug!({BRANCH_ID} = %branch_id, "Get branch by id");
                    // Read the generation before the record (WP-120): a race
                    // then costs the client one extra refresh, never a missed
                    // change.
                    let generation = read_generation::branch_generation(
                        domain_context,
                        repository.id.data(),
                        branch_id.data(),
                    )
                    .await;
                    get_by_id(repository, branch_id, generation).await
                }
                BranchGetQuery::Name(name) => {
                    debug!(name, "Get branch by name");
                    get_by_name(repository, &name, domain_context).await
                }
            }
        })
        .await
}

async fn get_by_id(
    repository: Arc<RepositoryContext>,
    branch_id: BranchId,
    branch_generation: Option<u64>,
) -> Result<Response<BranchGetResponse>, Status> {
    let metadata_hash = branch::metadata_hash(repository.clone(), branch_id)
        .await
        .filter_slow_down()?
        .map_err(|_err| Status::not_found(format!("Branch {branch_id} not found")))?;
    let metadata = branch::load_metadata(repository.clone(), metadata_hash)
        .await
        .filter_slow_down()?
        .warn_map_err(|err| Status::internal(err.to_string()))?;

    // Delete leaves metadata intact but clears the name → id mapping.
    let deleted = match branch::name(&metadata) {
        Ok(name) if !name.is_empty() => !branch::load_name_to_id_local(repository.clone(), name)
            .await
            .filter_slow_down()?
            .is_ok_and(|id| id == branch_id),
        _ => false,
    };

    let latest = branch::load_latest(repository, branch_id)
        .await
        .filter_slow_down()?
        .unwrap_or_default();
    let response_branch = build_branch(branch_id, &metadata, metadata_hash, deleted, latest);
    debug!({BRANCH_ID} = %branch_id, {METADATA} = %metadata_hash, deleted, "Branch get by id response");
    Ok(Response::new(BranchGetResponse {
        branch: Some(response_branch),
        branch_generation,
    }))
}

async fn get_by_name(
    repository: Arc<RepositoryContext>,
    name: &str,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchGetResponse>, Status> {
    // Read the generation before the record (WP-120): a race then costs the
    // client one extra refresh, never a missed change. The name resolves
    // twice; if the mapping moved in between, the generation belongs to
    // another branch and is dropped.
    let generation = if read_generation::is_authoritative(domain_context) {
        match branch::load_name_to_id_local(repository.clone(), name)
            .await
            .filter_slow_down()?
        {
            Ok(id) => {
                let id = BranchId::from(id);
                read_generation::branch_generation(domain_context, repository.id.data(), id.data())
                    .await
                    .map(|generation| (id, generation))
            }
            Err(_) => None,
        }
    } else {
        None
    };

    let branch_id_ctx = branch::load_name_to_id_local(repository.clone(), name)
        .await
        .filter_slow_down()?
        .map_err(|_err| Status::not_found(format!("Branch named '{name}' not found")))?;
    let branch_id = BranchId::from(branch_id_ctx);

    let metadata_hash = branch::metadata_hash(repository.clone(), branch_id)
        .await
        .filter_slow_down()?
        .map_err(|_err| Status::not_found(format!("Branch named '{name}' not found")))?;
    let metadata = branch::load_metadata(repository.clone(), metadata_hash)
        .await
        .filter_slow_down()?
        .warn_map_err(|err| Status::internal(err.to_string()))?;

    let latest = branch::load_latest(repository, branch_id)
        .await
        .filter_slow_down()?
        .unwrap_or_default();
    let response_branch = build_branch(branch_id, &metadata, metadata_hash, false, latest);
    debug!({BRANCH_ID} = %branch_id, {METADATA} = %metadata_hash, "Branch get by name response");
    let branch_generation = generation
        .filter(|(generation_id, _)| *generation_id == branch_id)
        .map(|(_, generation)| generation);
    Ok(Response::new(BranchGetResponse {
        branch: Some(response_branch),
        branch_generation,
    }))
}

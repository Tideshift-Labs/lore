// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::lore::repository::v1::RepositoryCreateRequest;
use lore_proto::lore::repository::v1::RepositoryCreateResponse;
use lore_revision::branch;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_revision::util;
use lore_telemetry::InstrumentProvider;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::Span;
use tracing::info;
use tracing::warn;

use super::record::build_repository;
use super::repository_get::repository_load_id;
use super::repository_get::repository_load_name;
use crate::domain::DomainContext;
use crate::domain::GovernedRepositoryCreate;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::domain::reject_unwired_governed_operation;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::ServerResultExt;
use crate::grpc::extract_authorization_header;
use crate::grpc::extract_correlation_id;
use crate::grpc::forwarded_requests::CallerContext;
use crate::grpc::forwarded_requests::ForwardedRequests;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_user_id;
use crate::grpc::get_write_token;
use crate::grpc::handlers::repository_create::governed_repository_create;
use crate::grpc::handlers::repository_create::repository_create_auth_resource;
use crate::grpc::hook_error_to_status;
use crate::grpc::none_or_status;
use crate::grpc::warn_error_to_status;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::util::setup_execution;

/// `lore.repository.v1.RepositoryService.RepositoryCreate` handler.
///
/// The caller pre-generates `id` and `default_branch_id` for retry
/// idempotency. The server assigns `created`. `creator` is hybrid:
/// caller-set if permitted, otherwise the authenticated JWT identity.
///
/// Depending on server configuration, this request may get completely delegated to another server
/// via `ForwardedRepositoryService`
#[tracing::instrument(
    name = "RepositoryCreate::v1::handle",
    skip_all,
    fields(requested_repo_id)
)]
// One argument over the clippy threshold, matching the convention already used
// for the repository services' constructors in this crate.
#[allow(clippy::too_many_arguments)]
pub async fn handler(
    request: Request<RepositoryCreateRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    forwarded_requests: &Option<Arc<dyn ForwardedRequests>>,
    hook_dispatcher: &HookDispatcher,
    instrument_provider: &impl InstrumentProvider,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<RepositoryCreateResponse>, Status> {
    // Captured before `into_inner` consumes the request: the domain-operation
    // headers and the verified principal both live outside the message body.
    let request_metadata = request.metadata().clone();
    let request_authorization = get_authorization_optional(request.extensions());
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = extract_authorization_header(&request);
    let req = request.into_inner();

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or authorization side effect.
    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::RepositoryCreate {
            repository_id: &req.id,
        },
    )?;

    let forwarding = forwarded_requests
        .as_ref()
        .is_some_and(|forwarded| forwarded.rpc_flags().repository_create);
    if forwarding && let Some(admitted) = admitted.as_ref() {
        // BLOCKED(WP-116): a forwarded create has no local coordinator call
        // site, and CR-029's CARRIAGE-02-LORE fences the forwarded entry point
        // until a frozen authenticated forwarding contract exists. This cell
        // would forward, so admitting the operation here would receipt it
        // against a transaction that happens somewhere else, or nowhere.
        return Err(reject_unwired_governed_operation(
            admitted,
            "lore.repository.v1.RepositoryService/RepositoryCreate (forwarded)",
        ));
    }

    // WP-116 Part 3 wires this site through the shared governed create seam.
    //
    // v1 is `created_mode = 0`: the server assigns the timestamp, so no caller
    // time is bound, and `creator` is optional on the wire rather than an empty
    // string. The handler's frozen size checks run first, because CR-029's
    // canonical-intent contract hashes only a request that has already passed
    // them.
    let wire_creator = req.creator.clone().filter(|creator| !creator.is_empty());
    let governed = match admitted {
        Some(admitted) => {
            validate_create_input(
                req.name.as_str(),
                req.description.as_str(),
                req.default_branch_name.as_str(),
                wire_creator.as_deref().unwrap_or_default(),
            )?;
            let digest = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
                repository_id: &req.id,
                name: req.name.as_str(),
                description: req.description.as_str(),
                default_branch_id: &req.default_branch_id,
                default_branch_name: req.default_branch_name.as_str(),
                creator: wire_creator.as_deref(),
                caller_created: None,
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            GovernedRepositoryCreate::prepare(domain_context, Some(admitted), digest).await?
        }
        None => None,
    };

    let caller_context = CallerContext {
        repository_id: RepositoryId::default(), // RepositoryCreate has no pre-existing repository
        user_id,
        correlation_id,
        authorization,
    };

    if forwarding && let Some(forwarded_requests) = forwarded_requests {
        forward_repository_create(req, caller_context, forwarded_requests).await
    } else {
        repository_create_implementation(
            req,
            caller_context,
            auth_url,
            immutable_store,
            mutable_store,
            hook_dispatcher,
            instrument_provider,
            governed,
        )
        .await
    }
}

/// This `RepositoryCreateRequest` should be handled by another server
/// and the response forwarded on to the client
async fn forward_repository_create(
    req: RepositoryCreateRequest,
    context: CallerContext,
    forwarded_requests: &Arc<dyn ForwardedRequests>,
) -> Result<Response<RepositoryCreateResponse>, Status> {
    let mut client = forwarded_requests.forwarded_repository_service();
    let request = context.to_forwarded_request(req)?;

    let repository_create_result = client
        .repository_create(request)
        .await
        .warn_map_err(|_err| Status::internal("Error making forwarded request"))?;

    // the Error arm of this result is for the client
    let response = repository_create_result?;
    Ok(response)
}

/// This `RepositoryCreateRequest` should be fulfilled by this server.
///
/// `governed` is `Some` only when this handler admitted domain-operation
/// carriage; the forwarded v1 entry point in `forwarded_repository/` calls this
/// with `None` and keeps its own CARRIAGE-02-LORE fence, so a shared
/// implementation cannot open a second, ungated way in (the exact hazard
/// `gating-a-front-door-handler-leaves-a-shared-implementation-s-other-entry-point-open`
/// records).
#[allow(clippy::too_many_arguments)]
pub async fn repository_create_implementation(
    req: RepositoryCreateRequest,
    caller_context: CallerContext,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    hook_dispatcher: &HookDispatcher,
    instrument_provider: &impl InstrumentProvider,
    governed: Option<GovernedRepositoryCreate>,
) -> Result<Response<RepositoryCreateResponse>, Status> {
    let user_id = caller_context.user_id;
    let correlation_id = caller_context.correlation_id;
    let authorization = caller_context.authorization;

    let id: RepositoryId = Context::from(req.id).into();
    let name = req.name;
    let description = req.description;
    let default_branch_id: Context = req.default_branch_id.into();
    let default_branch_name = req.default_branch_name;
    let creator = req
        .creator
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| user_id.clone());

    let created = util::time::timestamp();

    let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
    ));
    Span::current().record("requested_repo_id", id.to_string());

    LORE_CONTEXT
        .scope(execution, async move {
            let hook_ctx = HookContext::builder()
                .correlation_id(correlation_id)
                .hook_point(HookPoint::RepositoryCreate)
                .repository(id)
                .user(user_id)
                .build();

            hook_dispatcher
                .dispatch_pre(HookPoint::RepositoryCreate, &hook_ctx)
                .map_err(hook_error_to_status)?;

            let (created_metadata, metadata_hash) = match &governed {
                Some(governed) => governed_repository_create(
                    governed,
                    repository.clone(),
                    &name,
                    &description,
                    default_branch_id,
                    &default_branch_name,
                    // v1 resolves the creator once, before this point, and
                    // passes the same value to both metadata blobs.
                    &creator,
                    &creator,
                    created,
                    auth_url,
                    authorization,
                )
                .await
                .inspect_err(|err| warn!(error = ?err, "Governed repository create failed"))?,
                None => repository_create_inner(
                    repository.clone(),
                    &name,
                    &description,
                    default_branch_id,
                    &default_branch_name,
                    &creator,
                    created,
                    auth_url,
                    authorization,
                )
                .await
                .inspect_err(|err| warn!(error = ?err, "Repository create failed"))?,
            };

            hook_dispatcher.spawn_post(HookPoint::RepositoryCreate, hook_ctx);

            instrument_provider
                .counter("num_repositories_created")
                .add(1, &[]);

            Ok(Response::new(RepositoryCreateResponse {
                repository: Some(build_repository(id, &created_metadata, metadata_hash)),
            }))
        })
        .await
}

/// Reject oversized string fields early to prevent resource exhaustion.
#[lore_macro::test_pub]
fn validate_create_input(
    name: &str,
    description: &str,
    default_branch_name: &str,
    creator: &str,
) -> Result<(), Status> {
    if name.len() > repository::MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "Repository name exceeds maximum length of {} bytes",
            repository::MAX_NAME_LEN,
        )));
    }
    if description.len() > repository::MAX_DESCRIPTION_LEN {
        return Err(Status::invalid_argument(format!(
            "Repository description exceeds maximum length of {} bytes",
            repository::MAX_DESCRIPTION_LEN,
        )));
    }
    if default_branch_name.len() > repository::MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "Branch name exceeds maximum length of {} bytes",
            repository::MAX_NAME_LEN,
        )));
    }
    if creator.len() > repository::MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "Creator exceeds maximum length of {} bytes",
            repository::MAX_NAME_LEN,
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn repository_create_inner(
    repository: Arc<RepositoryContext>,
    name: &str,
    description: &str,
    default_branch_id: Context,
    default_branch_name: &str,
    creator: &str,
    created: u64,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<(RepositoryMetadata, lore_storage::Hash), Status> {
    validate_create_input(name, description, default_branch_name, creator)?;

    if !repository::is_valid_name(name) {
        return Err(Status::invalid_argument("Invalid repository name"));
    }

    if let Ok(name_id) = Context::from_str(name)
        && !name_id.is_zero()
        && RepositoryId::from(name_id) != repository.id
    {
        return Err(Status::invalid_argument("Invalid repository name"));
    }

    if let Ok((metadata, metadata_hash)) =
        repository_load_id(repository.clone(), repository.id, None, None)
            .await
            .filter_slow_down()?
    {
        return if metadata.name == name {
            info!(
                "Repository {} already exist with name {}, early out create successful",
                repository.id, metadata.name
            );

            if repository_load_name(repository.clone(), name, None, None)
                .await
                .filter_slow_down()?
                .is_err()
            {
                info!(
                    "Recreating repository name {} -> ID {} mapping",
                    name, repository.id
                );
                // no filter_slow_down()? usage here: the create has already
                // succeeded, so this mapping repair must not fail it.
                let _ = repository::store_name_to_id(repository.clone(), name, repository.id)
                    .await
                    .inspect_err(|err| info!("Recreate name -> ID mapping failed: {err}"));
            }

            Ok((metadata, metadata_hash))
        } else {
            Err(Status::already_exists(format!(
                "Repository {} already exist with name {} which does not match {}",
                repository.id, metadata.name, name
            )))
        };
    }
    // Name-collision guard: its absent path lets the create below rebind the
    // name, so an unreadable answer must not be read as absence.
    if let Some((id, metadata, metadata_hash)) = none_or_status(
        repository_load_name(repository.clone(), name, None, None).await,
        |err| err.is_address_not_found() || err.is_repository_not_found(),
    )? {
        return if id == repository.id {
            info!(
                "Repository {} already exist with id {}, early out create successful",
                name, id
            );
            Ok((metadata, metadata_hash))
        } else {
            Err(Status::already_exists(format!(
                "Repository {} already exist with id {} which does not match {}",
                name, id, repository.id
            )))
        };
    }

    if let Some(auth_url) = auth_url {
        let client = Box::new(crate::authnz::rebac::grpc_get_rebac_client(auth_url).await?);
        // The ungoverned v1 implementation. A governed v1 create never reaches
        // here: it is routed to the shared `governed_repository_create` seam,
        // which attaches the claim itself.
        repository_create_auth_resource(client, authorization, repository.id, name, None).await?;
    }

    let metadata = RepositoryMetadata {
        name: name.to_string(),
        description: description.to_string(),
        default_branch: default_branch_id,
        default_branch_name: default_branch_name.to_string(),
        creator: creator.to_string(),
        created,
    };

    let metadata_hash = repository::metadata_store(repository.clone(), metadata.clone())
        .await
        .filter_slow_down()?
        .warn_map_err(|err| {
            Status::internal(format!("Failed to serialize repository metadata: {err}"))
        })?;

    let stack = vec![];
    let write_token = get_write_token();
    match branch::create(
        repository.clone(),
        &write_token,
        default_branch_id,
        default_branch_name,
        branch::default_category(),
        creator,
        created,
        stack,
        false,
        false,
    )
    .await
    .filter_slow_down()?
    {
        Ok(_) => {}
        Err(err) if err.is_branch_already_exists() => {}
        Err(err) => {
            let response = warn_error_to_status(&err, |err| {
                Status::internal(format!("Failed to create default branch: {err}"))
            });
            return Err(response);
        }
    }

    repository::metadata_store_hash(repository.clone(), metadata_hash)
        .await
        .filter_slow_down()?
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to store metadata hash for {name}/{}: {err}",
                repository.id
            ))
        })?;

    repository::store_name_to_id(repository.clone(), name, repository.id)
        .await
        .filter_slow_down()?
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to store name to ID lookup for {name} -> {}: {err}",
                repository.id
            ))
        })?;

    info!("Created repository {} with ID {}", name, repository.id);

    Ok((metadata, metadata_hash))
}

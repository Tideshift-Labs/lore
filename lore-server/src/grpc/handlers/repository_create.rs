// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::RepositoryCreateRequest;
use lore_proto::RepositoryCreateResponse;
use lore_proto::rebac::CreateResourceRequest;
use lore_proto::rebac::CreateResourceResponse;
use lore_revision::branch;
use lore_revision::lore::RepositoryId;
use lore_revision::lore::execution_context;
use lore_revision::metadata::Metadata;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_telemetry::InstrumentProvider;
use lore_transport::RepositoryData;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::Span;
use tracing::info;
use tracing::warn;

use super::repository_query::repository_query_id;
use super::repository_query::repository_query_name;
use crate::authnz::common::create_request_with_authorization;
use crate::authnz::rebac::RebacApiClient;
use crate::authnz::rebac::grpc_get_rebac_client;
use crate::domain::DomainContext;
use crate::domain::GovernedCreateWitness;
use crate::domain::GovernedRepositoryCreate;
use crate::domain::GovernedScope;
use crate::domain::PLATFORM_METHOD_REPOSITORY_CREATE;
use crate::domain::RepositoryCreatePublication;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::ServerResultExt;
use crate::grpc::extract_authorization_header;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_user_id;
use crate::grpc::get_write_token;
use crate::grpc::hook_error_to_status;
use crate::grpc::warn_error_to_status;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::util::setup_execution;

#[tracing::instrument(name = "RepositoryCreate::handle", skip_all, fields(requested_repo_id))]
pub async fn handler(
    request: Request<RepositoryCreateRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
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

    // WP-116 Part 3 wires this site through the shared governed create seam.
    //
    // The digest is derived here, from this handler's own validated wire
    // values, through the one shared canonical-intent definition. v0 is
    // `created_mode = 1`: the caller supplies the timestamp, and its exact
    // `u64` is bound so two v0 requests differing only in caller time cannot
    // alias. The handler's frozen size checks run first, because CR-029's
    // canonical-intent contract hashes only a request that has already
    // passed them. The name-charset checks stay inside the shared governed
    // body: they do not change the digest bytes, and a request that fails
    // them is refused before any receipt is consumed.
    let governed = match admitted {
        Some(admitted) => {
            validate_create_input(
                req.name.as_str(),
                req.description.as_str(),
                req.default_branch_name.as_str(),
                req.creator.as_str(),
            )?;
            let digest = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
                repository_id: &req.id,
                name: req.name.as_str(),
                description: req.description.as_str(),
                default_branch_id: &req.default_branch_id,
                default_branch_name: req.default_branch_name.as_str(),
                creator: Some(req.creator.as_str()).filter(|creator| !creator.is_empty()),
                caller_created: Some(req.created),
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            GovernedRepositoryCreate::prepare(domain_context, Some(admitted), digest).await?
        }
        None => None,
    };

    let id: RepositoryId = Context::from(req.id).into();

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

            let default_branch_id = req.default_branch_id.into();
            let repository = match &governed {
                Some(governed) => {
                    // v0 resolves an empty wire creator to the authenticated
                    // identity for the *repository* metadata only; the branch
                    // metadata keeps the raw value, because that is exactly
                    // what this handler passes `branch::create` today and the
                    // governed path must publish the same blob bytes.
                    let repository_creator = if req.creator.is_empty() {
                        execution_context().user_id().await
                    } else {
                        req.creator.clone()
                    };
                    let (metadata, metadata_hash) = governed_repository_create(
                        governed,
                        repository,
                        req.name.as_str(),
                        req.description.as_str(),
                        default_branch_id,
                        req.default_branch_name.as_str(),
                        repository_creator.as_str(),
                        req.creator.as_str(),
                        req.created,
                        auth_url,
                        authorization,
                    )
                    .await
                    .inspect_err(|err| warn!(error = ?err, "Governed repository create failed"))?;
                    RepositoryData {
                        id,
                        name: metadata.name,
                        metadata: metadata_hash,
                    }
                }
                None => repository_create(
                    repository,
                    req.name.as_str(),
                    req.description.as_str(),
                    default_branch_id,
                    req.default_branch_name.as_str(),
                    req.creator.as_str(),
                    req.created,
                    auth_url,
                    authorization,
                )
                .await
                .inspect_err(|err| warn!(error = ?err, "Repository create failed"))?,
            };

            hook_dispatcher.spawn_post(HookPoint::RepositoryCreate, hook_ctx);

            let num_repositories_created = instrument_provider.counter("num_repositories_created");
            num_repositories_created.add(1, &[]);

            Ok(Response::new(RepositoryCreateResponse {
                repository: Some(lore_proto::Repository {
                    id: repository.id.into(),
                    name: repository.name,
                    metadata: repository.metadata.into(),
                }),
            }))
        })
        .await
}

// Reject oversized string fields early to prevent resource exhaustion.
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
async fn repository_create(
    repository: Arc<RepositoryContext>,
    name: &str,
    description: &str,
    default_branch_id: Context,
    default_branch_name: &str,
    creator: &str,
    created: u64,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<RepositoryData, Status> {
    validate_create_input(name, description, default_branch_name, creator)?;

    if !repository::is_valid_name(name) {
        return Err(Status::invalid_argument("Invalid repository name"));
    }

    // If the name is an ID, make sure it matches the actual ID as we do not want
    // to alias IDs with mismatching names
    if let Ok(name_id) = Context::from_str(name)
        && !name_id.is_zero()
        && RepositoryId::from(name_id) != repository.id
    {
        return Err(Status::invalid_argument("Invalid repository name"));
    }

    // Check if a repository already exist. Skip authz check to also check repositories registered by others
    if let Ok(data) = repository_query_id(
        repository.clone(),
        repository.id,
        None, /* auth url */
        None, /* authorization */
    )
    .await
    {
        return if data.name == name {
            info!(
                "Repository {} already exist with name {}, early out create successful",
                repository.id, data.name
            );

            // Make sure name -> ID mapping exist
            if repository_query_name(
                repository.clone(),
                name,
                None, /* auth url */
                None, /* authorization */
            )
            .await
            .is_err()
            {
                info!(
                    "Recreating repository name {} -> ID {} mapping",
                    name, repository.id
                );
                let _ = repository::store_name_to_id(repository.clone(), name, repository.id)
                    .await
                    .inspect_err(|err| info!("Recreate name -> ID mapping failed: {err}"));
            }

            Ok(data)
        } else {
            Err(Status::already_exists(format!(
                "Repository {} already exist with name {} which does not match {}",
                repository.id, data.name, name
            )))
        };
    }
    if let Ok(data) = repository_query_name(
        repository.clone(),
        name,
        None, /* auth url */
        None, /* authorization */
    )
    .await
    {
        return if data.id == repository.id {
            info!(
                "Repository {} already exist with id {}, early out create successful",
                name, data.id
            );
            Ok(data)
        } else {
            Err(Status::already_exists(format!(
                "Repository {} already exist with id {} which does not match {}",
                name, data.id, repository.id
            )))
        };
    }

    if let Some(auth_url) = auth_url {
        let client = Box::new(grpc_get_rebac_client(auth_url).await?);
        repository_create_auth_resource(client, authorization, repository.id, name, None).await?;
    }

    // Set up the repository metadata
    let metadata = RepositoryMetadata {
        name: name.to_string(),
        description: description.to_string(),
        default_branch: default_branch_id,
        default_branch_name: default_branch_name.to_string(),
        creator: if !creator.is_empty() {
            creator.to_string()
        } else {
            execution_context().user_id().await
        },
        created,
    };

    let metadata = repository::metadata_store(repository.clone(), metadata)
        .await
        .warn_map_err(|err| {
            Status::internal(format!("Failed to serialize repository metadata: {err}"))
        })?;

    let stack = vec![];

    // Create the default branch
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

    repository::metadata_store_hash(repository.clone(), metadata)
        .await
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to store metadata hash for {name}/{}: {err}",
                repository.id
            ))
        })?;

    repository::store_name_to_id(repository.clone(), name, repository.id)
        .await
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to store name to ID lookup for {name} -> {}: {err}",
                repository.id
            ))
        })?;

    info!("Created repository {} with ID {}", name, repository.id);

    Ok(RepositoryData {
        id: repository.id,
        name: name.to_string(),
        metadata,
    })
}

/// The governed repository-create body, shared by the v0 and v1 handlers.
///
/// This is the CR-029 Phase 4 "move repository operations" path: the same
/// publication the legacy `repository_create` performs with four unsynchronised
/// store writes, done as one domain transaction.
///
/// # The transaction boundary
///
/// Everything with a side effect outside Postgres happens **before** the
/// transaction opens, in this order:
///
/// 1. the frozen size, repository-name, and branch-name checks;
/// 2. the ReBAC `CreateResource` callback, when auth is on;
/// 3. both metadata blobs, serialized into the immutable store.
///
/// Only then does the coordinator open its transaction, which writes the
/// repository row, the default-branch row, both name rows, all five
/// `lore_mutable` projection rows, and both classified outbox events — or none
/// of them.
///
/// The blob writes are before rather than after on purpose: the transaction
/// then only ever commits pointers to content that already exists. The cost is
/// two orphan blobs, and it is paid in two places, not one. A create refused or
/// lost after step 3 leaves them, as expected — but so does every **successful
/// exact retry on v1**, because v1 assigns `created` itself and the timestamp
/// is excluded from the canonical intent, so a retry rebuilds both blobs at a
/// new time, writes them, and then finds the original pointers already
/// committed. That is accepted and deliberate: an orphan blob in a
/// content-addressed store is unreferenced and unreachable, whereas a committed
/// pointer to a blob that was never written is a repository that cannot be
/// read.
///
/// # What is deliberately not done here
///
/// The legacy path's four existence early-outs are absent. They read the
/// mutable projection and answer before any receipt is consumed, which on the
/// governed rail is the wrong authority and the wrong moment: an exact retry
/// must reach the coordinator so `begin_admitted` replays its committed
/// receipt, and a same-ID-different-intent create must be refused by the
/// creation fingerprint rather than by a name comparison. The coordinator
/// answers both under the repository row lock.
///
/// # Two creator arguments
///
/// `repository_creator` is recorded in the repository metadata blob and
/// `branch_creator` in the default branch's. They are separate because the
/// legacy path already treats them separately: v0 resolves an empty wire
/// creator to the authenticated identity for the repository metadata, but hands
/// `branch::create` the raw wire value. Collapsing them into one argument would
/// change the branch blob's bytes on exactly the requests where the wire
/// creator is empty. v1 passes its resolved value to both.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn governed_repository_create(
    governed: &GovernedRepositoryCreate,
    repository: Arc<RepositoryContext>,
    name: &str,
    description: &str,
    default_branch_id: Context,
    default_branch_name: &str,
    repository_creator: &str,
    branch_creator: &str,
    created: u64,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<(RepositoryMetadata, lore_storage::Hash), Status> {
    // `branch_creator` rather than `repository_creator` is the value the legacy
    // path checks on both versions: v0 validates its raw wire creator and v1
    // its resolved one, which is exactly what this argument carries in each
    // case. Checking the other one would tighten v0 and loosen nothing.
    validate_create_input(name, description, default_branch_name, branch_creator)?;

    if !repository::is_valid_name(name) {
        return Err(Status::invalid_argument("Invalid repository name"));
    }

    // A name that parses as a non-zero ID must be this repository's own ID, or
    // it would alias one identity under another's name.
    if let Ok(name_id) = Context::from_str(name)
        && !name_id.is_zero()
        && RepositoryId::from(name_id) != repository.id
    {
        return Err(Status::invalid_argument("Invalid repository name"));
    }

    // `branch::create` makes this the first thing it checks. The governed path
    // does not call it, so the check has to be repeated rather than inherited —
    // and it must run before the ReBAC callback, since a refused branch name
    // would otherwise leave an auth resource for a repository that was never
    // published.
    if !branch::is_valid_name(default_branch_name) {
        return Err(Status::invalid_argument("Invalid branch name"));
    }

    // An attached claim with nowhere to acknowledge it. `auth_url` and JWT
    // authentication are separate settings, so a cell can verify a principal,
    // enforce the domain, and still have no ReBAC endpoint configured — and on
    // that cell the `if let` below would skip the callback entirely and commit a
    // claimed create that nothing ever acknowledged. The acknowledgement is the
    // one ordering this callback exists to establish, so its absence is a cell
    // misconfiguration and refused, not a step quietly omitted.
    let create_witness = governed.create_witness();
    if create_witness.is_some() && auth_url.is_none() {
        return Err(Status::failed_precondition(
            "Governed repository create requires a configured authorization service to \
             acknowledge its claim",
        ));
    }

    if let Some(auth_url) = auth_url {
        let client = Box::new(grpc_get_rebac_client(auth_url).await?);
        repository_create_auth_resource(client, authorization, repository.id, name, create_witness)
            .await?;
    }

    let metadata = RepositoryMetadata {
        name: name.to_string(),
        description: description.to_string(),
        default_branch: default_branch_id,
        default_branch_name: default_branch_name.to_string(),
        creator: repository_creator.to_string(),
        created,
    };
    let metadata_hash = repository::metadata_store(repository.clone(), metadata.clone())
        .await
        .warn_map_err(|err| {
            Status::internal(format!("Failed to serialize repository metadata: {err}"))
        })?;

    // The default branch's own metadata blob. `branch::create` builds this and
    // then writes the mutable pointer itself; the governed path builds the same
    // blob and hands the pointer to the coordinator instead.
    let mut branch_metadata = Metadata::new();
    branch::metadata_populate(
        &mut branch_metadata,
        default_branch_id,
        default_branch_name,
        branch::default_category(),
        branch_creator,
        created,
        Vec::new(),
    )
    .map_err(|err| {
        warn_error_to_status(&err, |err| {
            Status::internal(format!("Failed to populate default branch metadata: {err}"))
        })
    })?;
    let branch_metadata_hash = branch_metadata
        .serialize(repository.clone())
        .await
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to serialize default branch metadata: {err}"
            ))
        })?;

    // A repository create has no branch point, so `branch::create` publishes
    // the default branch at the zero tip. The zero hash is the store's delete
    // sentinel, which is why the projection row for it is a delete rather than
    // a row of zero bytes.
    let default_branch_latest_hash = lore_storage::Hash::default();

    let outcome = governed
        .commit(&RepositoryCreatePublication {
            salt: repository.salt(),
            repository_id: repository.id.data(),
            name,
            metadata_hash: metadata_hash.as_ref(),
            default_branch_id: default_branch_id.data(),
            default_branch_name,
            default_branch_metadata_hash: branch_metadata_hash.as_ref(),
            default_branch_latest_hash: default_branch_latest_hash.as_ref(),
        })
        .await?;

    info!(
        "Created repository {} with ID {} (governed, generation {:?})",
        name, repository.id, outcome.repository_generation
    );

    if outcome.metadata_hash == metadata_hash {
        return Ok((metadata, metadata_hash));
    }
    // An exact retry of a create whose metadata has since moved. The caller is
    // owed the repository that exists, so load the committed pointer's blob
    // rather than reporting the one this call rebuilt.
    let committed = repository::metadata(repository, outcome.metadata_hash)
        .await
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to load committed repository metadata: {err}"
            ))
        })?;
    Ok((committed, outcome.metadata_hash))
}

/// Fill tags 3-21 of the ReBAC create callback from the attached claim.
///
/// One assignment per field, in tag order, so the reviewer's job is a
/// side-by-side read against `rebac_api.proto` rather than a hunt through
/// derivations. Two fields are not simple copies and both are load-bearing:
///
/// - `method` is the platform family constant, never the operation binding's
///   gRPC path. See [`PLATFORM_METHOD_REPOSITORY_CREATE`].
/// - `authorization_id` is the operation id. CR-029 freezes the two to the same
///   value until a separate authorization-id column exists, and the verifier
///   requires the equality rather than merely tolerating it.
fn attach_create_claim(payload: &mut CreateResourceRequest, witness: &GovernedCreateWitness) {
    payload.verified_issuer = witness.verified_issuer.clone();
    payload.authenticated_subject = witness.authenticated_subject.clone();
    payload.org_uuid = witness.org_uuid.to_vec().into();
    payload.initiating_principal_namespace = witness.initiating_principal_namespace.to_vec().into();
    payload.operation_id = witness.operation_id.to_vec().into();
    payload.method = PLATFORM_METHOD_REPOSITORY_CREATE.to_owned();
    payload.scope = witness.scope.clone().into();
    payload.fingerprint_version = witness.fingerprint_version;
    payload.fingerprint = witness.fingerprint.clone().into();
    payload.canonical_intent_digest = witness.canonical_intent_digest.clone().into();
    payload.authorization_id = witness.operation_id.to_vec().into();
    payload.authorization_revision = witness.claim.authorization_revision;
    payload.verification_nonce = witness.claim.verification_nonce.to_vec().into();
    payload.bound_fields_digest = witness.claim.bound_fields_digest.to_vec().into();
    payload.consumed_ticket_sha256 = witness.claim.consumed_ticket_sha256.to_vec().into();
    payload.claim_id = witness.claim.claim_id.to_vec().into();
    payload.claim_revision = witness.claim.claim_revision;
    payload.claim_verification_witness = witness.claim.claim_verification_witness.to_vec().into();
    payload.prepare_token = witness.prepare_token.to_vec().into();
}

/// Require an exact acknowledgement of the claim this call attached.
///
/// The response is the only evidence Lore gets that the platform recognised
/// *this* claim rather than merely permitting *a* create, and it is checked
/// before the mutation transaction opens. A default-valued response is the shape
/// an older auth-grpc — or a verifier that took the catalog branch — returns, so
/// it is refused rather than read as a silent success.
fn verify_create_acknowledgement(
    response: CreateResourceResponse,
    witness: &GovernedCreateWitness,
) -> Result<(), Status> {
    let matches = response.claim_id.as_ref() == witness.claim.claim_id.as_slice()
        && response.claim_revision == witness.claim.claim_revision
        && response.claim_verification_witness.as_ref()
            == witness.claim.claim_verification_witness.as_slice();
    if matches {
        return Ok(());
    }
    // Deliberately not logged field by field. The divergent value is the
    // platform's answer about a claim this caller may not hold, and the caller
    // already knows what it sent.
    warn!(
        operation_id = %uuid::Uuid::from_bytes(witness.operation_id),
        "Governed repository create acknowledgement did not match the attached claim"
    );
    Err(Status::failed_precondition(
        "Governed repository create was not acknowledged by the authorization service",
    ))
}

/// Register the repository's auth resource, attaching the platform claim when
/// this is a mediated governed create.
///
/// # Why `witness` is `Option` and why `None` must stay byte-identical
///
/// auth-grpc decides which of two paths a `CreateResource` takes by asking
/// whether **any** of tags 3-21 is present (`hasGovernedCreateWitness`), and the
/// governed path it selects is exact-match-or-deny with no fallback to the
/// catalog. Its proto loader runs with `defaults: false`, so an unset proto3
/// scalar arrives as `undefined` rather than a zero value — which is exactly
/// what prost's default elision produces for `..Default::default()`. That is
/// the property keeping every legacy and direct create on the catalog path, so
/// the `None` arm below must never set a field.
///
/// The mirror of that rule binds the `Some` arm: **every** field it sets is
/// non-default by construction (both revisions are refused at zero, the
/// fingerprint version is 1, every digest and identity is fixed-width and
/// non-empty, both strings come from a verified token). A field that could be
/// its type's default would be elided on the wire and arrive `undefined`,
/// failing the verifier's exact match with a denial that names the wrong cause.
pub(crate) async fn repository_create_auth_resource(
    mut client: Box<dyn RebacApiClient + Send + Sync>,
    authorization: Option<String>,
    repository_id: RepositoryId,
    name: &str,
    witness: Option<&GovernedCreateWitness>,
) -> Result<(), Status> {
    info!(
        "Repository create auth resource for {} with name {} (governed claim: {})",
        repository_id,
        name,
        witness.is_some()
    );

    let mut payload = CreateResourceRequest {
        resource_id: format!("urc-{repository_id}"),
        resource_name: String::from(name),
        ..Default::default()
    };
    if let Some(witness) = witness {
        attach_create_claim(&mut payload, witness);
    }
    let request = create_request_with_authorization(payload, authorization)?;

    match client.create_resource(request).await {
        Ok(response) => match witness {
            Some(witness) => verify_create_acknowledgement(response.into_inner(), witness),
            None => Ok(()),
        },
        Err(err) if err.code() == Code::AlreadyExists && witness.is_some() => {
            // The governed branch of the callback never answers this way: it
            // either acknowledges the claim or denies. Accepting it would let
            // the mutation proceed with no acknowledgement at all, which is the
            // one ordering CR-029 requires this callback to establish.
            info!(auth_error = ?err, requested_repo_id = %repository_id, "Governed create callback answered AlreadyExists with no claim acknowledgement");
            Err(Status::failed_precondition(
                "Governed repository create was not acknowledged by the authorization service",
            ))
        }
        Err(err) if err.code() == Code::AlreadyExists => {
            info!(auth_error = ?err, requested_repo_id = %repository_id, "Auth resource for already exists, continuing");
            Ok(())
        }
        Err(err) if err.code() == Code::PermissionDenied => {
            info!(?err, "Create resource in auth failed - permission denied");
            Err(Status::permission_denied(
                "Failed to create repository, permission denied",
            ))
        }
        Err(err) if err.code() == Code::Unauthenticated => {
            info!(?err, "Create resource in auth failed - unauthenticated");
            Err(Status::unauthenticated(
                "Failed to create repository, reauthenticate",
            ))
        }
        Err(err) if err.code() == Code::NotFound => {
            // there is an issue with misbehaving clients who create external Auth resources but don't check
            // for a success response before calling RepositoryCreate (which in turn depends on those external
            // resources). Doing so results in Auth Service returning a NotFound error that should effectively be bubbled up
            // to the client
            info!(auth_error = ?err, "Repository Create create_resource failed because of Auth 'NotFound'");
            Err(Status::failed_precondition(
                "A required Auth entity was not found",
            ))
            // todo(plockhart): Once auth service supports Richer Error Model, change to look for an error code
        }
        Err(err)
            if err.code() == Code::InvalidArgument
                && err
                    .message()
                    .contains("Missing resource context in resourceName") =>
        {
            info!(auth_error = ?err, requested_name = name, "Repository Create create_resource failed - invalid name was provided");
            Err(Status::invalid_argument(
                "Invalid repository name - missing Organization context",
            ))
        }
        Err(err) if err.code() == Code::InvalidArgument && witness.is_some() => {
            // The verifier reports a malformed claim field as `INVALID_ARGUMENT`
            // with a field-specific message. Only one such message had a mapping
            // before this change, because a create carried no claim to be
            // malformed; every other one fell through to the arm below and came
            // back as `INTERNAL`, blaming the server for a caller's wire fault
            // and paging an operator for it.
            //
            // The verifier's message is deliberately not forwarded. It names a
            // field of a claim this caller may not hold, and the caller already
            // knows what it attached.
            info!(auth_error = ?err, requested_repo_id = %repository_id, "Governed create claim was rejected as malformed by the authorization service");
            Err(Status::invalid_argument(
                "Governed repository create carriage was rejected by the authorization service",
            ))
        }
        Err(err) => Err(warn_error_to_status(&err, |err| {
            Status::internal(format!("Failed to call auth create_resource: {err}"))
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        use super::*;
        use crate::authnz::rebac::RebacApiResult;

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

            let error = repository_create_auth_resource(
                Box::new(client),
                None,
                repository,
                repo_name,
                None,
            )
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

            let error = repository_create_auth_resource(
                Box::new(client),
                None,
                repository,
                repo_name,
                None,
            )
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

            let error = repository_create_auth_resource(
                Box::new(client),
                None,
                repository,
                repo_name,
                None,
            )
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

            let error = repository_create_auth_resource(
                Box::new(client),
                None,
                repository,
                repo_name,
                None,
            )
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
        use rand::random;

        use super::*;
        use crate::hooks::HookDispatcher;
        use crate::store::test_store_create;

        struct TestInstrumentProvider;

        impl lore_telemetry::InstrumentProvider for TestInstrumentProvider {
            fn namespace(&self) -> &'static str {
                "test"
            }
        }

        fn make_request(
            repository_id: RepositoryId,
            name: &str,
        ) -> Request<RepositoryCreateRequest> {
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
}

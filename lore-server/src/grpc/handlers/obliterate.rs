// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::outbox::builders as outbox_builders;
use lore_proto::ObliterateRequest;
use lore_proto::ObliterateResponse;
use lore_revision::notification::NotificationSender;
use lore_storage::StoreObliterateStats;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::metadata::MetadataMap;
use tracing::info;
use tracing::warn;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::JwtVerifier;
use crate::auth::jwt_interceptor::extract_bearer_token;
use crate::domain::DomainContext;
use crate::domain::GovernedScope;
use crate::domain::PLATFORM_METHOD_REPOSITORY_OBLITERATE;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::can_obliterate;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::hook_error_to_status;
use crate::grpc::warn_mapped_error_status;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::util::setup_execution;

async fn authenticate_request(
    metadata: &MetadataMap,
    jwt_verifier: &JwtVerifier,
) -> Result<AuthorizationToken, Status> {
    let token = extract_bearer_token(metadata)
        .ok_or_else(|| Status::unauthenticated("authorization header required"))?;

    jwt_verifier
        .verify_token(&token)
        .await
        .map_err(|e| Status::unauthenticated(format!("invalid token ({e:?})")))
}

#[allow(clippy::todo)]
#[tracing::instrument(name = "Obliterate::handle", skip_all)]
pub async fn handler(
    mut request: Request<ObliterateRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    _mutable_store: Arc<dyn lore_storage::MutableStore>,
    notification: Arc<dyn NotificationSender>,
    hook_dispatcher: &HookDispatcher,
    jwt_verifier: &Arc<Option<JwtVerifier>>,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<ObliterateResponse>, Status> {
    if let Some(verifier) = &**jwt_verifier {
        let authorization = authenticate_request(request.metadata(), verifier).await?;
        request.extensions_mut().insert(authorization);
    }

    let repository = get_repository(request.metadata())?;
    let request_metadata = request.metadata().clone();
    let request_authorization = crate::grpc::get_authorization_optional(request.extensions());
    let extensions = request.extensions().clone();
    let user_id = get_user_id(&extensions);
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let req = request.into_inner();

    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: repository.data(),
        },
    )?;
    if let Some(raw_address) = req.address.as_ref()
        && (raw_address.hash.len() != 32 || raw_address.context.len() != 16)
    {
        return Err(Status::invalid_argument(
            "obliterate address must contain a 32-byte hash and 16-byte context",
        ));
    }
    let address = Address::from(req.address.unwrap_or_default());
    let governed = match admitted {
        Some(admitted) => {
            let domain = domain_context
                .ok_or_else(|| Status::failed_precondition("Domain coordinator is unavailable"))?;
            let digest = canonical_intent_digest(&CanonicalIntent::Obliterate {
                repository_id: repository.data(),
                address_hash: address.hash.as_ref(),
                address_context: address.context.as_ref(),
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            // CR-032 PIN-3: the obliteration fence commits exactly one
            // `repository.obliterated` row, in the same transaction as the
            // fence. Built here, before the transaction opens, so an over-wide
            // or malformed identity is a request rejection rather than a
            // rollback. `None` when this cell has no configured identity; see
            // `DomainContext::cell_id`.
            let event = match domain.outbox_cell_id() {
                Some(cell_id) => Some(
                    outbox_builders::repository_obliterated(
                        cell_id,
                        repository.data(),
                        address.hash.as_ref(),
                        address.context.as_ref(),
                    )
                    .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                ),
                None => None,
            };
            let operation = domain
                .complete_governed(admitted, PLATFORM_METHOD_REPOSITORY_OBLITERATE, digest)
                .await?;
            Some((domain.clone(), operation, event))
        }
        None => None,
    };

    let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

    LORE_CONTEXT
        .scope(execution, async move {
            if jwt_verifier.is_some() && !can_obliterate(&extensions, repository) {
                warn!("Attempt to obliterate {address} in repository, but user does not have the correct permissions");
                return Err(Status::permission_denied("Permission denied"));
            }

            let hook_ctx = HookContext::builder()
                .correlation_id(correlation_id)
                .hook_point(HookPoint::Obliterate)
                .repository(repository)
                .user(user_id)
                .build();

            hook_dispatcher
                .dispatch_pre(HookPoint::Obliterate, &hook_ctx)
                .map_err(|error| {
                    let source_error = error.clone();
                    let response = hook_error_to_status(error);
                    warn_mapped_error_status(&source_error, &response);
                    response
                })?;

            info!("Handling obliterate request for address {address}");

            if let Some((domain, operation, event)) = governed.as_ref() {
                let result = domain
                    .store()
                    .begin_obliterate(operation, repository.data(), event.as_ref())
                    .await
                    .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
                if let DomainOutcome::NotApplied { reason, .. } = result.outcome {
                    return Err(crate::grpc::map_domain_rejection_to_status(&reason));
                }
            }

            let stats = Arc::new(StoreObliterateStats::default());
            immutable_store
                .obliterate(repository, address, stats.clone())
                .await
                .filter_slow_down()?
                .map_err(|e| {
                    warn!("Failed to obliterate {address}: {e}");
                    if e.is_address_not_found() {
                        // Distinguish absent from internal failure so the client can map this
                        // back to `AddressNotFound` and treat it as idempotent success.
                        // Without this, every absent obliterate would surface as a generic
                        // Internal error.
                        Status::not_found(format!("Address not found: {address}"))
                    } else {
                        Status::internal(format!("Failed to obliterate {address}: {e}"))
                    }
                })?;

            info!("Successfully obliterated {address}, stats: {stats:?}");
            // TODO(jcohen): track metrics for stats

            notification
                .obliterate(repository, address)
                .await
                .map_err(|e| {
                    warn!("Failed to obliterate address: {address}: {e:?}");
                    Status::internal("Obliterate failed")
                })?;

            hook_dispatcher.spawn_post(HookPoint::Obliterate, hook_ctx);

            Ok(Response::new(ObliterateResponse {}))
        })
        .await
}

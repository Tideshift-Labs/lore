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
        // BLOCKED(WP-116): a frozen authenticated forwarding contract for the
        // forwarded v1 RepositoryService.
        //
        // This site is fenced by contract, not by missing effort. CR-029's
        // CARRIAGE-02-LORE obligation requires forwarded v1 repository create
        // to "refuse governed carriage before delegation and keep its
        // coordinator guard until a separately frozen authenticated forwarding
        // contract exists". The forwarded services carry no interceptor at all
        // (see INV-BD), so there is no verified principal here to select a
        // mediated scope from; wiring it would admit an operation whose
        // authority nothing established.
        //
        // Do not remove this guard when the sibling repository-create sites are
        // wired. Those have a verified principal; this one does not.
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
        // Always ungoverned: the guard above refuses every carriage that
        // reaches this entry point, so there is never an admitted operation to
        // pass on.
        None,
    )
    .await
}

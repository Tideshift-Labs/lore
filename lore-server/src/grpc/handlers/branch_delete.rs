// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_proto::BranchDeleteRequest;
use lore_proto::BranchDeleteResponse;
use lore_revision::lore::BranchId;
use lore_revision::notification::NotificationSender;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::tracing::fields::BRANCH_ID;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::authnz::repository_authorizer::Action;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::domain::DomainContext;
use crate::domain::GovernedBranchDelete;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::BranchWriteFollowUp;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::delete_branch_detached;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::hook_error_to_status;
use crate::grpc::require_action;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::util::setup_execution;

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(name = "BranchDelete::handle", skip_all)]
pub async fn handler(
    request: Request<BranchDeleteRequest>,
    authorizer: &Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    notification_sender: Arc<dyn NotificationSender>,
    hook_dispatcher: &Arc<HookDispatcher>,
    instrument_provider: &(impl InstrumentProvider + Clone + Send + 'static),
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchDeleteResponse>, Status> {
    let repository_id = get_repository(request.metadata())?;
    // Captured before `into_inner` consumes the request: the domain-operation
    // headers and the verified principal both live outside the message body.
    let request_metadata = request.metadata().clone();
    let request_authorization = get_authorization_optional(request.extensions());
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();

    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: repository_id.data(),
        },
    )?;
    // Upstream v0.13's explicit action check, after admission (R-BLOCK-2) and
    // before any governed prepare write.
    require_action(authorizer, &request, Action::Write).await?;
    let req = request.into_inner();
    let governed = if admitted.is_some() {
        let digest = canonical_intent_digest(&CanonicalIntent::BranchDelete {
            repository_id: repository_id.data(),
            branch_id: &req.branch,
        })
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        GovernedBranchDelete::prepare(domain_context, admitted, digest).await?
    } else {
        None
    };
    let branch = BranchId::from(req.branch);
    debug!({BRANCH_ID} = %branch, "Handling branch delete");

    let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));
    LORE_CONTEXT
        .scope(execution, async move {
            let hook_ctx = HookContext::builder()
                .correlation_id(correlation_id)
                .hook_point(HookPoint::BranchDelete)
                .repository(repository_id)
                .user(user_id)
                .branch(branch)
                .build();

            hook_dispatcher
                .dispatch_pre(HookPoint::BranchDelete, &hook_ctx)
                .await
                .map_err(hook_error_to_status)?;

            // FORK (CR-029): a governed delete commits through the domain
            // coordinator in one Postgres transaction, in the request; a lost
            // answer is reconciled through its receipt. Only the ungoverned
            // path runs its write detached (upstream 8e39850e). The governed
            // commit's follow-ups run in a spawned task, started in the same
            // poll the commit returns, so a request dropped after the commit
            // cannot cancel them (as upstream's `run_detached` does).
            if let Some(governed) = governed {
                governed.commit_branch(repository, branch).await?;
                let follow_up = lore_base::lore_spawn!(tracing::Instrument::in_current_span({
                    let hook_dispatcher = hook_dispatcher.clone();
                    let instrument_provider = instrument_provider.clone();
                    async move {
                        instrument_provider
                            .counter("num_branches_deleted")
                            .add(1, &[]);
                        notification_sender
                            .branch_deleted(repository_id, branch)
                            .await;
                        hook_dispatcher.spawn_post(HookPoint::BranchDelete, hook_ctx);
                    }
                }));
                // The delete is committed: a failed follow-up task must not fail it.
                if let Err(err) = follow_up.await {
                    warn!({BRANCH_ID} = %branch, error = ?err, "Branch delete follow-up task failed");
                }
                return Ok(Response::new(BranchDeleteResponse {}));
            }
            match delete_branch_detached(
                repository,
                branch,
                BranchWriteFollowUp {
                    notification_sender,
                    hook_dispatcher: hook_dispatcher.clone(),
                    hook_context: hook_ctx,
                    instrument_provider: instrument_provider.clone(),
                },
            )
            .await?
            .filter_slow_down()?
            {
                Ok(()) => {
                    debug!({BRANCH_ID} = %branch, "Branch deleted");
                    Ok(Response::new(BranchDeleteResponse {}))
                }
                Err(err) if err.is_branch_not_found() => {
                    info!({BRANCH_ID} = %branch, "Failed to delete branch - does not exist");
                    Ok(Response::new(BranchDeleteResponse {}))
                }
                Err(err) if err.is_delete_protected() => {
                    info!({BRANCH_ID} = %branch, "Failed to delete branch - DeleteProtected");
                    Err(Status::failed_precondition("Branch is delete protected"))
                }
                Err(err) => {
                    warn!({BRANCH_ID} = %branch, error = ?err, "Failed to delete branch");
                    Err(Status::internal(err.to_string()))
                }
            }
        })
        .await
}

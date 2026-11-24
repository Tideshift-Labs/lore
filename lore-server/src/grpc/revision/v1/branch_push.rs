// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::types::Hash;
use lore_proto::lore::revision::v1::BranchPushRequest;
use lore_proto::lore::revision::v1::BranchPushResponse;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::notification::NotificationSender;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::tracing::fields::BRANCH_ID;
use lore_telemetry::tracing::fields::REVISION;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::Instrument;
use tracing::Level;
use tracing::debug;
use tracing::info;
use tracing::span;

use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::domain::DomainContext;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_is_service_account;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::handlers::branch_push::PushAccess;
use crate::grpc::handlers::branch_push::PushHandler;
use crate::grpc::handlers::branch_push::PushPhase;
use crate::grpc::handlers::branch_push::PushReport;
use crate::grpc::handlers::branch_push::PushResult;
use crate::grpc::handlers::branch_push::carried_push_preparation_error;
use crate::grpc::handlers::branch_push::dispatch_response_message;
use crate::grpc::handlers::branch_push::enforce_fenced_locks;
use crate::grpc::handlers::branch_push::extract_client_ip;
use crate::grpc::handlers::branch_push::load_branch_and_head;
use crate::grpc::handlers::branch_push::load_response_repository_metadata;
use crate::grpc::handlers::branch_push::prepare_governed_push;
use crate::grpc::handlers::branch_push::push_loaded;
use crate::grpc::handlers::branch_push::settle_governed_push;
use crate::grpc::handlers::push_lock_guard;
use crate::grpc::hook_error_to_status;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::hooks::context::METADATA_BRANCH_NAME;
use crate::hooks::context::METADATA_IS_SERVICE_ACCOUNT;
use crate::util::setup_execution;

/// `lore.revision.v1.RevisionService.BranchPush` handler.
///
/// Soft rejection (non-fast-forward without `force`/`fast_forward_merge`,
/// or fast-forward merge with conflicts) is conveyed via
/// `FailedPrecondition` with a detail message that distinguishes the
/// two cases and embeds the current branch latest. Pushing to a branch
/// id whose metadata is missing returns `NotFound`. Pushing to a
/// deleted branch reinstates the name → id mapping if the name is
/// still free, or returns `AlreadyExists` if claimed by a different
/// live branch. The pre-handlers run between reading the branch and
/// reinstating its mapping, so a rejected push writes nothing.
///
/// A fragment of the pushed revision the server does not hold is the
/// other `FailedPrecondition`, and the only one carrying an address in
/// the status details. `NotFound` names an absent branch alone, so a
/// caller reads it as one without inspecting the status further.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(name = "BranchPush::v1::handle", skip_all)]
pub async fn handler(
    request: Request<BranchPushRequest>,
    authorizer: Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    notification: Arc<dyn NotificationSender>,
    hook_dispatcher: &HookDispatcher,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
    instrument_provider: &impl InstrumentProvider,
    lock_enforcement: Option<&push_lock_guard::PushLockEnforcement>,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchPushResponse>, Status> {
    let user_id = get_user_id(request.extensions());
    let is_service_account = get_is_service_account(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let repository_id = get_repository(request.metadata())?;
    let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

    PushReport::new(PushHandler::V1, repository_id)
        .run(execution, async move |report| {
            let request_metadata = request.metadata().clone();
            let request_authorization =
                crate::grpc::get_authorization_optional(request.extensions());
            let access = PushAccess::of(&authorizer, request.extensions(), repository_id).await?;

            let client_ip: Option<String> = extract_client_ip(&request).map(|ip| ip.to_string());
            let req = request.into_inner();

            // FORK-LOCAL (Tideshift, CR-029): the one shared reader of the
            // domain-operation headers.
            let admitted = admit_at_entry(
                domain_context,
                &request_metadata,
                request_authorization.as_ref(),
                GovernedScope::TargetRepository {
                    repository_id: repository_id.data(),
                },
            )?;
            let branch_id = BranchId::from(req.id);
            let revision = Hash::from(req.revision_signature);
            let force = req.force;
            let fast_forward_merge = req.fast_forward_merge;
            report.set_target(branch_id, revision);

            // Request validation precedes witness capture: a zero-revision request is
            // malformed, not a CR-019 bypass, and must not pay for a database read
            // before it is rejected (INV-EE P2-10).
            if revision.is_zero() {
                info!("Invalid branch push request, revision_signature is zero");
                return Err(carried_push_preparation_error(
                    admitted.as_ref(),
                    Status::invalid_argument("revision_signature must be non-zero"),
                ));
            }

            let fenced_coordinator =
                domain_context.and_then(|domain| domain.lock_coordinator().cloned());
            let governed_push = prepare_governed_push(
                domain_context,
                admitted,
                repository_id,
                branch_id,
                revision,
                force,
                fast_forward_merge,
            )
            .await?;

            debug!(
                {REVISION} = %revision,
                ?access,
                {BRANCH_ID} = %branch_id,
                force,
                fast_forward_merge,
                "Handling branch push request",
            );

            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                repository_id,
            ));
            let repository_id: RepositoryId = repository.id;

            // FORK-LOCAL (Tideshift, CR-019/CR-029/CR-030): everything from the
            // branch read to the publication is one result, so a governed push's
            // refusal is settled against its publication receipt before it is
            // answered. See the shared v0 handler.
            let admitted_push = async {
                let (branch_metadata, loaded) =
                    load_branch_and_head(repository.clone(), branch_id, revision).await;
                let branch_metadata = branch_metadata?;

                let mut ctx_builder = HookContext::builder()
                    .correlation_id(correlation_id.clone())
                    .hook_point(HookPoint::BranchPush)
                    .repository(repository_id)
                    .user(user_id.clone())
                    .branch(branch_id)
                    .revision(revision)
                    .metadata(
                        METADATA_BRANCH_NAME,
                        branch::name(&branch_metadata).unwrap_or_default(),
                    )
                    .metadata(METADATA_IS_SERVICE_ACCOUNT, is_service_account.to_string());

                if let Some(ip) = client_ip {
                    ctx_builder = ctx_builder.metadata("client_ip", ip);
                }

                let hook_ctx = ctx_builder.build();

                hook_dispatcher
                    .dispatch_pre(HookPoint::BranchPush, &hook_ctx)
                    .await
                    .map_err(hook_error_to_status)?;

                // On a fenced cell the coordinator checks every push, governed or
                // not, because it is the only authority holding a lock's verified
                // owner pair; off a fenced cell CR-019's opt-in guard applies.
                if let Some(coordinator) = fenced_coordinator.as_ref() {
                    let pusher = match governed_push.as_ref() {
                        Some(governed) => governed.owner.clone(),
                        None => {
                            push_lock_guard::verified_push_owner(request_authorization.as_ref())?
                        }
                    };
                    enforce_fenced_locks(
                        coordinator,
                        repository.clone(),
                        branch_id,
                        revision,
                        &pusher,
                    )
                    .await?;
                } else if let Some(enforcement) = lock_enforcement {
                    let pusher =
                        push_lock_guard::verified_push_owner(request_authorization.as_ref())?;
                    push_lock_guard::enforce_push_locks(
                        repository.clone(),
                        enforcement,
                        branch_id,
                        revision,
                        &pusher,
                    )
                    .await?;
                }
                Ok::<_, Status>((branch_metadata, loaded, hook_ctx))
            }
            .await;

            let (pushed, hook_ctx, repository_metadata) = match admitted_push {
                Ok((branch_metadata, loaded, hook_ctx)) => {
                    let (pushed, repository_metadata) = tokio::join!(
                        async {
                            let pushed = push_loaded(
                                repository.clone(),
                                branch_id,
                                revision,
                                access,
                                force,
                                fast_forward_merge,
                                history_step_size,
                                acceleration,
                                branch_metadata,
                                loaded,
                                governed_push.as_ref(),
                                &mut *report,
                            )
                            .await;
                            report.enter(PushPhase::Respond);
                            pushed
                        },
                        load_response_repository_metadata(hook_dispatcher, repository.clone()),
                    );
                    (pushed, Some(hook_ctx), repository_metadata)
                }
                Err(status) => {
                    report.enter(PushPhase::Respond);
                    (Err(status), None, None)
                }
            };
            let PushResult {
                success,
                advanced,
                fast_forward_merged,
                revision: resulting_revision,
                revision_number,
                branch_name,
            } = settle_governed_push(governed_push.as_ref(), pushed).await?;

            // A successful no-op push (the current head again) is answered but
            // emits no push side effect: Lorehub reads a hook as a real branch
            // transition.
            if advanced {
                instrument_provider
                    .counter("num_branches_pushed")
                    .add(1, &[]);
            }

            if !success {
                let detail = if fast_forward_merge {
                    format!("Fast-forward merge has conflicts; branch latest: {resulting_revision}")
                } else {
                    format!(
                        "Branch push is not a fast-forward; branch latest: {resulting_revision}"
                    )
                };
                debug!(
                    {BRANCH_ID} = %branch_id,
                    branch_latest = %resulting_revision,
                    fast_forward_merge,
                    "Branch push rejected",
                );
                return Err(Status::failed_precondition(detail));
            }

            if advanced && let Some(mut hook_ctx) = hook_ctx {
                lore_spawn!({
                    let user_id = user_id.clone();
                    async move {
                        notification
                            .branch_pushed(
                                repository_id,
                                branch_id,
                                &user_id,
                                resulting_revision,
                                revision_number,
                            )
                            .instrument(span!(Level::DEBUG, "publish_notification"))
                            .await;
                    }
                    .in_current_span()
                });

                hook_ctx.set_revision_number(revision_number);
                hook_dispatcher.spawn_post(HookPoint::BranchPush, hook_ctx);
            }

            let message = dispatch_response_message(
                hook_dispatcher,
                &correlation_id,
                &user_id,
                repository_id,
                branch_id,
                &branch_name,
                resulting_revision,
                repository_metadata.as_ref(),
            );

            debug!(
                {BRANCH_ID} = %branch_id,
                {REVISION} = %resulting_revision,
                revision_number,
                fast_forward_merged,
                "Branch push response",
            );

            Ok(Response::new(BranchPushResponse {
                revision_signature: resulting_revision.into(),
                revision_number,
                fast_forward_merged,
                message,
            }))
        })
        .await
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::net::IpAddr;
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::locks::PostgresLockCoordinator;
use lore_postgres::domain::locks::PushLockWitness;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_postgres::domain::outbox::builders as outbox_builders;
use lore_proto::BranchPushRequest;
use lore_proto::BranchPushResponse;
use lore_revision::branch;
use lore_revision::branch::BranchError;
use lore_revision::branch::LATEST;
use lore_revision::branch::PROTECT;
use lore_revision::branch::load_latest;
use lore_revision::branch::metadata;
use lore_revision::branch::push;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::notification::NotificationSender;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::state;
use lore_revision::state::State;
use lore_storage::StoreError;
use lore_storage::StoreMatch;
use lore_storage::StoreMatchResult;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::tracing::fields::BRANCH_ID;
use lore_telemetry::tracing::fields::REVISION;
use tokio::task::JoinSet;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::Instrument;
use tracing::Level;
use tracing::debug;
use tracing::instrument;
use tracing::span;
use tracing::warn;

use super::push_lock_guard;
use super::push_lock_guard::PushLockEnforcement;
use crate::cache;
use crate::domain::AdmittedOperation;
use crate::domain::DomainContext;
use crate::domain::GovernedScope;
use crate::domain::admit_at_entry;
use crate::domain::reject_unwired_governed_operation;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::ServerResultExt;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::get_write_token;
use crate::grpc::hook_error_to_status;
use crate::grpc::warn_error_to_status;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::util::setup_execution;

#[cfg(test)]
mod governed_tests;

pub(crate) fn extract_client_ip<T>(request: &Request<T>) -> Option<IpAddr> {
    // try to get the LAST entry from XFF metadata header (injected by ALB)
    if let Some(ip_str) = request
        .metadata()
        .get("x-forwarded-for")
        .and_then(|header_value| header_value.to_str().ok())
        .and_then(|ip_list| ip_list.rsplit(',').next()) // use the last value, if multiple are present
        .map(str::trim)
        && let Ok(ip) = ip_str.parse::<IpAddr>()
    {
        return Some(ip);
    }

    // if XFF is not available, fallback to using remote_addr()
    request.remote_addr().map(|socket_addr| socket_addr.ip())
}

#[tracing::instrument(name = "BranchPush::handle", skip_all)]
#[allow(clippy::too_many_arguments)]
pub async fn handler(
    request: Request<BranchPushRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    notification: Arc<dyn NotificationSender>,
    hook_dispatcher: &HookDispatcher,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
    instrument_provider: &impl InstrumentProvider,
    lock_enforcement: Option<&PushLockEnforcement>,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<BranchPushResponse>, Status> {
    let request_metadata = request.metadata().clone();
    let request_authorization = crate::grpc::get_authorization_optional(request.extensions());
    let user_info = get_authorization(request.extensions());
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let repository = get_repository(request.metadata())?;

    // TODO(mjansson): Once we have authz permission model with read/write/admin
    // this should be upgraded to check for the correct permission rather than
    // hardwired to service accounts. For now used to protect while allowing mirroring
    let mut bypass_protection = false;
    if let Ok(user_info) = user_info
        && user_info.is_service_account.unwrap_or_default()
    {
        bypass_protection = true;
    }

    let client_ip: Option<String> = extract_client_ip(&request).map(|ip_addr| ip_addr.to_string());
    let req = request.into_inner();

    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: repository.data(),
        },
    )?;
    let branch = BranchId::from(req.branch);
    let revision = Hash::from(req.revision);
    let force = req.force;
    let fast_forward_merge = req.fast_forward_merge;

    // Request validation precedes witness capture: a zero-revision request is
    // malformed, not a CR-019 bypass, and must not pay for a database read
    // before it is rejected (INV-EE P2-10).
    if revision.is_zero() {
        warn!("Invalid branch push request, revision is zero");
        return Err(Status::invalid_argument("Invalid revision"));
    }

    let fenced_coordinator = domain_context.and_then(|domain| domain.lock_coordinator().cloned());
    let governed_push = prepare_governed_push(
        domain_context,
        admitted,
        repository,
        branch,
        revision,
        force,
        fast_forward_merge,
    )
    .await?;

    debug!({REVISION} = %revision, bypass_protection, {BRANCH_ID} = %branch, force, fast_forward_merge,
        "Handling branch push request",
    );

    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository,
    ));

    let repository_id: RepositoryId = repository.id;

    let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

    LORE_CONTEXT
        .scope(execution, async move {
            let mut ctx_builder = HookContext::builder()
                .correlation_id(correlation_id.clone())
                .hook_point(HookPoint::BranchPush)
                .repository(repository_id)
                .user(user_id.clone())
                .branch(branch)
                .revision(revision);

            if let Some(ip) = client_ip {
                ctx_builder = ctx_builder.metadata("client_ip", ip);
            }

            let mut hook_ctx = ctx_builder.build();

            hook_dispatcher
                .dispatch_pre(HookPoint::BranchPush, &hook_ctx)
                .map_err(hook_error_to_status)?;

            // On a fenced cell the coordinator is the only authority that can
            // read a lock's verified owner pair, so it checks every push,
            // governed or not, and the legacy subject-only guard is skipped.
            // Off a fenced cell CR-019's opt-in guard applies: `Some` only when
            // the `enforce_locks_on_push` feature is on AND a lock store exists;
            // absent → no behavior change (Lore's default advisory semantics).
            if let Some(coordinator) = fenced_coordinator.as_ref() {
                let pusher = match governed_push.as_ref() {
                    Some(governed) => governed.owner.clone(),
                    None => push_lock_guard::verified_push_owner(request_authorization.as_ref())?,
                };
                enforce_fenced_locks(coordinator, repository.clone(), branch, revision, &pusher)
                    .await?;
            } else if let Some(enforcement) = lock_enforcement {
                let pusher = push_lock_guard::verified_push_owner(request_authorization.as_ref())?;
                push_lock_guard::enforce_push_locks(
                    repository.clone(),
                    enforcement,
                    branch,
                    revision,
                    &pusher,
                )
                .await?;
            }

            let PushResult {
                success,
                advanced,
                fast_forward_merged,
                revision,
                revision_number,
            } = push_with_governance(
                repository.clone(),
                branch,
                revision,
                bypass_protection,
                force,
                fast_forward_merge,
                history_step_size,
                acceleration,
                governed_push.as_ref(),
            )
            .await?;

            if advanced {
                lore_spawn!({
                    let user_id = user_id.clone();
                    async move {
                        notification
                            .branch_pushed(
                                repository_id,
                                branch,
                                &user_id,
                                revision,
                                revision_number,
                            )
                            .instrument(span!(Level::DEBUG, "publish_notification"))
                            .await;
                    }
                    .in_current_span()
                });

                // Post-hook dispatch (async, non-blocking)
                hook_ctx.set_revision_number(revision_number);
                hook_dispatcher.spawn_post(HookPoint::BranchPush, hook_ctx);
            }

            if advanced {
                let num_branches_pushed = instrument_provider.counter("num_branches_pushed");
                num_branches_pushed.add(1, &[]);
            }

            let message = if success {
                dispatch_response_message(
                    hook_dispatcher,
                    &correlation_id,
                    &user_id,
                    repository_id,
                    branch,
                    revision,
                    repository.clone(),
                )
                .await
            } else {
                None
            };

            Ok(Response::new(BranchPushResponse {
                success,
                fast_forward_merged,
                revision: revision.into(),
                revision_number,
                message,
            }))
        })
        .await
}

/// Pre-computes repository and branch metadata, then dispatches response hooks
/// to generate an optional message for the client.
///
/// Metadata lookup failures are silently ignored — absent metadata keys cause
/// response hooks to return an empty response.
pub(crate) async fn dispatch_response_message(
    hook_dispatcher: &HookDispatcher,
    correlation_id: &str,
    user_id: &str,
    repository_id: RepositoryId,
    branch: BranchId,
    revision: Hash,
    repository: Arc<RepositoryContext>,
) -> Option<String> {
    let mut builder = HookContext::builder()
        .correlation_id(correlation_id)
        .hook_point(HookPoint::BranchPush)
        .repository(repository_id)
        .user(user_id)
        .branch(branch)
        .revision(revision);

    if let Ok(metadata_hash) = repository::metadata_hash(repository.clone()).await
        && let Ok(repository_metadata) =
            repository::metadata(repository.clone(), metadata_hash).await
    {
        builder = builder
            .metadata("repository_name", repository_metadata.name.clone())
            .metadata(
                "default_branch_name",
                &repository_metadata.default_branch_name,
            )
            .metadata(
                "is_default_branch",
                if repository_metadata.default_branch == branch {
                    "true"
                } else {
                    "false"
                },
            );
    }

    if let Ok(branch_meta) = branch::metadata(repository.clone(), branch).await
        && let Ok(branch_meta) =
            branch::branch_metadata(repository.clone(), branch, &branch_meta).await
    {
        builder = builder.metadata("branch_name", branch_meta.name);
    }

    let response_ctx = builder.build();
    hook_dispatcher
        .dispatch_response(HookPoint::BranchPush, &response_ctx)
        .message
}

#[derive(Debug)]
pub struct PushResult {
    pub success: bool,
    /// Whether this call moved the branch head. A successful push of the
    /// current head is an idempotent no-op and must not emit push side effects.
    pub advanced: bool,
    pub fast_forward_merged: bool,
    pub revision: Hash,
    pub revision_number: u64,
}

/// Preflight state consumed exactly once at the final publication boundary.
pub(crate) struct GovernedPushCommit {
    domain: Arc<DomainContext>,
    operation: lore_postgres::domain::coordinator::GovernedOperation,
    repository_generation: i64,
    branch_generation: i64,
    expected_latest_hash: Vec<u8>,
    lock_witness: PushLockWitness,
    pub(crate) owner: VerifiedLockOwner,
    /// The branch's authored name, carried for the event's bounded payload.
    ///
    /// Not an identity: CR-032's 2026-09-03 branch amendment makes the branch
    /// aggregate's `aggregate_id` the 16-byte branch id, precisely because a
    /// name can run to 1,000 bytes. It is read from the same preflight snapshot
    /// as the generation it is published alongside, so the payload names the
    /// branch the CAS was asserted against rather than whatever it is called by
    /// the time a consumer reads the row.
    branch_name: String,
}

/// Capture SCHEMA-117's witness independently of CR-019 and prepare the
/// governed final-push call when operation identity is present.
pub(crate) async fn prepare_governed_push(
    domain: Option<&Arc<DomainContext>>,
    admitted: Option<AdmittedOperation>,
    repository_id: RepositoryId,
    branch_id: BranchId,
    requested_revision: Hash,
    force: bool,
    fast_forward_merge: bool,
) -> Result<Option<GovernedPushCommit>, Status> {
    let Some(domain) = domain else {
        if let Some(admitted) = admitted.as_ref() {
            return Err(reject_unwired_governed_operation(
                admitted,
                "branch_push_commit",
            ));
        }
        return Ok(None);
    };
    let Some(lock_coordinator) = domain.lock_coordinator() else {
        if let Some(admitted) = admitted.as_ref() {
            return Err(reject_unwired_governed_operation(
                admitted,
                "branch_push_commit",
            ));
        }
        return Ok(None);
    };

    // This read is unconditional whenever fenced routing is present. It is
    // deliberately before either CR-019's feature gate or its no-change early
    // return, as required by F-030-2's amendment.
    let lock_witness = lock_coordinator
        .capture_push_witness(repository_id.as_ref(), branch_id.as_ref())
        .await
        .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
    let Some(admitted) = admitted else {
        return Ok(None);
    };

    let repository = domain
        .store()
        .repository_snapshot(repository_id.as_ref())
        .await
        .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?
        .filter(|snapshot| snapshot.live)
        .ok_or_else(|| Status::not_found("Repository not found"))?;
    let branch = domain
        .store()
        .branch_snapshot(repository_id.as_ref(), branch_id.as_ref())
        .await
        .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?
        .filter(|snapshot| snapshot.live)
        .ok_or_else(|| Status::not_found("Branch not found"))?;

    let digest = canonical_intent_digest(&CanonicalIntent::BranchPush {
        repository_id: repository_id.as_ref(),
        branch_id: branch_id.as_ref(),
        requested_revision: requested_revision.as_ref(),
        force,
        fast_forward_merge,
    })
    .map_err(|error| Status::invalid_argument(error.to_string()))?;

    let owner = VerifiedLockOwner {
        verified_issuer: admitted.key.verified_issuer.clone(),
        authenticated_subject: admitted.key.authenticated_subject.clone(),
    };
    Ok(Some(GovernedPushCommit {
        domain: domain.clone(),
        operation: admitted.into_governed("branch_push_commit", digest),
        repository_generation: repository.generation,
        branch_generation: branch.generation,
        expected_latest_hash: branch.latest_hash,
        lock_witness,
        owner,
        branch_name: branch.name,
    }))
}

/// Reject a push that touches a resource locked by another verified owner pair.
///
/// A free function rather than a method on [`GovernedPushCommit`] because it
/// must also run for an *ungoverned* push on a fenced cell: a client that
/// carries no domain-operation headers still gets no licence to push over a
/// foreign lock (INV-EE P1-1). The legacy `push_lock_guard` cannot serve a
/// fenced cell — it reads subject-only owners from the legacy store — so on a
/// fenced cell this is the only push-lock comparison, and it is unconditional
/// with respect to CR-019's `enforce_locks_on_push` (CR-030 F-030-2 amendment).
pub(crate) async fn enforce_fenced_locks(
    coordinator: &PostgresLockCoordinator,
    repository: Arc<RepositoryContext>,
    branch: BranchId,
    new_revision: Hash,
    pusher: &VerifiedLockOwner,
) -> Result<(), Status> {
    let foreign_locks = coordinator
        .query(repository.id.as_ref(), Some(branch.as_ref()), None)
        .await
        .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?
        .into_iter()
        .filter(|lock| !lock.owner.ct_matches(pusher))
        .collect::<Vec<_>>();
    if foreign_locks.is_empty() {
        return Ok(());
    }

    let prior_tip = load_latest(repository.clone(), branch)
        .await
        .map_err(|error| Status::internal(format!("failed to load branch tip: {error}")))?;
    // Shared with the legacy guard so the two authorities cannot drift on the
    // rename-endpoint expansion or the path-to-resource-hash mapping, which is
    // the part that must agree with what a client used to acquire the lock.
    let changed = push_lock_guard::changed_paths(repository, prior_tip, new_revision).await?;
    let conflicts = push_lock_guard::conflicts_for_changed_paths(changed, branch, |hash| {
        foreign_locks
            .iter()
            .find(|lock| lock.resource_hash.as_slice() == hash.as_ref())
            .map(|lock| lock.owner.authenticated_subject.clone())
    });

    if let Some(first) = conflicts.first() {
        warn!(
            path = %first.path,
            conflict_count = conflicts.len(),
            "Rejecting push: changed path is locked by another verified owner pair",
        );
        return Err(Status::permission_denied(format!(
            "push blocked: {} file(s) changed are locked by another verified owner; \
             e.g. '{}' is locked by {}",
            conflicts.len(),
            first.path,
            first.owner,
        )));
    }
    Ok(())
}

impl GovernedPushCommit {
    async fn publish(
        &self,
        repository: &RepositoryContext,
        branch: BranchId,
        current_head: Hash,
        new_head: Hash,
    ) -> Result<Hash, Status> {
        if self.expected_latest_hash.as_slice() != current_head.as_ref() {
            return Err(Status::aborted("Branch preflight changed; rerun preflight"));
        }
        let (key, key_type) = branch::mutable_key(repository.salt(), LATEST, repository.id, branch);
        // The classified `branch.pushed` row.
        //
        // `branch_push_commit` remains the **only** suppression authority for a
        // current-head push: it compares the locked row and returns before its
        // append, which is the point WP-119's inventory (disagreement C1)
        // requires be pinned. Skipping the build here is not a second
        // suppression decision, it is a build skip on the one case where the
        // coordinator's answer is already determined. `publish` has just
        // asserted `expected_latest_hash == current_head`, so
        // `current_head == new_head` means `expected == new` and the
        // coordinator's no-op arm is forced. CR-032 classifies that push as
        // "No new event", so building one would be work whose only possible
        // outcomes are discarded or a spurious error. The reverse direction
        // stays safe: if the handler thinks the head advances and the
        // coordinator finds it did not, the coordinator suppresses and the
        // built event is simply unused.
        //
        // `None` also when this cell has no configured identity; see
        // `DomainContext::cell_id`.
        let event = match (self.domain.cell_id(), current_head == new_head) {
            (Some(cell_id), false) => Some(
                outbox_builders::branch_pushed(
                    cell_id,
                    repository.id.as_ref(),
                    branch.as_ref(),
                    &self.branch_name,
                    current_head.as_ref(),
                    new_head.as_ref(),
                )
                .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
            ),
            (Some(_), true) | (None, _) => None,
        };
        let input = BranchPushCommitInput {
            repository_id: repository.id.as_ref().to_vec(),
            branch_id: branch.as_ref().to_vec(),
            expected_repository_generation: self.repository_generation,
            expected_branch_generation: self.branch_generation,
            expected_repository_lock_generation: self.lock_witness.repository_lock_generation,
            expected_branch_lock_generation: self.lock_witness.branch_lock_generation,
            expected_branch_lock_namespace_last_applied_fence: self
                .lock_witness
                .branch_lock_namespace_last_applied_fence,
            expected_latest_hash: current_head.as_ref().to_vec(),
            new_latest_hash: new_head.as_ref().to_vec(),
            projection: vec![ProjectionWrite {
                partition: repository.id.as_ref().to_vec(),
                key_type: key_type as i16,
                key: key.as_ref().to_vec(),
                value: Some(new_head.as_ref().to_vec()),
            }],
            event,
        };
        let result = self
            .domain
            .store()
            .branch_push_commit(&self.operation, &input)
            .await
            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
        match result.outcome {
            DomainOutcome::Applied => Ok(new_head),
            DomainOutcome::NotApplied { reason, .. } => match reason.as_str() {
                lore_postgres::domain::coordinator::TOMBSTONED_V1
                | lore_postgres::domain::coordinator::NOT_FOUND_V1 => {
                    Err(Status::not_found("Branch not found"))
                }
                lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1
                | lore_postgres::domain::coordinator::CAS_MISMATCH_V1 => {
                    Err(Status::aborted("Branch preflight changed; rerun preflight"))
                }
                _ => Err(Status::failed_precondition(reason)),
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[instrument(level = "debug", skip_all, fields(branch))]
pub async fn push(
    repository: Arc<RepositoryContext>,
    branch: BranchId,
    latest: Hash,
    bypass_protection: bool,
    force: bool,
    fast_forward_merge: bool,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
) -> Result<PushResult, Status> {
    push_with_governance(
        repository,
        branch,
        latest,
        bypass_protection,
        force,
        fast_forward_merge,
        history_step_size,
        acceleration,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn push_with_governance(
    repository: Arc<RepositoryContext>,
    branch: BranchId,
    latest: Hash,
    bypass_protection: bool,
    force: bool,
    fast_forward_merge: bool,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
    governed: Option<&GovernedPushCommit>,
) -> Result<PushResult, Status> {
    // Zero hash is never valid to push as latest pointer
    if latest.is_zero() {
        return Err(Status::failed_precondition("invalid revision signature"));
    }

    // Check if branch is protected
    let branch_metadata = metadata(repository.clone(), branch)
        .await
        .warn_map_err(|err| Status::internal(format!("Failed to load branch metadata: {err}")))?;

    if branch_metadata.get_bool(PROTECT).unwrap_or_default() {
        if bypass_protection {
            debug!("Bypass branch protection and push to protected branch");
        } else {
            warn!("Branch push failed, branch is protected");
            return Err(Status::permission_denied("protected"));
        }
    }

    // Verify the branch has not been deleted by checking the name→id mapping
    if let Ok(branch_name) = branch::name(&branch_metadata)
        && !branch_name.is_empty()
    {
        let is_mapped = branch::load_name_to_id_local(repository.clone(), branch_name)
            .await
            .is_ok_and(|id| id == branch);
        if !is_mapped {
            debug!("Branch push rejected, name-to-id mapping missing for deleted branch");
            return Err(Status::not_found("Branch not found"));
        }
    }

    let mut current_head = load_latest(repository.clone(), branch)
        .await
        .unwrap_or_default();

    // Verify the validity of the revision to push to latest
    let state = State::deserialize(repository.clone(), latest)
        .await
        .filter_slow_down()?
        .warn_map_err(|err| {
            if err.is_not_found() {
                Status::not_found(format!(
                    "Revision '{latest}' to push to latest is not found"
                ))
            } else {
                Status::internal(format!("failed to load current latest state: {err}"))
            }
        })?;

    // If the incoming revision is already the latest revision the push is a no-op
    if current_head == latest {
        if let Some(governed) = governed {
            governed
                .publish(repository.as_ref(), branch, current_head, current_head)
                .await?;
        }
        return Ok(PushResult {
            success: true,
            advanced: false,
            fast_forward_merged: false,
            revision: current_head,
            revision_number: state.revision_number(),
        });
    }

    let mut new_head = latest;
    loop {
        // Verify the current latest revision is parent of the incoming revision unless the push is forced
        if current_head != state.parent_self() && !force {
            if current_head.is_zero() {
                warn!("Branch push failed, branch does not exist");
                return Err(Status::not_found("Branch not found"));
            }

            if !fast_forward_merge {
                return Ok(PushResult {
                    success: false,
                    advanced: false,
                    fast_forward_merged: false,
                    revision: current_head,
                    revision_number: 0,
                });
            }

            // Fast-forward merge: the incoming revision's parent_self no longer matches
            // the branch head. Attempt to create a new merge revision with
            // parent_self=current_head and parent_other=incoming_revision.
            return try_fast_forward_merge(
                repository.clone(),
                branch,
                state.clone(),
                current_head,
                history_step_size,
                acceleration,
                governed,
            )
            .await;
        }

        let state_parent = State::deserialize(repository.clone(), state.parent_self())
            .await
            .filter_slow_down()?
            .warn_map_err(|err| {
                Status::internal(format!("Failed to load incoming state: {err}"))
            })?;

        // Verify that all new fragments exist
        let mut state_other = None;
        if !state.parent_other().is_zero() {
            let state_parent = State::deserialize(repository.clone(), state.parent_other())
                .await
                .filter_slow_down()?
                .warn_map_err(|err| {
                    Status::internal(format!("Failed to load other parent state: {err}"))
                })?;
            state_other = Some(state_parent);
        }

        verify_fragments(repository.clone(), state_parent.clone(), state.clone()).await?;

        // Verify that the revision number is valid
        let revision_number = next_revision_number(
            state_parent.revision_number(),
            state_other.as_ref().map_or(0, |s| s.revision_number()),
        );

        if state.revision_number() != revision_number {
            // Rewrite the revision with a correct revision number
            state.set_revision_number(revision_number);
            let write_token = get_write_token();
            new_head = state
                .serialize(repository.clone(), &write_token)
                .await
                .warn_map_err(|err| {
                    Status::internal(format!("Failed to serialize state: {err}"))
                })?;
        }

        let previous_head = if let Some(governed) = governed {
            governed
                .publish(repository.as_ref(), branch, current_head, new_head)
                .await?;
            current_head
        } else {
            try_store_latest(repository.clone(), branch, current_head, new_head)
                .await
                .warn_map_err(|err| {
                    Status::internal(format!("Failed to store new latest pointer: {err}"))
                })?
        };

        // Check if the compare-and-swap was successful by checking match with expected value
        if previous_head == current_head {
            // If equal it means the value was swapped, i.e the push was successful. Set the
            // new latest revision signature and break out of the loop to return success
            current_head = new_head;

            store_history_step(
                repository.clone(),
                branch,
                state_parent.revision_number(),
                history_step_size,
                acceleration,
                state.clone(),
            )
            .await;

            break;
        }

        // Latest pointer moved during the processing of this push call, loop and try again
        current_head = previous_head;
    }

    Ok(PushResult {
        success: true,
        advanced: true,
        fast_forward_merged: false,
        revision: current_head,
        revision_number: state.revision_number(),
    })
}

/// Attempts a server-side fast-forward merge when the target branch head has moved
/// since the client created the merge revision.
///
/// Creates a new merge revision with:
/// - `parent_self` = current branch head (target branch)
/// - `parent_other` = the incoming merge revision
///
/// Uses a three-way diff between the original merge base, the incoming revision,
/// and the current head. If conflicts are detected, returns failure so the client
/// can resolve locally.
///
/// Retries via CAS loop if the branch head moves again during processing.
#[instrument(level = "debug", skip_all)]
async fn try_fast_forward_merge(
    repository: Arc<RepositoryContext>,
    branch: BranchId,
    incoming_state: Arc<State>,
    mut current_head: Hash,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
    governed: Option<&GovernedPushCommit>,
) -> Result<PushResult, Status> {
    let incoming_revision = incoming_state.revision();
    let original_base = incoming_state.parent_self();

    debug!(
        %incoming_revision, %original_base, %current_head,
        "Attempting fast-forward merge"
    );

    // Verify that all new fragments from the incoming revision exist in the store,
    // matching the verification done in the normal push path. Without this check a
    // client could reference fragments that were never fully uploaded.
    let base_state = State::deserialize(repository.clone(), original_base)
        .await
        .filter_slow_down()?
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to load base state for fragment verification: {err}"
            ))
        })?;

    verify_fragments(repository.clone(), base_state, incoming_state.clone()).await?;

    loop {
        // Three-way diff: base=original merge target, source=incoming merge, target=current head
        debug!(
            %original_base, %incoming_revision, %current_head,
            "Computing diff3 for fast-forward merge"
        );
        let diff_result = lore_revision::revision::diff3_collect(
            repository.clone(),
            original_base,
            incoming_revision,
            current_head,
            None,
            false,
        )
        .await
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to compute diff3 for fast-forward merge: {err}"
            ))
        })?;
        debug!(
            changes = diff_result.changes.len(),
            conflicts = diff_result.conflicts.len(),
            "diff3 result for fast-forward merge"
        );

        if !diff_result.conflicts.is_empty() {
            debug!(
                conflicts = diff_result.conflicts.len(),
                "Fast-forward merge has conflicts, rejecting"
            );
            return Ok(PushResult {
                success: false,
                advanced: false,
                fast_forward_merged: false,
                revision: current_head,
                revision_number: 0,
            });
        }

        // Deserialize the current head state to use as base for the new merge revision
        let state_current = State::deserialize(repository.clone(), current_head)
            .await
            .filter_slow_down()?
            .warn_map_err(|err| {
                Status::internal(format!(
                    "Failed to deserialize current head for fast-forward merge: {err}"
                ))
            })?;

        // Apply the non-conflicting changes to the current head state
        state::apply_tree_changes(
            repository.clone(),
            state_current.clone(),
            &diff_result.changes,
        )
        .await
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to apply tree changes for fast-forward merge: {err}"
            ))
        })?;

        // Set parents: self=current head (target branch), other=incoming merge revision
        state_current.set_parent_self(current_head);
        state_current.set_parent_other(incoming_revision);

        // Compute revision number from both parents
        let state_current_number = {
            let parent_state = State::deserialize(repository.clone(), current_head)
                .await
                .filter_slow_down()?
                .warn_map_err(|err| {
                    Status::internal(format!("Failed to load current head state: {err}"))
                })?;
            parent_state.revision_number()
        };
        let revision_number =
            next_revision_number(state_current_number, incoming_state.revision_number());
        state_current.set_revision_number(revision_number);

        // Copy metadata from the incoming revision and set merged-by to "server"
        let incoming_metadata_hash = incoming_state.metadata_hash();
        if !incoming_metadata_hash.is_zero() {
            let mut metadata = lore_revision::metadata::Metadata::deserialize(
                repository.clone(),
                incoming_metadata_hash,
            )
            .await
            .warn_map_err(|err| {
                Status::internal(format!("Failed to load incoming revision metadata: {err}"))
            })?;

            metadata
                .set_branch(branch)
                .warn_map_err(|_| Status::internal("Failed to set branch in metadata"))?;
            // Preserve the existing merged-by field if set, otherwise fall back to "server"
            if metadata
                .get_string(lore_revision::metadata::MERGED_BY)
                .is_err()
            {
                metadata
                    .set_string(lore_revision::metadata::MERGED_BY, "server")
                    .warn_map_err(|_| Status::internal("Failed to set merged-by in metadata"))?;
            }
            metadata
                .set_u64(lore_revision::metadata::FAST_FORWARD_MERGE, 1)
                .warn_map_err(|_| {
                    Status::internal("Failed to set fast-forward-merge in metadata")
                })?;

            let metadata_hash = metadata
                .serialize(repository.clone())
                .await
                .warn_map_err(|_| Status::internal("Failed to serialize metadata"))?;
            state_current.set_metadata_hash(metadata_hash);
        }

        // Serialize the new merge state
        let write_token = get_write_token();
        let new_revision = state_current
            .serialize(repository.clone(), &write_token)
            .await
            .warn_map_err(|err| {
                Status::internal(format!(
                    "Failed to serialize fast-forward merge state: {err}"
                ))
            })?;

        // CAS: attempt to set the new revision as branch head
        let previous_head = if let Some(governed) = governed {
            governed
                .publish(repository.as_ref(), branch, current_head, new_revision)
                .await?;
            current_head
        } else {
            try_store_latest(repository.clone(), branch, current_head, new_revision)
                .await
                .warn_map_err(|err| {
                    Status::internal(format!("Failed to store fast-forward merge latest: {err}"))
                })?
        };

        if previous_head == current_head {
            // CAS succeeded
            debug!(
                %new_revision, revision_number,
                "Fast-forward merge succeeded"
            );

            // Store acceleration index if needed
            store_history_step(
                repository.clone(),
                branch,
                state_current_number,
                history_step_size,
                acceleration,
                state_current.clone(),
            )
            .await;

            return Ok(PushResult {
                success: true,
                advanced: true,
                fast_forward_merged: true,
                revision: new_revision,
                revision_number,
            });
        }

        // CAS failed — branch head moved again, retry with updated head
        debug!(
            %previous_head, %current_head,
            "Fast-forward merge CAS failed, retrying"
        );
        current_head = previous_head;
    }
}

/// Compute the next revision number from the parent revision numbers.
/// The revision number is one greater than the maximum of the two parents.
fn next_revision_number(parent_self_number: u64, parent_other_number: u64) -> u64 {
    std::cmp::max(parent_self_number, parent_other_number) + 1
}

/// Store the history-step skip pointer (if a boundary was crossed) and any
/// revision-list cache entries for segments newly closed by this push.
///
/// A segment `B` (= `N * history_step_size`) is *closed* by this push iff
/// `parent_revision_number <= B < revision_number`. A single push can close
/// multiple segments (e.g. a merge that jumps past several boundaries). For
/// each closed segment we walk `parent_self` from `state` and persist the
/// items whose number falls in `(B - step, B]`.
///
/// Errors are ignored — this is purely an acceleration construct and will be
/// recreated on the next lookup if any step fails.
async fn store_history_step(
    repository: Arc<RepositoryContext>,
    branch: BranchId,
    parent_revision_number: u64,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
    state: Arc<State>,
) {
    let revision_number = state.revision_number();
    let revision = state.revision();

    if acceleration.step_keys
        && parent_revision_number / history_step_size != revision_number / history_step_size
    {
        let (key, key_type) = branch::revision_step_key(
            repository::SALT_LORE,
            repository.id,
            branch,
            revision_number,
            history_step_size,
        );
        let write_token = get_write_token();
        let _ = repository
            .clone()
            .write_mutable_store(&write_token)
            .store(repository.id, key, revision, key_type)
            .await;
    }

    if !acceleration.list_cache {
        return;
    }

    // Determine which segment boundaries are *newly closed* by this push.
    // A boundary B (multiple of history_step_size) is newly closed iff
    // P <= B < N (where P = parent_revision_number, N = revision_number).
    let lowest_b = parent_revision_number.div_ceil(history_step_size) * history_step_size;
    let highest_b = if revision_number > 0 {
        ((revision_number - 1) / history_step_size) * history_step_size
    } else {
        return;
    };
    if lowest_b == 0 || lowest_b > highest_b {
        return;
    }

    // Walk parent chain from the new revision until we cross below the lowest
    // closed segment, capturing items for each closed boundary.
    let stop_below = lowest_b.saturating_sub(history_step_size);
    let span_segments = (highest_b.saturating_sub(lowest_b) / history_step_size) + 1;
    let max_items = (span_segments as usize)
        .saturating_mul(history_step_size as usize)
        // Allow a small overshoot so partial segments above the closed range
        // (the still-open one containing N) and the one terminator item can
        // still be walked.
        .saturating_add(history_step_size as usize)
        .saturating_add(1);

    let walk =
        cache::revision::walk_segment_revisions(&repository, revision, stop_below, max_items).await;

    if !walk.reached_terminator {
        // Walk was bounded by max_items; the last segment may be partial.
        // Skip cache writes — next reader will rebuild them via backfill.
        return;
    }

    let segments = cache::revision::partition_into_segments(&walk.items, history_step_size);
    for (segment_b, list) in segments {
        if segment_b >= lowest_b && segment_b <= highest_b {
            cache::revision::store_cached_list(
                &repository,
                branch,
                segment_b,
                history_step_size,
                &list,
            )
            .await;
        }
    }
}

/// Verify that all new fragments between `parent_state` and `state` exist in the
/// immutable store. Also includes the other parent hash if the state is a merge.
/// Returns an error if any fragment is missing.
async fn verify_fragments(
    repository: Arc<RepositoryContext>,
    parent_state: Arc<State>,
    state: Arc<State>,
) -> Result<(), Status> {
    let mut new_fragments = state::collect_new_fragments(
        repository.clone(),
        parent_state.clone(),
        state.clone(),
        true, /* Ignore already durably stored fragments */
    )
    .instrument(span!(Level::DEBUG, "collect_new_fragments"))
    .await
    .filter_slow_down()?
    .warn_map_err(|err| {
        if let Some(converted_error) = err.as_address_not_found() {
            return Status::not_found(format!(
                "Failed to collect new fragments for verification. Missing address '{converted_error}'"
            ));
        }

        Status::internal(format!(
            "Failed to collect new fragments for verification: {err}"
        ))
    })?;

    if !state.parent_other().is_zero() {
        new_fragments.push(Address::zero_context_hash(state.parent_other()));
    }

    new_fragments.sort_unstable();
    new_fragments.dedup();

    let mut retry = lore_revision::util::time::retry(
        push::RETRY_START_DURATION,
        push::RETRY_MAX_DURATION,
        push::RETRY_MAX_ATTEMPTS,
    );

    let max_batch_size = repository
        .immutable_store()
        .max_query_batch()
        .unwrap_or(1000)
        .clamp(100, 10000);

    let mut tasks = JoinSet::new();
    while !new_fragments.is_empty() || !tasks.is_empty() {
        let batch_span = span!(
            Level::DEBUG,
            "exist_batch",
            items = new_fragments.len(),
            batch_size = max_batch_size
        );

        batch_span.in_scope(|| {
            while !new_fragments.is_empty() {
                let repository = repository.clone();
                let batch =
                    new_fragments.split_off(new_fragments.len().saturating_sub(max_batch_size));
                lore_spawn!(
                    tasks,
                    async move {
                        let mut resolved = vec![StoreMatchResult::default(); batch.len()];
                        let result = repository
                            .immutable_store()
                            .query(repository.id, batch.as_slice(), &mut resolved)
                            .await
                            .map(|()| resolved);
                        (batch, result)
                    }
                    .in_current_span()
                );
            }
        });

        let mut num_slow_downs = 0;
        while let Some(result) = tasks.join_next().await {
            let (mut batch, result) =
                result.warn_map_err(|err| Status::internal(format!("Query task failed: {err}")))?;
            match result {
                Ok(result) => {
                    if result.iter().enumerate().any(|(pos, resolved)| {
                        if resolved.match_made != StoreMatch::MatchFull {
                            warn!("Branch push failed, fragment not found for {}", batch[pos]);
                            true
                        } else {
                            false
                        }
                    }) {
                        return Err(Status::failed_precondition("Missing fragments"));
                    }
                }
                Err(StoreError::SlowDown(_)) => {
                    new_fragments.append(&mut batch);
                    num_slow_downs += 1;
                }
                Err(err) => {
                    let response = warn_error_to_status(&err, |err| {
                        Status::internal(format!("Store query failed: {err}"))
                    });
                    return Err(response);
                }
            }
        }

        if !new_fragments.is_empty() && !retry.wait().await {
            warn!("Exhausted {num_slow_downs} fragment exist retries");
            return Err(Status::resource_exhausted("Slow down"));
        }
    }

    Ok(())
}

#[instrument(level = "debug", skip_all, fields(branch))]
pub async fn try_store_latest(
    repository: Arc<RepositoryContext>,
    branch: BranchId,
    current_expected_latest: Hash,
    new_latest: Hash,
) -> Result<Hash, BranchError> {
    lore_revision::branch::mutable_try_store(
        repository.clone(),
        LATEST,
        branch,
        current_expected_latest,
        new_latest,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use lore_base::error::SlowDown;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Context;
    use lore_base::types::Fragment;
    use lore_base::types::Partition;
    use lore_postgres::domain::PostgresDomainStore;
    use lore_postgres::domain::receipts::ReceiptKey;
    use lore_postgres::pool::TlsConfig;
    use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
    use lore_revision::node::Node;
    use lore_revision::node::ROOT_NODE;
    use lore_storage::ImmutableStore;
    use lore_storage::StoreGetData;
    use lore_storage::StoreMatchResult;
    use lore_storage::StoreObliterateStats;
    use lore_storage::hash::hash_string;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_storage::local::immutable_store::LocalImmutableStore;
    use lore_transport::grpc::REPOSITORY_ID_KEY;
    use opentelemetry::metrics::Meter;
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::InMemoryMetricExporter;
    use opentelemetry_sdk::metrics::SdkMeterProvider;
    use opentelemetry_sdk::metrics::data::AggregatedMetrics;
    use opentelemetry_sdk::metrics::data::MetricData;
    use rand::random;
    use tokio::sync::mpsc;
    use tonic::Code;
    use tonic::Request;
    use tonic::metadata::MetadataValue;
    use tonic::transport::server::TcpConnectInfo;
    use uuid::Uuid;

    use super::*;
    use crate::grpc::domain_operation_metadata::DomainOperationMetadata;
    use crate::grpc::get_write_token;
    use crate::grpc::server::RevisionListAcceleration;
    use crate::hooks::Hook;
    use crate::hooks::HookError;
    use crate::lock::store::LocalLockStore;
    use crate::notification::testing::MockNotificationSender;
    use crate::store::test_store_create;

    struct RecordingInstrumentProvider {
        meter_provider: SdkMeterProvider,
        exporter: InMemoryMetricExporter,
    }

    impl RecordingInstrumentProvider {
        fn new() -> Self {
            let exporter = InMemoryMetricExporter::default();
            let meter_provider = SdkMeterProvider::builder()
                .with_periodic_exporter(exporter.clone())
                .build();
            Self {
                meter_provider,
                exporter,
            }
        }

        fn counter_value(&self, name: &str) -> u64 {
            self.meter_provider
                .force_flush()
                .expect("metric flush should succeed");
            let expected_name = format!("{}.{}", self.namespace(), name);
            let values: Vec<u64> = self
                .exporter
                .get_finished_metrics()
                .expect("metrics should be exported")
                .iter()
                .flat_map(|resource| resource.scope_metrics())
                .flat_map(|scope| scope.metrics())
                .filter(|metric| metric.name() == expected_name)
                .map(|metric| match metric.data() {
                    AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                        sum.data_points().map(|point| point.value()).sum()
                    }
                    data => panic!("expected u64 sum metric, got {data:?}"),
                })
                .collect();
            assert_eq!(
                values.len(),
                1,
                "expected exactly one exported {expected_name} metric"
            );
            values[0]
        }
    }

    #[tokio::test]
    #[ignore = "run with lore-postgres/tests/run-lock-fencing-live.ps1"]
    async fn real_witness_capture_precedes_both_cr019_bypass_conditions() {
        let url = std::env::var("LORE_TEST_PG_URL")
            .expect("the checked-in live runner must provide PostgreSQL");
        let store = Arc::new(
            PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
                .await
                .expect("connect domain store"),
        );
        let coordinator = Arc::new(store.lock_coordinator());
        coordinator
            .bootstrap()
            .await
            .expect("install isolated SCHEMA-117 fixture");

        let (direct, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect direct fixture client");
        lore_base::lore_spawn!(async move {
            if let Err(error) = connection.await {
                eprintln!("push witness fixture connection error: {error}");
            }
        });
        let repository_id: RepositoryId = random();
        let branch_id: BranchId = random();
        let repository_bytes = repository_id.as_ref().to_vec();
        let branch_bytes = branch_id.as_ref().to_vec();
        let hash = random::<[u8; 32]>().to_vec();
        direct.execute(
            "INSERT INTO lore_domain_repositories(repository_id,state,generation,name,metadata_hash,default_branch_id,creation_fingerprint_version,creation_fingerprint,created_at) VALUES($1,0,1,'witness-fixture',$2,$3,1,$4,clock_timestamp())",
            &[&repository_bytes, &hash, &branch_bytes, &hash],
        ).await.expect("insert repository fixture");
        direct.execute(
            "INSERT INTO lore_domain_branches(repository_id,branch_id,repository_generation,state,generation,name,metadata_hash,latest_hash,creation_fingerprint_version,creation_fingerprint,created_at) VALUES($1,$2,1,0,1,'main',$3,$3,1,$3,clock_timestamp())",
            &[&repository_bytes, &branch_bytes, &hash],
        ).await.expect("insert branch fixture and namespace");

        let context = Arc::new(DomainContext::new_with_lock_coordinator(
            store,
            false,
            coordinator.clone(),
        ));

        // CR-019 disabled: a missing namespace remains observable before the
        // admitted-none legacy return. Moving capture below that return would
        // make this incorrectly succeed with None.
        let missing_branch: BranchId = random();
        let disabled = prepare_governed_push(
            Some(&context),
            None,
            repository_id,
            missing_branch,
            random(),
            false,
            false,
        )
        .await;
        let disabled = match disabled {
            Err(status) => status,
            Ok(_) => panic!("missing namespace must fail before the CR-019-disabled bypass"),
        };
        assert_eq!(disabled.code(), Code::FailedPrecondition);

        // Capture a concrete witness, then drive the real CR-019 no-foreign-
        // locks guard. The bogus revision and absent local branch would fail
        // if that guard tried to diff instead of taking its early return.
        let operation_id = Uuid::now_v7();
        let admitted = crate::domain::AdmittedOperation {
            key: ReceiptKey {
                verified_issuer: "https://issuer.example".to_owned(),
                authenticated_subject: "wp117-pusher".to_owned(),
                tenant_scope_key: vec![7; 16],
                operation_id,
            },
            carried: DomainOperationMetadata {
                operation_id,
                fingerprint_version: 1,
                fingerprint: vec![8; 32],
                prepare_token: [9; 32],
                mediated_scope: None,
            },
        };
        let governed = prepare_governed_push(
            Some(&context),
            Some(admitted),
            repository_id,
            branch_id,
            random(),
            false,
            false,
        )
        .await
        .expect("capture before CR-019 empty-query return")
        .expect("admitted push carries its witness");
        assert_eq!(governed.lock_witness.repository_lock_generation, 1);
        assert_eq!(governed.lock_witness.branch_lock_generation, 1);
        assert_eq!(
            governed
                .lock_witness
                .branch_lock_namespace_last_applied_fence,
            0
        );

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("create CR-019 stores");
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable_store,
            mutable_store,
            repository_id,
        ));
        let enforcement = PushLockEnforcement {
            lock_store: Arc::new(LocalLockStore::default()),
            issuer_policy: push_lock_guard::LockOwnerIssuerPolicy::Pinned(
                "https://issuer.example".to_owned(),
            ),
        };
        let pusher = VerifiedLockOwner {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "wp117-pusher".to_owned(),
        };
        let bogus_revision = Hash::hash_buffer(b"never serialized for wp117 bypass fixture");
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            push_lock_guard::enforce_push_locks(
                repository,
                &enforcement,
                branch_id,
                bogus_revision,
                &pusher,
            )
            .await
            .expect("real CR-019 empty-lock guard must take its early return");
        }))
        .await;
    }

    impl InstrumentProvider for RecordingInstrumentProvider {
        fn namespace(&self) -> &'static str {
            "test"
        }

        fn meter(&self) -> Meter {
            self.meter_provider.meter(self.namespace())
        }
    }

    struct RecordingPostHook {
        sender: mpsc::UnboundedSender<()>,
    }

    #[async_trait]
    impl Hook for RecordingPostHook {
        fn name(&self) -> &'static str {
            "recording-post"
        }

        fn hook_points(&self) -> &'static [HookPoint] {
            &[HookPoint::BranchPush]
        }

        async fn post_handler(&self, _ctx: &HookContext) -> Result<(), HookError> {
            self.sender
                .send(())
                .expect("post-hook observation receiver dropped");
            Ok(())
        }
    }

    async fn create_root_branch(
        repository_context: &Arc<RepositoryContext>,
        name: &str,
    ) -> BranchId {
        let write_token = get_write_token();
        lore_revision::branch::create(
            repository_context.clone(),
            &write_token,
            BranchId::from(uuid::Uuid::now_v7()),
            name,
            branch::default_category(),
            "test-creator",
            1,
            vec![],
            false,
            false,
        )
        .await
        .expect("Could not create root branch")
    }

    async fn build_revision(repository_context: &Arc<RepositoryContext>) -> Hash {
        let state = State::new();
        state.set_revision_number(1);
        state
            .serialize(repository_context.clone(), &get_write_token())
            .await
            .expect("Failed to serialize state")
    }

    fn make_request(
        repository: RepositoryId,
        branch: BranchId,
        revision: Hash,
    ) -> Request<BranchPushRequest> {
        let mut request = Request::new(BranchPushRequest {
            branch: branch.into(),
            revision: revision.into(),
            force: false,
            fast_forward_merge: false,
        });
        request.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );
        request
    }

    #[tokio::test]
    #[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
    async fn enforcing_cell_rejects_before_legacy_branch_push_body() {
        let Some(domain) = crate::domain::test_support::configured_enforcing_context().await else {
            panic!("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");
        };
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, _) = test_store_create().await.expect("test stores");
        let notification = Arc::new(MockNotificationSender::new());
        let hooks = HookDispatcher::empty();
        let instruments = RecordingInstrumentProvider::new();
        let error = handler(
            make_request(repository, BranchId::default(), Hash::default()),
            immutable_store,
            mutable_store,
            notification,
            &hooks,
            DEFAULT_HISTORY_STEP_SIZE,
            RevisionListAcceleration::default(),
            &instruments,
            None,
            Some(&domain),
        )
        .await
        .expect_err("enforcement must reject missing operation carriage at entry");
        assert_eq!(error.code(), Code::InvalidArgument);
    }

    #[test]
    fn use_x_forwarded_when_available() {
        let mut req = Request::new(());

        let xff_metadata_value: MetadataValue<_> = "10.0.0.1, 10.0.0.2".parse().unwrap();
        req.metadata_mut()
            .insert("x-forwarded-for", xff_metadata_value);

        // set remote address to make sure it's NOT used in presence of the XFF header
        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 4242));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
    }

    #[test]
    fn dont_use_xff_when_it_contains_invalid_value() {
        let mut req = Request::new(());

        let xff_metadata_value: MetadataValue<_> = "10.0.0.lol, 10.0.0.wat".parse().unwrap();
        req.metadata_mut()
            .insert("x-forwarded-for", xff_metadata_value);

        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 4242));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)))
        );
    }

    #[test]
    fn still_uses_last_ip_when_xff_contains_invalid_value_in_chain() {
        let mut req = Request::new(());

        let xff_metadata_value: MetadataValue<_> =
            "10.0.0.lol, 10.0.0.wat, 10.0.0.42".parse().unwrap();
        req.metadata_mut()
            .insert("x-forwarded-for", xff_metadata_value);

        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 4242));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
        );
    }

    #[test]
    fn fallback_to_remote_addr() {
        let mut req = Request::new(());

        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 31415));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)))
        );
    }

    #[tokio::test]
    async fn push_unknown_revision_returns_not_found() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                repository_id,
            ));

            let write_token = get_write_token();
            branch::create(
                repository_context.clone(),
                &write_token,
                branch_id,
                "test-branch",
                branch::personal_category(),
                "test-creator",
                1,
                vec![],
                false,
                false,
            )
            .await
            .expect("Failed to create branch");

            // A hash with no corresponding state data in the immutable store
            let nonexistent_revision = random::<Hash>();

            let result = push(
                repository_context,
                branch_id,
                nonexistent_revision,
                true,
                true,
                false,
                DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
            )
            .await;

            assert!(result.is_err());
            assert_eq!(result.err().unwrap().code(), Code::NotFound);
        }))
        .await;
    }

    #[tokio::test]
    async fn no_op_push_does_not_repeat_notification_or_post_hook() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        let (notification_tx, mut notification_rx) = mpsc::unbounded_channel();
        let notification_observer = notification_tx.clone();
        let mut notification_sender = MockNotificationSender::new();
        notification_sender
            .expect_branch_pushed()
            .times(1)
            .returning(move |_, _, _, _, _| {
                notification_observer
                    .send(())
                    .expect("notification observation receiver dropped");
            });
        let notification_sender = Arc::new(notification_sender);
        let instrument_provider = RecordingInstrumentProvider::new();

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let main = create_root_branch(&repository_context, "main").await;
            let revision = build_revision(&repository_context).await;

            let (hook_tx, mut hook_rx) = mpsc::unbounded_channel();
            let hook_dispatcher = HookDispatcher::from_hooks_default(vec![(
                "recording-post".to_string(),
                Box::new(RecordingPostHook { sender: hook_tx }),
            )]);

            let first = handler(
                make_request(repository, main, revision),
                immutable_store.clone(),
                mutable_store.clone(),
                notification_sender.clone(),
                &hook_dispatcher,
                DEFAULT_HISTORY_STEP_SIZE,
                crate::grpc::server::RevisionListAcceleration::default(),
                &instrument_provider,
                None,
                None,
            )
            .await
            .expect("first push should succeed");
            assert!(first.into_inner().success);
            notification_rx
                .recv()
                .await
                .expect("advancing push should publish a notification");
            hook_rx
                .recv()
                .await
                .expect("advancing push should dispatch a post-hook");

            let repeated = handler(
                make_request(repository, main, revision),
                immutable_store.clone(),
                mutable_store.clone(),
                notification_sender.clone(),
                &hook_dispatcher,
                DEFAULT_HISTORY_STEP_SIZE,
                crate::grpc::server::RevisionListAcceleration::default(),
                &instrument_provider,
                None,
                None,
            )
            .await
            .expect("no-op re-push should succeed");
            assert!(repeated.into_inner().success);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), notification_rx.recv())
                    .await
                    .is_err(),
                "no-op re-push published a notification"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), hook_rx.recv())
                    .await
                    .is_err(),
                "no-op re-push dispatched a post-hook"
            );
            assert_eq!(
                instrument_provider.counter_value("num_branches_pushed"),
                1,
                "only the advancing push should increment num_branches_pushed"
            );
            drop(notification_tx);
        }))
        .await;
    }

    /// Wraps a real, in-memory `LocalImmutableStore` and, once armed, returns
    /// `StoreError::SlowDown` from every `query()` call. Delegates everything
    /// else straight through, so a repository's states can be built normally
    /// before the fault is armed. Mirrors the fixture pattern in
    /// `lore-revision/tests/state.rs`.
    struct SlowDownQueryStore {
        inner: Arc<LocalImmutableStore>,
        armed: AtomicBool,
    }

    impl SlowDownQueryStore {
        fn wrapping(inner: Arc<LocalImmutableStore>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                armed: AtomicBool::new(false),
            })
        }

        fn arm(&self) {
            self.armed.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ImmutableStore for SlowDownQueryStore {
        async fn query(
            self: Arc<Self>,
            partition: Partition,
            addresses: &[Address],
            results: &mut [StoreMatchResult],
        ) -> Result<(), StoreError> {
            if self.armed.load(Ordering::SeqCst) {
                return Err(StoreError::from(SlowDown));
            }
            self.inner
                .clone()
                .query(partition, addresses, results)
                .await
        }

        async fn get_metadata(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<StoreGetData, StoreError> {
            self.inner.clone().get_metadata(partition, address).await
        }

        async fn get(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<StoreGetData, StoreError> {
            self.inner.clone().get(partition, address).await
        }

        async fn put(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            fragment: Fragment,
            payload: Option<Bytes>,
            force: bool,
        ) -> Result<(), StoreError> {
            self.inner
                .clone()
                .put(partition, address, fragment, payload, force)
                .await
        }

        async fn obliterate(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            stats: Arc<StoreObliterateStats>,
        ) -> Result<(), StoreError> {
            self.inner
                .clone()
                .obliterate(partition, address, stats)
                .await
        }

        async fn evict(
            self: Arc<Self>,
            max_capacity: usize,
            sync_data: bool,
            sink: Option<lore_storage::gc_event::GcEventSinkRef>,
        ) -> Result<usize, StoreError> {
            self.inner
                .clone()
                .evict(max_capacity, sync_data, sink)
                .await
        }

        async fn compact(
            self: Arc<Self>,
            max_size: usize,
            at: Option<usize>,
            sync_data: bool,
            sink: Option<lore_storage::gc_event::GcEventSinkRef>,
        ) -> Result<Option<usize>, StoreError> {
            self.inner
                .clone()
                .compact(max_size, at, sync_data, sink)
                .await
        }

        async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
            self.inner.clone().compact_resume_at().await
        }

        async fn compact_stop(self: Arc<Self>) {
            self.inner.clone().compact_stop().await
        }

        fn max_query_batch(&self) -> Option<usize> {
            self.inner.max_query_batch()
        }

        async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
            self.inner.clone().flush(sync_data).await
        }

        async fn verify(self: Arc<Self>, heal: bool) -> Result<(), StoreError> {
            self.inner.clone().verify(heal).await
        }

        async fn copy(
            self: Arc<Self>,
            source_partition: Partition,
            source_address: Address,
            destination_partition: Partition,
            destination_context: Context,
            durable: bool,
        ) -> Result<(), StoreError> {
            self.inner
                .clone()
                .copy(
                    source_partition,
                    source_address,
                    destination_partition,
                    destination_context,
                    durable,
                )
                .await
        }
    }

    #[tokio::test]
    async fn verify_fragments_maps_slow_down_to_resource_exhausted() {
        // Reproduces the mismatch this CR fixed: without `.filter_slow_down()?`
        // on the `collect_new_fragments` call inside `verify_fragments`, a
        // `StateError::SlowDown` fell through to the generic `warn_map_err`
        // below it and surfaced as `Status::internal(..)` — the wrong gRPC
        // code for a condition the client should back off and retry on, and
        // inconsistent with the `exist_batch` verification loop a few dozen
        // lines below, which already maps its own SlowDown to
        // `Status::resource_exhausted(..)`.
        let (_immutable_store, mutable_store, execution) = crate::store::test_store_create()
            .await
            .expect("Failed to create stores");
        let repository_id: Context = rand::random();

        let status = LORE_CONTEXT
            .scope(execution.clone(), async move {
                let real_store = LocalImmutableStore::new(None, ImmutableStoreSettings::default())
                    .await
                    .expect("Failed to create store");
                let fault_store = SlowDownQueryStore::wrapping(real_store);

                let repository = Arc::new(RepositoryContext::new_server_context(
                    fault_store.clone(),
                    mutable_store.clone(),
                    repository_id.into(),
                ));

                let write_token = get_write_token();

                let parent_state = Arc::new(State::new());
                let name = "test-node";
                let node = Node {
                    name_hash: hash_string(name),
                    ..Default::default()
                };
                parent_state
                    .node_add(repository.clone(), ROOT_NODE, node, name)
                    .await
                    .expect("Failed to add node");
                let parent_signature = parent_state
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize parent state");
                let parent_state = State::deserialize(repository.clone(), parent_signature)
                    .await
                    .expect("Failed to deserialize parent state");

                // A second, differing state so `verify_fragments` actually has
                // something to query (an unmodified diff never reaches the
                // store).
                let other_name = "other-test-node";
                let other_node = Node {
                    name_hash: hash_string(other_name),
                    ..Default::default()
                };
                let state = Arc::new(State::new());
                state
                    .node_add(repository.clone(), ROOT_NODE, other_node, other_name)
                    .await
                    .expect("Failed to add node");
                let signature = state
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize state");
                let state = State::deserialize(repository.clone(), signature)
                    .await
                    .expect("Failed to deserialize state");

                fault_store.arm();

                verify_fragments(repository, parent_state, state).await
            })
            .await
            .expect_err("Expected verify_fragments to surface a SlowDown as an error status");

        assert_eq!(
            status.code(),
            tonic::Code::ResourceExhausted,
            "Expected a SlowDown out of collect_new_fragments to map to \
             resource_exhausted (matching the exist_batch verification loop), \
             got: {status:?}"
        );
    }
}

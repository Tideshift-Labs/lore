// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::net::IpAddr;
use std::sync::Arc;

use lore_base::error::AddressNotFound;
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
use lore_telemetry::tracing::fields::ADDRESS;
use lore_telemetry::tracing::fields::BRANCH_ID;
use lore_telemetry::tracing::fields::REVISION;
use lore_transport::grpc::address_not_found_status;
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
use crate::cache::revision::store_history_step;
use crate::domain::AdmittedOperation;
use crate::domain::DomainContext;
use crate::domain::GovernedScope;
use crate::domain::PLATFORM_METHOD_BRANCH_PUSH;
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

#[lore_macro::test_pub]
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
        return Err(carried_push_preparation_error(
            admitted.as_ref(),
            Status::invalid_argument("Invalid revision"),
        ));
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

            let push_result = async {
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
                        None => {
                            push_lock_guard::verified_push_owner(request_authorization.as_ref())?
                        }
                    };
                    enforce_fenced_locks(
                        coordinator,
                        repository.clone(),
                        branch,
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
                        branch,
                        revision,
                        &pusher,
                    )
                    .await?;
                }

                push_with_governance(
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
                .await
            }
            .await;
            let PushResult {
                success,
                advanced,
                fast_forward_merged,
                revision,
                revision_number,
            } = settle_governed_push(governed_push.as_ref(), push_result).await?;

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

    // no filter_slow_down()? usage here: these reads only decorate the hook
    // context, and the push they describe has already succeeded.
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

/// Return a refusal only once the exact publication receipt proves it terminal.
#[lore_macro::test_pub]
pub(crate) async fn settle_governed_push(
    governed: Option<&GovernedPushCommit>,
    result: Result<PushResult, Status>,
) -> Result<PushResult, Status> {
    if result.as_ref().is_ok_and(|push| push.success) {
        return result;
    }
    let Some(governed) = governed else {
        return result;
    };
    match governed
        .domain
        .store()
        .branch_push_refuse(&governed.operation)
        .await
    {
        Ok(DomainOutcome::NotApplied { .. }) => result,
        // A lost publication response can reach here after Applied. Do not
        // fabricate its response or turn it into a decisive local refusal.
        Ok(DomainOutcome::Applied) | Err(_) => Err(unknown_push_refusal()),
    }
}

/// Preflight state consumed exactly once at the final publication boundary.
#[lore_macro::test_pub]
pub(crate) struct GovernedPushCommit {
    domain: Arc<DomainContext>,
    operation: lore_postgres::domain::coordinator::GovernedOperation,
    repository_generation: i64,
    branch_generation: i64,
    expected_latest_hash: Vec<u8>,
    lock_witness: PushLockWitness,
    fragment_witness: Option<lore_postgres::domain::fragments::PushGenerationWitness>,
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
#[lore_macro::test_pub]
pub(crate) async fn prepare_governed_push(
    domain: Option<&Arc<DomainContext>>,
    admitted: Option<AdmittedOperation>,
    repository_id: RepositoryId,
    branch_id: BranchId,
    requested_revision: Hash,
    force: bool,
    fast_forward_merge: bool,
) -> Result<Option<GovernedPushCommit>, Status> {
    let carried = admitted.as_ref().is_some_and(|operation| {
        matches!(operation.source, crate::domain::AdmissionSource::Carried(_))
    });
    prepare_governed_push_inner(
        domain,
        admitted,
        repository_id,
        branch_id,
        requested_revision,
        force,
        fast_forward_merge,
    )
    .await
    .map_err(|status| {
        if carried {
            unknown_push_refusal()
        } else {
            status
        }
    })
}

#[lore_macro::test_pub]
pub(crate) fn carried_push_preparation_error(
    admitted: Option<&AdmittedOperation>,
    status: Status,
) -> Status {
    if admitted.is_some_and(|operation| {
        matches!(operation.source, crate::domain::AdmissionSource::Carried(_))
    }) {
        unknown_push_refusal()
    } else {
        status
    }
}

fn unknown_push_refusal() -> Status {
    crate::grpc::map_domain_error_to_status(
        &lore_postgres::domain::errors::DomainError::OutcomeUnknown(
            "branch push refusal could not be proved".to_owned(),
        ),
    )
}

fn push_store_refusal(stage: &'static str, status: Status) -> Status {
    // The active execution span carries correlation. Keep this discriminator
    // fixed and bounded: no request bodies, ownership tokens or provider keys.
    warn!(stage, code = ?status.code(), "Branch push store admission refused");
    status
}

#[allow(clippy::too_many_arguments)]
async fn prepare_governed_push_inner(
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
        if domain.fragment_coordinator().is_some() {
            return Err(Status::failed_precondition(
                "fragment push requires governed admission",
            ));
        }
        return Ok(None);
    };

    let fragment_witness = if let Some(coordinator) = domain.fragment_coordinator() {
        Some(
            coordinator
                .capture_push_witness(repository_id.as_ref())
                .await
                .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?
                .ok_or_else(|| Status::not_found("Repository not found"))?,
        )
    } else {
        None
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
    let operation = domain
        .complete_governed(admitted, PLATFORM_METHOD_BRANCH_PUSH, digest)
        .await?;
    Ok(Some(GovernedPushCommit {
        domain: domain.clone(),
        operation,
        repository_generation: repository.generation,
        branch_generation: branch.generation,
        expected_latest_hash: branch.latest_hash,
        lock_witness,
        fragment_witness,
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
#[lore_macro::test_pub]
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
    #[lore_macro::test_pub]
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
        let event = match (self.domain.outbox_cell_id(), current_head == new_head) {
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
            fragment_witness: self.fragment_witness,
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
                lore_postgres::domain::fragments::REQUIRED_FRAGMENT_CHANGED
                | lore_postgres::domain::fragments::REQUIRED_FRAGMENT_PROOF_UNAVAILABLE => {
                    Err(Status::aborted(reason))
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
#[lore_macro::test_pub]
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
        .filter_slow_down()?
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
            .filter_slow_down()?
            .is_ok_and(|id| id == branch);
        if !is_mapped {
            debug!("Branch push rejected, name-to-id mapping missing for deleted branch");
            return Err(Status::not_found("Branch not found"));
        }
    }

    let mut current_head = load_latest(repository.clone(), branch)
        .await
        .filter_slow_down()?
        .unwrap_or_default();

    // Verify the validity of the revision to push to latest
    let state = State::deserialize(repository.clone(), latest)
        .await
        .filter_slow_down()
        .map_err(|status| push_store_refusal("state_load", status))?
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
            .filter_slow_down()
            .map_err(|status| push_store_refusal("parent_load", status))?
            .warn_map_err(|err| {
                Status::internal(format!("Failed to load incoming state: {err}"))
            })?;

        let state_other = load_other_parent_state(repository.clone(), &state)
            .await
            .map_err(|status| {
                if status.code() == tonic::Code::ResourceExhausted {
                    push_store_refusal("other_parent_load", status)
                } else {
                    status
                }
            })?;

        // Verify that all new fragments exist
        verify_fragments(
            repository.clone(),
            state_parent.clone(),
            state_other.clone(),
            state.clone(),
        )
        .await?;

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
                .filter_slow_down()?
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
                .filter_slow_down()?
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
                history_step_size,
                acceleration,
                state_parent,
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
        .filter_slow_down()
        .map_err(|status| push_store_refusal("merge_base_load", status))?
        .warn_map_err(|err| {
            Status::internal(format!(
                "Failed to load base state for fragment verification: {err}"
            ))
        })?;

    let other_parent_state = load_other_parent_state(repository.clone(), &incoming_state).await?;

    verify_fragments(
        repository.clone(),
        base_state,
        other_parent_state,
        incoming_state.clone(),
    )
    .await?;

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
        .filter_slow_down()?
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
            .filter_slow_down()
            .map_err(|status| push_store_refusal("merge_current_load", status))?
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
        let parent_state = State::deserialize(repository.clone(), current_head)
            .await
            .filter_slow_down()
            .map_err(|status| push_store_refusal("merge_parent_load", status))?
            .warn_map_err(|err| {
                Status::internal(format!("Failed to load current head state: {err}"))
            })?;

        let revision_number = next_revision_number(
            parent_state.revision_number(),
            incoming_state.revision_number(),
        );
        state_current.set_revision_number(revision_number);

        // Copy metadata from the incoming revision and set merged-by to "server"
        let incoming_metadata_hash = incoming_state.metadata_hash();
        if !incoming_metadata_hash.is_zero() {
            let mut metadata = lore_revision::metadata::Metadata::deserialize(
                repository.clone(),
                incoming_metadata_hash,
            )
            .await
            .filter_slow_down()?
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
                .filter_slow_down()?
                .warn_map_err(|_| Status::internal("Failed to serialize metadata"))?;
            state_current.set_metadata_hash(metadata_hash);
        }

        // Serialize the new merge state
        let write_token = get_write_token();
        let new_revision = state_current
            .serialize(repository.clone(), &write_token)
            .await
            .filter_slow_down()?
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
                .filter_slow_down()?
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
                history_step_size,
                acceleration,
                parent_state,
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

/// The first address in `batch` the store did not answer with a full match,
/// warned where it is found.
fn first_missing_fragment(batch: &[Address], answers: &[StoreMatchResult]) -> Option<Address> {
    let address = batch
        .iter()
        .zip(answers.iter())
        .find(|(_, answer)| answer.match_made != StoreMatch::MatchFull)
        .map(|(address, _)| *address)?;

    warn!({ADDRESS} = %address, "Branch push failed, fragment not found");
    Some(address)
}

/// The state of the second parent `state` names, or `None` when it names none.
///
/// Only a merge revision names one, and both the revision number the merge takes and the
/// fragments it is verified against come from that parent. A parent the store cannot
/// answer for is reported as `FAILED_PRECONDITION` naming its address, as a missing
/// fragment is. The address is the one the load asked for, since a state the store cannot
/// answer for is reported as a plain absence carrying no address of its own.
async fn load_other_parent_state(
    repository: Arc<RepositoryContext>,
    state: &State,
) -> Result<Option<Arc<State>>, Status> {
    if state.parent_other().is_zero() {
        return Ok(None);
    }

    let address = Address::zero_context_hash(state.parent_other());
    let other_parent_state = State::deserialize(repository, state.parent_other())
        .await
        .filter_slow_down()?
        .warn_map_err(|err| {
            if err.is_not_found() {
                return address_not_found_status(
                    &AddressNotFound::from(address),
                    format!("Missing fragment '{address}'"),
                );
            }

            Status::internal(format!("Failed to load other parent state: {err}"))
        })?;

    Ok(Some(other_parent_state))
}

/// Verify that all new fragments between `parent_state` and `state` exist in the
/// immutable store. Also includes the other parent hash if the state is a merge.
/// Returns an error if any fragment is missing.
///
/// A merge revision joins two lines of history, and what it names is new to this
/// branch against either of them, so `other_parent_state` is collected against as well.
/// Reading that parent's own tree is what refuses a peer that pushed the merge without
/// the tip of the line it merged.
///
/// A missing fragment is reported as `FAILED_PRECONDITION` naming the address,
/// whether the walk cannot read it or the store answers that it is absent.
/// `NOT_FOUND` is left to name an absent branch, which a caller reinstates.
#[lore_macro::test_pub]
async fn verify_fragments(
    repository: Arc<RepositoryContext>,
    parent_state: Arc<State>,
    other_parent_state: Option<Arc<State>>,
    state: Arc<State>,
) -> Result<(), Status> {
    let collect = async |parent_state: Arc<State>| {
        state::collect_new_fragments(
            repository.clone(),
            parent_state,
            state.clone(),
            true, /* Ignore already durably stored fragments */
        )
        .instrument(span!(Level::DEBUG, "collect_new_fragments"))
        .await
        .filter_slow_down()
        .map_err(|status| push_store_refusal("fragment_collect", status))?
        .warn_map_err(|err| {
            if let Some(converted_error) = err.as_address_not_found() {
                return address_not_found_status(
                    converted_error,
                    format!(
                        "Failed to collect new fragments for verification. Missing address '{converted_error}'"
                    ),
                );
            }

            Status::internal(format!(
                "Failed to collect new fragments for verification: {err}"
            ))
        })
    };

    let mut new_fragments = collect(parent_state).await?;

    if let Some(other_parent_state) = other_parent_state {
        new_fragments.append(&mut collect(other_parent_state).await?);
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
                    if let Some(missing) = first_missing_fragment(&batch, &result) {
                        return Err(address_not_found_status(
                            &AddressNotFound::from(missing),
                            format!("Missing fragment '{missing}'"),
                        ));
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

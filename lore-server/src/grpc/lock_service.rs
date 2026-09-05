// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use lore_base::error::InvalidArguments;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::LockResource;
use lore_postgres::domain::locks::AcquireOrRenewInput;
use lore_postgres::domain::locks::FencedLock;
use lore_postgres::domain::locks::ForceReleaseInput;
use lore_postgres::domain::locks::LockMutationResult;
use lore_postgres::domain::locks::LockRejection;
use lore_postgres::domain::locks::LockResourceInput;
use lore_postgres::domain::locks::PostgresLockCoordinator;
use lore_postgres::domain::locks::ReleaseInput;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_postgres::domain::locks::acquire_or_renew_binding;
use lore_postgres::domain::locks::force_release_binding;
use lore_postgres::domain::locks::release_binding;
use lore_proto::LockService;
use lore_proto::lock::AdminLockRequest;
use lore_proto::lock::AdminLockResponse;
use lore_proto::lock::ForceUnlockRequest;
use lore_proto::lock::ForceUnlockResponse;
use lore_proto::lock::LockRequest;
use lore_proto::lock::LockResponse;
use lore_proto::lock::QueryRequest;
use lore_proto::lock::QueryResponse;
use lore_proto::lock::StatusRequest;
use lore_proto::lock::StatusResponse;
use lore_proto::lock::UnlockRequest;
use lore_proto::lock::UnlockResponse;
use lore_revision::lock::LockError;
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lore::RepositoryId;
use lore_revision::notification::NotificationSender;
use lore_telemetry::InstrumentProvider;
use opentelemetry::metrics::Histogram;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;
use tracing::warn;

use super::extract_correlation_id;
use super::get_authorization;
use super::get_repository;
use super::get_user_id;
use super::is_owner_or_admin;
use super::timeout_grpc;
use crate::grpc::can_admin_lock;
use crate::grpc::require_permission;
use crate::hooks::HookContext;
use crate::hooks::HookDispatcher;
use crate::hooks::HookPoint;
use crate::util::setup_execution;

const STATUS_MAX_RESOURCE_LEN: usize = 100;

#[derive(Clone)]
struct LoreLockServiceInstrumentProvider {}

fn lock_query_from_request(
    repository: RepositoryId,
    request: &QueryRequest,
) -> Result<LockQuery, LockError> {
    match (&request.branch, &request.owner, &request.description) {
        // Repository
        (None, None, None) => Ok(LockQuery::Repository(repository)),
        // RepositoryBranch
        (Some(branch), None, None) => Ok(LockQuery::RepositoryBranch(repository, branch.into())),
        // RepositoryBranchDescription
        (Some(branch), None, Some(description)) => Ok(LockQuery::RepositoryBranchDescription(
            repository,
            branch.into(),
            description.clone(),
        )),
        // OwnerRepository
        (None, Some(owner), None) => Ok(LockQuery::OwnerRepository(owner.clone(), repository)),
        // OwnerRepositoryBranch
        (Some(branch), Some(owner), None) => Ok(LockQuery::OwnerRepositoryBranch(
            owner.clone(),
            repository,
            branch.into(),
        )),
        _ => Err(InvalidArguments {
            reason: "unsupported lock query combination".into(),
        }
        .into()),
    }
}

fn handle_lock_error(error: LockError) -> Status {
    match error {
        LockError::LockNotFound(_) => Status::not_found(error.to_string()),
        LockError::LockNotOwned(_) => Status::failed_precondition(error.to_string()),
        LockError::SlowDown(_) => Status::resource_exhausted(error.to_string()),
        LockError::InvalidArguments(_) => Status::invalid_argument(error.to_string()),
        LockError::Internal(_) => {
            warn!(error = ?error, "LockData operation failed");
            Status::internal(error.to_string())
        }
    }
}

#[derive(Clone)]
pub struct LoreLockService {
    lock_store: Arc<dyn LockStore>,
    notification: Arc<dyn NotificationSender>,
    /// Fires the compile-in post-commit hooks (e.g. `lorehub_notify`) on
    /// lock/unlock — the lock service is the one write service that historically
    /// wasn't handed a dispatcher (CR-015).
    hook_dispatcher: Arc<HookDispatcher>,
    rpc_timeout: Duration,
    enforce_write_permission: bool,
    fenced_coordinator: Option<Arc<PostgresLockCoordinator>>,
    /// The CR-029 domain context, needed on a fenced cell so a public lock
    /// mutation can obtain the `GovernedOperation` the coordinator requires.
    ///
    /// Held beside the coordinator rather than reached through it: the
    /// coordinator is the lock authority and knows nothing about receipts,
    /// verifiers, or admission.
    fenced_domain: Option<Arc<crate::domain::DomainContext>>,

    instrument_provider: LoreLockServiceInstrumentProvider,
    locking_histogram: Histogram<u64>,
    status_histogram: Histogram<u64>,
}

impl LoreLockService {
    pub fn new(
        lock_store: Arc<dyn LockStore>,
        notification: Arc<dyn NotificationSender>,
        hook_dispatcher: Arc<HookDispatcher>,
        rpc_timeout: Duration,
        enforce_write_permission: bool,
    ) -> Self {
        let instrument_provider = LoreLockServiceInstrumentProvider {};

        Self {
            lock_store,
            notification,
            hook_dispatcher,
            rpc_timeout,
            enforce_write_permission,
            fenced_coordinator: None,
            fenced_domain: None,
            locking_histogram: instrument_provider.length_histogram(
                "locking.request.resources.length",
                vec![1., 5., 10., 25., 50., 75., 100., 200.],
            ),
            status_histogram: instrument_provider.length_histogram(
                "status.request.resources.length",
                vec![
                    1., 5., 10., 50., 100., 200., 300., 500., 2_500., 5_000., 10_000., 20_000.,
                    40_000., 60_000., 80_000.,
                ],
            ),
            instrument_provider,
        }
    }

    /// Route every operation through the active fenced authority.
    ///
    /// Reads moved here in WP-117. WP-120 moved the three mutations, so a cell
    /// with a coordinator now serves `Lock`, `Unlock`, `AdminLock` and
    /// `ForceUnlock` from it rather than refusing them.
    ///
    /// The domain context travels with the coordinator because a fenced
    /// mutation needs both: the coordinator is the lock authority, and the
    /// domain context is where a caller with no carriage gets the
    /// `GovernedOperation` that authority demands. A coordinator without a
    /// domain context cannot serve a mutation, which is why they are set
    /// together rather than through two independent builders.
    pub fn with_fenced_coordinator(
        mut self,
        coordinator: Option<Arc<PostgresLockCoordinator>>,
        domain: Option<Arc<crate::domain::DomainContext>>,
    ) -> Self {
        self.fenced_coordinator = coordinator;
        self.fenced_domain = domain;
        self
    }
}

/// Project a committed fenced lock onto the public wire.
///
/// `ownership_token` is deliberately left empty here. This converter serves the
/// read paths (`Query`, `Status`), which return **other people's** locks, and a
/// token is the bearer secret that authorizes releasing one. Only
/// [`fenced_lock_to_wire_with_token`] fills it in, and only for the caller that
/// just acquired or renewed the row.
fn fenced_lock_to_wire(lock: FencedLock) -> Result<lore_proto::lock::Lock, Status> {
    let elapsed = lock
        .acquired_at
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|_| Status::internal("Stored lock timestamp predates the Unix epoch"))?;
    let seconds = i64::try_from(elapsed.as_secs())
        .map_err(|_| Status::internal("Stored lock timestamp exceeds the wire range"))?;
    Ok(lore_proto::lock::Lock {
        resource: Some(lore_proto::lock::Resource {
            branch: lock.branch_id.into(),
            hash: lock.resource_hash.into(),
            description: lock.description,
            expected_ownership_token: Default::default(),
        }),
        owner: lock.owner.authenticated_subject,
        ownership_token: Default::default(),
        locked_at: Some(prost_types::Timestamp {
            seconds,
            nanos: i32::try_from(elapsed.subsec_nanos())
                .map_err(|_| Status::internal("Stored lock nanoseconds exceed the wire range"))?,
        }),
    })
}

/// Project a committed fenced lock **to the caller that just acquired it**,
/// including the 32-byte ownership token it needs to renew or release the row.
///
/// CR-030's public shape: the token is issued on acquire and required on
/// release. It is returned only from `Lock` and `AdminLock`, never from a read.
fn fenced_lock_to_wire_with_token(lock: FencedLock) -> Result<lore_proto::lock::Lock, Status> {
    let token = lock.ownership_token;
    let mut wire = fenced_lock_to_wire(lock)?;
    wire.ownership_token = bytes::Bytes::copy_from_slice(&token);
    Ok(wire)
}

/// Exactly 16 bytes, or a request rejection.
///
/// `BranchId` coerces a wrong-length value rather than refusing it, so a short
/// or long branch would silently address a different lock namespace than the
/// caller named. The width is checked here, once, before any namespace is
/// derived from it.
fn fenced_branch_id(value: &[u8]) -> Result<[u8; 16], Status> {
    value
        .try_into()
        .map_err(|_| Status::invalid_argument("lock resource branch must be exactly 16 bytes"))
}

/// One wire lock batch, normalised for the fenced coordinator.
struct FencedBatch {
    branch_id: [u8; 16],
    resources: Vec<LockResourceInput>,
}

/// Normalise a wire resource batch into the coordinator's typed input.
///
/// Three things happen here that the legacy path never had to do:
///
/// * **One branch per batch.** The coordinator locks one
///   `(repository, branch)` namespace atomically, so a batch spanning two
///   branches is not a batch it can serve. The legacy path silently took the
///   first resource's branch and ignored the rest; refusing is the fenced
///   answer, because "silently ignored" here means locking rows in a namespace
///   the caller did not name.
/// * **Token width.** Absent is `None` (a first acquire); exactly 32 bytes is
///   `Some`; anything else is a malformed request rather than a token that
///   happens not to match.
/// * **`require_token`.** Release and force-release name a specific row, so a
///   tokenless resource there would ask the server to release whatever it finds.
fn fenced_batch(
    resources: &[lore_proto::lock::Resource],
    require_token: bool,
) -> Result<FencedBatch, Status> {
    let Some(first) = resources.first() else {
        return Err(Status::invalid_argument("At least one resource needed"));
    };
    let branch_id = fenced_branch_id(first.branch.as_ref())?;
    let mut inputs = Vec::with_capacity(resources.len());
    for resource in resources {
        if fenced_branch_id(resource.branch.as_ref())? != branch_id {
            return Err(Status::invalid_argument(
                "every resource in one lock request must name the same branch",
            ));
        }
        let token = match resource.expected_ownership_token.as_ref() {
            [] if require_token => {
                // Named rather than generic, because the caller most likely to
                // hit this is a client that predates the token contract: a
                // stock build with no field to put one in, or the holder of a
                // lock that was converted by cutover and whose token was never
                // issued to anyone. The message names the only remedy that
                // actually works for both — re-acquiring does NOT mint a
                // replacement, because a tokenless acquire over a current row is
                // refused even to that row's own owner.
                return Err(Status::invalid_argument(
                    "releasing a lock on this cell requires the ownership token returned when it \
                     was acquired; a lock whose token was never issued, or was lost, must be \
                     cleared by an administrator through ForceUnlock",
                ));
            }
            [] => None,
            bytes => Some(<[u8; 32]>::try_from(bytes).map_err(|_| {
                Status::invalid_argument("lock ownership token must be exactly 32 bytes")
            })?),
        };
        inputs.push(LockResourceInput {
            resource_hash: resource.hash.to_vec(),
            description: resource.description.clone(),
            expected_ownership_token: token,
        });
    }
    Ok(FencedBatch {
        branch_id,
        resources: inputs,
    })
}

/// Map a decisive fenced rejection onto a gRPC status.
///
/// Every arm is a conclusive answer about state the caller can observe and
/// correct, so none of them is `INTERNAL`. `AuthorityMismatch` deliberately does
/// not distinguish "wrong token" from "wrong owner": both mean the caller does
/// not hold this row, and separating them would tell a prober which half it got
/// right.
fn fenced_rejection_to_status(rejection: LockRejection) -> Status {
    match rejection {
        LockRejection::NotFound => Status::not_found("No matching lock is held"),
        LockRejection::ForeignOwner => {
            Status::failed_precondition("A lock in this request is held by another user")
        }
        LockRejection::AuthorityMismatch => {
            Status::failed_precondition("The presented lock ownership does not match")
        }
        LockRejection::NamespaceMismatch => {
            Status::failed_precondition("The repository or branch lock state is absent or stale")
        }
        LockRejection::AdmissionRejected => {
            Status::aborted("The lock operation's admission was not consumable")
        }
    }
}

/// Turn one committed coordinator result into either its locks or a refusal.
fn fenced_applied(result: LockMutationResult) -> Result<Vec<FencedLock>, Status> {
    if let Some(rejection) = result.rejection {
        return Err(fenced_rejection_to_status(rejection));
    }
    match result.outcome {
        lore_postgres::domain::errors::DomainOutcome::Applied => Ok(result.locks),
        lore_postgres::domain::errors::DomainOutcome::NotApplied { reason, .. } => {
            Err(crate::grpc::map_domain_rejection_to_status(&reason))
        }
    }
}

impl InstrumentProvider for LoreLockServiceInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.lock_service"
    }
}

/// Everything a fenced mutation needs from the request, resolved once.
struct FencedCall {
    coordinator: Arc<PostgresLockCoordinator>,
    domain: Arc<crate::domain::DomainContext>,
    /// The caller's verified token, carried whole rather than reduced to its
    /// owner pair. `prepare_direct_lock_operation` excludes service accounts,
    /// and that exclusion reads `is_service_account` — a reconstructed token
    /// with only the issuer and subject would silently default that field and
    /// let a service account through the check meant to stop it.
    authorization: crate::auth::jwt::AuthorizationToken,
    caller: VerifiedLockOwner,
    bearer: String,
}

impl LoreLockService {
    /// Resolve the fenced authority, the acting principal, and its bearer token,
    /// or `Ok(None)` when this cell is on the legacy route.
    ///
    /// A cell with a coordinator but no domain context is a wiring fault, not a
    /// legacy cell: it would route reads through the fenced authority and
    /// mutations through the legacy store, which is the two-writers-under-two-
    /// lock-disciplines state CR-030 exists to end. It refuses rather than
    /// silently splitting.
    fn fenced_call(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
    ) -> Result<Option<FencedCall>, Status> {
        let Some(coordinator) = self.fenced_coordinator.as_ref() else {
            return Ok(None);
        };
        let Some(domain) = self.fenced_domain.as_ref() else {
            return Err(Status::failed_precondition(
                "Fenced lock routing is active but this cell has no domain coordinator",
            ));
        };
        let authorization = get_authorization(extensions)?;
        let bearer = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| Status::unauthenticated("Missing authorization"))?;
        let caller = VerifiedLockOwner {
            verified_issuer: authorization.issuer.clone(),
            authenticated_subject: authorization.user_id.clone(),
        };
        Ok(Some(FencedCall {
            coordinator: coordinator.clone(),
            domain: domain.clone(),
            authorization,
            caller,
            bearer,
        }))
    }

    /// Acquire or renew through the fenced authority.
    ///
    /// `for_owner` is `None` for an ordinary `Lock` (the caller locks for
    /// itself) and `Some(subject)` for `AdminLock` (the caller locks on
    /// another's behalf, and is recorded as the acting administrator).
    ///
    /// PIN(WP-120, 2026-09-04): the issuer half of an administered owner is the
    /// **calling administrator's** verified issuer. The wire carries only a
    /// subject string, and a fenced cell pins exactly one JWT issuer
    /// (`resolve_lock_fencing` refuses to arm without a non-empty
    /// `jwt_issuer`), so every principal this cell can authenticate shares that
    /// issuer and the pair is provable rather than guessed. The fenced `Query`
    /// arm already resolves an owner filter the same way.
    async fn fenced_acquire(
        &self,
        call: &FencedCall,
        repository: RepositoryId,
        resources: &[lore_proto::lock::Resource],
        for_owner: Option<&str>,
        correlation_id: &str,
    ) -> Result<Vec<lore_proto::lock::Lock>, Status> {
        let batch = fenced_batch(resources, false)?;
        let owner = match for_owner {
            Some(subject) => VerifiedLockOwner {
                verified_issuer: call.caller.verified_issuer.clone(),
                authenticated_subject: subject.to_owned(),
            },
            None => call.caller.clone(),
        };
        let acting_owner = for_owner.map(|_| call.caller.clone());
        let input = AcquireOrRenewInput {
            repository_id: repository.as_ref().to_vec(),
            branch_id: batch.branch_id.to_vec(),
            owner,
            acting_owner,
            resources: batch.resources,
            // Finite leases stay off: no public client renews one, so an expiry
            // would drop a lock its holder still believes it has.
            // `resolve_lock_fencing` refuses to arm a cell that enabled them.
            lease_duration: None,
            outbox_cell_id: call.domain.cell_id().map(str::to_owned),
        };
        let binding = acquire_or_renew_binding(&input)
            .map_err(|error| super::map_domain_error_to_status(&error))?;
        let operation = call
            .domain
            .prepare_direct_lock_operation(
                &call.authorization,
                &call.bearer,
                repository.as_ref(),
                &batch.branch_id,
                binding,
            )
            .await?;
        let result = call
            .coordinator
            .acquire_or_renew(&operation, &input)
            .await
            .map_err(|error| super::map_domain_error_to_status(&error))?;
        let locks = fenced_applied(result)?;

        self.announce_lock_transition(
            repository,
            batch.branch_id,
            &input.owner.authenticated_subject,
            &locks,
            HookPoint::ResourceLock,
            correlation_id,
        )
        .await;

        locks
            .into_iter()
            .map(fenced_lock_to_wire_with_token)
            .collect()
    }

    /// Release through the fenced authority, on the caller's own behalf.
    async fn fenced_release(
        &self,
        call: &FencedCall,
        repository: RepositoryId,
        resources: &[lore_proto::lock::Resource],
        correlation_id: &str,
    ) -> Result<Vec<lore_proto::lock::Resource>, Status> {
        let batch = fenced_batch(resources, true)?;
        let input = ReleaseInput {
            repository_id: repository.as_ref().to_vec(),
            branch_id: batch.branch_id.to_vec(),
            owner: call.caller.clone(),
            resources: batch.resources,
            outbox_cell_id: call.domain.cell_id().map(str::to_owned),
        };
        let binding =
            release_binding(&input).map_err(|error| super::map_domain_error_to_status(&error))?;
        let operation = call
            .domain
            .prepare_direct_lock_operation(
                &call.authorization,
                &call.bearer,
                repository.as_ref(),
                &batch.branch_id,
                binding,
            )
            .await?;
        let result = call
            .coordinator
            .release(&operation, &input)
            .await
            .map_err(|error| super::map_domain_error_to_status(&error))?;
        fenced_applied(result)?;
        self.announce_release(
            repository,
            batch.branch_id,
            &call.caller.authenticated_subject,
            resources,
            correlation_id,
        )
        .await;
        Ok(released_resources(resources))
    }

    /// Administratively release locks held by another owner.
    async fn fenced_force_release(
        &self,
        call: &FencedCall,
        repository: RepositoryId,
        resources: &[lore_proto::lock::Resource],
        target_owner: &str,
        correlation_id: &str,
    ) -> Result<Vec<lore_proto::lock::Resource>, Status> {
        // Tokens are NOT required here, unlike an ordinary release. An
        // administrator holds no other owner's token and no read path issues
        // one, so demanding one would make force-release unperformable by the
        // only principal that ever needs it — and would leave every
        // cutover-converted legacy row unreleasable by anybody. A token is still
        // honoured if supplied.
        let batch = fenced_batch(resources, false)?;
        let input = ForceReleaseInput {
            repository_id: repository.as_ref().to_vec(),
            branch_id: batch.branch_id.to_vec(),
            // Explicit, never inferred from the stored row. See
            // `ForceUnlockRequest.owner`.
            target_owner: VerifiedLockOwner {
                verified_issuer: call.caller.verified_issuer.clone(),
                authenticated_subject: target_owner.to_owned(),
            },
            acting_owner: call.caller.clone(),
            resources: batch.resources,
            outbox_cell_id: call.domain.cell_id().map(str::to_owned),
        };
        let binding = force_release_binding(&input)
            .map_err(|error| super::map_domain_error_to_status(&error))?;
        let operation = call
            .domain
            .prepare_direct_lock_operation(
                &call.authorization,
                &call.bearer,
                repository.as_ref(),
                &batch.branch_id,
                binding,
            )
            .await?;
        let result = call
            .coordinator
            .force_release(&operation, &input)
            .await
            .map_err(|error| super::map_domain_error_to_status(&error))?;
        fenced_applied(result)?;
        self.announce_release(
            repository,
            batch.branch_id,
            target_owner,
            resources,
            correlation_id,
        )
        .await;
        Ok(released_resources(resources))
    }

    /// Fire the same local notification and CR-015 hook the legacy acquire path
    /// fires, so today's consumers see a fenced lock exactly as they see a
    /// legacy one. The CR-032 outbox row is an addition to this, not a
    /// replacement for it.
    async fn announce_lock_transition(
        &self,
        repository: RepositoryId,
        branch_id: [u8; 16],
        owner: &str,
        locks: &[FencedLock],
        point: HookPoint,
        correlation_id: &str,
    ) {
        if locks.is_empty() {
            return;
        }
        let branch = lore_revision::lore::BranchId::from(branch_id.as_slice());
        let resources: Vec<LockResource> = locks
            .iter()
            .map(|lock| LockResource {
                branch,
                hash: lore_base::types::Hash::from(lock.resource_hash.as_slice()),
                description: lock.description.clone(),
            })
            .collect();
        self.notification
            .resource_locked(repository, branch, owner, &resources)
            .await;
        self.hook_dispatcher.spawn_post(
            point,
            lock_hook_context(
                correlation_id,
                point,
                repository,
                branch,
                owner,
                &resources[0],
            ),
        );
    }

    /// The release-side counterpart of [`Self::announce_lock_transition`].
    async fn announce_release(
        &self,
        repository: RepositoryId,
        branch_id: [u8; 16],
        owner: &str,
        resources: &[lore_proto::lock::Resource],
        correlation_id: &str,
    ) {
        if resources.is_empty() {
            return;
        }
        let branch = lore_revision::lore::BranchId::from(branch_id.as_slice());
        let released: Vec<LockResource> = resources
            .iter()
            .map(|resource| LockResource {
                branch,
                hash: lore_base::types::Hash::from(resource.hash.as_ref()),
                description: resource.description.clone(),
            })
            .collect();
        self.notification
            .resource_unlocked(repository, branch, owner, &released)
            .await;
        self.hook_dispatcher.spawn_post(
            HookPoint::ResourceUnlock,
            lock_hook_context(
                correlation_id,
                HookPoint::ResourceUnlock,
                repository,
                branch,
                owner,
                &released[0],
            ),
        );
    }
}

/// Echo back the resources a release named, without their ownership tokens.
///
/// The coordinator releases the exact batch or refuses it, so a successful
/// release released precisely what was asked for. The tokens are stripped
/// because they are spent: the rows they authorised no longer exist.
fn released_resources(resources: &[lore_proto::lock::Resource]) -> Vec<lore_proto::lock::Resource> {
    resources
        .iter()
        .map(|resource| lore_proto::lock::Resource {
            branch: resource.branch.clone(),
            hash: resource.hash.clone(),
            description: resource.description.clone(),
            expected_ownership_token: Default::default(),
        })
        .collect()
}

impl LoreLockService {
    async fn lock_as_user(
        &self,
        repository: RepositoryId,
        resources: Vec<lore_proto::lock::Resource>,
        owner_id: &str,
        correlation_id: &str,
    ) -> Result<Vec<lore_proto::lock::Lock>, Status> {
        if resources.is_empty() {
            return Err(Status::invalid_argument("At least one resource needed"));
        }

        let lock_resources: Vec<LockResource> = resources.into_iter().map(Into::into).collect();

        let locks = self
            .lock_store
            .lock_resources(owner_id, repository, &lock_resources)
            .await
            .map_err(handle_lock_error)?;

        // TODO: UCS-13626 move branch out of individual resources into the main message
        // All resources are on the same branch and the lock call has to be made with at least 1 resource
        let branch = lock_resources[0].branch;
        let locked_resources: Vec<LockResource> =
            locks.iter().map(|lock| lock.resource.clone()).collect();

        self.notification
            .resource_locked(repository, branch, owner_id, &locked_resources)
            .await;

        // CR-015: also notify the Lorehub platform over the `lorehub_notify` HTTP hook
        // (post-commit, fire-and-forget — never blocks or fails the lock). One event per
        // RPC; the first request resource carries the batch's branch/hash for the
        // event-id discriminator. `spawn_post` is a no-op when no hook is registered.
        // Caveat (accepted for partition-only liveness): the discriminator is only the
        // FIRST resource's hash, so two distinct lock RPCs in the same second on the same
        // repo whose first resource matches would collide on `event_id` and the receiver
        // would drop one — a momentarily-missing lock row the next lock/unlock corrects.
        self.hook_dispatcher.spawn_post(
            HookPoint::ResourceLock,
            lock_hook_context(
                correlation_id,
                HookPoint::ResourceLock,
                repository,
                branch,
                owner_id,
                &lock_resources[0],
            ),
        );

        let locks = locks.into_iter().map(Into::into).collect();

        Ok(locks)
    }
}

/// Builds the [`HookContext`] for a lock/unlock post-hook. The path is not available
/// server-side (the `hash` is a client-computed digest of it); the human `description`
/// rides `metadata` for anyone who wants it, but Lorehub's liveness consumer (WP-065)
/// reads only the partition off the resulting payload-free hint.
fn lock_hook_context(
    correlation_id: &str,
    point: HookPoint,
    repository: RepositoryId,
    branch: lore_revision::lore::BranchId,
    user_id: &str,
    resource: &LockResource,
) -> HookContext {
    HookContext::builder()
        .correlation_id(correlation_id)
        .hook_point(point)
        .repository(repository)
        .user(user_id)
        .branch(branch)
        .metadata("lock_hash", resource.hash.to_string())
        .metadata("lock_description", resource.description.clone())
        .build()
}

impl LoreLockService {
    async fn handle_lock(
        &self,
        request: Request<LockRequest>,
    ) -> Result<Response<LockResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        let user_id = get_user_id(request.extensions());
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let fenced = self.fenced_call(request.metadata(), request.extensions())?;

        let lock_request = request.into_inner();

        self.locking_histogram.record(
            lock_request.resources.len() as u64,
            &self
                .instrument_provider
                .get_labels_for_operation_context("lock"),
        );

        if lock_request.resources.is_empty() {
            return Ok(Response::new(LockResponse { locks: vec![] }));
        }

        let resources = lock_request.resources;

        let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

        // The fenced arm runs inside the same execution scope as the legacy
        // one, so the post-commit hook tasks `lore_spawn!` starts inherit the
        // same `LORE_CONTEXT` and correlation id on both routes.
        if let Some(call) = fenced {
            return LORE_CONTEXT
                .scope(execution, async move {
                    let locks = self
                        .fenced_acquire(&call, repository, &resources, None, &correlation_id)
                        .await?;
                    Ok(Response::new(LockResponse { locks }))
                })
                .await;
        }

        LORE_CONTEXT
            .scope(execution, async move {
                self.lock_as_user(repository, resources, &user_id, &correlation_id)
                    .await
                    .map(|locks| Response::new(LockResponse { locks }))
            })
            .await
    }

    async fn handle_query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        let user_id = get_user_id(request.extensions());
        let repository = get_repository(request.metadata())?;
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let query_request = request.get_ref();

        let query =
            lock_query_from_request(repository, query_request).map_err(handle_lock_error)?;

        if let Some(coordinator) = &self.fenced_coordinator {
            let authorization = get_authorization(request.extensions())?;
            let owner = query_request
                .owner
                .as_ref()
                .map(|subject| VerifiedLockOwner {
                    verified_issuer: authorization.issuer.clone(),
                    authenticated_subject: subject.clone(),
                });
            let locks = coordinator
                .query_filtered(
                    repository.as_ref(),
                    query_request.branch.as_deref(),
                    owner.as_ref(),
                    query_request.description.as_deref(),
                )
                .await
                .map_err(|error| super::map_domain_error_to_status(&error))?
                .into_iter()
                .map(fenced_lock_to_wire)
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Response::new(QueryResponse { result: locks }));
        }

        let execution = setup_execution(module_path!(), correlation_id, user_id.clone());

        LORE_CONTEXT
            .scope(execution, async move {
                self.lock_store
                    .query_locks(query)
                    .await
                    .map(|result| {
                        Response::new(QueryResponse {
                            result: result.into_iter().map(Into::into).collect(),
                        })
                    })
                    .map_err(handle_lock_error)
            })
            .await
    }

    async fn handle_status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let user_id = get_user_id(request.extensions());
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let repository = get_repository(request.metadata())?;
        let fenced_authorization = if self.fenced_coordinator.is_some() {
            Some(get_authorization(request.extensions())?)
        } else {
            None
        };
        let status_request = request.into_inner();

        if status_request.resources.len() > STATUS_MAX_RESOURCE_LEN {
            return Err(Status::invalid_argument("Resource count exceeds limit"));
        }

        self.status_histogram.record(
            status_request.resources.len() as u64,
            &self
                .instrument_provider
                .get_labels_for_operation_context("status"),
        );

        if status_request.resources.is_empty() {
            return Ok(Response::new(StatusResponse { locks: vec![] }));
        }

        if let Some(coordinator) = &self.fenced_coordinator {
            let _authorization = fenced_authorization
                .ok_or_else(|| Status::unauthenticated("Missing authorization"))?;
            // One checkout and one query for the batch, as the legacy store
            // does. A resource-at-a-time loop took a pool checkout per entry
            // off the shared CR-029 domain pool (INV-EE P1-8).
            let requested = status_request
                .resources
                .iter()
                .map(|resource| (resource.branch.as_ref(), resource.hash.as_ref()))
                .collect::<Vec<_>>();
            let locks = coordinator
                .status_many(repository.as_ref(), &requested)
                .await
                .map_err(|error| super::map_domain_error_to_status(&error))?
                .into_iter()
                .map(fenced_lock_to_wire)
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(Response::new(StatusResponse { locks }));
        }

        info!(
            num_items = status_request.resources.len(),
            "Handling LockService::Status request"
        );

        let resources: Vec<LockResource> = status_request
            .resources
            .into_iter()
            .map(Into::into)
            .collect();

        let execution = setup_execution(module_path!(), correlation_id, user_id.clone());

        LORE_CONTEXT
            .scope(execution, async move {
                let locks = self
                    .lock_store
                    .check_locks_status(repository, &resources)
                    .await
                    .map_err(handle_lock_error)?;

                Ok(Response::new(StatusResponse {
                    locks: locks.into_iter().map(Into::into).collect(),
                }))
            })
            .await
    }

    async fn handle_unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        let user_id = get_user_id(request.extensions());
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let repository = get_repository(request.metadata())?;
        let validate_user = !is_owner_or_admin(request.extensions(), repository);
        let fenced = self.fenced_call(request.metadata(), request.extensions())?;
        let unlock_request = request.into_inner();

        self.locking_histogram.record(
            unlock_request.resources.len() as u64,
            &self
                .instrument_provider
                .get_labels_for_operation_context("unlock"),
        );

        if unlock_request.resources.is_empty() {
            return Ok(Response::new(UnlockResponse { resources: vec![] }));
        }

        let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

        if let Some(call) = fenced {
            // Deliberately not routed by `validate_user`. On the legacy store an
            // owner or admin could unlock anyone's row through this RPC; on a
            // fenced cell that is `ForceUnlock`'s job, and it is a different
            // transition with a different audit record. `Unlock` here always
            // releases the caller's own rows, under the caller's own tokens.
            let wire_resources = unlock_request.resources;
            let correlation_id = correlation_id.clone();
            return LORE_CONTEXT
                .scope(execution, async move {
                    let resources = self
                        .fenced_release(&call, repository, &wire_resources, &correlation_id)
                        .await?;
                    Ok(Response::new(UnlockResponse { resources }))
                })
                .await;
        }

        let resources: Vec<LockResource> =
            unlock_request.resources.iter().map(Into::into).collect();

        LORE_CONTEXT
            .scope(execution, async move {
                let resources = self
                    .lock_store
                    .unlock_resources(user_id.as_str(), validate_user, repository, &resources)
                    .await
                    .map_err(handle_lock_error)?;

                // TODO: UCS-13626 move branch out of individual resources into the main message
                // All resources are on the same branch and the lock call has to be made with at least 1 resource
                if !resources.is_empty() {
                    self.notification
                        .resource_unlocked(repository, resources[0].branch, &user_id, &resources)
                        .await;

                    // CR-015: notify the Lorehub platform (post-commit, fire-and-forget).
                    self.hook_dispatcher.spawn_post(
                        HookPoint::ResourceUnlock,
                        lock_hook_context(
                            &correlation_id,
                            HookPoint::ResourceUnlock,
                            repository,
                            resources[0].branch,
                            &user_id,
                            &resources[0],
                        ),
                    );
                }

                Ok(Response::new(UnlockResponse {
                    resources: resources.into_iter().map(Into::into).collect(),
                }))
            })
            .await
    }

    async fn handle_admin_lock(
        &self,
        request: Request<AdminLockRequest>,
    ) -> Result<Response<AdminLockResponse>, Status> {
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let repository = get_repository(request.metadata())?;
        let extensions = request.extensions().clone();
        let fenced = self.fenced_call(request.metadata(), request.extensions())?;

        let user_id = get_user_id(request.extensions());
        let lock_request = request.into_inner();

        self.locking_histogram.record(
            lock_request.resources.len() as u64,
            &self
                .instrument_provider
                .get_labels_for_operation_context("admin_lock"),
        );

        if lock_request.resources.is_empty() {
            return Ok(Response::new(AdminLockResponse { locks: vec![] }));
        }

        let resources = lock_request.resources;
        let owner = lock_request.owner;

        let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

        LORE_CONTEXT
            .scope(execution, async move {
                if !can_admin_lock(&extensions, repository) {
                    warn!("Attempt to apply admin locks, but user does not have the correct permissions");
                    return Err(Status::permission_denied("Permission denied"));
                }

                if let Some(call) = fenced {
                    let locks = self
                        .fenced_acquire(
                            &call,
                            repository,
                            &resources,
                            Some(&owner),
                            &correlation_id,
                        )
                        .await?;
                    return Ok(Response::new(AdminLockResponse { locks }));
                }

                self.lock_as_user(repository, resources, &owner, &correlation_id)
                    .await
                    .map(|locks| Response::new(AdminLockResponse { locks }))
            })
            .await
    }

    /// Administratively release another owner's locks.
    ///
    /// A fenced-only path. There is no legacy force-release: the legacy store
    /// expresses the same intent as an owner-or-admin `Unlock`, which is exactly
    /// the conflation CR-030 separates. On a cell that is not routing through
    /// the fenced authority this refuses rather than quietly falling back to
    /// that older, weaker behaviour.
    async fn handle_force_unlock(
        &self,
        request: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        let correlation_id = extract_correlation_id(&request).unwrap_or_default();
        let repository = get_repository(request.metadata())?;
        let extensions = request.extensions().clone();
        let user_id = get_user_id(request.extensions());

        // The permission bar comes first, before this handler reports anything
        // about the cell. `fenced_call`'s refusals name whether fenced routing
        // is active and whether the cell is wired for it, and a caller with no
        // administrative permission has no business learning either.
        if !can_admin_lock(&extensions, repository) {
            warn!("Attempt to force unlock, but user does not have the correct permissions");
            return Err(Status::permission_denied("Permission denied"));
        }

        let fenced = self.fenced_call(request.metadata(), request.extensions())?;
        let force_request = request.into_inner();

        self.locking_histogram.record(
            force_request.resources.len() as u64,
            &self
                .instrument_provider
                .get_labels_for_operation_context("force_unlock"),
        );

        if force_request.resources.is_empty() {
            return Ok(Response::new(ForceUnlockResponse { resources: vec![] }));
        }
        if force_request.owner.is_empty() {
            return Err(Status::invalid_argument(
                "force unlock must name the owner being released",
            ));
        }

        let Some(call) = fenced else {
            return Err(Status::failed_precondition(
                "Force unlock requires fenced lock routing on this cell",
            ));
        };

        let execution = setup_execution(module_path!(), correlation_id.clone(), user_id);

        LORE_CONTEXT
            .scope(execution, async move {
                let resources = self
                    .fenced_force_release(
                        &call,
                        repository,
                        &force_request.resources,
                        &force_request.owner,
                        &correlation_id,
                    )
                    .await?;
                Ok(Response::new(ForceUnlockResponse { resources }))
            })
            .await
    }
}

#[tonic::async_trait]
impl LockService for LoreLockService {
    #[tracing::instrument(name = "LoreLockService::lock", skip_all)]
    async fn lock(&self, request: Request<LockRequest>) -> Result<Response<LockResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission,
        )?;
        timeout_grpc(self.rpc_timeout, self.handle_lock(request)).await
    }

    #[tracing::instrument(name = "LoreLockService::query", skip_all)]
    async fn query(
        &self,
        request: Request<QueryRequest>,
    ) -> Result<Response<QueryResponse>, Status> {
        timeout_grpc(self.rpc_timeout, self.handle_query(request)).await
    }

    #[tracing::instrument(name = "LoreLockService::status", skip_all)]
    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        timeout_grpc(self.rpc_timeout, self.handle_status(request)).await
    }

    #[tracing::instrument(name = "LoreLockService::unlock", skip_all)]
    async fn unlock(
        &self,
        request: Request<UnlockRequest>,
    ) -> Result<Response<UnlockResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission,
        )?;
        timeout_grpc(self.rpc_timeout, self.handle_unlock(request)).await
    }

    #[tracing::instrument(name = "LoreLockService::admin_lock", skip_all)]
    async fn admin_lock(
        &self,
        request: Request<AdminLockRequest>,
    ) -> Result<Response<AdminLockResponse>, Status> {
        timeout_grpc(self.rpc_timeout, self.handle_admin_lock(request)).await
    }

    #[tracing::instrument(name = "LoreLockService::force_unlock", skip_all)]
    async fn force_unlock(
        &self,
        request: Request<ForceUnlockRequest>,
    ) -> Result<Response<ForceUnlockResponse>, Status> {
        // The `migrate` permission check lives in the handler, beside
        // `AdminLock`'s, rather than a `require_permission("write")` here: a
        // force release is an administrative action and "write" would be the
        // wrong bar for it.
        timeout_grpc(self.rpc_timeout, self.handle_force_unlock(request)).await
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::time::Duration;

    use lore_proto::LockService;
    use lore_revision::lore::RepositoryId;
    use lore_transport::grpc::REPOSITORY_ID_KEY;
    use rand::random;
    use tonic::Code;
    use tonic::Request;

    use crate::grpc::lock_service::LoreLockService;

    /// CR-015: `lock_hook_context` is the pure builder that both `lock_as_user` and
    /// `handle_unlock` feed into `hook_dispatcher.spawn_post(...)`. Asserting the
    /// spawned post-handler actually fired end-to-end would need to await a detached
    /// `lore_spawn!` task with no join handle — flaky by construction — so we pin the
    /// context-building contract here instead, which is deterministic and exercises
    /// the exact CR-015 delta (metadata keys + which fields get threaded through).
    mod hook_context {
        use lore_base::types::Hash;
        use lore_base::types::LockResource;
        use lore_revision::lore::BranchId;
        use lore_revision::lore::RepositoryId;
        use rand::random;

        use crate::grpc::lock_service::lock_hook_context;
        use crate::hooks::HookPoint;

        #[test]
        fn builds_context_with_repository_user_branch_and_lock_metadata() {
            let repository = random::<RepositoryId>();
            let branch = random::<BranchId>();
            let resource = LockResource {
                branch,
                hash: Hash::from([0x42u8; 32]),
                description: "content/characters/hero.uasset".to_string(),
            };

            let ctx = lock_hook_context(
                "corr-abc",
                HookPoint::ResourceLock,
                repository,
                branch,
                "user-1",
                &resource,
            );

            assert_eq!(ctx.correlation_id(), "corr-abc");
            assert_eq!(ctx.hook_point(), HookPoint::ResourceLock);
            assert_eq!(ctx.repository(), repository);
            assert_eq!(ctx.user(), Some("user-1"));
            assert_eq!(ctx.branch(), Some(branch));
            assert_eq!(
                ctx.get_metadata("lock_hash"),
                Some(resource.hash.to_string()).as_deref()
            );
            assert_eq!(
                ctx.get_metadata("lock_description"),
                Some("content/characters/hero.uasset")
            );
            // No revision on a lock/unlock event.
            assert!(ctx.revision().is_none());
        }

        #[test]
        fn builds_distinct_context_for_unlock_point() {
            let repository = random::<RepositoryId>();
            let branch = random::<BranchId>();
            let resource = LockResource {
                branch,
                hash: Hash::from([0x99u8; 32]),
                description: "content/props/box.uasset".to_string(),
            };

            let ctx = lock_hook_context(
                "corr-xyz",
                HookPoint::ResourceUnlock,
                repository,
                branch,
                "user-2",
                &resource,
            );

            assert_eq!(ctx.hook_point(), HookPoint::ResourceUnlock);
            assert_eq!(
                ctx.get_metadata("lock_hash"),
                Some(resource.hash.to_string()).as_deref()
            );
        }
    }

    mod store {
        use async_trait::async_trait;
        use lore_base::types::LockData;
        use lore_base::types::LockResource;
        use lore_revision::lock::LockError;
        use lore_revision::lock::LockQuery;
        use lore_revision::lock::LockStore;
        use lore_revision::lore::RepositoryId;

        mockall::mock! {
             pub MockLockStore {}

             #[async_trait]
             impl LockStore for MockLockStore {

                async fn lock_resources(
                    &self,
                    owner_id: &str,
                    repository: RepositoryId,
                    resources: &[LockResource],
                ) -> Result<Vec<LockData>, LockError>;

                async fn query_locks(&self, query: LockQuery) -> Result<Vec<LockData>, LockError>;

                async fn check_locks_status(
                    &self,
                    repository: RepositoryId,
                    resources: &[LockResource],
                ) -> Result<Vec<LockData>, LockError>;


                async fn unlock_resources(
                    &self,
                    owner_id: &str,
                    validate_user: bool,
                    repository: RepositoryId,
                    resources: &[LockResource],
                ) -> Result<Vec<LockResource>, LockError>;
            }
        }
    }

    mod status {
        use lore_proto::lock::Resource;
        use lore_proto::lock::StatusRequest;

        use super::*;
        use crate::notification::local::NotificationSender;

        #[tokio::test]
        async fn resource_count_exceeds_limit() {
            let lock_store = super::store::MockMockLockStore::new();

            let notification_sender = Arc::new(NotificationSender::default());
            let lock_service = LoreLockService::new(
                Arc::new(lock_store),
                notification_sender,
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                false,
            );

            let resources: Vec<Resource> = (0..101)
                .map(|_| Resource {
                    branch: Default::default(),
                    hash: Default::default(),
                    description: "".to_string(),
                    expected_ownership_token: Default::default(),
                })
                .collect();

            let mut request = Request::new(StatusRequest { resources });
            let repository = random::<RepositoryId>();
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let error_status = lock_service
                .status(request)
                .await
                .expect_err("Status should fail when resource count exceeds limit");

            assert_eq!(error_status.code(), Code::InvalidArgument);
        }

        #[tokio::test]
        async fn resource_count_at_limit() {
            let mut lock_store = super::store::MockMockLockStore::new();
            lock_store
                .expect_check_locks_status()
                .return_once(|_, _| Ok(vec![]));

            let notification_sender = Arc::new(NotificationSender::default());
            let lock_service = LoreLockService::new(
                Arc::new(lock_store),
                notification_sender,
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                false,
            );

            let resources: Vec<Resource> = (0..100)
                .map(|_| Resource {
                    branch: Default::default(),
                    hash: Default::default(),
                    description: "".to_string(),
                    expected_ownership_token: Default::default(),
                })
                .collect();

            let mut request = Request::new(StatusRequest { resources });
            let repository = random::<RepositoryId>();
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let _ = lock_service
                .status(request)
                .await
                .expect("Status should succeed when resource count is at limit");
        }
    }

    mod unlock {
        use lore_proto::lock::AdminLockRequest;
        use lore_proto::lock::LockRequest;
        use lore_proto::lock::Resource;
        use lore_proto::lock::StatusRequest;
        use lore_proto::lock::UnlockRequest;

        use super::*;
        use crate::notification::local::NotificationSender;

        #[tokio::test]
        async fn lock_zero_resources() {
            let lock_store = super::store::MockMockLockStore::new();

            let notification_sender = Arc::new(NotificationSender::default());
            let lock_service = LoreLockService::new(
                Arc::new(lock_store),
                notification_sender,
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                false,
            );

            let mut request = Request::new(LockRequest { resources: vec![] });
            let repository = random::<RepositoryId>();
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let _ = lock_service
                .lock(request)
                .await
                .expect("LockData did not return ok status");
        }

        #[tokio::test]
        async fn unlock_zero_resources() {
            let lock_store = super::store::MockMockLockStore::new();

            let notification_sender = Arc::new(NotificationSender::default());
            let lock_service = LoreLockService::new(
                Arc::new(lock_store),
                notification_sender,
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                false,
            );

            let mut request = Request::new(UnlockRequest { resources: vec![] });
            let repository = random::<RepositoryId>();
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let _ = lock_service
                .unlock(request)
                .await
                .expect("Unlock did not return ok status");
        }

        #[tokio::test]
        async fn status_zero_resources() {
            let lock_store = super::store::MockMockLockStore::new();

            let notification_sender = Arc::new(NotificationSender::default());
            let lock_service = LoreLockService::new(
                Arc::new(lock_store),
                notification_sender,
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                false,
            );

            let mut request = Request::new(StatusRequest { resources: vec![] });
            let repository = random::<RepositoryId>();
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let _ = lock_service
                .status(request)
                .await
                .expect("Status did not return ok status");
        }

        #[tokio::test]
        async fn admin_unlock_zero_resources() {
            let lock_store = super::store::MockMockLockStore::new();

            let notification_sender = Arc::new(NotificationSender::default());
            let lock_service = LoreLockService::new(
                Arc::new(lock_store),
                notification_sender,
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                false,
            );

            let mut request = Request::new(AdminLockRequest {
                resources: vec![],
                owner: "".to_string(),
            });
            let repository = random::<RepositoryId>();
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let _ = lock_service
                .admin_lock(request)
                .await
                .expect("Admin lock did not return ok status");
        }

        #[tokio::test]
        async fn unlock_fails_for_other_owner() {
            let mut lock_store = super::store::MockMockLockStore::new();
            lock_store
                .expect_unlock_resources()
                .return_once(|_, _, _, _| Err(lore_base::error::LockNotOwned.into()));

            let notification_sender = Arc::new(NotificationSender::default());
            let lock_service = LoreLockService::new(
                Arc::new(lock_store),
                notification_sender,
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                false,
            );

            let mut request = Request::new(UnlockRequest {
                resources: vec![Resource {
                    branch: Default::default(),
                    hash: Default::default(),
                    description: "".to_string(),
                    expected_ownership_token: Default::default(),
                }],
            });
            let repository = random::<RepositoryId>();
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );

            let error_status = lock_service
                .unlock(request)
                .await
                .expect_err("Unlock did not return error status");

            assert_eq!(error_status.code(), Code::FailedPrecondition);
        }
    }

    mod permission {
        use lore_proto::lock::LockRequest;
        use lore_proto::lock::Resource;
        use lore_proto::lock::UnlockRequest;

        use super::*;
        use crate::auth::jwt::AuthorizationToken;
        use crate::auth::jwt::ResourcePermission;
        use crate::notification::local::NotificationSender;

        fn make_service(enforce: bool) -> LoreLockService {
            let lock_store = super::store::MockMockLockStore::new();
            LoreLockService::new(
                Arc::new(lock_store),
                Arc::new(NotificationSender::default()),
                Arc::new(crate::hooks::HookDispatcher::empty()),
                Duration::from_secs(60),
                enforce,
            )
        }

        fn with_token<T>(
            mut request: Request<T>,
            repository: RepositoryId,
            perms: &[&str],
        ) -> Request<T> {
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
            );
            request.extensions_mut().insert(AuthorizationToken {
                user_id: "test-user".into(),
                resources: Some(vec![ResourcePermission {
                    resource_id: format!("urc-{repository}"),
                    permission: perms.iter().map(|p| p.to_string()).collect(),
                }]),
                ..Default::default()
            });
            request
        }

        fn one_resource() -> Vec<Resource> {
            vec![Resource {
                branch: Default::default(),
                hash: Default::default(),
                description: String::new(),
                expected_ownership_token: Default::default(),
            }]
        }

        #[tokio::test]
        async fn read_only_lock_is_denied() {
            let service = make_service(true);
            let repository = random::<RepositoryId>();
            let request = with_token(
                Request::new(LockRequest {
                    resources: one_resource(),
                }),
                repository,
                &["read"],
            );
            let err = service
                .lock(request)
                .await
                .expect_err("read-only lock must be denied");
            assert_eq!(err.code(), Code::PermissionDenied);
        }

        #[tokio::test]
        async fn read_only_unlock_is_denied() {
            let service = make_service(true);
            let repository = random::<RepositoryId>();
            let request = with_token(
                Request::new(UnlockRequest {
                    resources: one_resource(),
                }),
                repository,
                &["read"],
            );
            let err = service
                .unlock(request)
                .await
                .expect_err("read-only unlock must be denied");
            assert_eq!(err.code(), Code::PermissionDenied);
        }

        #[tokio::test]
        async fn write_token_lock_passes_permission_check() {
            let service = make_service(true);
            let repository = random::<RepositoryId>();
            // Empty resources → `handle_lock` returns early, after the
            // gate has already been cleared by the write permission.
            let request = with_token(
                Request::new(LockRequest { resources: vec![] }),
                repository,
                &["read", "write"],
            );
            service
                .lock(request)
                .await
                .expect("a write token may acquire locks");
        }

        #[tokio::test]
        async fn enforcement_disabled_allows_read_only_lock() {
            let service = make_service(false);
            let repository = random::<RepositoryId>();
            let request = with_token(
                Request::new(LockRequest { resources: vec![] }),
                repository,
                &["read"],
            );
            service
                .lock(request)
                .await
                .expect("enforcement disabled lets a read-only token through");
        }
    }
}

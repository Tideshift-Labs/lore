// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use lore_base::error::InvalidArguments;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::LockResource;
use lore_postgres::domain::locks::FencedLock;
use lore_postgres::domain::locks::PostgresLockCoordinator;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_proto::LockService;
use lore_proto::lock::AdminLockRequest;
use lore_proto::lock::AdminLockResponse;
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

    /// Route read operations through the active fenced authority. Public
    /// token-bearing mutations remain dark until WP-120 adds their wire shape.
    pub fn with_fenced_coordinator(
        mut self,
        coordinator: Option<Arc<PostgresLockCoordinator>>,
    ) -> Self {
        self.fenced_coordinator = coordinator;
        self
    }
}

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
        }),
        owner: lock.owner.authenticated_subject,
        locked_at: Some(prost_types::Timestamp {
            seconds,
            nanos: i32::try_from(elapsed.subsec_nanos())
                .map_err(|_| Status::internal("Stored lock nanoseconds exceed the wire range"))?,
        }),
    })
}

/// The single refusal every fenced lock **mutation** site returns.
///
/// BLOCKED(WP-117): unfenced lock path reaches store/lock_store.rs directly;
/// events flow only when fenced routing is armed
/// (PUBLIC_MUTATION_CONTRACT_AVAILABLE, WP-120).
///
/// Concretely: on a cell with no coordinator, Lock/Unlock/AdminLock write
/// `lore-postgres`'s `store/lock_store.rs` with no transaction, no fence, and
/// no coordinator call, so there is nothing for a producer to append to. On a
/// cell that *has* a coordinator, all three refuse here rather than route,
/// because `PostgresLockCoordinator::acquire_or_renew`/`release` need two
/// things the public wire cannot supply today: a `GovernedOperation` (the
/// CR-029 receipt key, binding, and prepare token, which the public lock RPCs
/// carry no metadata for) and a per-resource `expected_ownership_token`, which
/// is precisely the token-bearing contract WP-120 owns. Both are contract
/// gaps, not missing plumbing here.
///
/// WP-119 Part L therefore stops at the coordinator: every committed lock
/// transition now builds and appends its pinned `lock_namespace` event
/// (`LockTransition`), so arming the route in WP-120 is the only remaining step
/// before lock events reach the outbox. The producer half is not deferred, only
/// its caller.
fn fenced_public_mutation_unavailable() -> Status {
    Status::failed_precondition(
        "Fenced lock mutations require the token-bearing public contract from WP-120",
    )
}

impl InstrumentProvider for LoreLockServiceInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.lock_service"
    }
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

        if self.fenced_coordinator.is_some() {
            return Err(fenced_public_mutation_unavailable());
        }

        let resources = lock_request.resources;

        let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

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

        if self.fenced_coordinator.is_some() {
            return Err(fenced_public_mutation_unavailable());
        }

        let resources: Vec<LockResource> =
            unlock_request.resources.iter().map(Into::into).collect();

        let execution = setup_execution(module_path!(), correlation_id.clone(), user_id.clone());

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

                if self.fenced_coordinator.is_some() {
                    return Err(fenced_public_mutation_unavailable());
                }

                self.lock_as_user(repository, resources, &owner, &correlation_id)
                    .await
                    .map(|locks| Response::new(AdminLockResponse { locks }))
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

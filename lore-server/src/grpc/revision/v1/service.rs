// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use lore_proto::lore::revision::v1::BranchCreateRequest;
use lore_proto::lore::revision::v1::BranchCreateResponse;
use lore_proto::lore::revision::v1::BranchDeleteRequest;
use lore_proto::lore::revision::v1::BranchDeleteResponse;
use lore_proto::lore::revision::v1::BranchGetRequest;
use lore_proto::lore::revision::v1::BranchGetResponse;
use lore_proto::lore::revision::v1::BranchListRequest;
use lore_proto::lore::revision::v1::BranchListResponse;
use lore_proto::lore::revision::v1::BranchMetadataGetRequest;
use lore_proto::lore::revision::v1::BranchMetadataGetResponse;
use lore_proto::lore::revision::v1::BranchMetadataSetRequest;
use lore_proto::lore::revision::v1::BranchMetadataSetResponse;
use lore_proto::lore::revision::v1::BranchPushRequest;
use lore_proto::lore::revision::v1::BranchPushResponse;
use lore_proto::lore::revision::v1::RevisionListRequest;
use lore_proto::lore::revision::v1::RevisionListResponse;
use lore_proto::lore::revision::v1::revision_service_server::RevisionService;
use lore_revision::notification::NotificationSender;
use lore_telemetry::InstrumentProvider;
use opentelemetry::metrics::Histogram;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::codegen::tokio_stream::Stream;

use super::branch_create;
use super::branch_delete;
use super::branch_get;
use super::branch_list;
use super::branch_metadata_get;
use super::branch_metadata_set;
use super::branch_push;
use super::revision_list;
use crate::grpc::get_repository;
use crate::grpc::require_permission;
use crate::grpc::timeout_grpc;
use crate::hooks::HookDispatcher;

type BranchListStream =
    Pin<Box<dyn Stream<Item = Result<BranchListResponse, Status>> + Send + 'static>>;

#[derive(Clone)]
pub struct RevisionListInstruments {
    pub resolve_start_duration: Histogram<f64>,
    pub relative_age_seconds: Histogram<u64>,
    pub walk_duration: Histogram<f64>,
}

/// Zero-sized `InstrumentProvider` carrying the v1 service's metric
/// namespace. Standalone so the constructor can mint histograms before
/// `LoreRevisionV1Service` exists.
#[derive(Clone)]
struct RevisionServiceInstrumentProvider;

impl InstrumentProvider for RevisionServiceInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "lore.revision.v1.revision_service"
    }
}

/// Dispatch struct for `lore.revision.v1.RevisionService`. Placeholder
/// methods are replaced one by one with real handlers backed by
/// `lore-revision` and `lore-storage` primitives.
#[derive(Clone)]
pub struct LoreRevisionV1Service {
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    notification: Arc<dyn NotificationSender>,
    hook_dispatcher: Arc<HookDispatcher>,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
    rpc_timeout: Duration,
    enforce_write_permission: bool,
    instrument_provider: RevisionServiceInstrumentProvider,
    revision_list_instruments: RevisionListInstruments,
}

impl LoreRevisionV1Service {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
        notification: Arc<dyn NotificationSender>,
        hook_dispatcher: Arc<HookDispatcher>,
        history_step_size: u64,
        acceleration: crate::grpc::server::RevisionListAcceleration,
        rpc_timeout: Duration,
        enforce_write_permission: bool,
    ) -> Self {
        let instrument_provider = RevisionServiceInstrumentProvider;
        let seconds_in_one_day = 86400f64;
        let revision_list_instruments = RevisionListInstruments {
            resolve_start_duration: instrument_provider
                .latency_histogram_ms("revision_list.resolve_start.duration"),
            relative_age_seconds: instrument_provider.length_histogram(
                "revision_list.resolve_start.relative_age_seconds",
                vec![
                    seconds_in_one_day / 24f64,
                    seconds_in_one_day / 2f64,
                    seconds_in_one_day,
                    seconds_in_one_day * 3f64,
                    seconds_in_one_day * 7f64,
                    seconds_in_one_day * 14f64,
                    seconds_in_one_day * 30f64,
                    seconds_in_one_day * 60f64,
                    seconds_in_one_day * 180f64,
                ],
            ),
            walk_duration: instrument_provider.latency_histogram_ms("revision_list.walk.duration"),
        };
        Self {
            immutable_store,
            mutable_store,
            notification,
            hook_dispatcher,
            history_step_size,
            acceleration,
            rpc_timeout,
            enforce_write_permission,
            instrument_provider,
            revision_list_instruments,
        }
    }

    pub fn immutable_store(&self) -> &Arc<dyn lore_storage::ImmutableStore> {
        &self.immutable_store
    }

    pub fn mutable_store(&self) -> &Arc<dyn lore_storage::MutableStore> {
        &self.mutable_store
    }

    pub fn notification(&self) -> &Arc<dyn NotificationSender> {
        &self.notification
    }

    pub fn hook_dispatcher(&self) -> &Arc<HookDispatcher> {
        &self.hook_dispatcher
    }

    pub fn history_step_size(&self) -> u64 {
        self.history_step_size
    }
}

#[tonic::async_trait]
impl RevisionService for LoreRevisionV1Service {
    async fn branch_create(
        &self,
        request: Request<BranchCreateRequest>,
    ) -> Result<Response<BranchCreateResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission,
        )?;
        timeout_grpc(
            self.rpc_timeout,
            branch_create::handler(
                request,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                self.notification.clone(),
                &self.hook_dispatcher,
                &self.instrument_provider,
            ),
        )
        .await
    }

    async fn branch_delete(
        &self,
        request: Request<BranchDeleteRequest>,
    ) -> Result<Response<BranchDeleteResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission,
        )?;
        timeout_grpc(
            self.rpc_timeout,
            branch_delete::handler(
                request,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                self.notification.clone(),
                &self.hook_dispatcher,
                &self.instrument_provider,
            ),
        )
        .await
    }

    async fn branch_get(
        &self,
        request: Request<BranchGetRequest>,
    ) -> Result<Response<BranchGetResponse>, Status> {
        timeout_grpc(
            self.rpc_timeout,
            branch_get::handler(
                request,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
            ),
        )
        .await
    }

    type BranchListStream = BranchListStream;

    async fn branch_list(
        &self,
        request: Request<BranchListRequest>,
    ) -> Result<Response<Self::BranchListStream>, Status> {
        branch_list::handler(
            request,
            self.immutable_store.clone(),
            self.mutable_store.clone(),
        )
        .await
    }

    async fn branch_push(
        &self,
        request: Request<BranchPushRequest>,
    ) -> Result<Response<BranchPushResponse>, Status> {
        let repository = get_repository(request.metadata())?;
        require_permission(
            request.extensions(),
            repository,
            "write",
            self.enforce_write_permission,
        )?;
        timeout_grpc(
            self.rpc_timeout,
            branch_push::handler(
                request,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                self.notification.clone(),
                &self.hook_dispatcher,
                self.history_step_size,
                self.acceleration,
                &self.instrument_provider,
            ),
        )
        .await
    }

    async fn branch_metadata_get(
        &self,
        request: Request<BranchMetadataGetRequest>,
    ) -> Result<Response<BranchMetadataGetResponse>, Status> {
        timeout_grpc(
            self.rpc_timeout,
            branch_metadata_get::handler(
                request,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
            ),
        )
        .await
    }

    async fn branch_metadata_set(
        &self,
        request: Request<BranchMetadataSetRequest>,
    ) -> Result<Response<BranchMetadataSetResponse>, Status> {
        timeout_grpc(
            self.rpc_timeout,
            branch_metadata_set::handler(
                request,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                self.enforce_write_permission,
            ),
        )
        .await
    }

    async fn revision_list(
        &self,
        request: Request<RevisionListRequest>,
    ) -> Result<Response<RevisionListResponse>, Status> {
        timeout_grpc(
            self.rpc_timeout,
            revision_list::handler(
                request,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                self.history_step_size,
                self.acceleration,
                &self.revision_list_instruments,
            ),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Hash;
    use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
    use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_transport::grpc::REPOSITORY_ID_KEY;
    use rand::random;
    use tonic::Code;

    use super::*;
    use crate::auth::jwt::AuthorizationToken;
    use crate::auth::jwt::ResourcePermission;
    use crate::notification::testing::MockNotificationSender;
    use crate::store::test_store_create;

    /// Compile-time check that `LoreRevisionV1Service` fully implements
    /// the generated `RevisionService` trait — wrapping it in
    /// `RevisionServiceServer` requires the trait bound to hold.
    #[allow(dead_code)]
    fn assert_implements_trait(
        service: LoreRevisionV1Service,
    ) -> RevisionServiceServer<LoreRevisionV1Service> {
        RevisionServiceServer::new(service)
    }

    fn service_with(
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
        enforce: bool,
    ) -> LoreRevisionV1Service {
        LoreRevisionV1Service::new(
            immutable_store,
            mutable_store,
            Arc::new(MockNotificationSender::new()),
            Arc::new(HookDispatcher::empty()),
            DEFAULT_HISTORY_STEP_SIZE,
            crate::grpc::server::RevisionListAcceleration::default(),
            Duration::from_secs(60),
            enforce,
        )
    }

    /// Insert an `AuthorizationToken` carrying a single `urc-<repo>`
    /// resource with `perms`, optionally flagged as a service account.
    fn insert_token<T>(
        request: &mut Request<T>,
        repository: RepositoryId,
        perms: &[&str],
        service_account: bool,
    ) {
        request.extensions_mut().insert(AuthorizationToken {
            user_id: "test-user".into(),
            is_service_account: Some(service_account),
            resources: Some(vec![ResourcePermission {
                resource_id: format!("urc-{repository}"),
                permission: perms.iter().map(|p| p.to_string()).collect(),
            }]),
            ..Default::default()
        });
    }

    fn push_request(
        repository: RepositoryId,
        perms: &[&str],
        service_account: bool,
    ) -> Request<BranchPushRequest> {
        let mut request = Request::new(BranchPushRequest {
            id: BranchId::from(uuid::Uuid::now_v7()).into(),
            revision_signature: Hash::from([1u8; 32].as_slice()).into(),
            force: false,
            fast_forward_merge: false,
        });
        request.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );
        insert_token(&mut request, repository, perms, service_account);
        request
    }

    #[tokio::test]
    async fn read_only_token_push_is_denied() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("stores");
        let service = service_with(immutable_store, mutable_store, true);

        let err = service
            .branch_push(push_request(repository, &["read"], false))
            .await
            .expect_err("read-only push must be denied");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn write_token_push_passes_permission_check() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("stores");
        let service = service_with(immutable_store, mutable_store, true);

        // A write token clears the gate; the push then fails downstream
        // because the branch doesn't exist — proving the check passed.
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let err = service
                .branch_push(push_request(repository, &["read", "write"], false))
                .await
                .expect_err("non-existent branch should be NotFound");
            assert_eq!(err.code(), Code::NotFound);
        }))
        .await;
    }

    #[tokio::test]
    async fn enforcement_disabled_allows_read_only_push() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("stores");
        let service = service_with(immutable_store, mutable_store, false);

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let err = service
                .branch_push(push_request(repository, &["read"], false))
                .await
                .expect_err("non-existent branch should be NotFound");
            // Not PermissionDenied — the flag is off.
            assert_eq!(err.code(), Code::NotFound);
        }))
        .await;
    }

    #[tokio::test]
    async fn read_only_service_account_push_is_denied() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("stores");
        let service = service_with(immutable_store, mutable_store, true);

        // Service accounts are NOT exempt from write enforcement.
        let err = service
            .branch_push(push_request(repository, &["read"], true))
            .await
            .expect_err("read-only service account must not write");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    /// Every unary write RPC on the v1 revision service must reject a
    /// read-only token, so a newly added write RPC can't silently bypass.
    #[tokio::test]
    async fn all_write_rpcs_reject_read_only_token() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("stores");
        let service = service_with(immutable_store, mutable_store, true);

        // branch_push
        let err = service
            .branch_push(push_request(repository, &["read"], false))
            .await
            .expect_err("push denied");
        assert_eq!(err.code(), Code::PermissionDenied, "branch_push");

        // branch_create
        let mut create = Request::new(BranchCreateRequest {
            id: BranchId::from(uuid::Uuid::now_v7()).into(),
            name: "main".into(),
            creator: Some("alice".into()),
            category: "default".into(),
            stack: vec![],
        });
        create.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );
        insert_token(&mut create, repository, &["read"], false);
        let err = service
            .branch_create(create)
            .await
            .expect_err("create denied");
        assert_eq!(err.code(), Code::PermissionDenied, "branch_create");

        // branch_delete
        let mut delete = Request::new(BranchDeleteRequest {
            id: BranchId::from(uuid::Uuid::now_v7()).into(),
        });
        delete.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );
        insert_token(&mut delete, repository, &["read"], false);
        let err = service
            .branch_delete(delete)
            .await
            .expect_err("delete denied");
        assert_eq!(err.code(), Code::PermissionDenied, "branch_delete");
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use lore_revision::environment::EnvironmentConfig;
use lore_telemetry::InstrumentProvider;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use super::handlers::repository_create;
use super::handlers::repository_delete;
use super::handlers::repository_list;
use super::handlers::repository_metadata_get;
use super::handlers::repository_metadata_set;
use super::handlers::repository_query;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::authnz::repository_catalog::RepositoryCatalog;
use crate::domain::DomainContext;
use crate::grpc::timeout_grpc;
use crate::hooks::HookDispatcher;
use crate::legacy::rpc::repository_service_server::RepositoryService;

#[derive(Clone)]
pub struct LoreRepositoryService {
    environment: EnvironmentConfig,
    authorizer: Arc<dyn RepositoryAuthorizer>,
    repository_catalog: Arc<dyn RepositoryCatalog>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    hook_dispatcher: Arc<HookDispatcher>,
    rpc_timeout: Duration,
    /// FORK-LOCAL (Tideshift, CR-029): see [`DomainBinding`].
    domain: DomainBinding,
}

/// FORK-LOCAL (Tideshift, CR-029): whether this cell's domain coordinator was
/// attached. Upstream's `new` cannot take it without going over the argument
/// limit, so [`LoreRepositoryService::with_domain_context`] attaches it. A
/// service built with `new` alone is `Unbound`, and the handlers that route
/// through the coordinator refuse with `Internal` rather than silently taking
/// the legacy path, which a governed cell must not take.
#[derive(Clone)]
enum DomainBinding {
    Unbound,
    /// `None` is the legacy path (a cell with no coordinator), not an error.
    Bound(Option<Arc<DomainContext>>),
}

impl InstrumentProvider for LoreRepositoryService {
    fn namespace(&self) -> &'static str {
        "urc.repository_service"
    }
}

impl LoreRepositoryService {
    pub fn new(
        environment: EnvironmentConfig,
        authorizer: Arc<dyn RepositoryAuthorizer>,
        repository_catalog: Arc<dyn RepositoryCatalog>,
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
        hook_dispatcher: Arc<HookDispatcher>,
        rpc_timeout: Duration,
    ) -> Self {
        Self {
            environment,
            authorizer,
            repository_catalog,
            immutable_store,
            mutable_store,
            hook_dispatcher,
            rpc_timeout,
            domain: DomainBinding::Unbound,
        }
    }

    /// FORK-LOCAL (Tideshift, CR-029): attaches the cell's domain coordinator,
    /// `None` for a cell without one. Required: see [`DomainBinding`].
    #[must_use]
    pub fn with_domain_context(mut self, domain_context: Option<Arc<DomainContext>>) -> Self {
        self.domain = DomainBinding::Bound(domain_context);
        self
    }

    fn domain_context(&self) -> Result<Option<&Arc<DomainContext>>, Status> {
        match &self.domain {
            DomainBinding::Bound(domain_context) => Ok(domain_context.as_ref()),
            DomainBinding::Unbound => {
                tracing::error!("repository service built without with_domain_context");
                Err(Status::internal(
                    "repository service was built without a domain binding",
                ))
            }
        }
    }
}

#[tonic::async_trait]
impl RepositoryService for LoreRepositoryService {
    async fn repository_create(
        &self,
        request: Request<lore_proto::RepositoryCreateRequest>,
    ) -> Result<Response<lore_proto::RepositoryCreateResponse>, Status> {
        let domain_context = self.domain_context()?;
        timeout_grpc(
            self.rpc_timeout,
            repository_create::handler(
                request,
                self.environment
                    .endpoint
                    .as_ref()
                    .and_then(|endpoint| endpoint.auth_url.clone()),
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                &self.hook_dispatcher,
                self,
                domain_context,
            ),
        )
        .await
    }

    async fn repository_delete(
        &self,
        request: Request<lore_proto::RepositoryDeleteRequest>,
    ) -> Result<Response<lore_proto::RepositoryDeleteResponse>, Status> {
        let domain_context = self.domain_context()?;
        timeout_grpc(
            self.rpc_timeout,
            repository_delete::handler(
                request,
                self.environment
                    .endpoint
                    .as_ref()
                    .and_then(|endpoint| endpoint.auth_url.clone()),
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                self,
                domain_context,
            ),
        )
        .await
    }

    async fn repository_query(
        &self,
        request: Request<lore_proto::RepositoryQueryRequest>,
    ) -> Result<Response<lore_proto::RepositoryQueryResponse>, Status> {
        timeout_grpc(
            self.rpc_timeout,
            repository_query::handler(
                request,
                self.authorizer.clone(),
                self.immutable_store.clone(),
                self.mutable_store.clone(),
            ),
        )
        .await
    }

    async fn repository_list(
        &self,
        request: Request<lore_proto::RepositoryListRequest>,
    ) -> Result<Response<lore_proto::RepositoryListResponse>, Status> {
        timeout_grpc(
            self.rpc_timeout,
            repository_list::handler(
                request,
                self.repository_catalog.clone(),
                self.rpc_timeout,
                self.immutable_store.clone(),
                self.mutable_store.clone(),
            ),
        )
        .await
    }

    async fn repository_metadata_get(
        &self,
        request: Request<lore_proto::RepositoryMetadataGetRequest>,
    ) -> Result<Response<lore_proto::RepositoryMetadataGetResponse>, Status> {
        timeout_grpc(
            self.rpc_timeout,
            repository_metadata_get::handler(
                request,
                self.authorizer.clone(),
                self.immutable_store.clone(),
                self.mutable_store.clone(),
            ),
        )
        .await
    }

    async fn repository_metadata_set(
        &self,
        request: Request<lore_proto::RepositoryMetadataSetRequest>,
    ) -> Result<Response<lore_proto::RepositoryMetadataSetResponse>, Status> {
        let domain_context = self.domain_context()?;
        timeout_grpc(
            self.rpc_timeout,
            repository_metadata_set::handler(
                request,
                self.authorizer.clone(),
                self.immutable_store.clone(),
                self.mutable_store.clone(),
                domain_context,
            ),
        )
        .await
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, CR-029): the repository service's domain binding.
use std::sync::Arc;
use std::time::Duration;

use lore_base::runtime::LORE_CONTEXT;
use lore_revision::environment::EnvironmentConfig;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_catalog::repository_catalog;
use lore_server::grpc::repository_service::LoreRepositoryService;
use lore_server::hooks::HookDispatcher;
use lore_server::legacy::rpc::repository_service_server::RepositoryService;
use tonic::Code;
use tonic::Request;

use crate::store::test_support::test_store_create;

const UNBOUND: &str = "built without a domain binding";

async fn service() -> (
    LoreRepositoryService,
    Arc<lore_revision::interface::ExecutionContext>,
) {
    let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
    let catalog = repository_catalog(None, None, immutable.clone(), mutable.clone())
        .expect("baseline catalog");
    let service = LoreRepositoryService::new(
        EnvironmentConfig::default(),
        Arc::new(AllowAllRepositoryAuthorizer),
        catalog,
        immutable,
        mutable,
        Arc::new(HookDispatcher::empty()),
        Duration::from_secs(60),
    );
    (service, execution)
}

/// A service built without `with_domain_context` must not fall back to the
/// legacy path: a governed cell that forgot the call would bypass its
/// coordinator. Every handler that takes the coordinator refuses instead.
#[tokio::test]
async fn an_unbound_service_refuses_every_coordinated_call() {
    let (service, execution) = service().await;

    LORE_CONTEXT
        .scope(execution, async move {
            let create = service
                .repository_create(Request::new(Default::default()))
                .await
                .expect_err("create must refuse");
            let delete = service
                .repository_delete(Request::new(Default::default()))
                .await
                .expect_err("delete must refuse");
            let metadata_set = service
                .repository_metadata_set(Request::new(Default::default()))
                .await
                .expect_err("metadata set must refuse");

            for status in [create, delete, metadata_set] {
                assert_eq!(status.code(), Code::Internal, "{status:?}");
                assert!(status.message().contains(UNBOUND), "{status:?}");
            }
        })
        .await;
}

/// The positive control: a bound service, even one bound to no coordinator,
/// reaches the handler, so the refusal above is the binding and nothing else.
#[tokio::test]
async fn a_service_bound_to_no_coordinator_reaches_the_handler() {
    let (service, execution) = service().await;
    let service = service.with_domain_context(None);

    LORE_CONTEXT
        .scope(execution, async move {
            let delete = service
                .repository_delete(Request::new(Default::default()))
                .await;
            if let Err(status) = delete {
                assert!(!status.message().contains(UNBOUND), "{status:?}");
            }
        })
        .await;
}

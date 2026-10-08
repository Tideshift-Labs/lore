// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, CR-029): the gRPC server builder binds the v0
//! repository service to the cell's domain context. A service built without
//! `with_domain_context` refuses every coordinated call with `Internal`, so a
//! builder that dropped the call would break every repository create, delete
//! and metadata set on a running server. This drives the real builder and a
//! real client, so it fails if the builder stops binding the service.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use lore_revision::environment::EnvironmentConfig;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
use lore_server::grpc::server::FeatureSettings;
use lore_server::grpc::server::GrpcServerBuilder;
use lore_server::grpc::server::GrpcTimeouts;
use lore_server::hooks::HookDispatcher;
use lore_server::legacy::rpc::repository_service_client::RepositoryServiceClient;
use lore_server::settings::BaselineAccess;

use crate::store::test_support::test_store_create;

const UNBOUND: &str = "built without a domain binding";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_builder_binds_the_v0_repository_service_to_the_domain_context() {
    let (immutable, mutable, _execution) = test_store_create().await.expect("test stores");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
        Arc::new(lore_server::notification::local::NotificationSender::default());
    let repository_catalog = Arc::new(BaselineRepositoryCatalog::new(
        BaselineAccess::Reachable,
        immutable.clone(),
        mutable.clone(),
    ));
    let server = GrpcServerBuilder::new()
        .with_environment(EnvironmentConfig::default())
        .with_feature(FeatureSettings::default())
        .with_immutable_store(immutable.clone(), immutable)
        .with_mutable_store(mutable)
        .with_lock_store(None)
        .with_domain_context(None)
        .with_notification(notification_sender, None)
        .with_hook_dispatcher(Arc::new(HookDispatcher::empty()))
        .with_tls_config(None, None, None)
        .unwrap()
        .with_admin_endpoints(HashMap::new(), vec![])
        .with_http2_config(
            None,
            None,
            GrpcTimeouts {
                request_handler: Duration::from_secs(30),
                authorization: Duration::from_secs(30),
            },
            Default::default(),
            Default::default(),
            None,
        )
        .with_jwt_verifier(
            None,
            false,
            Arc::new(AllowAllRepositoryAuthorizer),
            repository_catalog,
        )
        .unwrap();
    let serving = lore_base::lore_spawn!(async move {
        server
            .serve_with_listener(listener, async {
                shutdown_rx.await.ok();
            })
            .await
    });

    let mut client = None;
    for _ in 0..100 {
        if let Ok(connected) = RepositoryServiceClient::connect(format!("http://{addr}")).await {
            client = Some(connected);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut client = client.expect("the test gRPC server must accept a connection");

    // A default request names no repository, so the handler answers it however
    // it answers that; what matters is that the binding let it reach the handler.
    if let Err(status) = client
        .repository_delete(lore_proto::RepositoryDeleteRequest::default())
        .await
    {
        assert!(
            !status.message().contains(UNBOUND),
            "the builder must bind the v0 repository service: {status:?}"
        );
    }

    let _ = shutdown_tx.send(());
    let _ = serving.await;
}

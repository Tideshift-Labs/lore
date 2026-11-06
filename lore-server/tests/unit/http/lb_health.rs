// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;

use axum::Router;
use axum::http::StatusCode;
use axum::routing;
use axum_test::TestServer;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::drain::DrainState;
use lore_server::http::lb_health;
use lore_server::http::server::LoreHttpServerSettings;
use lore_server::http::server::ServerHealth;
use lore_server::http::server::ServerState;
use lore_server::http::server::create_router;

use crate::store::test_support::test_store_create;

fn health_with(drain: Option<Arc<DrainState>>) -> Arc<ServerHealth> {
    Arc::new(ServerHealth {
        immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
        available: AtomicBool::new(true),
        interval_timeout: None,
        store_health_check: false,
        drain,
        write_behind: None,
        event_relay: None,
        fragment_prune: None,
        cell_retention: None,
    })
}

fn lb_server(health: Arc<ServerHealth>) -> TestServer {
    let app = Router::new().route(
        "/lb_health",
        routing::get(lb_health::handler).with_state(health),
    );
    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn plain_server_is_ok() {
    let response = lb_server(health_with(None)).get("/lb_health").await;

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.text(), "ok");
}

#[tokio::test]
async fn response_is_never_cached() {
    let response = lb_server(health_with(None)).get("/lb_health").await;
    assert_eq!(response.header("cache-control"), "no-store");

    let drain = DrainState::new();
    drain.begin_drain();
    let response = lb_server(health_with(Some(drain))).get("/lb_health").await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.header("cache-control"), "no-store");
}

#[tokio::test]
async fn draining_is_unavailable() {
    let drain = DrainState::new();
    drain.begin_drain();

    let response = lb_server(health_with(Some(drain))).get("/lb_health").await;

    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.text(), "draining");
}

#[tokio::test]
async fn lame_duck_is_unavailable() {
    let drain = DrainState::new();
    drain.begin_lame_duck();

    let response = lb_server(health_with(Some(drain))).get("/lb_health").await;

    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.text(), "lame_duck");
}

#[tokio::test]
async fn drain_state_present_but_not_draining_is_ok() {
    let response = lb_server(health_with(Some(DrainState::new())))
        .get("/lb_health")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.text(), "ok");
}

#[tokio::test]
async fn verdict_matches_the_handler_reasons() {
    assert_eq!(
        lb_health::verdict(&health_with(None)),
        (StatusCode::OK, "ok")
    );
    let drain = DrainState::new();
    drain.begin_drain();
    assert_eq!(
        lb_health::verdict(&health_with(Some(drain))),
        (StatusCode::SERVICE_UNAVAILABLE, "draining")
    );
    let drain = DrainState::new();
    drain.begin_lame_duck();
    assert_eq!(
        lb_health::verdict(&health_with(Some(drain))),
        (StatusCode::SERVICE_UNAVAILABLE, "lame_duck")
    );
}

#[tokio::test]
async fn unavailable_store_is_still_ok_on_lb_health_but_not_on_health_check() {
    let (immutable_store, mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");

    let test_health = ServerHealth {
        immutable_store: Arc::downgrade(&immutable_store),
        available: AtomicBool::new(false),
        interval_timeout: None,
        store_health_check: true,
        drain: None,
        write_behind: None,
        event_relay: None,
        fragment_prune: None,
        cell_retention: None,
    };
    let test_shared_state = ServerState {
        immutable_store,
        mutable_store,
        jwt_verifier: None,
        repository_authorizer: Arc::new(AllowAllRepositoryAuthorizer),
        max_file_size: 100,
        presign_config: None,
        enforce_write_permission: true,
    };
    let settings = LoreHttpServerSettings {
        store_health_check: true,
        ..Default::default()
    };
    let app = create_router(test_shared_state, test_health, &settings);
    let test_server = TestServer::new(app).unwrap();

    // The store is down: the cell-wide probe says so ...
    let response = test_server.get("/health_check").await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);

    // ... but the load-balancer probe must not eject this replica for it.
    let response = test_server.get("/lb_health").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.text(), "ok");
}

#[test]
fn a_write_behind_fault_reaches_the_verdict() {
    for fault in ["worker_stopped", "root_unavailable"] {
        assert_eq!(
            lb_health::verdict_from(None, Some(fault)),
            (StatusCode::SERVICE_UNAVAILABLE, fault)
        );
    }
    assert_eq!(lb_health::verdict_from(None, None), (StatusCode::OK, "ok"));
    let idle = DrainState::new();
    assert_eq!(
        lb_health::verdict_from(Some(&idle), Some("worker_stopped")),
        (StatusCode::SERVICE_UNAVAILABLE, "worker_stopped")
    );
}

#[test]
fn drain_reasons_outrank_a_write_behind_fault() {
    let lame_duck = DrainState::new();
    lame_duck.begin_lame_duck();
    assert_eq!(
        lb_health::verdict_from(Some(&lame_duck), Some("worker_stopped")),
        (StatusCode::SERVICE_UNAVAILABLE, "lame_duck")
    );

    let draining = DrainState::new();
    draining.begin_drain();
    assert_eq!(
        lb_health::verdict_from(Some(&draining), Some("root_unavailable")),
        (StatusCode::SERVICE_UNAVAILABLE, "draining")
    );
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;

use axum::routing;
use axum_test::TestServer;
use serde_json::Value;

use crate::drain::DrainState;
use crate::drain::QuinnConnectionRegistry;
use crate::http::server::ServerHealth;

fn app(drain: Option<Arc<DrainState>>) -> TestServer {
    let health = Arc::new(ServerHealth {
        immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
        available: AtomicBool::new(true),
        interval_timeout: None,
        store_health_check: false,
        drain,
        write_behind: None,
        event_relay: None,
        fragment_prune: None,
        cell_retention: None,
    });
    TestServer::new(axum::Router::new().route(
        "/drain_status",
        routing::get(super::handler).with_state(health),
    ))
    .unwrap()
}

#[tokio::test]
async fn drain_status_reports_rpc_count_separately_from_quic_and_keeps_http_available() {
    let state = DrainState::new();
    let registry = QuinnConnectionRegistry::new("public");
    state.add_registry(registry.clone());
    let handshake = registry.begin_handshake();
    let rpc = state.begin_rpc();
    let server = state.register_public_grpc();
    state.begin_drain();
    let app = app(Some(state.clone()));
    let response = app.get("/drain_status").await;
    assert_eq!(response.status_code(), http::StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["active_connections"], 1);
    assert_eq!(body["active_rpc_requests"], 1);
    assert_eq!(body["draining"], true);
    assert_eq!(body["drained"], false);
    assert_eq!(
        body["endpoints"],
        serde_json::json!([{"name":"public", "active":0}])
    );
    drop(rpc);
    drop(handshake);
    let body: Value = app.get("/drain_status").await.json();
    assert_eq!(body["active_connections"], 0);
    assert_eq!(body["active_rpc_requests"], 0);
    assert_eq!(
        body["drained"], false,
        "zero requests does not prove admission has closed"
    );
    drop(server);
    assert!(state.is_drained());
    let body: Value = app.get("/drain_status").await.json();
    assert_eq!(body["drained"], true);
}

#[tokio::test]
async fn disabled_drain_reports_zero_rpc_requests() {
    let body: Value = app(None).get("/drain_status").await.json();
    assert_eq!(body["active_rpc_requests"], 0);
    assert_eq!(body["active_connections"], 0);
    assert_eq!(body["draining"], false);
    assert_eq!(body["drained"], false);
}

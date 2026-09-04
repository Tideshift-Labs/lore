// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Unauthenticated drain-status endpoint (`/drain_status`).
//!
//! A deploy controller polls this during a graceful drain to know when the
//! node is empty and safe to stop: `draining` flips true on the shutdown
//! signal (when `[server] graceful_drain = true`) and `active_connections`
//! counts the established QUIC connections still being served.
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::http::server::ServerHealth;

#[derive(Serialize)]
pub struct DrainStatusResponse {
    pub draining: bool,
    pub active_connections: u64,
    pub endpoints: Vec<DrainEndpointStatus>,
}

#[derive(Serialize)]
pub struct DrainEndpointStatus {
    pub name: String,
    pub active: u64,
}

pub async fn handler(State(state): State<Arc<ServerHealth>>) -> impl IntoResponse {
    let response = match state.drain.as_ref() {
        Some(drain) => DrainStatusResponse {
            draining: drain.is_draining(),
            active_connections: drain.total_active(),
            endpoints: drain
                .endpoint_counts()
                .into_iter()
                .map(|(name, active)| DrainEndpointStatus { name, active })
                .collect(),
        },
        None => DrainStatusResponse {
            draining: false,
            active_connections: 0,
            endpoints: Vec::new(),
        },
    };
    Json(response)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Weak;
    use std::sync::atomic::AtomicBool;

    use axum::http::StatusCode;
    use axum::routing;
    use axum_test::TestServer;
    use serde_json::Value;

    use crate::drain::ConnectionRegistry;
    use crate::drain::DrainState;
    use crate::http::server::ServerHealth;

    fn health_with_drain(drain: Option<Arc<DrainState>>) -> Arc<ServerHealth> {
        Arc::new(ServerHealth {
            immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
            available: AtomicBool::new(true),
            interval_timeout: None,
            store_health_check: false,
            drain,
            event_relay: None,
            fragment_prune: None,
            cell_retention: None,
        })
    }

    fn app(health: Arc<ServerHealth>) -> TestServer {
        let router = axum::Router::new().route(
            "/drain_status",
            routing::get(super::handler).with_state(health),
        );
        TestServer::new(router).unwrap()
    }

    #[tokio::test]
    async fn no_drain_state_reports_idle() {
        // graceful_drain disabled entirely (ServerHealth.drain == None): the
        // endpoint must still respond, reporting an idle, non-draining node.
        let test_server = app(health_with_drain(None));

        let response = test_server.get("/drain_status").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: Value = response.json();
        assert_eq!(body["draining"], false);
        assert_eq!(body["active_connections"], 0);
        assert_eq!(body["endpoints"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn idle_drain_state_reports_not_draining() {
        // graceful_drain enabled but no shutdown signal received yet.
        let drain = DrainState::new();
        let public = ConnectionRegistry::<quinn::Connection>::new("public");
        drain.add_registry(public);

        let test_server = app(health_with_drain(Some(drain)));

        let response = test_server.get("/drain_status").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: Value = response.json();
        assert_eq!(body["draining"], false);
        assert_eq!(body["active_connections"], 0);
        assert_eq!(
            body["endpoints"],
            serde_json::json!([{"name": "public", "active": 0}])
        );
    }

    #[tokio::test]
    async fn draining_state_is_reflected_in_the_response() {
        let drain = DrainState::new();
        let public = ConnectionRegistry::<quinn::Connection>::new("public");
        let internal = ConnectionRegistry::<quinn::Connection>::new("internal");
        drain.add_registry(public);
        drain.add_registry(internal);
        drain.begin_drain();

        let test_server = app(health_with_drain(Some(drain)));

        let response = test_server.get("/drain_status").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: Value = response.json();
        assert_eq!(
            body["draining"], true,
            "begin_drain() must flip the draining flag in the response"
        );
        assert_eq!(
            body["endpoints"],
            serde_json::json!([
                {"name": "public", "active": 0},
                {"name": "internal", "active": 0}
            ]),
            "every registered endpoint must be listed by name"
        );
    }

    #[tokio::test]
    async fn drain_status_is_reachable_through_the_full_app_router_without_a_token() {
        // Exercise the real create_router wiring (not the single-route test
        // harness above): /drain_status must sit in the unauthenticated
        // merge, not the /v1 nest that requires a bearer token.
        let (immutable_store, mutable_store, _execution) = crate::store::test_store_create()
            .await
            .expect("Failed to create stores");
        let health = ServerHealth::new_without_availability(immutable_store.clone());
        let shared_state = crate::http::server::ServerState {
            immutable_store,
            mutable_store,
            jwt_verifier: None,
            max_file_size: 100,
            presign_config: None,
        };
        let settings = crate::http::server::LoreHttpServerSettings::default();
        let router = crate::http::server::create_router(shared_state, health, &settings);
        let test_server = TestServer::new(router).unwrap();

        let response = test_server.get("/drain_status").await;

        assert_eq!(response.status_code(), StatusCode::OK);
    }
}

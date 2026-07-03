// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::http::server::ServerHealth;

pub async fn handler(State(state): State<Arc<ServerHealth>>) -> impl IntoResponse {
    // A draining server reports unhealthy so load balancers stop routing new
    // work to it while established connections finish (`/drain_status` keeps
    // reporting the remaining count).
    if let Some(drain) = state.drain.as_ref()
        && drain.is_draining()
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    if state.store_health_check && !state.available.load(Ordering::Relaxed) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Weak;
    use std::sync::atomic::AtomicBool;

    use axum::http::StatusCode;
    use axum::routing;
    use axum_test::TestServer;

    use crate::drain::DrainState;
    use crate::http::server::LoreHttpServerSettings;
    use crate::http::server::ServerHealth;
    use crate::http::server::ServerState;
    use crate::http::server::create_router;
    use crate::store::test_store_create;

    #[tokio::test]
    async fn test_server_is_up_and_listening() {
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("Failed to create stores");

        // Create the server and test the request
        let test_health = ServerHealth::new_without_availability(immutable_store.clone());
        let test_shared_state = ServerState {
            immutable_store,
            mutable_store,
            jwt_verifier: None,
            max_file_size: 100,
            presign_config: None,
        };
        let settings = LoreHttpServerSettings::default();
        let app = create_router(test_shared_state, test_health, &settings);
        let test_server = TestServer::new(app).unwrap();

        let response = test_server.get("/health_check").await;

        assert_eq!(response.status_code(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_unavailable_store_server_is_not_healthy() {
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("Failed to create stores");

        // Create the server and test the request
        let test_health = ServerHealth {
            immutable_store: Arc::downgrade(&immutable_store),
            available: AtomicBool::new(false),
            interval_timeout: None,
            store_health_check: true,
            drain: None,
        };
        let test_shared_state = ServerState {
            immutable_store,
            mutable_store,
            jwt_verifier: None,
            max_file_size: 100,
            presign_config: None,
        };
        let settings = LoreHttpServerSettings {
            store_health_check: true,
            ..Default::default()
        };
        let app = create_router(test_shared_state, test_health, &settings);
        let test_server = TestServer::new(app).unwrap();

        let response = test_server.get("/health_check").await;

        assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_maintenance_mode_health_check_returns_ok() {
        // Simulate maintenance mode: no backing store, store_health_check disabled
        let health = Arc::new(ServerHealth {
            immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
            available: AtomicBool::new(true),
            interval_timeout: None,
            store_health_check: false,
            drain: None,
        });

        let app = axum::Router::new().route(
            "/health_check",
            routing::get(super::handler).with_state(health),
        );
        let test_server = TestServer::new(app).unwrap();

        let response = test_server.get("/health_check").await;

        assert_eq!(response.status_code(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_draining_server_is_not_healthy() {
        // A draining node must report unhealthy even though the store itself
        // is fine, so a load balancer stops sending it new work.
        let drain = DrainState::new();
        drain.begin_drain();

        let health = Arc::new(ServerHealth {
            immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
            available: AtomicBool::new(true),
            interval_timeout: None,
            store_health_check: false,
            drain: Some(drain),
        });

        let app = axum::Router::new().route(
            "/health_check",
            routing::get(super::handler).with_state(health),
        );
        let test_server = TestServer::new(app).unwrap();

        let response = test_server.get("/health_check").await;

        assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_non_draining_server_with_drain_state_is_healthy() {
        // A DrainState is present (graceful_drain enabled) but no drain has
        // been triggered yet — behavior must be unchanged from the
        // drain-disabled case.
        let drain = DrainState::new();

        let health = Arc::new(ServerHealth {
            immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
            available: AtomicBool::new(true),
            interval_timeout: None,
            store_health_check: false,
            drain: Some(drain),
        });

        let app = axum::Router::new().route(
            "/health_check",
            routing::get(super::handler).with_state(health),
        );
        let test_server = TestServer::new(app).unwrap();

        let response = test_server.get("/health_check").await;

        assert_eq!(response.status_code(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_draining_takes_priority_over_unavailable_store() {
        // Both conditions independently return 503, but drain is checked
        // first; assert the combination still yields exactly one 503 rather
        // than, say, a panic from a bad early return.
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("Failed to create stores");
        let drain = DrainState::new();
        drain.begin_drain();

        let test_health = ServerHealth {
            immutable_store: Arc::downgrade(&immutable_store),
            available: AtomicBool::new(false),
            interval_timeout: None,
            store_health_check: true,
            drain: Some(drain),
        };
        let test_shared_state = ServerState {
            immutable_store,
            mutable_store,
            jwt_verifier: None,
            max_file_size: 100,
            presign_config: None,
        };
        let settings = LoreHttpServerSettings {
            store_health_check: true,
            ..Default::default()
        };
        let app = create_router(test_shared_state, test_health, &settings);
        let test_server = TestServer::new(app).unwrap();

        let response = test_server.get("/health_check").await;

        assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

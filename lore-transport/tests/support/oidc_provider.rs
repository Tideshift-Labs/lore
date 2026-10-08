// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

//! A stub OIDC provider for the discovery tests.
//!
//! Lives under `tests/support/` so cargo does not build it as a test target of its own; each
//! test binary pulls it in with `#[path]`.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Router;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// A provider on a loopback port. `respond` gets the issuer URL and the number of the
/// request, counted from zero, and answers every path.
pub struct Provider {
    pub issuer: String,
    pub requests: Arc<AtomicUsize>,
    /// Requests the provider is still answering. A request leaves when its response is sent
    /// or its client disconnects.
    pub in_flight: Arc<AtomicUsize>,
}

/// Counts a request in flight until dropped.
struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    fn enter(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub async fn spawn_provider(
    respond: impl Fn(&str, usize) -> Response + Clone + Send + Sync + 'static,
) -> Provider {
    spawn_gated_provider(watch::channel(true).1, respond).await
}

/// A provider that holds every response until `gate` turns true.
pub async fn spawn_gated_provider(
    gate: watch::Receiver<bool>,
    respond: impl Fn(&str, usize) -> Response + Clone + Send + Sync + 'static,
) -> Provider {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let issuer = format!("http://{}", listener.local_addr().expect("local address"));
    let requests = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let handler = {
        let issuer = issuer.clone();
        let requests = requests.clone();
        let in_flight = in_flight.clone();
        move || {
            let issuer = issuer.clone();
            let request = requests.fetch_add(1, Ordering::SeqCst);
            let respond = respond.clone();
            let mut gate = gate.clone();
            let in_flight = InFlight::enter(&in_flight);
            async move {
                let _in_flight = in_flight;
                gate.wait_for(|open| *open)
                    .await
                    .expect("gate sender alive");
                respond(&issuer, request)
            }
        }
    };
    let app = Router::new().fallback(get(handler));
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve the provider");
    });

    Provider {
        issuer,
        requests,
        in_flight,
    }
}

pub fn document(issuer: &str, endpoint_base: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "token_endpoint": format!("{endpoint_base}/token"),
        "jwks_uri": format!("{endpoint_base}/jwks"),
        "device_authorization_endpoint": format!("{endpoint_base}/device"),
        "revocation_endpoint": format!("{endpoint_base}/revoke"),
        "end_session_endpoint": format!("{endpoint_base}/logout"),
    })
}

pub fn json(value: &serde_json::Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

pub fn conforming(issuer: &str, _request: usize) -> Response {
    json(&document(issuer, issuer))
}

pub async fn wait_until(condition: impl Fn() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub async fn wait_for_requests(provider: &Provider, count: usize) {
    wait_until(
        || provider.requests.load(Ordering::SeqCst) >= count,
        "the provider to see the requests",
    )
    .await;
}

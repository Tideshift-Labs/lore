// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Unauthenticated event-plane readiness endpoint (`/event_readiness`).
//!
//! CR-032 requires storage readiness, relay readiness, and durable-receiver
//! readiness to be **separate** signals, because broker loss must not make
//! reads or unrelated storage unavailable. `/health_check` is the storage and
//! drain signal a load balancer polls to decide whether this node serves
//! traffic at all; putting relay lag into it would take a node out of rotation
//! for a condition that does not affect a single read.
//!
//! So this is its own route, and it is deliberately **always 200**. The facets
//! are in the body. A poller that wants to gate on one reads the field it cares
//! about; nothing here can accidentally become the thing that empties a cell.
//!
//! A cell with no relay configured reports `configured: false` and both facets
//! false. That is the honest answer rather than a vacuous green: "no relay is
//! running" and "the relay is caught up" are different states, and a reader
//! that cannot tell them apart is why this endpoint exists.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::http::server::ServerHealth;

/// The event-plane readiness body.
#[derive(Serialize)]
pub struct EventReadinessResponse {
    /// Whether this loreserver is configured to run a relay at all.
    pub configured: bool,
    /// CR-032's relay facet.
    pub relay_ready: bool,
    /// CR-032's event facet: false while any unresolved terminal row is parked.
    pub event_ready: bool,
    /// Whether the worker loop reports itself alive.
    pub loop_running: bool,
    /// Oldest unpublished row age in seconds at the last observation.
    pub oldest_unpublished_age_seconds: Option<f64>,
    /// Unpublished rows at the last observation (a bounded probe).
    pub pending_count: i64,
    /// Dead letters awaiting an operator disposition.
    pub dead_letter_count: i64,
    /// Age of that observation, in seconds.
    pub observation_age_seconds: Option<f64>,
    /// Whether the observation is too old to decide on.
    pub stale: bool,
    /// Fixed reason string when `relay_ready` is false.
    pub relay_reason: Option<&'static str>,
    /// TODO(WP-119 Step C): the durable-receiver facet. It needs the receiver
    /// membership and checkpoint projection, which Step C owns; reporting a
    /// hard-coded value here would be worse than reporting its absence.
    pub receiver_ready: Option<bool>,
}

impl EventReadinessResponse {
    /// The body for a cell with no relay configured.
    fn unconfigured() -> Self {
        Self {
            configured: false,
            relay_ready: false,
            event_ready: false,
            loop_running: false,
            oldest_unpublished_age_seconds: None,
            pending_count: 0,
            dead_letter_count: 0,
            observation_age_seconds: None,
            stale: false,
            relay_reason: Some(crate::event_relay::readiness::REASON_LOOP_NOT_RUNNING),
            receiver_ready: None,
        }
    }
}

pub async fn handler(State(state): State<Arc<ServerHealth>>) -> impl IntoResponse {
    let response = match state.event_relay.as_ref() {
        None => EventReadinessResponse::unconfigured(),
        Some(readiness) => {
            let snapshot = readiness.snapshot();
            EventReadinessResponse {
                configured: true,
                relay_ready: snapshot.relay_ready,
                event_ready: snapshot.event_ready,
                loop_running: snapshot.loop_running,
                oldest_unpublished_age_seconds: snapshot
                    .oldest_unpublished_age
                    .map(|age| age.as_secs_f64()),
                pending_count: snapshot.pending_count,
                dead_letter_count: snapshot.dead_letter_count,
                observation_age_seconds: snapshot.observation_age.map(|age| age.as_secs_f64()),
                stale: snapshot.stale,
                relay_reason: snapshot.relay_reason,
                receiver_ready: None,
            }
        }
    };
    Json(response)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Weak;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use axum::http::StatusCode;
    use axum::routing;
    use axum_test::TestServer;
    use lore_postgres::domain::outbox::OutboxBacklog;

    use crate::event_relay::readiness::EventRelayReadiness;
    use crate::http::server::ServerHealth;

    fn health(event_relay: Option<Arc<EventRelayReadiness>>) -> Arc<ServerHealth> {
        Arc::new(ServerHealth {
            immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
            available: AtomicBool::new(true),
            interval_timeout: None,
            store_health_check: false,
            drain: None,
            event_relay,
        })
    }

    async fn body(health: Arc<ServerHealth>) -> serde_json::Value {
        let app = axum::Router::new().route(
            "/event_readiness",
            routing::get(super::handler).with_state(health),
        );
        let server = TestServer::new(app).expect("test server");
        let response = server.get("/event_readiness").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        response.json()
    }

    #[tokio::test]
    async fn a_cell_with_no_relay_reports_unconfigured_rather_than_green() {
        let json = body(health(None)).await;
        assert_eq!(json["configured"], false);
        assert_eq!(json["relay_ready"], false);
        assert_eq!(json["event_ready"], false);
    }

    #[tokio::test]
    async fn a_healthy_relay_reports_both_facets_true() {
        let readiness = Arc::new(EventRelayReadiness::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ));
        readiness.set_loop_running(true);
        readiness.record_backlog(&OutboxBacklog {
            pending_count: 1,
            pending_bytes: 8,
            oldest_pending_age: Some(Duration::from_secs(1)),
            claimed_count: 0,
            dead_letter_count: 0,
        });
        let json = body(health(Some(readiness))).await;
        assert_eq!(json["configured"], true);
        assert_eq!(json["relay_ready"], true);
        assert_eq!(json["event_ready"], true);
        assert_eq!(json["pending_count"], 1);
    }

    /// The whole reason this is a separate route: a relay incident must be
    /// reportable without the endpoint itself going unavailable.
    #[tokio::test]
    async fn a_failing_relay_still_answers_two_hundred_with_the_reason_in_the_body() {
        let readiness = Arc::new(EventRelayReadiness::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ));
        readiness.set_loop_running(true);
        readiness.record_backlog(&OutboxBacklog {
            pending_count: 5,
            pending_bytes: 40,
            oldest_pending_age: Some(Duration::from_secs(120)),
            claimed_count: 0,
            dead_letter_count: 2,
        });
        let json = body(health(Some(readiness))).await;
        assert_eq!(json["relay_ready"], false);
        assert_eq!(json["event_ready"], false);
        assert_eq!(json["dead_letter_count"], 2);
        assert_eq!(
            json["relay_reason"],
            crate::event_relay::readiness::REASON_OLDEST_UNPUBLISHED
        );
    }

    /// Step C's facet must read as absent, not as a passing value.
    #[tokio::test]
    async fn the_receiver_facet_is_absent_rather_than_defaulted() {
        let json = body(health(None)).await;
        assert!(json["receiver_ready"].is_null());
    }
}

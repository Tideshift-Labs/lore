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
    /// This process's own durable-receiver facet.
    ///
    /// `None` — absent, not false — when this loreserver runs no receiver,
    /// which is every cell that has not declared `[plugins.remote.receiver]`.
    /// "No receiver is configured here" and "the receiver is behind" are
    /// different states and a reader that cannot tell them apart is why this
    /// endpoint exists.
    pub receiver_ready: Option<bool>,
    /// Fixed reason string when `receiver_ready` is false. `None` when the
    /// receiver is ready or absent.
    pub receiver_reason: Option<&'static str>,
    /// Distance from the receiver's contiguous frontier to the highest
    /// sequence it has seen.
    pub receiver_lag: u64,
    /// The membership generation the receiver is running, once it has one.
    pub receiver_generation: Option<i64>,
    /// Whether this cell runs WP-114 CD-6's terminal write-claim prune
    /// scheduler at all. False on every cell whose governed fragment route is
    /// off, which writes no claims to prune.
    pub prune_configured: bool,
    /// The prune facet: false while the scheduler cannot show the claims table
    /// draining. `None` when no scheduler is configured, so a reader cannot
    /// mistake "not running" for "drained".
    pub prune_ready: Option<bool>,
    /// Fixed reason string when `prune_ready` is false.
    pub prune_reason: Option<&'static str>,
    /// Consecutive prune passes that made no progress.
    pub prune_consecutive_stalls: u32,
    /// Claim rows the last pass removed.
    pub prune_last_pruned: u64,
    /// Candidates the last pass planned.
    pub prune_last_examined: u64,
    /// Terminal rows past retention that no live send barrier is blocking, at
    /// the last pass, bounded by the batch size plus one. This, not
    /// `prune_last_examined`, is what `prune_ready` is decided on: a pass can
    /// plan nothing while rows sit past retention forever. `-1` means the probe
    /// did not run, which is not the same as zero.
    pub prune_last_unblocked_backlog: i64,
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
            receiver_reason: None,
            receiver_lag: 0,
            receiver_generation: None,
            prune_configured: false,
            prune_ready: None,
            prune_reason: None,
            prune_consecutive_stalls: 0,
            prune_last_pruned: 0,
            prune_last_examined: 0,
            prune_last_unblocked_backlog: -1,
        }
    }
}

pub async fn handler(State(state): State<Arc<ServerHealth>>) -> impl IntoResponse {
    let mut response = match state.event_relay.as_ref() {
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
                receiver_ready: snapshot.durable_receiver_ready,
                receiver_reason: snapshot.durable_receiver_reason,
                receiver_lag: snapshot.durable_receiver_lag,
                receiver_generation: snapshot.durable_receiver_generation,
                prune_configured: false,
                prune_ready: None,
                prune_reason: None,
                prune_consecutive_stalls: 0,
                prune_last_pruned: 0,
                prune_last_examined: 0,
                prune_last_unblocked_backlog: -1,
            }
        }
    };
    // The prune facet is independent of the relay: a cell can run the governed
    // fragment route with no relay, or a relay with the legacy fragment route,
    // so it is filled in separately rather than inside either arm.
    if let Some(prune) = state.fragment_prune.as_ref() {
        let snapshot = prune.snapshot();
        response.prune_configured = true;
        response.prune_ready = Some(snapshot.prune_ready);
        response.prune_reason = snapshot.prune_reason;
        response.prune_consecutive_stalls = snapshot.consecutive_stalls;
        response.prune_last_pruned = snapshot.last_pruned;
        response.prune_last_examined = snapshot.last_examined;
        response.prune_last_unblocked_backlog = snapshot.last_unblocked_backlog;
    }
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
            fragment_prune: None,
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

    /// The durable-receiver facet must read as absent, not as a passing value,
    /// on a cell that runs no receiver — with or without a relay.
    #[tokio::test]
    async fn the_receiver_facet_is_absent_rather_than_defaulted() {
        let json = body(health(None)).await;
        assert!(json["receiver_ready"].is_null());

        let readiness = Arc::new(EventRelayReadiness::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ));
        readiness.set_loop_running(true);
        readiness.record_backlog(&OutboxBacklog {
            pending_count: 0,
            pending_bytes: 0,
            oldest_pending_age: None,
            claimed_count: 0,
            dead_letter_count: 0,
        });
        let json = body(health(Some(readiness))).await;
        assert_eq!(json["relay_ready"], true);
        assert!(
            json["receiver_ready"].is_null(),
            "a healthy relay must not imply a receiver this process does not run"
        );
    }

    /// An attached receiver is reported through this surface, with its reason.
    #[tokio::test]
    async fn an_attached_receiver_reports_its_facet_and_reason() {
        let readiness = Arc::new(EventRelayReadiness::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ));
        readiness
            .attach_durable_receiver(Arc::new(
                crate::plugins::remote_notification::ReceiverReadiness::new(),
            ))
            .expect("the first attach must be accepted");
        let json = body(health(Some(readiness))).await;
        assert_eq!(json["receiver_ready"], false);
        assert_eq!(
            json["receiver_reason"],
            crate::plugins::remote_notification::receiver::REASON_NOT_STARTED
        );
    }
}

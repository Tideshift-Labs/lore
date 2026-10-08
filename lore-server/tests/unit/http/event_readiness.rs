// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, CR-032): `/event_readiness` tests, moved out of the
//! inline `http::event_readiness::tests` module.

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing;
use axum_test::TestServer;
use lore_postgres::domain::outbox::OutboxBacklog;
use lore_server::event_relay::readiness::EventRelayReadiness;
use lore_server::http::server::ServerHealth;

fn health(event_relay: Option<Arc<EventRelayReadiness>>) -> Arc<ServerHealth> {
    Arc::new(ServerHealth {
        immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
        available: AtomicBool::new(true),
        interval_timeout: None,
        store_health_check: false,
        drain: None,
        event_relay,
        write_behind: None,
        fragment_prune: None,
        cell_retention: None,
    })
}

async fn body(health: Arc<ServerHealth>) -> serde_json::Value {
    let app = axum::Router::new().route(
        "/event_readiness",
        routing::get(lore_server::http::event_readiness::handler).with_state(health),
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
        lore_server::event_relay::readiness::REASON_OLDEST_UNPUBLISHED
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
            lore_server::plugins::remote_notification::ReceiverReadiness::new(),
        ))
        .expect("the first attach must be accepted");
    let json = body(health(Some(readiness))).await;
    assert_eq!(json["receiver_ready"], false);
    assert_eq!(
        json["receiver_reason"],
        lore_server::plugins::remote_notification::receiver::REASON_NOT_STARTED
    );
}

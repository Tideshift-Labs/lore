// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): unauthenticated load-balancer membership endpoint
//! (`/lb_health`).
//!
//! A cell's network load balancer probes this to decide whether to send this
//! replica NEW connections. It answers 503 only for a condition that belongs
//! to this replica alone:
//!
//! - the replica is draining, or is in its lame-duck period (`DrainState`);
//! - the write-behind worker on this replica has stopped, or this host's own
//!   stage/spool roots are unusable
//!   ([`FragmentWriteBehindReadiness::replica_fault`]).
//!
//! The write-behind fault depends on the replica's `write_behind.role`
//! (WP-115 K6):
//!
//! - `full`: `worker_stopped` or `root_unavailable`, as above.
//! - `stage`: `observer_stopped`. The stage is one shared export, so a
//!   stage-root fault is cell-wide and is not a membership signal here. One
//!   exception (WP-115 K11, `crate::stage_liveness`):
//!   `stage_unavailable_local` when this host's own probe of the stage has
//!   been failing for 15 s while a peer of the same cell can still write it.
//!   With no fresh peer, or no recent peer view, it answers 200.
//! - `drain`: always `drain_role`. The dedicated drain worker is not a
//!   load-balancer member, and a 503 keeps a misconfigured pool from adding it.
//!
//! It deliberately ignores every cell-wide signal: store availability, the
//! write-behind readiness verdict (`drain_not_progressing`, `worker_stale`,
//! `cleanup_stale`, `capacity_unavailable`, backpressure), and the event-plane
//! facets. Every replica of a cell reads those from the same Postgres and
//! object store, so on a load balancer they eject the replicas one after
//! another and refuse the whole cell. They stay on `/health_check` and
//! `/event_readiness`, and they still reach clients as typed `SlowDown`.
//!
//! One per-host input is ignored on purpose: `capacity_unavailable` includes
//! this host's free-space check (`free_space_below_minimum`, from the local
//! spool volume). Replicas take the same load, so their disks fill together,
//! and ejecting one only moves its load onto the others. Free space stays a
//! per-operation `Refuse` and an alert, not a membership signal.
//!
//! The maintenance-mode server does not serve this route, on purpose: a
//! replica in maintenance cannot serve repositories, so the probe's 404 takes
//! it out of the pool (its `/health_check` still answers 200 for monitoring).
//!
//! When it cannot decide (for example the write-behind observation is stale),
//! it answers 200: an undecided check must not eject. The handler reads only
//! in-memory state, so it does no database or network work.
//!
//! [`FragmentWriteBehindReadiness::replica_fault`]:
//!     crate::fragment_write_behind::FragmentWriteBehindReadiness::replica_fault
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::IntoResponse;

use crate::drain::DrainState;
use crate::http::server::ServerHealth;

/// The load-balancer verdict and the reason word written as the body.
#[lore_macro::test_pub]
fn verdict(state: &ServerHealth) -> (StatusCode, &'static str) {
    verdict_from(
        state.drain.as_deref(),
        state
            .write_behind
            .as_ref()
            .and_then(|facet| facet.replica_fault()),
    )
}

/// [`verdict`] over its inputs, so the fault mapping is testable without a
/// live write-behind facet.
#[lore_macro::test_pub]
fn verdict_from(
    drain: Option<&DrainState>,
    replica_fault: Option<&'static str>,
) -> (StatusCode, &'static str) {
    if let Some(drain) = drain {
        if drain.is_lame_duck() {
            return (StatusCode::SERVICE_UNAVAILABLE, "lame_duck");
        }
        if drain.is_draining() {
            return (StatusCode::SERVICE_UNAVAILABLE, "draining");
        }
    }
    if let Some(fault) = replica_fault {
        return (StatusCode::SERVICE_UNAVAILABLE, fault);
    }
    (StatusCode::OK, "ok")
}

pub async fn handler(State(state): State<Arc<ServerHealth>>) -> impl IntoResponse {
    let (status, reason) = verdict(&state);
    (status, [(header::CACHE_CONTROL, "no-store")], reason)
}

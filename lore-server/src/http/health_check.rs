// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
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
    if state
        .write_behind
        .as_ref()
        .is_some_and(|facet| !facet.snapshot().ready)
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}

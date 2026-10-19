// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Unauthenticated drain-status endpoint (`/drain_status`).
//!
//! A deploy controller polls this during a graceful drain to know when the
//! node is empty and safe to stop: `draining` flips true on the shutdown
//! signal (when `[server] graceful_drain = true` or `lame_duck_seconds > 0`)
//! and `active_connections` counts QUIC connections and pending handshakes.
//! `active_rpc_requests` counts public RPC handlers and response bodies.
//! `lame_duck` is true while the node still admits work after the signal; it
//! is never `drained` then. Only `drained` also confirms that public gRPC
//! serving has ended; a momentary zero count is not that proof.
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::http::server::ServerHealth;

#[derive(Serialize)]
pub struct DrainStatusResponse {
    pub draining: bool,
    pub lame_duck: bool,
    pub drained: bool,
    pub active_connections: u64,
    pub active_rpc_requests: u64,
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
            lame_duck: drain.is_lame_duck(),
            drained: drain.is_drained(),
            active_connections: drain.total_active(),
            active_rpc_requests: drain.active_rpc_requests(),
            endpoints: drain
                .endpoint_counts()
                .into_iter()
                .map(|(name, active)| DrainEndpointStatus { name, active })
                .collect(),
        },
        None => DrainStatusResponse {
            draining: false,
            lame_duck: false,
            drained: false,
            active_connections: 0,
            active_rpc_requests: 0,
            endpoints: Vec::new(),
        },
    };
    Json(response)
}

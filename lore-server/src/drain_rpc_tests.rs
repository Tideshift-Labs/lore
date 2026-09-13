// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;

use futures::FutureExt;

use super::DrainState;
use super::QuinnConnectionRegistry;

#[tokio::test(start_paused = true)]
async fn rpc_only_server_waits_for_rpc_but_quic_shutdown_does_not() {
    let state = DrainState::new();
    let first = state.begin_rpc();
    let second = state.begin_rpc();
    assert_eq!(state.active_rpc_requests(), 2);
    assert_eq!(state.total_active(), 0, "legacy total remains QUIC-only");
    assert!(state.endpoint_counts().is_empty());
    assert!(state.wait_quic_idle().now_or_never().is_some());
    assert!(state.wait_idle().now_or_never().is_none());
    drop(first);
    assert_eq!(state.active_rpc_requests(), 1);
    assert!(state.wait_idle().now_or_never().is_none());
    drop(second);
    tokio::time::timeout(Duration::from_secs(1), state.wait_idle())
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn wait_idle_requires_both_quic_handshake_and_rpc_completion() {
    let state = DrainState::new();
    let registry = QuinnConnectionRegistry::new("public");
    state.add_registry(registry.clone());
    let handshake = registry.begin_handshake();
    let rpc = state.begin_rpc();
    assert_eq!(state.total_active(), 1);
    assert_eq!(state.active_rpc_requests(), 1);
    assert!(state.wait_quic_idle().now_or_never().is_none());
    drop(handshake);
    assert!(state.wait_quic_idle().now_or_never().is_some());
    assert!(state.wait_idle().now_or_never().is_none());
    drop(rpc);
    assert!(state.wait_idle().now_or_never().is_some());
}

#[tokio::test(start_paused = true)]
async fn public_server_registration_keeps_status_alive_without_faking_an_active_rpc() {
    let state = DrainState::new();
    let server = state.register_public_grpc();
    assert_eq!(state.active_rpc_requests(), 0);
    assert_eq!(state.total_active(), 0);
    assert!(state.wait_quic_idle().now_or_never().is_some());
    assert!(state.wait_idle().now_or_never().is_none());
    let rpc = state.begin_rpc();
    drop(server);
    assert!(state.wait_idle().now_or_never().is_none());
    drop(rpc);
    assert!(state.wait_idle().now_or_never().is_some());
}

#[tokio::test]
async fn cancelling_outer_server_handle_keeps_status_alive_until_serving_and_detached_rpc_finish() {
    let state = DrainState::new();
    state.begin_drain();
    let server_guard = state.register_public_grpc();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (served_tx, served_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, mut finished_rx) = tokio::sync::oneshot::channel();
    let handle = lore_base::lore_spawn_net!(async move {
        crate::grpc::server::serve_with_drain_guard(Some(server_guard), async move {
            entered_tx.send(()).unwrap();
            release_rx.await.unwrap();
            served_tx.send(()).unwrap();
        })
        .await;
        finished_tx.send(()).unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    drop(handle);
    assert_eq!(state.active_rpc_requests(), 0);
    assert!(
        !state.is_drained(),
        "outer cancellation cannot drop the net task's registration"
    );
    assert!(state.wait_idle().now_or_never().is_none());
    let rpc = state.begin_rpc();
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), served_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.active_rpc_requests(), 1);
    assert!(
        !state.is_drained(),
        "tonic completion cannot hide a detached handler"
    );
    assert!(state.wait_idle().now_or_never().is_none());
    assert_eq!(
        finished_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    );
    drop(rpc);
    tokio::time::timeout(Duration::from_secs(5), finished_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(state.is_drained());
    assert!(state.wait_idle().now_or_never().is_some());
}

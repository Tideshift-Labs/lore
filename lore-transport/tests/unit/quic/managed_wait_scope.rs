// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124: the managed wait scope crosses a spawn without becoming a managed caller, and bounds a
//! reconnect only, never the total time of a workflow.
//!
//! [CLIENT]-class (`lore-transport`). A session start or a Query batch runs in a spawned task, and
//! task-locals do not cross a spawn, so its reconnect had no managed deadline. `carry_managed_wait_scope`
//! decides in the spawning task and enters only the workflow marker in the spawned one.
//!
//! Every case drives the real `StorageClient` against the scripted peer, with the managed reconnect
//! bound shortened by `set_managed_idle_for_test`.
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_base::types::RepositoryId;
use lore_transport::CallerOperationContext;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::VolatileAttemptStore;
use lore_transport::error::ProtocolError;
use lore_transport::error::is_managed_reconnect_expired;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::client::StorageClient;
use uuid::Uuid;

use super::scripted_storage_peer::Peer;

const BOUND: Duration = Duration::from_secs(2);
const LATE_MARGIN: Duration = Duration::from_secs(7);

fn partition() -> Partition {
    Partition::from([0x25u8; 16])
}

async fn client_with_session(peer: &Peer) -> (Arc<StorageClient>, u32) {
    let client = StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "",
        "managed-wait-scope",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer");
    client.quic().set_managed_idle_for_test(BOUND);
    let session = client
        .session_start_declared(partition(), "wait-scope", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    (Arc::new(client), session)
}

/// Close every connection and the endpoint, and wait until the client's connection is gone.
async fn make_unreachable(peer: &Peer) {
    peer.stop();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;
}

/// A session start on `client`, spawned the way `StorageConnector::session_pool` spawns one, with
/// the scope carried from the spawning task. Returns what the spawned task saw.
fn spawn_carried_start(
    client: &Arc<StorageClient>,
) -> tokio::task::JoinHandle<(bool, Result<(), ProtocolError>)> {
    let client = client.clone();
    lore_base::lore_spawn!(lore_transport::carry_managed_wait_scope(async move {
        let managed_caller = lore_transport::has_managed_caller();
        let result = client
            .session_start_declared(partition(), "spawned", "outcome_unknown_v1")
            .await
            .map(|_| ());
        (managed_caller, result)
    }))
}

fn managed_operation() -> CallerOperationContext {
    CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x25u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    )
}

async fn finish_within_hang_guard(
    handle: tokio::task::JoinHandle<(bool, Result<(), ProtocolError>)>,
) -> (bool, Result<(), ProtocolError>) {
    tokio::time::timeout(BOUND + Duration::from_secs(40), handle)
        .await
        .expect("the spawned start never ended: its reconnect has no managed deadline")
        .expect("the spawned task finished")
}

/// A spawned start from a managed workflow, on a dead path, ends at the bound with the marker, and
/// the spawned task is not a managed caller.
#[tokio::test]
async fn a_spawned_start_in_a_managed_workflow_ends_at_the_bound_and_is_not_a_managed_caller() {
    let peer = Peer::start();
    let (client, _) = client_with_session(&peer).await;
    make_unreachable(&peer).await;

    let started = Instant::now();
    let (managed_caller, result) = lore_transport::with_managed_workflow(async {
        finish_within_hang_guard(spawn_carried_start(&client)).await
    })
    .await;
    let elapsed = started.elapsed();

    assert!(
        !managed_caller,
        "the spawned task must not be a managed caller"
    );
    let error = result.expect_err("an unreachable server ends the start");
    assert!(is_managed_reconnect_expired(&error), "{error:?}");
    assert!(elapsed >= BOUND - Duration::from_millis(500), "{elapsed:?}");
    assert!(elapsed < BOUND + LATE_MARGIN, "{elapsed:?}");
}

/// The same from inside a managed caller (a stage's caller operation).
#[tokio::test]
async fn a_spawned_start_in_a_managed_caller_ends_at_the_bound_and_is_not_a_managed_caller() {
    let peer = Peer::start();
    let (client, _) = client_with_session(&peer).await;
    make_unreachable(&peer).await;

    let started = Instant::now();
    let (managed_caller, result) =
        lore_transport::with_caller_operation(managed_operation(), async {
            assert!(lore_transport::has_managed_caller());
            finish_within_hang_guard(spawn_carried_start(&client)).await
        })
        .await;
    let elapsed = started.elapsed();

    assert!(
        !managed_caller,
        "the spawned task must not be a managed caller"
    );
    let error = result.expect_err("an unreachable server ends the start");
    assert!(is_managed_reconnect_expired(&error), "{error:?}");
    assert!(elapsed < BOUND + LATE_MARGIN, "{elapsed:?}");
}

/// Control: carrying the scope from an UNMANAGED task adds no bound. The same start is still
/// reconnecting well past twice the bound.
#[tokio::test]
async fn a_carried_start_from_an_unmanaged_task_keeps_the_old_unbounded_behaviour() {
    let peer = Peer::start();
    let (client, _) = client_with_session(&peer).await;
    make_unreachable(&peer).await;

    assert!(!lore_transport::in_managed_wait_scope());
    let handle = spawn_carried_start(&client);
    let pending = tokio::time::timeout(BOUND * 2 + Duration::from_secs(1), handle).await;
    assert!(
        pending.is_err(),
        "an unmanaged spawned start must keep reconnecting past the managed bound"
    );
}

/// Control: without the carry, a spawn from a managed workflow loses the scope and is unbounded.
/// This is the defect the carry exists for.
#[tokio::test]
async fn an_uncarried_spawn_from_a_managed_workflow_is_unbounded() {
    let peer = Peer::start();
    let (client, _) = client_with_session(&peer).await;
    make_unreachable(&peer).await;

    let pending = lore_transport::with_managed_workflow(async {
        let handle = lore_base::lore_spawn!(async move {
            client
                .session_start_declared(partition(), "uncarried", "outcome_unknown_v1")
                .await
                .map(|_| ())
        });
        tokio::time::timeout(BOUND * 2 + Duration::from_secs(1), handle).await
    })
    .await;
    assert!(
        pending.is_err(),
        "a spawn that did not carry the scope has no managed deadline"
    );
}

/// No total-time cap. Inside a managed workflow, spawned carried commands keep making progress on a
/// LIVE connection for longer than the bound in total, and none is cut off: the bound is for a
/// reconnect, and none is needed here.
#[tokio::test]
async fn a_managed_workflow_that_keeps_progressing_on_a_live_connection_is_not_cut_off() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;

    let started = Instant::now();
    let mut completed = 0usize;
    lore_transport::with_managed_workflow(async {
        // Each step is a spawned, carried command, as a Query batch is, with a pause between steps
        // so the whole run outlasts the bound several times over.
        while started.elapsed() < BOUND * 3 {
            let client = client.clone();
            let step =
                lore_base::lore_spawn!(lore_transport::carry_managed_wait_scope(async move {
                    let address = Address {
                        hash: Hash::from(rand::random::<[u8; 32]>()),
                        context: Context::from(rand::random::<[u8; 16]>()),
                    };
                    let fragment = Fragment {
                        flags: 0,
                        size_payload: 8,
                        size_content: 8,
                    };
                    client
                        .put_outcome(
                            session,
                            address,
                            fragment,
                            Some(Bytes::from_static(&[7u8; 8])),
                        )
                        .await
                }));
            let outcome = step.await.expect("the step finished");
            let outcome = outcome.expect("a live connection never yields the expiry marker");
            assert!(
                matches!(outcome, lore_transport::replay::MutableOutcome::Applied(())),
                "each step is answered"
            );
            completed += 1;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;

    let elapsed = started.elapsed();
    assert!(
        elapsed > BOUND * 3,
        "the run must outlast the bound several times over: {elapsed:?}"
    );
    assert!(completed >= 6, "completed only {completed} steps");
    assert_eq!(
        peer.accepted_connections(),
        1,
        "no reconnect was needed or made"
    );
}

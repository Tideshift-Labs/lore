// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! A reconnect that is stalled by a LIVE peer still ends at the reconnect deadline.
//!
//! [CLIENT]-class (`lore-transport`). `reconnect_until` raced its handshakes and backoff against
//! the deadline but not two awaits after the connection swap:
//!
//! - **(A) the restart flow**: `create_initial_stream` holds the connection write lock across
//!   `open_bi`, then `reconnect_authorize` writes `ClientIdentify`. A peer that completes the
//!   handshake but grants zero bidirectional streams leaves `open_bi` pending for good, and
//!   keep-alive stops quinn's idle timeout from ending it.
//! - **(B) the reader drain** (second pass): a replacement whose restart flow failed
//!   (`Terminated`/`StreamOpen`) was kept, so the next pass's swap awaited that connection's
//!   readers under the write lock, and a reader ends only when its stream ends.
//!
//! Every case drives the real `StorageClient` against the scripted peer, which stays LIVE and
//! keeps accepting (a dead or black-holed peer is `unmanaged_reconnect_bound.rs`). Every case wraps
//! the command in a hard outer timeout so a missing bound fails red instead of hanging the suite.
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;
use std::time::Instant;

use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::error::ProtocolError;
use lore_transport::error::is_managed_reconnect_expired;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const QUERY: u8 = Command::Query as u8;

/// The shortened reconnect deadline (unmanaged and managed).
const BOUND: Duration = Duration::from_secs(3);

/// The command must be over by the deadline plus this: scheduling margin only, because the stalled
/// awaits are raced by the deadline itself.
const MARGIN: Duration = Duration::from_secs(3);

/// The hard outer guard: a command that outlives it is the defect, reported by name.
const HANG_GUARD: Duration = Duration::from_secs(9);

/// A replacement connection's per-stream credit for the (B) case: smaller than one command header,
/// so the `ClientIdentify` write cannot complete, yet one stream's first frame reaches the peer.
const TINY_WINDOW: u64 = 1;

fn partition() -> Partition {
    Partition::from([0x26u8; 16])
}

fn address() -> Address {
    Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    }
}

async fn connect(peer: &Peer) -> Arc<StorageClient> {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "reconnect-stall",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
        lore_transport::quic::client::CongestionAlgorithm::default(),
    )
    .await
    .expect("connect to the scripted peer")
}

/// A connected client with an open declared session and one `Query` that already succeeded, so
/// the process has really used QUIC to this server. Both bounds are shortened.
async fn used_client(peer: &Peer) -> (Arc<StorageClient>, u32) {
    peer.rule(QUERY, Reply::Ok(vec![0]));
    let client = connect(peer).await;
    client.quic().set_reconnect_timeout_for_test(BOUND);
    client.quic().set_managed_idle_for_test(BOUND);
    let session = client
        .session_start_declared(partition(), "stall", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    client
        .query(session, &[address()])
        .await
        .expect("one Query succeeds while the peer is healthy");
    (client, session)
}

/// Close every connection from the peer's side and wait until the client's is gone. The peer keeps
/// accepting, so the client's reconnect handshakes succeed.
async fn drop_the_path(peer: &Peer) {
    peer.close_connections();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;
}

/// The command ended (a hang is a named failure), with the error `what` describes.
fn ended<T>(
    outcome: Result<Result<T, ProtocolError>, tokio::time::error::Elapsed>,
    elapsed: Duration,
    what: &str,
) -> ProtocolError {
    let result = outcome.unwrap_or_else(|_| {
        panic!("{what}: the command never ended ({elapsed:?}): a reconnect await is not bounded")
    });
    match result {
        Ok(_) => panic!("{what}: the stalled reconnect cannot have succeeded"),
        Err(error) => error,
    }
}

fn assert_within_bound(elapsed: Duration, what: &str) {
    assert!(
        elapsed >= BOUND - Duration::from_millis(500),
        "{what}: gave up before the bound: {elapsed:?}"
    );
    assert!(
        elapsed < BOUND + MARGIN,
        "{what}: outlasted the bound: {elapsed:?}"
    );
}

/// (A), unmanaged: the replacement connection grants zero bidirectional streams, so the restart
/// flow's `open_bi` never returns. The command ends `Disconnected` at the unmanaged bound.
#[tokio::test]
async fn an_unmanaged_command_ends_at_the_bound_when_the_peer_grants_no_streams() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    peer.set_new_connection_limits(0, super::scripted_storage_peer::WINDOW);
    drop_the_path(&peer).await;

    let started = Instant::now();
    let outcome = tokio::time::timeout(HANG_GUARD, client.query(session, &[address()])).await;
    let elapsed = started.elapsed();

    // The reconnect really reached the live peer: it accepted the replacement handshake.
    assert!(
        peer.accepted_connections() >= 2,
        "the reconnect never reached the live peer"
    );
    let error = ended(outcome, elapsed, "unmanaged query");
    assert!(error.is_disconnected(), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(!is_managed_reconnect_expired(&error), "{error:?}");
    assert_within_bound(elapsed, "unmanaged query");
}

/// (A), managed: the same stall inside a managed workflow ends with the typed managed expiry.
#[tokio::test]
async fn a_managed_command_expires_at_the_bound_when_the_peer_grants_no_streams() {
    let peer = Peer::start();
    let (client, _session) = used_client(&peer).await;
    peer.set_new_connection_limits(0, super::scripted_storage_peer::WINDOW);
    drop_the_path(&peer).await;

    let started = Instant::now();
    let outcome = tokio::time::timeout(
        HANG_GUARD,
        lore_transport::with_managed_workflow(client.session_start_declared(
            partition(),
            "stalled",
            "outcome_unknown_v1",
        )),
    )
    .await;
    let elapsed = started.elapsed();

    assert!(
        peer.accepted_connections() >= 2,
        "the reconnect never reached the live peer"
    );
    let error = ended(outcome, elapsed, "managed session start");
    assert!(is_managed_reconnect_expired(&error), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert_within_bound(elapsed, "managed session start");
}

/// (B): pass 1's replacement grants no stream-data credit, so the `ClientIdentify` write blocks;
/// the peer then `STOP_SENDING`s that stream (the write fails `Stopped`, `Terminated`) and keeps its
/// own send half open, so the replacement's reader never ends. The retry's handshake succeeds, and
/// pass 2's swap must not wait for that reader under the connection write lock.
#[tokio::test]
async fn an_unmanaged_command_ends_at_the_bound_when_a_failed_replacements_reader_never_ends() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    peer.set_new_connection_limits(16, TINY_WINDOW);
    peer.stop_first_stream_of_new_connections(true);
    drop_the_path(&peer).await;

    let started = Instant::now();
    let outcome = tokio::time::timeout(HANG_GUARD, client.query(session, &[address()])).await;
    let elapsed = started.elapsed();

    eprintln!(
        "reconnect_stall (B): elapsed {elapsed:?}, stopped streams {}, accepted connections {}",
        peer.stopped_streams(),
        peer.accepted_connections()
    );
    // Scripted preconditions, checked before the verdict so a red names its cause: pass 1's
    // replacement was stopped, and the retry's handshake was accepted (the connection count is the
    // initial one, pass 1's, and pass 2's).
    assert!(
        peer.stopped_streams() >= 1,
        "precondition: the peer never stopped a replacement's first stream"
    );
    assert!(
        peer.accepted_connections() >= 3,
        "precondition: the retry's handshake was never accepted ({} connections)",
        peer.accepted_connections()
    );
    let error = ended(outcome, elapsed, "unmanaged query");
    assert!(error.is_disconnected(), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(!is_managed_reconnect_expired(&error), "{error:?}");
    assert_within_bound(elapsed, "unmanaged query");
}

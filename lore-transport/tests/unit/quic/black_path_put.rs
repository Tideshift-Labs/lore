// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Black-path cases at the transport layer: a QUIC path that goes black while the connection is
//! live, so the client finds it only by quinn's idle timeout.
//!
//! D-QS1 pin: a `Put` that was dispatched on a LIVE connection whose path then goes black ends as
//! an unknown outcome and is dispatched exactly once, even though the reconnect deadline now counts
//! from when the path went silent.
//!
//! [CLIENT]-class (`lore-transport`). The reconnect deadline only decides how long a reconnect may
//! take; it must never turn a `MutableNoReplay` command that was already dispatched into a resend.
//! The count is read on a LIVE peer after the path returns (a count against a dead peer is vacuous:
//! a resend that never arrives is not counted). A UDP relay in front of the scripted peer lets the
//! test black out the path while the client's connection stays up, so the client finds the loss by
//! quinn's 30 s idle timeout, not by a close frame.
//!
//! Scope: the transport layer (`send_with_reconnect` / `reconnect_and_retry`) only. The session
//! layer's `replaced` gate in `StorageSession::attempt` is not exercised here; its pin is
//! `not_dispatched_generation_mover_rebinds_and_retries_once` in
//! `lore-integration-tests/tests/quic_session_rebind_test.rs`.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::MutableOutcome;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const PUT: u8 = Command::Put as u8;
const QUERY: u8 = Command::Query as u8;

/// Quinn's 30 s idle timeout is how the client finds the black path, plus margin. A hang guard,
/// so a missing outcome fails red.
const OUTCOME_GUARD: Duration = Duration::from_secs(90);

/// Let anything a bug would have sent after the outcome reach the live peer before it is counted.
const GRACE: Duration = Duration::from_millis(700);

fn partition() -> Partition {
    Partition::from([0x31u8; 16])
}

fn address() -> Address {
    Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    }
}

/// A UDP relay in front of `upstream`. While `blocked` is set, nothing passes either way.
struct Relay {
    port: u16,
    blocked: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    async fn start(upstream: SocketAddr) -> Relay {
        let front = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind relay");
        let port = front.local_addr().expect("relay addr").port();
        let blocked = Arc::new(AtomicBool::new(false));
        let relay_blocked = blocked.clone();
        let task = lore_base::lore_spawn!(async move {
            let front = Arc::new(front);
            let mut peers: HashMap<SocketAddr, Arc<tokio::net::UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, from)) = front.recv_from(&mut buf).await else {
                    continue;
                };
                if relay_blocked.load(Ordering::Relaxed) {
                    continue;
                }
                let up = if let Some(up) = peers.get(&from) {
                    up.clone()
                } else {
                    let up = Arc::new(
                        tokio::net::UdpSocket::bind("127.0.0.1:0")
                            .await
                            .expect("bind upstream"),
                    );
                    up.connect(upstream).await.expect("connect upstream");
                    let back = up.clone();
                    let front = front.clone();
                    let blocked = relay_blocked.clone();
                    let _reverse = lore_base::lore_spawn!(async move {
                        let mut buf = vec![0u8; 65536];
                        while let Ok(n) = back.recv(&mut buf).await {
                            if !blocked.load(Ordering::Relaxed) {
                                let _ = front.send_to(&buf[..n], from).await;
                            }
                        }
                    });
                    peers.insert(from, up.clone());
                    up
                };
                let _ = up.send(&buf[..n]).await;
            }
        });
        Relay {
            port,
            blocked,
            task,
        }
    }

    fn url(&self) -> String {
        format!("lore://127.0.0.1:{}", self.port)
    }

    fn block(&self) {
        self.blocked.store(true, Ordering::Relaxed);
    }

    fn unblock(&self) {
        self.blocked.store(false, Ordering::Relaxed);
    }
}

/// A `Put` is dispatched and read in full by a live peer that never answers it, then the path goes
/// black. The command ends as an unknown outcome (no error, no reconnect-and-resend). After the
/// path returns, a further command proves the peer is alive and reconnected, and the peer has seen
/// the `Put` exactly once.
#[tokio::test]
async fn a_dispatched_put_on_a_black_path_is_unknown_and_dispatched_once_on_a_live_peer() {
    let peer = Peer::start();
    // The peer reads the whole Put and never answers; it stays alive and accepting, so a resend
    // (or a replay after reconnect) would be counted.
    peer.rule(PUT, Reply::Silent);
    peer.rule(QUERY, Reply::Ok(vec![0]));
    let relay = Relay::start(SocketAddr::from(([127, 0, 0, 1], peer.port))).await;

    let client = StorageClient::connect(
        Weak::new(),
        &relay.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "black-path-put",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
        lore_transport::quic::client::CongestionAlgorithm::default(),
    )
    .await
    .expect("connect through the relay");
    let session = client
        .session_start_declared(partition(), "black-path", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    // The process has really used QUIC to this server.
    client
        .query(session, &[address()])
        .await
        .expect("one Query succeeds while the path is up");
    let accepted_before = peer.accepted_connections();

    let fragment = Fragment {
        flags: 0,
        size_payload: 64,
        size_content: 64,
    };
    let put = client.put_outcome(
        session,
        address(),
        fragment,
        Some(Bytes::from(vec![0xA5u8; 64])),
    );
    // The path goes black only after the live peer has read the whole Put: it is dispatched.
    let blackout = async {
        peer.wait_until("the Put to be read in full", |peer| {
            peer.done_heads(PUT).len() == 1
        })
        .await;
        relay.block();
    };
    let started = Instant::now();
    let (result, ()) = tokio::join!(
        async {
            tokio::time::timeout(OUTCOME_GUARD, put)
                .await
                .expect("the dispatched Put never ended: nothing found the black path")
        },
        blackout
    );
    let elapsed = started.elapsed();

    match result {
        Ok(MutableOutcome::Unknown(_)) => {}
        Ok(MutableOutcome::Applied(())) => panic!("a Put nobody answered cannot be applied"),
        Err(error) => panic!("a dispatched Put on a black path must be unknown, got {error:?}"),
    }
    assert!(
        elapsed < OUTCOME_GUARD,
        "the outcome took {elapsed:?} to arrive"
    );

    // The path returns. One more command proves the peer is alive and the client reaches it again.
    relay.unblock();
    // The old session died with the old connection and is not resumed (`SessionRebindRequired`), so
    // the follow-up starts a fresh one, which dispatches nothing the peer counts as a Put.
    let (fresh, _) = tokio::time::timeout(
        Duration::from_secs(45),
        client.session_start_declared(partition(), "after-black-path", "outcome_unknown_v1"),
    )
    .await
    .expect("the follow-up command never ended")
    .expect("a command after the path returns must reach the live peer");
    client
        .query(fresh, &[address()])
        .await
        .expect("a Query on the recovered connection");
    tokio::time::sleep(GRACE).await;

    assert!(
        peer.accepted_connections() > accepted_before,
        "the follow-up must have reconnected to the live peer, or the count proves nothing"
    );
    assert_eq!(peer.seen_opcode(QUERY).len(), 2, "the peer is alive");
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        1,
        "the Put was dispatched exactly once and never resent"
    );
    assert_eq!(
        peer.done_heads(PUT).len(),
        1,
        "the Put was read in full exactly once"
    );
}

/// Quinn's idle timeout plus margin: by then the client has found the black path itself.
const IDLE_DEATH: Duration = Duration::from_secs(32);

/// How long after the waiting command starts the path returns: past the waiter's own 5 s floor,
/// well inside the managed owner's bound.
const BACK_AFTER: Duration = Duration::from_secs(8);

/// D-QS3 refined: a command that waits on another command's reconnect is not cut short at its own
/// anchored deadline while that reconnect is still inside its bound.
///
/// The connection dies by idle timeout, so the path has been silent 30 s already: an unmanaged
/// command's anchored deadline is only its 5 s floor, while a managed command's (60 s bound) still
/// has about 30 s. The managed command owns the reconnect; the unmanaged one waits on the guard.
/// The path returns 8 s later. The owner's reconnect succeeds, and the waiter must succeed on it,
/// not report `Disconnected` at its floor (which marked the connection stale and failed a warm sync
/// closed on a path that was coming back).
#[tokio::test]
async fn a_command_waiting_on_a_reconnect_that_recovers_succeeds() {
    let peer = Peer::start();
    peer.rule(QUERY, Reply::Ok(vec![0]));
    let relay = Relay::start(SocketAddr::from(([127, 0, 0, 1], peer.port))).await;
    let client = StorageClient::connect(
        Weak::new(),
        &relay.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "waiter-on-recovering-reconnect",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
        lore_transport::quic::client::CongestionAlgorithm::default(),
    )
    .await
    .expect("connect through the relay");
    let session = client
        .session_start_declared(partition(), "warm", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    client
        .query(session, &[address()])
        .await
        .expect("one Query succeeds while the path is up");
    let accepted_before = peer.accepted_connections();

    relay.block();
    tokio::time::sleep(IDLE_DEATH).await;

    let owner = async {
        lore_transport::with_managed_workflow(client.session_start_declared(
            partition(),
            "owner",
            "outcome_unknown_v1",
        ))
        .await
    };
    let waiter = async {
        // Starts once the owner holds the reconnect guard.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = Instant::now();
        let result = client
            .session_start_declared(partition(), "waiter", "outcome_unknown_v1")
            .await;
        (result, started.elapsed())
    };
    let path_returns = async {
        tokio::time::sleep(Duration::from_millis(500) + BACK_AFTER).await;
        relay.unblock();
    };
    let (owner, (waiter, waited), ()) = tokio::time::timeout(OUTCOME_GUARD, async {
        tokio::join!(owner, waiter, path_returns)
    })
    .await
    .expect("the reconnect never ended");

    owner.expect("the owner's reconnect is inside its bound when the path returns");
    let (fresh, _) = waiter.unwrap_or_else(|error| {
        panic!(
            "the waiter must succeed on the recovered connection, got {error:?} after {waited:?}"
        )
    });
    assert!(
        waited >= BACK_AFTER - Duration::from_secs(1),
        "the waiter cannot succeed before the path returns: {waited:?}"
    );
    assert!(
        peer.accepted_connections() > accepted_before,
        "a reconnect landed"
    );
    client
        .query(fresh, &[address()])
        .await
        .expect("a Query on the waiter's session");
}

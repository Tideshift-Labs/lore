// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Pins around the unmanaged reconnect bound (lane M), each against the real `StorageClient` and
//! the scripted peer.
//!
//! [CLIENT]-class (`lore-transport`).
//!
//! - **P1**: a command that finds the connection given up (epoch 0) reports the give-up it is,
//!   `ReconnectFailed` carrying the stored unreachable endpoint, not a bare `Disconnected` or a
//!   plain client error. `classify`'s epoch-0 arm is called directly: the live paths that reach a
//!   given-up connection also fail through other arms that name the endpoint, so only the arm
//!   itself can be pinned.
//! - **P2**: a client that opts out of the unmanaged bound (`bounds_unmanaged_reconnect() ==
//!   false`, the replication client's shape) keeps upstream's attempt-count loop: it reconnects
//!   past a short bound and recovers when the peer returns. The control is the bounded client in
//!   the same scenario, which gives up.
//! - **P3**: a `Put` dispatched before the path died, with an unmanaged reconnect then giving up at
//!   its bound, is an unknown outcome returned as `Ok`, dispatched once, never resent.
use std::net::UdpSocket;
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
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::error::ProtocolError;
use lore_transport::error::is_managed_reconnect_expired;
use lore_transport::quic::QuicClientError;
use lore_transport::quic::client::AuthAdapter;
use lore_transport::quic::client::EndpointConfig;
use lore_transport::quic::client::IgnoreOutcome;
use lore_transport::quic::client::QuicConnection;
use lore_transport::quic::client::SendFailure;
use lore_transport::quic::client::SendWithReconnectError;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::client::TransportConfig;
use lore_transport::quic::client::Verdict;
use lore_transport::quic::client::classify;
use lore_transport::quic::client::send_with_reconnect;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::MutableOutcome;
use lore_transport::replay::ReplayClass;
use tokio::sync::SemaphorePermit;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const PUT: u8 = Command::Put as u8;
const QUERY: u8 = Command::Query as u8;

/// The shortened unmanaged reconnect bound.
const BOUND: Duration = Duration::from_secs(3);

/// One 5 s handshake may still be in flight at the deadline, plus scheduling margin.
const CEILING: Duration = Duration::from_secs(3 + 5 + 7);

/// Let anything a bug would have sent reach the peer before a count is read.
const GRACE: Duration = Duration::from_millis(700);

fn partition() -> Partition {
    Partition::from([0x27u8; 16])
}

fn address() -> Address {
    Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    }
}

async fn used_client(peer: &Peer) -> (Arc<StorageClient>, u32) {
    peer.rule(QUERY, Reply::Ok(vec![0]));
    let client = StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "unmanaged-reconnect-pins",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
        lore_transport::quic::client::CongestionAlgorithm::default(),
    )
    .await
    .expect("connect to the scripted peer");
    client.quic().set_reconnect_timeout_for_test(BOUND);
    let session = client
        .session_start_declared(partition(), "pins", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    client
        .query(session, &[address()])
        .await
        .expect("one Query succeeds while the peer is live");
    (client, session)
}

/// Close the peer's connections and endpoint, wait until the client's connection is gone, and
/// release the port.
async fn take_down(peer: Peer) -> u16 {
    let port = peer.port;
    peer.stop();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;
    drop(peer);
    port
}

/// Bind `port` again, retrying while the OS releases it.
async fn rebind<T>(port: u16, mut bind: impl FnMut(u16) -> std::io::Result<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match bind(port) {
            Ok(bound) => return bound,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "could not rebind port {port}: {error}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// The server goes away and its port is held by a socket that never answers (no ICMP, so a
/// handshake times out instead of failing at once).
async fn black_hole(peer: Peer) -> (UdpSocket, u16) {
    let port = take_down(peer).await;
    let socket = rebind(port, |port| UdpSocket::bind(("127.0.0.1", port))).await;
    (socket, port)
}

/// The unreachable `Disconnected`, naming `127.0.0.1:port`.
fn assert_names_endpoint(error: &ProtocolError, port: u16, what: &str) {
    assert!(error.is_disconnected(), "{what}: {error:?}");
    assert!(!is_managed_reconnect_expired(error), "{what}: {error:?}");
    let unreachable = error
        .quic_unreachable()
        .unwrap_or_else(|| panic!("{what}: the error carries no unreachable detail: {error:?}"));
    assert_eq!(unreachable.host, "127.0.0.1", "{what}");
    assert_eq!(unreachable.port, port, "{what}");
}

// P1 -----------------------------------------------------------------------------------------

/// `classify`'s epoch-0 arm answers `ReconnectFailed(<stored endpoint>)`. A plain `Disconnected`
/// (the mutant) carries no endpoint, and a plain client error is not a disconnect at all.
#[tokio::test]
async fn classify_reports_a_given_up_connection_with_the_stored_endpoint() {
    let peer = Peer::start();
    let (client, _session) = used_client(&peer).await;
    // The failure that reaches the arm: not dispatched, not one of the arms before it.
    let failure = SendFailure::not_dispatched(QuicClientError::Write);

    // Control: on a connection that has not given up the same failure is a plain client error,
    // so the endpoint in the next verdict can only come from the give-up.
    let epoch = client
        .quic()
        .epoch
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_ne!(epoch, 0, "the connection is live");
    match classify(&*client, Command::Query, epoch, &failure) {
        Verdict::Failed(error) => assert!(
            error.quic_unreachable().is_none() && !error.is_disconnected(),
            "control: a live connection's plain failure is not a give-up: {error:?}"
        ),
        Verdict::Reconnect => panic!("control: `Write` before dispatch is not a reconnect"),
        Verdict::Unknown => panic!("control: a not-dispatched failure is never unknown"),
    }

    let (_socket, port) = black_hole(peer).await;
    let gave_up = tokio::time::timeout(Duration::from_secs(45), client.query(0, &[address()]))
        .await
        .expect("the first command never ended: the reconnect loop is unbounded")
        .expect_err("a black-holed server cannot answer");
    assert_names_endpoint(&gave_up, port, "the command that gave up");
    assert_eq!(
        client
            .quic()
            .epoch
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the unmanaged give-up leaves the connection given up"
    );

    // A later failing command finds epoch 0. `epoch` 1 is what it sampled before the loss.
    match classify(&*client, Command::Query, 1, &failure) {
        Verdict::Failed(error) => assert_names_endpoint(&error, port, "classify at epoch 0"),
        Verdict::Reconnect => panic!("a given-up connection must not ask for another reconnect"),
        Verdict::Unknown => panic!("a not-dispatched failure is never unknown"),
    }
}

// P2 -----------------------------------------------------------------------------------------

/// A client that opts out of the unmanaged bound, delegating everything else to a real
/// `StorageClient`. It stands in for the replication store client (`lore-server`), which cannot be
/// built against this peer.
struct NoBound(Arc<StorageClient>);

impl ServiceClient for NoBound {
    const ALPN: &'static str = <StorageClient as ServiceClient>::ALPN;
    const DEFAULT_PORT: u16 = <StorageClient as ServiceClient>::DEFAULT_PORT;
    type RequestType = Command;
    type ErrorType = ProtocolError;

    async fn acquire_command_permit(&self) -> Option<SemaphorePermit<'_>> {
        self.0.acquire_command_permit().await
    }

    fn quic(&self) -> &Arc<QuicConnection> {
        self.0.quic()
    }

    fn endpoint_config(&self) -> EndpointConfig {
        self.0.endpoint_config()
    }

    fn alpn(&self) -> &str {
        self.0.alpn()
    }

    fn map_send_error(
        &self,
        failed_request: Self::RequestType,
        error: SendWithReconnectError,
    ) -> Self::ErrorType {
        self.0.map_send_error(failed_request, error)
    }

    fn auth_adapter(&self) -> &Arc<dyn AuthAdapter<ErrorType = Self::ErrorType>> {
        self.0.auth_adapter()
    }

    fn transport_config(&self) -> TransportConfig {
        self.0.transport_config()
    }

    fn v4_protocol(&self) -> bool {
        self.0.v4_protocol()
    }

    fn bounds_unmanaged_reconnect(&self) -> bool {
        false
    }

    fn replay_class(&self, request: Self::RequestType) -> ReplayClass {
        self.0.replay_class(request)
    }

    fn request_name(&self, request: Self::RequestType) -> &'static str {
        self.0.request_name(request)
    }
}

/// One session-less `Query` through `send_with_reconnect`: after a reconnect no session id of the
/// old connection is valid, and the peer answers any `Query`.
async fn query_through<C>(client: &C) -> Result<Bytes, ProtocolError>
where
    C: ServiceClient<RequestType = Command, ErrorType = ProtocolError>,
{
    send_with_reconnect::<_, _, 1, false, false>(
        client,
        Command::Query,
        0,
        || [Bytes::from(vec![0u8; 48])],
        IgnoreOutcome,
    )
    .await
}

/// How long the peer stays away in the P2 cases: past the bound, inside upstream's loop.
const DOWN: Duration = Duration::from_secs(6);

/// The opt-out client reconnects past the (shortened) bound and recovers when the peer returns.
#[tokio::test]
async fn a_client_that_opts_out_of_the_unmanaged_bound_keeps_reconnecting_past_it() {
    let peer = Peer::start();
    let (client, _session) = used_client(&peer).await;
    let opt_out = NoBound(client);
    let port = take_down(peer).await;

    let revive = async {
        tokio::time::sleep(DOWN).await;
        let revived = rebind(port, Peer::start_on).await;
        revived.rule(QUERY, Reply::Ok(vec![0]));
        revived
    };
    let command = async {
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(60), query_through(&opt_out))
            .await
            .expect("the opt-out command never ended");
        (result, started.elapsed())
    };
    let (revived, (result, elapsed)) = tokio::join!(revive, command);

    result.expect("an opt-out client keeps reconnecting and recovers when the peer returns");
    assert!(
        elapsed > BOUND,
        "the command must outlast the bound the opt-out ignores: {elapsed:?}"
    );
    assert!(
        elapsed >= DOWN - Duration::from_secs(1),
        "the command cannot succeed before the peer is back: {elapsed:?}"
    );
    assert_ne!(
        opt_out
            .quic()
            .epoch
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the connection was never given up"
    );
    assert_eq!(revived.seen_opcode(QUERY).len(), 1, "the Query landed");
}

/// Control for the case above: the same scenario through the bounded client gives up at the bound,
/// so the opt-out case passing is the opt-out's doing and not a slack scenario.
#[tokio::test]
async fn the_bounded_client_gives_up_in_the_same_scenario() {
    let peer = Peer::start();
    let (client, _session) = used_client(&peer).await;
    let port = take_down(peer).await;

    let revive = async {
        tokio::time::sleep(DOWN).await;
        rebind(port, Peer::start_on).await
    };
    let command = async {
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(60), query_through(&*client))
            .await
            .expect("the bounded command never ended");
        (result, started.elapsed())
    };
    let (_revived, (result, elapsed)) = tokio::join!(revive, command);

    let error = result.expect_err("the bounded client gives up before the peer returns");
    assert!(error.is_disconnected(), "{error:?}");
    assert!(
        elapsed < CEILING && elapsed < DOWN + Duration::from_secs(5),
        "gave up at the bound: {elapsed:?}"
    );
}

// P3 -----------------------------------------------------------------------------------------

/// A `Put` the peer read and never answered, then the path dies (the endpoint closes and its port
/// is held by a socket that never answers), and a second command's unmanaged reconnect gives up at
/// its bound. The `Put` is an unknown outcome returned as `Ok`; the peer saw exactly one `Put`; and
/// a live peer that returns afterwards sees none, because nothing was queued for a replay.
///
/// Distinct from `an_unmanaged_put_whose_answer_is_lost_is_unknown_and_dispatched_once`: that
/// case's peer closes the connection itself and no reconnect gives up. Here the give-up happens
/// while the `Put`'s fate is being settled, and a replay would reach the revived peer.
#[tokio::test]
async fn a_put_in_flight_when_the_unmanaged_reconnect_gives_up_is_unknown_and_dispatched_once() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    peer.rule(PUT, Reply::Silent);

    let put = {
        let client = client.clone();
        lore_base::lore_spawn!(async move {
            let fragment = Fragment {
                flags: 0,
                size_payload: 64,
                size_content: 64,
            };
            client
                .put_outcome(
                    session,
                    address(),
                    fragment,
                    Some(Bytes::from(vec![0xA5u8; 64])),
                )
                .await
        })
    };
    peer.wait_until("the Put to reach the peer", |peer| {
        peer.seen_opcode(PUT).len() == 1
    })
    .await;
    let first_peer_puts = peer.seen_opcode(PUT).len();

    let (_socket, port) = black_hole(peer).await;

    let started = Instant::now();
    let query = tokio::time::timeout(Duration::from_secs(45), client.query(session, &[address()]))
        .await
        .expect("the command never ended: the reconnect loop is unbounded")
        .expect_err("a black-holed server cannot answer");
    let elapsed = started.elapsed();
    assert_names_endpoint(&query, port, "the command that gave up");
    assert!(elapsed < CEILING, "gave up at the bound: {elapsed:?}");

    let put = tokio::time::timeout(Duration::from_secs(45), put)
        .await
        .expect("the in-flight Put never ended")
        .expect("the Put task finished")
        .expect("a dispatched Put with a lost answer is an Ok outcome, not an error");
    match put {
        MutableOutcome::Unknown(_) => {}
        MutableOutcome::Applied(()) => panic!("a Put whose answer never came cannot be applied"),
    }
    assert_eq!(first_peer_puts, 1, "the Put was dispatched exactly once");

    // The server returns on the same port. Nothing replays the Put to it.
    drop(_socket);
    let revived = rebind(port, Peer::start_on).await;
    revived.rule(PUT, Reply::Ok(Vec::new()));
    tokio::time::sleep(GRACE + Duration::from_secs(1)).await;
    assert!(
        revived.seen_opcode(PUT).is_empty(),
        "a Put must never be resent to a peer that returns after the give-up"
    );
    assert_eq!(
        revived.accepted_connections(),
        0,
        "nothing reconnects once the connection has given up"
    );
}

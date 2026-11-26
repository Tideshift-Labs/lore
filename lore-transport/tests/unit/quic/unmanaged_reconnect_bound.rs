// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! An unmanaged command whose QUIC connection died and whose server stays unreachable gives up
//! at the reconnect bound with `Disconnected` and says where it went.
//!
//! [CLIENT]-class (`lore-transport`). A process that already used QUIC to a server keeps its cached
//! connection. When UDP to that server is then dropped, the next storage command fails before
//! dispatch and goes to reconnect. Outside a managed wait scope the stock loop (10 attempts, 5 s
//! per handshake, backoff 1 s doubling to 30 s) ran for about 3.5 minutes with no error. The loop
//! now has a deadline of its own (default 30 s, shortened here by `set_reconnect_timeout_for_test`).
//!
//! Every case drives the real `StorageClient` against the scripted peer. "Unreachable" is the
//! peer's endpoint closed and its UDP port taken over by a bound socket that never reads, so the
//! reconnect handshakes time out with no answer (no ICMP, which would fail them at once).
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
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::client::reconnect_timeout_from;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::MutableOutcome;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const PUT: u8 = Command::Put as u8;
const QUERY: u8 = Command::Query as u8;

/// The shortened reconnect deadline of the unreachable cases.
const BOUND: Duration = Duration::from_secs(3);

/// The deadline may fire while one 5 s handshake is in flight and that handshake still has to
/// finish, plus scheduling margin.
const CEILING: Duration = Duration::from_secs(3 + 5 + 7);

/// The default bound when nothing sets one.
const DEFAULT_BOUND: Duration = Duration::from_secs(30);

/// Let anything a bug would have sent after the call reach the peer before the count is read.
const GRACE: Duration = Duration::from_millis(700);

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

fn address() -> Address {
    Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    }
}

/// A query of one address answered as present.
fn answer_queries(peer: &Peer) {
    peer.rule(QUERY, Reply::Ok(vec![0]));
}

async fn connect(peer: &Peer) -> Arc<StorageClient> {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "unmanaged-reconnect-bound",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
        lore_transport::quic::client::CongestionAlgorithm::default(),
    )
    .await
    .expect("connect to the scripted peer")
}

/// A connected client with an open declared session and one `Query` that already succeeded, so the
/// process has really used QUIC to this server.
async fn used_client(peer: &Peer) -> (Arc<StorageClient>, u32) {
    answer_queries(peer);
    let client = connect(peer).await;
    let session = client
        .session_start_declared(partition(), "unmanaged", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    client
        .query(session, &[address()])
        .await
        .expect("one Query succeeds while the peer is live");
    (client, session)
}

/// Close the peer's connections and endpoint, release its port, and wait until the client's
/// connection is gone.
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

/// The server goes away and its port is held by a socket that never answers.
async fn black_hole(peer: Peer) -> (UdpSocket, u16) {
    let port = take_down(peer).await;
    let socket = rebind(port, |port| UdpSocket::bind(("127.0.0.1", port))).await;
    (socket, port)
}

/// `error` is the unreachable `Disconnected`: not unknown, not a managed expiry, with the typed
/// detail for `host:port` over the `tcp_url` scheme the peer's remote maps to.
fn assert_unreachable(error: &ProtocolError, port: u16, what: &str) {
    assert!(error.is_disconnected(), "{what}: {error:?}");
    assert!(!error.is_outcome_unknown(), "{what}: {error:?}");
    assert!(!is_managed_reconnect_expired(error), "{what}: {error:?}");
    let unreachable = error
        .quic_unreachable()
        .unwrap_or_else(|| panic!("{what}: the error carries no unreachable detail: {error:?}"));
    assert_eq!(unreachable.host, "127.0.0.1", "{what}");
    assert_eq!(unreachable.port, port, "{what}");
    // The scripted peer's URL is `lore://`, which is plain TCP's `grpc://` (`lores://` is
    // `grpcs://`, pinned by `unreachable_handshake.rs`).
    assert_eq!(
        unreachable.tcp_url,
        format!("grpc://127.0.0.1:{port}"),
        "{what}"
    );
}

/// The defect: the command ends with the typed `Disconnected` about one bound after the path dies,
/// not minutes after.
#[tokio::test]
async fn an_unmanaged_command_gives_up_at_the_reconnect_bound_naming_the_endpoint() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    client.quic().set_reconnect_timeout_for_test(BOUND);
    let (_socket, port) = black_hole(peer).await;

    let started = Instant::now();
    // A missing bound must fail red, not hang for minutes.
    let result = tokio::time::timeout(Duration::from_secs(45), client.query(session, &[address()]))
        .await
        .expect("the unmanaged command never ended: the reconnect loop is unbounded");
    let elapsed = started.elapsed();

    let error = result.expect_err("a black-holed server cannot answer");
    assert_unreachable(&error, port, "first command");
    assert!(
        elapsed >= BOUND - Duration::from_millis(500),
        "gave up before the bound: {elapsed:?}"
    );
    assert!(
        elapsed < CEILING,
        "outlasted the bound plus one handshake: {elapsed:?}"
    );
}

/// After giving up, the next command on the same client fails fast with `Disconnected` and does
/// not start another long loop.
#[tokio::test]
async fn after_giving_up_the_next_command_fails_fast_and_does_not_loop_again() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    client.quic().set_reconnect_timeout_for_test(BOUND);
    let (_socket, port) = black_hole(peer).await;

    let first = tokio::time::timeout(Duration::from_secs(45), client.query(session, &[address()]))
        .await
        .expect("the first command never ended")
        .expect_err("a black-holed server cannot answer");
    assert_unreachable(&first, port, "first command");

    let started = Instant::now();
    let second = tokio::time::timeout(Duration::from_secs(45), client.query(session, &[address()]))
        .await
        .expect("the second command never ended: it started another long loop")
        .expect_err("the server is still unreachable");
    let elapsed = started.elapsed();

    // The give-up recorded the endpoint, so the later command names it too.
    assert_unreachable(&second, port, "second command");
    assert!(
        elapsed < BOUND - Duration::from_secs(1),
        "the second command must fail well under the bound, took {elapsed:?}"
    );
}

/// A `Put` that was dispatched and whose answer was lost when the path died, outside a managed
/// scope, is an unknown outcome returned as `Ok`: one dispatch on a LIVE peer, never resent.
#[tokio::test]
async fn an_unmanaged_put_whose_answer_is_lost_is_unknown_and_dispatched_once() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    client.quic().set_reconnect_timeout_for_test(BOUND);
    // The peer reads the whole Put and closes the connection without answering. It stays alive
    // and accepting, so a resend (or a replay after reconnect) would be counted.
    peer.rule(PUT, Reply::Disconnect);

    let (address, fragment, payload) = {
        let address = address();
        let fragment = Fragment {
            flags: 0,
            size_payload: 64,
            size_content: 64,
        };
        (address, fragment, Bytes::from(vec![0xA5u8; 64]))
    };
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(45),
        client.put_outcome(session, address, fragment, Some(payload)),
    )
    .await
    .expect("the lost Put never ended: the reconnect loop is unbounded");
    let elapsed = started.elapsed();
    tokio::time::sleep(GRACE).await;

    match result {
        Ok(MutableOutcome::Unknown(_)) => {}
        Ok(MutableOutcome::Applied(())) => panic!("a Put with a lost answer cannot be applied"),
        Err(error) => panic!("a dispatched Put with a lost answer must be unknown, got {error:?}"),
    }
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        1,
        "the Put was dispatched exactly once and never resent"
    );
    assert!(
        elapsed < BOUND,
        "a lost mutable answer is not retried through a reconnect loop: {elapsed:?}"
    );
}

/// Active-active recovery: the server goes away and comes back on the same port well inside the
/// default bound (a replica restart or lame-duck drain). An unmanaged command issued while it is
/// down recovers, with no error. No seam: the default bound is what ships.
#[tokio::test]
async fn an_unmanaged_command_recovers_when_the_server_returns_inside_the_default_bound() {
    let peer = Peer::start();
    let (client, _session) = used_client(&peer).await;
    let port = take_down(peer).await;

    // The server returns about 8 s from now, on the same port.
    let down = Duration::from_secs(8);
    let revive = async {
        tokio::time::sleep(down).await;
        let revived = rebind(port, Peer::start_on).await;
        answer_queries(&revived);
        revived
    };
    let command = async {
        let started = Instant::now();
        let result = tokio::time::timeout(
            DEFAULT_BOUND + Duration::from_secs(30),
            client.session_start_declared(partition(), "recovered", "outcome_unknown_v1"),
        )
        .await
        .expect("the command never ended");
        (result, started.elapsed())
    };
    let (revived, (result, elapsed)) = tokio::join!(revive, command);

    let (fresh, _) = result.expect("a command issued while the server restarts must recover");
    assert!(
        elapsed >= down - Duration::from_secs(1),
        "the command cannot succeed before the server is back: {elapsed:?}"
    );
    assert!(
        elapsed < DEFAULT_BOUND,
        "recovery must fit inside the default bound: {elapsed:?}"
    );
    assert_eq!(revived.accepted_connections(), 1, "one reconnect landed");

    // The recovered connection serves a command on the new session.
    client
        .query(fresh, &[address()])
        .await
        .expect("a Query on the recovered connection");
    assert_eq!(revived.seen_opcode(QUERY).len(), 1);
}

/// A second command that waits on the first one's reconnect finds the connection given up and
/// reports the same endpoint, not a bare `Disconnected`. It starts a second after the first so its
/// own deadline falls after the first's give-up: it must then acquire the guard and read the
/// recorded detail rather than time out waiting for it.
#[tokio::test]
async fn a_second_command_waiting_on_the_reconnect_also_names_the_endpoint() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    client.quic().set_reconnect_timeout_for_test(BOUND);
    let (_socket, port) = black_hole(peer).await;

    let run = |delay: Duration| {
        let client = client.clone();
        async move {
            tokio::time::sleep(delay).await;
            let started = Instant::now();
            let result =
                tokio::time::timeout(Duration::from_secs(45), client.query(session, &[address()]))
                    .await
                    .expect("a command never ended: the reconnect loop is unbounded");
            (result, started.elapsed())
        }
    };
    let ((first, first_elapsed), (second, second_elapsed)) =
        tokio::join!(run(Duration::ZERO), run(Duration::from_secs(1)));

    assert_unreachable(
        &first.expect_err("a black-holed server cannot answer"),
        port,
        "first command",
    );
    assert_unreachable(
        &second.expect_err("a black-holed server cannot answer"),
        port,
        "waiting command",
    );
    assert!(first_elapsed < CEILING, "{first_elapsed:?}");
    assert!(second_elapsed < CEILING, "{second_elapsed:?}");
}

/// A command held behind another command's reconnect (the guard) past its own unmanaged bound
/// gives up as `Disconnected`. It is not the managed expiry, which belongs to managed scopes and
/// reads as "not sent". The old connection is already dead, so the command fails before dispatch
/// and goes to reconnect, where it can only wait for the guard.
#[tokio::test]
async fn an_unmanaged_command_held_behind_the_reconnect_guard_gives_up_as_disconnected() {
    let peer = Peer::start();
    let (client, session) = used_client(&peer).await;
    client.quic().set_reconnect_timeout_for_test(BOUND);
    let port = take_down(peer).await;
    let guard = client.quic().hold_reconnect_guard_for_test().await;

    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(45), client.query(session, &[address()]))
        .await
        .expect("the held command never ended: the guard wait has no unmanaged deadline");
    let elapsed = started.elapsed();
    drop(guard);

    let error = result.expect_err("the guard is never released inside the bound");
    assert!(error.is_disconnected(), "{error:?}");
    assert!(
        !is_managed_reconnect_expired(&error),
        "an unmanaged command must not get the managed expiry (port {port}): {error:?}"
    );
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(
        elapsed >= BOUND - Duration::from_millis(500) && elapsed < BOUND + Duration::from_secs(2),
        "gave up at the bound, took {elapsed:?}"
    );
}

/// Active-active recovery through a black hole: the port is held by a socket that never answers
/// for about 8 s, then the real server returns on it. An unmanaged command issued at the start
/// recovers inside the default 30 s bound with no error. The bound is set explicitly, so an
/// ambient `LORE_QUIC_RECONNECT_TIMEOUT` cannot change the case.
#[tokio::test]
async fn an_unmanaged_command_recovers_when_a_black_holed_server_returns_inside_the_bound() {
    let peer = Peer::start();
    let (client, _session) = used_client(&peer).await;
    client.quic().set_reconnect_timeout_for_test(DEFAULT_BOUND);
    let (socket, port) = black_hole(peer).await;

    let down = Duration::from_secs(8);
    let revive = async move {
        tokio::time::sleep(down).await;
        drop(socket);
        let revived = rebind(port, Peer::start_on).await;
        answer_queries(&revived);
        revived
    };
    let command = async {
        let started = Instant::now();
        let result = tokio::time::timeout(
            DEFAULT_BOUND + Duration::from_secs(30),
            client.session_start_declared(partition(), "recovered", "outcome_unknown_v1"),
        )
        .await
        .expect("the command never ended");
        (result, started.elapsed())
    };
    let (revived, (result, elapsed)) = tokio::join!(revive, command);

    let (fresh, _) = result.expect("a command issued while the server is black-holed must recover");
    assert!(
        elapsed >= down - Duration::from_secs(1),
        "the command cannot succeed before the server is back: {elapsed:?}"
    );
    assert!(
        elapsed < DEFAULT_BOUND,
        "recovery must fit inside the bound: {elapsed:?}"
    );
    assert!(revived.accepted_connections() >= 1, "a reconnect landed");

    client
        .query(fresh, &[address()])
        .await
        .expect("a Query on the recovered connection");
    assert_eq!(revived.seen_opcode(QUERY).len(), 1);
}
/// The environment override: only a positive whole number of seconds replaces the default.
#[test]
fn the_reconnect_timeout_reads_a_positive_number_of_seconds_and_defaults_to_thirty() {
    for ignored in [None, Some(""), Some("0"), Some("abc")] {
        assert_eq!(
            reconnect_timeout_from(ignored),
            DEFAULT_BOUND,
            "{ignored:?}"
        );
    }
    assert_eq!(reconnect_timeout_from(Some("12")), Duration::from_secs(12));
}

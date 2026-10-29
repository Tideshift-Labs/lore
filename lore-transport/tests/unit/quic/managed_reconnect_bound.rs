// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124: a managed command that needs a reconnect gives up at the managed idle bound.
//!
//! [CLIENT]-class (`lore-transport`). Before the bound, a push whose QUIC connection was gone and
//! whose server stayed unreachable ran the whole reconnect loop (10 attempts, backoff to 30 s,
//! 5 s per handshake) and hung for minutes with no error. Inside a managed scope the loop now ends
//! at the deadline with a typed, not-dispatched error, and leaves the connection able to
//! reconnect on the next command.
//!
//! Every case drives the real `StorageClient` against the scripted peer; "unreachable" is the
//! peer's endpoint closed, so the reconnect handshakes fail or time out for real.
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::Ordering;
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
use lore_transport::error::is_unjournaled_answer_lost;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::MutableOutcome;
use lore_transport::with_caller_operation;
use uuid::Uuid;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const PUT: u8 = Command::Put as u8;

/// The managed deadline for reconnecting. Long enough to be measurable, short enough to keep the
/// cases fast.
const BOUND: Duration = Duration::from_secs(3);

/// One in-flight 5 s handshake may finish after the deadline, plus scheduling margin.
const LATE_MARGIN: Duration = Duration::from_secs(7);

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

fn managed_context() -> CallerOperationContext {
    CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    )
}

async fn connect(peer: &Peer) -> StorageClient {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "",
        "managed-reconnect-bound",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer")
}

/// A client with an open declared session, the connection live, and the managed bound shortened.
async fn client_with_session(peer: &Peer) -> (StorageClient, u32) {
    let client = connect(peer).await;
    client.quic().set_managed_idle_for_test(BOUND);
    let session = client
        .session_start_declared(partition(), "reconnect-bound", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    (client, session)
}

/// Take the server away: close every connection and the endpoint, and wait until the client's
/// connection is gone. Reconnect handshakes now fail or time out.
async fn make_unreachable(peer: &Peer) {
    peer.stop();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;
}

fn put_args() -> (Address, Fragment, Bytes) {
    let address = Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    };
    let fragment = Fragment {
        flags: 0,
        size_payload: 64,
        size_content: 64,
    };
    (address, fragment, Bytes::from(vec![0xA5u8; 64]))
}

async fn managed_put(
    client: &StorageClient,
    session: u32,
) -> Result<MutableOutcome<()>, ProtocolError> {
    let (address, fragment, payload) = put_args();
    with_caller_operation(
        managed_context(),
        client.put_outcome(session, address, fragment, Some(payload)),
    )
    .await
}

/// The error is the typed expiry and none of the signals a retry layer or caller acts on.
fn assert_expired(error: &ProtocolError, what: &str) {
    assert!(is_managed_reconnect_expired(error), "{what}: {error:?}");
    assert!(!error.is_outcome_unknown(), "{what}: {error:?}");
    assert!(!error.is_disconnected(), "{what}: {error:?}");
    assert!(!is_unjournaled_answer_lost(error), "{what}: {error:?}");
    // `SessionRebindRequired` is `pub(crate)` and has no public predicate, so the proof is read
    // off the text only it renders.
    let text = format!("{error} | {error:?}");
    assert!(
        !text.contains("storage command was not dispatched"),
        "{what}: must not read as the session-rebind proof, or StorageSession::attempt retries it: {text}"
    );
}

fn assert_bounded(elapsed: Duration, what: &str) {
    assert!(
        elapsed >= BOUND - Duration::from_millis(500),
        "{what}: gave up early: {elapsed:?}"
    );
    assert!(
        elapsed < BOUND + LATE_MARGIN,
        "{what}: outlasted the bound: {elapsed:?}"
    );
}

/// The defect: a managed Put with the server gone returns the typed expiry within the bound, sends
/// nothing, and leaves the epoch nonzero (the connection can still reconnect later).
#[tokio::test]
async fn a_managed_put_with_the_server_unreachable_expires_at_the_bound() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    let epoch_before = client.quic().epoch.load(Ordering::Relaxed);
    assert_ne!(epoch_before, 0);
    make_unreachable(&peer).await;

    let started = Instant::now();
    // A missing bound must fail red, not hang for minutes.
    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        managed_put(&client, session),
    )
    .await
    .expect("the managed Put never ended: the reconnect loop is unbounded");
    let elapsed = started.elapsed();

    let error = result.expect_err("an unreachable server ends a managed Put");
    assert_expired(&error, "managed put");
    assert_bounded(elapsed, "managed put");
    assert!(
        peer.seen_opcode(PUT).is_empty(),
        "no byte of the command reached the peer"
    );
    assert_ne!(
        client.quic().epoch.load(Ordering::Relaxed),
        0,
        "giving up at the deadline must not poison the connection"
    );
}

/// The same bound on the session-start path: a start (no session id yet) needs the reconnect and
/// gets the same typed error.
#[tokio::test]
async fn a_managed_session_start_with_the_server_unreachable_expires_at_the_bound() {
    let peer = Peer::start();
    let (client, _) = client_with_session(&peer).await;
    make_unreachable(&peer).await;
    let starts_before = peer.done().len();

    let started = Instant::now();
    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        with_caller_operation(
            managed_context(),
            client.session_start_declared(partition(), "expired", "outcome_unknown_v1"),
        ),
    )
    .await
    .expect("the managed session start never ended: the reconnect loop is unbounded");
    let elapsed = started.elapsed();

    let error = result.expect_err("an unreachable server ends a managed session start");
    assert_expired(&error, "managed session start");
    assert_bounded(elapsed, "managed session start");
    assert_eq!(
        peer.done().len(),
        starts_before,
        "nothing of the start reached the peer"
    );
    assert_ne!(client.quic().epoch.load(Ordering::Relaxed), 0);
}

/// Giving up is not terminal: when the server is back at the same address, the next managed
/// command reconnects through the normal path and succeeds.
#[tokio::test]
async fn after_an_expiry_the_next_command_reconnects_when_the_server_is_back() {
    let peer = Peer::start();
    let port = peer.port;
    let (client, session) = client_with_session(&peer).await;
    make_unreachable(&peer).await;

    let error = managed_put(&client, session)
        .await
        .expect_err("the first command expires");
    assert_expired(&error, "first command");
    let epoch_after_expiry = client.quic().epoch.load(Ordering::Relaxed);
    assert_ne!(epoch_after_expiry, 0);

    // Bring a peer back on the same address. The old endpoint releases the port once dropped.
    drop(peer);
    let revived = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match Peer::start_on(port) {
                Ok(peer) => break peer,
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "could not rebind port {port}: {error}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    };

    // The old session id belongs to the dead connection, so the caller starts a new session; that
    // start is what reconnects. This is the same recovery a session layer performs.
    let (fresh, _) = tokio::time::timeout(
        Duration::from_secs(30),
        with_caller_operation(
            managed_context(),
            client.session_start_declared(partition(), "recovered", "outcome_unknown_v1"),
        ),
    )
    .await
    .expect("the reconnect after recovery must finish")
    .expect("the next managed command reconnects once the server is back");
    assert_eq!(revived.accepted_connections(), 1, "one reconnect landed");
    assert!(
        client.quic().epoch.load(Ordering::Relaxed) > epoch_after_expiry,
        "the reconnect is a completed one"
    );

    let outcome = managed_put(&client, fresh)
        .await
        .expect("a managed Put on the recovered connection");
    assert!(matches!(outcome, MutableOutcome::Applied(())));
    assert_eq!(
        revived.seen_opcode(PUT).len(),
        1,
        "exactly one Put reached the revived peer"
    );
}

/// Only a command whose first send failed BEFORE dispatch may say "not sent". A read that reached
/// the wire, was never answered, and then lost its connection keeps its own error: reporting
/// "not sent" for it would be a false proof of non-dispatch.
#[tokio::test]
async fn a_dispatched_read_whose_connection_dies_keeps_its_own_error_at_the_bound() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    peer.rule(Command::Get as u8, Reply::Silent);

    let address = put_args().0;
    let started = Instant::now();
    let read = async {
        tokio::time::timeout(
            BOUND + Duration::from_secs(40),
            with_caller_operation(managed_context(), client.get(session, &address)),
        )
        .await
        .expect("the managed read never ended: the reconnect loop is unbounded")
    };
    let kill = async {
        peer.wait_until("the Get to be read", |peer| {
            !peer.seen_opcode(Command::Get as u8).is_empty()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        make_unreachable(&peer).await;
    };
    let (result, ()) = tokio::join!(read, kill);
    let elapsed = started.elapsed();

    let error = result.expect_err("a lost read ends in an error");
    assert!(
        !is_managed_reconnect_expired(&error),
        "a dispatched read must keep its first error, not claim it was not sent: {error:?}"
    );
    assert!(
        elapsed < BOUND + LATE_MARGIN,
        "the reconnect still ends at the bound: {elapsed:?}"
    );
    assert_eq!(
        peer.seen_opcode(Command::Get as u8).len(),
        1,
        "the read was dispatched once and never resent"
    );
    assert_ne!(client.quic().epoch.load(Ordering::Relaxed), 0);
}

/// Control: outside a managed scope the old loop still runs. The same command is still pending
/// well past twice the bound, so the bound is the managed scope's, not a global change.
#[tokio::test]
async fn an_unmanaged_put_with_the_server_unreachable_is_still_pending_after_twice_the_bound() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    make_unreachable(&peer).await;

    let (address, fragment, payload) = put_args();
    let pending = tokio::time::timeout(
        BOUND * 2 + Duration::from_secs(1),
        client.put_outcome(session, address, fragment, Some(payload)),
    )
    .await;
    assert!(
        pending.is_err(),
        "an unmanaged command keeps reconnecting past the managed bound: {pending:?}"
    );
    assert!(peer.seen_opcode(PUT).is_empty());
    // The timeout dropped the future mid-loop. The epoch is untouched because the loop has not
    // given up.
    assert_ne!(client.quic().epoch.load(Ordering::Relaxed), 0);
}

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
use lore_transport::quic::QuicClientError;
use lore_transport::quic::client::RecordOutcome;
use lore_transport::quic::client::SendFailure;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::client::reconnect_and_retry;
use lore_transport::quic::client::send_with_reconnect;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::MutableOutcome;
use lore_transport::replay::OutcomeUnknown;
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

async fn connect(peer: &Peer) -> Arc<StorageClient> {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "managed-reconnect-bound",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer")
}

/// A client with an open declared session, the connection live, and the managed bound shortened.
async fn client_with_session(peer: &Peer) -> (Arc<StorageClient>, u32) {
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

/// The guard at the top of `reconnect_and_retry` ends a dispatched `MutableNoReplay` before any
/// reconnect: no wait, so well under the bound.
fn assert_immediate(elapsed: Duration, what: &str) {
    assert!(
        elapsed < BOUND / 3,
        "{what}: a dispatched mutation must not wait for a reconnect: {elapsed:?}"
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

/// Run `command` managed against a peer that reads it and never answers, kill the peer once the
/// request was read, and return what the caller got and how long it took.
async fn lost_after_read<T>(
    peer: &Peer,
    opcode: u8,
    command: impl std::future::Future<Output = Result<T, ProtocolError>>,
) -> (Result<T, ProtocolError>, Duration) {
    let started = Instant::now();
    let run = async {
        tokio::time::timeout(
            BOUND + Duration::from_secs(40),
            with_caller_operation(managed_context(), command),
        )
        .await
        .expect("the managed command never ended: the reconnect loop is unbounded")
    };
    let kill = async {
        peer.wait_until("the request to be read", |peer| {
            !peer.seen_opcode(opcode).is_empty()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        make_unreachable(peer).await;
    };
    let (result, ()) = tokio::join!(run, kill);
    (result, started.elapsed())
}

/// A replay-safe read (`ReadRetryable`) that reached the wire, was never answered, and then lost
/// its connection gets the managed expiry at the bound: asking again is safe, and the caller must
/// learn the bound fired. It is NOT the not-sent proof (the read may have reached the server), and
/// it is never resent.
#[tokio::test]
async fn a_dispatched_read_whose_connection_dies_gets_the_read_expiry_at_the_bound() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    peer.rule(Command::Get as u8, Reply::Silent);

    let address = put_args().0;
    let (result, elapsed) =
        lost_after_read(&peer, Command::Get as u8, client.get(session, &address)).await;

    let error = result.expect_err("a lost read ends in an error");
    assert!(
        is_managed_reconnect_expired(&error),
        "a dispatched read that hit the deadline reports the expiry: {error:?}"
    );
    let text = format!("{error} | {error:?}");
    assert!(
        text.contains("after the read was sent") && !text.contains("before the command was sent"),
        "it must not claim the read was not sent: {text}"
    );
    assert!(!error.is_outcome_unknown(), "{error:?}");
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

/// A managed Put whose answer is lost because the peer read it and then died is a lost answer,
/// never the managed expiry. This pins the 2b answer-bound outcome as seen from the reconnect
/// tests: the Put is `is_unjournaled_answer_lost`, is sent once, and is not
/// `is_managed_reconnect_expired`. It does NOT reach the reconnect deadline: the lost answer is
/// classified before any reconnect starts (a mutation that gave dispatched mutations the expiry
/// at the deadline is not caught here, and no harness reaches that arm).
#[tokio::test]
async fn a_managed_put_lost_to_a_dying_connection_is_a_lost_answer_not_the_managed_expiry() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    peer.rule(PUT, Reply::Silent);

    let (address, fragment, payload) = put_args();
    let (result, elapsed) = lost_after_read(
        &peer,
        PUT,
        client.put_outcome(session, address, fragment, Some(payload)),
    )
    .await;

    match result {
        Err(error) => {
            assert!(
                !is_managed_reconnect_expired(&error),
                "a dispatched write must keep its own error, not the managed expiry: {error:?}"
            );
            assert!(
                is_unjournaled_answer_lost(&error),
                "a managed write's lost answer is the unjournaled loss: {error:?}"
            );
        }
        Ok(MutableOutcome::Unknown(unknown)) => {
            panic!("a managed write handed back an unknown outcome as Ok: {unknown:?}")
        }
        Ok(MutableOutcome::Applied(())) => panic!("a silent peer cannot have answered"),
    }
    assert!(
        elapsed < BOUND + LATE_MARGIN,
        "the reconnect still ends at the bound: {elapsed:?}"
    );
    assert_eq!(peer.seen_opcode(PUT).len(), 1, "the Put was never resent");
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

/// What `reconnect_and_retry` returns when its managed deadline fires after `first_failure`, on a
/// connection whose peer is gone, for `request`. Calls the function directly with the CURRENT
/// epoch: an older epoch means "someone else reconnected" and skips the deadline entirely.
///
/// Returns the error, the outcome sink contents and the elapsed time. The peer is dead, so a resend
/// is unobservable here; the no-resend proof is that the call returns at the deadline arm, before
/// any resend code runs.
async fn deadline_outcome(
    request: Command,
    first_failure: SendFailure,
    no_reconnect: bool,
) -> (ProtocolError, Option<OutcomeUnknown>, Duration) {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    make_unreachable(&peer).await;
    let sink = parking_lot::Mutex::new(None);
    let epoch = client.quic().epoch.load(Ordering::Relaxed);

    let started = Instant::now();
    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        lore_transport::with_managed_workflow(reconnect_and_retry::<_, _, 1, false, true>(
            &*client,
            request,
            session,
            || [Bytes::from_static(b"payload")],
            RecordOutcome(&sink),
            epoch,
            first_failure,
        )),
    )
    .await
    .expect("reconnect_and_retry never returned: the managed deadline did not arm");
    let elapsed = started.elapsed();

    let error = result.expect_err("an unreachable server never yields a reply");
    let recorded = sink.lock().clone();
    if no_reconnect {
        assert_eq!(
            client.quic().epoch.load(Ordering::Relaxed),
            epoch,
            "a dispatched mutation must not start a reconnect"
        );
    }
    (error, recorded, elapsed)
}

/// The storage client's `map_send_error` collapses an unknown outcome to `Disconnected`; the typed
/// `OutcomeUnknown` travels in the sink, exactly as `classify` reports it. So an unknown outcome is
/// the sink holding `Some` and the error being neither the expiry nor an answered refusal.
fn assert_collapsed_unknown(error: &ProtocolError, recorded: &Option<OutcomeUnknown>) {
    assert!(recorded.is_some(), "the sink must hold the unknown outcome");
    assert!(!is_managed_reconnect_expired(error), "{error:?}");
    assert!(error.is_disconnected(), "{error:?}");
}

/// A dispatched `MutableNoReplay` whose answer was lost is an unknown outcome: reported in the sink
/// and never the not-sent expiry. `reconnect_and_retry` returns at once, without a reconnect.
#[tokio::test]
async fn a_lost_mutable_answer_at_the_reconnect_deadline_is_an_unknown_outcome() {
    let (error, recorded, elapsed) = deadline_outcome(
        Command::Put,
        SendFailure::response_lost(QuicClientError::Read),
        true,
    )
    .await;

    assert_collapsed_unknown(&error, &recorded);
    assert_immediate(elapsed, "lost mutable answer");
}

/// The peer reported a lost lower transport: the same unknown outcome, even though the failure
/// itself was an answered one.
#[tokio::test]
async fn a_peer_reported_outcome_unknown_at_the_reconnect_deadline_stays_unknown() {
    let (error, recorded, elapsed) = deadline_outcome(
        Command::Put,
        SendFailure::answered(QuicClientError::OutcomeUnknown),
        true,
    )
    .await;

    assert_collapsed_unknown(&error, &recorded);
    assert_immediate(elapsed, "peer-reported unknown");
}

/// An answered failure is final: it keeps its own error, is not the expiry and is not recorded as
/// unknown.
#[tokio::test]
async fn an_answered_failure_at_the_reconnect_deadline_keeps_its_own_error() {
    let (error, recorded, elapsed) = deadline_outcome(
        Command::Put,
        SendFailure::answered(QuicClientError::NotFound),
        true,
    )
    .await;

    assert!(!is_managed_reconnect_expired(&error), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(recorded.is_none(), "an answered failure is not unknown");
    assert!(
        format!("{error:?}").to_lowercase().contains("notfound")
            || format!("{error}").to_lowercase().contains("not found"),
        "the answered error is kept: {error:?}"
    );
    assert_immediate(elapsed, "answered failure");
}

/// Not dispatched: the typed expiry, recorded as nothing.
#[tokio::test]
async fn a_not_dispatched_failure_at_the_reconnect_deadline_is_the_not_sent_expiry() {
    let (error, recorded, elapsed) = deadline_outcome(
        Command::Put,
        SendFailure::not_dispatched(QuicClientError::StreamOpen),
        false,
    )
    .await;

    assert_expired(&error, "not dispatched");
    assert!(recorded.is_none());
    assert_bounded(elapsed, "not dispatched");
}

/// A dispatched `ReadRetryable` still gets the dispatched expiry, not an unknown outcome.
#[tokio::test]
async fn a_dispatched_read_at_the_reconnect_deadline_still_gets_the_read_expiry() {
    let (error, recorded, elapsed) = deadline_outcome(
        Command::Get,
        SendFailure::response_lost(QuicClientError::Read),
        false,
    )
    .await;

    assert!(is_managed_reconnect_expired(&error), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(recorded.is_none());
    assert_bounded(elapsed, "dispatched read");
}

// ---- Executed no-resend proof: a dispatched `MutableNoReplay` is never sent again around the
// managed reconnect deadline. The peer stays alive and counts every `Put` header it reads.

/// The raw `Put` body the scripted peer reads. It does not parse a `Put`, only its framing.
fn raw_put() -> [Bytes; 1] {
    [Bytes::from(vec![0xA5u8; 64])]
}

/// Dispatch one `Put` for real to a peer that reads it and never answers, and wait until the peer
/// has counted it. The sending task is then aborted so it cannot act on the failure that follows.
async fn dispatch_silent_put(peer: &Peer, client: &Arc<StorageClient>, session: u32) {
    peer.rule(PUT, Reply::Silent);
    let sender = {
        let client = client.clone();
        lore_base::lore_spawn!(lore_transport::with_managed_workflow(async move {
            let sink = parking_lot::Mutex::new(None);
            let _ = send_with_reconnect::<_, _, 1, false, true>(
                &*client,
                Command::Put,
                session,
                raw_put,
                RecordOutcome(&sink),
            )
            .await;
        }))
    };
    peer.wait_until("the Put to reach the peer", |peer| {
        peer.seen_opcode(PUT).len() == 1
    })
    .await;
    sender.abort();
}

/// Let anything a bug would have sent after the call reach the peer before the count is read.
const GRACE: Duration = Duration::from_millis(700);

/// A `Put` was dispatched and its answer lost. Drive `reconnect_and_retry` at the current epoch in
/// a managed workflow. `peer_stays_reachable` decides what the peer does to the connection first.
async fn recover_lost_put(
    session_id_of: impl FnOnce(u32) -> u32,
    peer_stays_reachable: bool,
    failure: SendFailure,
) -> (
    ProtocolError,
    Option<OutcomeUnknown>,
    Duration,
    usize,
    Peer,
    Arc<StorageClient>,
) {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    dispatch_silent_put(&peer, &client, session).await;
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        1,
        "the Put was dispatched once"
    );

    if peer_stays_reachable {
        // The connection dies; the peer keeps accepting, so the reconnect succeeds.
        peer.close_connections();
        peer.wait_until("the connection to close", |peer| {
            peer.closed_connections() == peer.accepted_connections()
        })
        .await;
    } else {
        // Every new handshake fails until the deadline. The peer object stays alive and counting.
        make_unreachable(&peer).await;
    }

    let sink = parking_lot::Mutex::new(None);
    let epoch = client.quic().epoch.load(Ordering::Relaxed);
    let started = Instant::now();
    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        lore_transport::with_managed_workflow(reconnect_and_retry::<_, _, 1, false, true>(
            &*client,
            Command::Put,
            session_id_of(session),
            raw_put,
            RecordOutcome(&sink),
            epoch,
            failure,
        )),
    )
    .await
    .expect("reconnect_and_retry never returned");
    let elapsed = started.elapsed();
    tokio::time::sleep(GRACE).await;
    let error = result.expect_err("a lost Put is never answered");
    let recorded = sink.lock().clone();
    let puts = peer.seen_opcode(PUT).len();
    (error, recorded, elapsed, puts, peer, client)
}

/// A. A live, counting peer whose handshakes all fail: one dispatch, an unknown outcome, and an
/// immediate return (the guard at the top of `reconnect_and_retry` ends it before any reconnect).
#[tokio::test]
async fn a_dispatched_put_is_not_resent_when_the_reconnect_deadline_fires() {
    let (error, recorded, elapsed, puts, _peer, _client) = recover_lost_put(
        |session| session,
        false,
        SendFailure::response_lost(QuicClientError::Read),
    )
    .await;

    assert_eq!(puts, 1, "the Put must be dispatched exactly once");
    assert_collapsed_unknown(&error, &recorded);
    assert_immediate(elapsed, "dispatched put, dead peer");
}

/// B1. The connection is replaced before the deadline, with a session id: the id belongs to the
/// dead connection, so nothing may be framed on the new one. One dispatch.
#[tokio::test]
async fn a_dispatched_put_with_a_session_is_not_resent_on_the_replaced_connection() {
    let (error, recorded, elapsed, puts, peer, _client) = recover_lost_put(
        |session| session,
        true,
        SendFailure::response_lost(QuicClientError::Read),
    )
    .await;

    eprintln!(
        "B session!=0: puts={puts} connections={} elapsed={elapsed:?} sink={recorded:?} error={error:?}",
        peer.accepted_connections()
    );
    assert_eq!(puts, 1, "no second Put on the replacement connection");
    assert!(!is_managed_reconnect_expired(&error), "{error:?}");
}

/// B0. The same with session id 0: after a successful reconnect `reconnect_and_retry` sends again
/// when the id is 0. The guard at the top of the function keeps a dispatched mutation out of that
/// path; before the guard this test saw two Puts.
#[tokio::test]
async fn a_dispatched_put_without_a_session_is_not_resent_on_the_replaced_connection() {
    let (error, recorded, elapsed, puts, peer, _client) = recover_lost_put(
        |_| 0,
        true,
        SendFailure::response_lost(QuicClientError::Read),
    )
    .await;

    eprintln!(
        "B session==0: puts={puts} connections={} elapsed={elapsed:?} sink={recorded:?} error={error:?}",
        peer.accepted_connections()
    );
    assert_eq!(puts, 1, "no second Put on the replacement connection");
}

/// C. The real entry: `send_with_reconnect` for a `Put` in a managed workflow, against a live
/// peer that reads it and never answers. The silence is a lost answer at the managed bound: one
/// dispatch, the unknown outcome in the sink, about one bound, and no reconnect.
#[tokio::test]
async fn send_with_reconnect_dispatches_a_silent_put_once_and_reports_unknown() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    peer.rule(PUT, Reply::Silent);
    let sink = parking_lot::Mutex::new(None);

    let started = Instant::now();
    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        lore_transport::with_managed_workflow(send_with_reconnect::<_, _, 1, false, true>(
            &*client,
            Command::Put,
            session,
            raw_put,
            RecordOutcome(&sink),
        )),
    )
    .await
    .expect("send_with_reconnect never returned");
    let elapsed = started.elapsed();
    tokio::time::sleep(GRACE).await;

    let error = result.expect_err("a silent peer never answers");
    let recorded = sink.lock().clone();
    assert_eq!(peer.seen_opcode(PUT).len(), 1, "dispatched exactly once");
    assert_collapsed_unknown(&error, &recorded);
    assert_bounded(elapsed, "send_with_reconnect");
    assert_eq!(peer.accepted_connections(), 1, "no reconnect, no resend");
}

/// C0. As C, outside any session (id 0), the one shape where a reconnect would be followed by a
/// second send: `classify` keeps the lost `Put` from reaching the reconnect at all (the guard in
/// `reconnect_and_retry` is the second gate).
#[tokio::test]
async fn send_with_reconnect_without_a_session_dispatches_a_silent_put_once() {
    let peer = Peer::start();
    let (client, _) = client_with_session(&peer).await;
    peer.rule(PUT, Reply::Silent);
    let sink = parking_lot::Mutex::new(None);

    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        lore_transport::with_managed_workflow(send_with_reconnect::<_, _, 1, false, true>(
            &*client,
            Command::Put,
            0,
            raw_put,
            RecordOutcome(&sink),
        )),
    )
    .await
    .expect("send_with_reconnect never returned");
    tokio::time::sleep(GRACE).await;

    let error = result.expect_err("a silent peer never answers");
    let recorded = sink.lock().clone();
    assert_eq!(peer.seen_opcode(PUT).len(), 1, "dispatched exactly once");
    assert_collapsed_unknown(&error, &recorded);
}

/// B0 answered twin. An answered failure on a dispatched, session-less `Put`, with a peer that
/// accepts the reconnect: it keeps its own error, records nothing, and sends nothing more.
#[tokio::test]
async fn an_answered_put_without_a_session_is_not_resent_on_the_replaced_connection() {
    let (error, recorded, _elapsed, puts, _peer, _client) = recover_lost_put(
        |_| 0,
        true,
        SendFailure::answered(QuicClientError::NotFound),
    )
    .await;

    assert_eq!(puts, 1, "an answered Put is final and is never sent again");
    assert!(recorded.is_none(), "an answered failure is not unknown");
    assert!(!is_managed_reconnect_expired(&error), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(
        format!("{error:?}").to_lowercase().contains("notfound")
            || format!("{error}").to_lowercase().contains("not found"),
        "the answered error is kept: {error:?}"
    );
}

/// D. The deadline fires during the wait for the reconnect guard, so the OLD connection is still
/// open and the peer is reachable: a send in the deadline arm would be counted. A command that was
/// not dispatched gets the not-sent expiry after one bound, and the peer sees no `Put`.
#[cfg(feature = "test_seams")]
#[tokio::test]
async fn the_deadline_arm_sends_nothing_for_a_not_dispatched_put_on_a_live_connection() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    let guard = client.quic().hold_reconnect_guard_for_test().await;
    peer.rule(PUT, Reply::Silent);

    let sink = parking_lot::Mutex::new(None);
    let epoch = client.quic().epoch.load(Ordering::Relaxed);
    let started = Instant::now();
    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        lore_transport::with_managed_workflow(reconnect_and_retry::<_, _, 1, false, true>(
            &*client,
            Command::Put,
            session,
            raw_put,
            RecordOutcome(&sink),
            epoch,
            SendFailure::not_dispatched(QuicClientError::StreamOpen),
        )),
    )
    .await
    .expect("reconnect_and_retry never returned");
    let elapsed = started.elapsed();
    drop(guard);
    tokio::time::sleep(GRACE).await;

    let error = result.expect_err("the deadline ends the call");
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        0,
        "the deadline arm must not send the command"
    );
    assert_expired(&error, "not dispatched, guard held");
    assert!(sink.lock().is_none());
    assert_bounded(elapsed, "not dispatched, guard held");
    assert_eq!(peer.accepted_connections(), 1, "no reconnect happened");
}

/// C, dispatched. The same hold, a `Put` that was dispatched and lost: one dispatch, an unknown
/// outcome, at once. The old connection is open, so a send in any branch would be counted.
#[cfg(feature = "test_seams")]
#[tokio::test]
async fn the_deadline_arm_sends_nothing_for_a_dispatched_put_on_a_live_connection() {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    dispatch_silent_put(&peer, &client, session).await;
    let guard = client.quic().hold_reconnect_guard_for_test().await;

    let sink = parking_lot::Mutex::new(None);
    let epoch = client.quic().epoch.load(Ordering::Relaxed);
    let started = Instant::now();
    let result = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        lore_transport::with_managed_workflow(reconnect_and_retry::<_, _, 1, false, true>(
            &*client,
            Command::Put,
            session,
            raw_put,
            RecordOutcome(&sink),
            epoch,
            SendFailure::response_lost(QuicClientError::Read),
        )),
    )
    .await
    .expect("reconnect_and_retry never returned");
    let elapsed = started.elapsed();
    drop(guard);
    tokio::time::sleep(GRACE).await;

    let error = result.expect_err("a lost Put is never answered");
    let recorded = sink.lock().clone();
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        1,
        "a dispatched Put is never sent again"
    );
    assert_collapsed_unknown(&error, &recorded);
    assert_immediate(elapsed, "dispatched, guard held");
}

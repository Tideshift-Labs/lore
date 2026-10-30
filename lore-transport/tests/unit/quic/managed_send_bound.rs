// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! WP-124 slice 2b: the no-progress bound on a managed QUIC write, and what a lost answer means
//! inside a managed scope.
//!
//! Every case drives the real `StorageClient` against the scripted peer in
//! `scripted_storage_peer.rs`, so the bytes the client frames, the credit it waits for and the
//! answers it gets are the wire's, not a stand-in's.
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
use lore_base::types::KeyType;
use lore_base::types::Partition;
use lore_base::types::RepositoryId;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use lore_transport::CallerOperationContext;
use lore_transport::LockOwnership;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::VolatileAttemptStore;
use lore_transport::auth::authentication;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::error::ProtocolError;
use lore_transport::error::is_quic_declaration_refused;
use lore_transport::error::is_unjournaled_answer_lost;
use lore_transport::error::is_unsupported_client;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::MutableOutcome;
use lore_transport::traits::Authentication;
use lore_transport::types::AuthSession;
use lore_transport::types::AuthenticationToken;
use lore_transport::types::AuthorizationToken;
use lore_transport::with_caller_operation;
use uuid::Uuid;
use zerocopy::IntoBytes;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;
use super::scripted_storage_peer::WINDOW;

const PUT: u8 = Command::Put as u8;

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

async fn connect(peer: &Peer) -> StorageClient {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "",
        "managed-send-bound",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer")
}

/// Open all eight streams and settle on the one a sequential caller keeps using.
///
/// Streams open lazily, one per command until all exist, and a caller with one request at a time
/// then stays on the lowest stream outside the two reserved for metadata. Nine round trips are
/// enough to get there. Returns the session id and that stream's index on the peer.
async fn warm_up(peer: &Peer, client: &StorageClient) -> (u32, usize) {
    let mut session = 0;
    for _ in 0..9 {
        session = client
            .session_start(partition(), "warm-up")
            .await
            .expect("session start");
    }
    assert_eq!(client.quic().stream_count.load(Ordering::Relaxed), 8);
    let last = peer.seen().last().cloned().expect("a command was seen");
    (session, last.stream)
}

/// A `Put` of `payload_len` payload bytes at a fresh address. The peer never validates it.
fn put_args(payload_len: usize) -> (Address, Fragment, Bytes) {
    let address = Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    };
    let fragment = Fragment {
        flags: 0,
        size_payload: payload_len as u32,
        size_content: payload_len as u64,
    };
    (address, fragment, Bytes::from(vec![0xA5u8; payload_len]))
}

/// The peer and the client agree on the stream layout the other cases rely on: a sequential
/// caller settles on one stream, and what the peer has read there stays under the threshold at
/// which quinn would raise the client's credit.
#[tokio::test]
async fn a_sequential_caller_settles_on_one_stream_below_the_credit_refresh_threshold() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let (session, stream) = warm_up(&peer, &client).await;

    let (address, fragment, payload) = put_args(100);
    client
        .put(session, address, fragment, Some(payload))
        .await
        .expect("put");
    let seen = peer.seen_opcode(PUT);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].stream, stream,
        "a sequential caller stays on its stream"
    );
    assert!(
        peer.bytes_read_on_stream(stream) < WINDOW / 8,
        "the setup must stay below the peer's credit refresh threshold, got {}",
        peer.bytes_read_on_stream(stream)
    );
}

/// Frame overhead of a `Put` ahead of its payload: header (12) + `Address` (48) + `Fragment` (16).
const PUT_OVERHEAD: u64 = 12 + 48 + 16;

/// Fill the client's remaining credit on `stream` to the byte with a write that completes.
///
/// The peer answers the filler from its header alone and then stops reading (gate closed), so the
/// client's `put` returns while the stream has no credit left. Everything the client sent so far
/// on this stream the peer has read, and the peer reads too little to ever raise the credit, so
/// the remainder is `WINDOW` minus what the peer counted. The next write on this stream is then
/// accepted zero bytes until the gate opens.
async fn fill_stream_credit(peer: &Peer, client: &StorageClient, session: u32, stream: usize) {
    peer.rule(PUT, Reply::EarlyOk);
    peer.close_gate();
    let remaining = WINDOW - peer.bytes_read_on_stream(stream);
    let (address, fragment, payload) = put_args((remaining - PUT_OVERHEAD) as usize);
    tokio::time::timeout(
        Duration::from_secs(5),
        client.put(session, address, fragment, Some(payload)),
    )
    .await
    .expect("the filler fits the credit exactly, so its write completes")
    .expect("filler put");
    peer.rule(PUT, Reply::Ok(Vec::new()));
}

/// Pin the fixture's flow control on today's code, with nothing managed: a write that fits the
/// credit exactly completes, and the next one is accepted no bytes while the peer's gate is
/// closed, then goes through when it opens. Unmanaged, nothing times it out.
#[tokio::test]
async fn an_exact_fill_completes_and_the_next_write_waits_for_credit() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let (session, stream) = warm_up(&peer, &client).await;

    fill_stream_credit(&peer, &client, session, stream).await;

    let (address, fragment, payload) = put_args(64);
    let blocked = tokio::time::timeout(
        Duration::from_millis(700),
        client.put(session, address, fragment, Some(payload)),
    )
    .await;
    assert!(
        blocked.is_err(),
        "a stream with no credit must not take the write"
    );

    peer.open_gate();
    let (address, fragment, payload) = put_args(64);
    client
        .put(session, address, fragment, Some(payload))
        .await
        .expect("the write goes through once the peer reads again");
}
// ---------------------------------------------------------------------------------------------
// Managed scope, outcome mapping, typed refusals
// ---------------------------------------------------------------------------------------------

fn managed_context() -> CallerOperationContext {
    CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    )
}

/// A fresh client on its own peer with a declared session, as a managed push would hold it.
async fn declared_session(peer: &Peer, client: &StorageClient) -> u32 {
    let _ = peer;
    client
        .session_start_declared(partition(), "managed", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0
}

/// The three unjournaled fragment writes, one verb each.
#[derive(Clone, Copy, Debug)]
enum Write {
    Put,
    Copy,
    PutResolved,
}

impl Write {
    const ALL: [Write; 3] = [Write::Put, Write::Copy, Write::PutResolved];

    fn opcode(self) -> u8 {
        match self {
            Write::Put => Command::Put as u8,
            Write::Copy => Command::Copy as u8,
            Write::PutResolved => Command::PutResolved as u8,
        }
    }

    async fn run(
        self,
        client: &StorageClient,
        session: u32,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        let (address, fragment, payload) = put_args(64);
        match self {
            Write::Put => {
                client
                    .put_outcome(session, address, fragment, Some(payload))
                    .await
            }
            Write::Copy => {
                client
                    .copy_outcome(session, partition(), address, Context::from([7u8; 16]))
                    .await
            }
            Write::PutResolved => {
                let key = Hash::from([9u8; 32]);
                client
                    .put_resolved_outcome(session, &key, address, fragment, Some(payload))
                    .await
            }
        }
    }
}

/// Wait long enough for a stray resend or reconnect to show up on the wire.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

#[tokio::test]
async fn outside_a_scope_a_lost_answer_is_still_mutable_outcome_unknown() {
    for write in Write::ALL {
        let peer = Peer::start();
        let client = connect(&peer).await;
        let session = declared_session(&peer, &client).await;
        peer.rule(write.opcode(), Reply::Disconnect);

        let outcome = write.run(&client, session).await.unwrap_or_else(|error| {
            panic!("{write:?}: an unmanaged lost answer is not an Err: {error:?}")
        });
        assert!(
            matches!(outcome, MutableOutcome::Unknown(_)),
            "{write:?}: unmanaged behavior must not change"
        );
        settle().await;
        assert_eq!(
            peer.seen_opcode(write.opcode()).len(),
            1,
            "{write:?}: one dispatch, never resent"
        );
    }
}

#[tokio::test]
async fn in_a_scope_a_lost_answer_is_unjournaled_answer_lost_and_never_resent() {
    for write in Write::ALL {
        let peer = Peer::start();
        let client = connect(&peer).await;
        let session = declared_session(&peer, &client).await;
        peer.rule(write.opcode(), Reply::Disconnect);

        let result = with_caller_operation(managed_context(), write.run(&client, session)).await;
        let error = result.expect_err(&format!("{write:?}: a managed lost answer must be an Err"));
        assert!(is_unjournaled_answer_lost(&error), "{write:?}: {error:?}");
        assert!(
            !error.is_outcome_unknown(),
            "{write:?}: must not read as OutcomeUnknown"
        );
        settle().await;
        assert_eq!(
            peer.seen_opcode(write.opcode()).len(),
            1,
            "{write:?}: one dispatch, never resent"
        );
    }
}

/// A positive control for the two above: in a scope, an answered write is admitted and applied.
#[tokio::test]
async fn in_a_scope_an_answered_write_reaches_the_wire_and_succeeds() {
    for write in Write::ALL {
        let peer = Peer::start();
        let client = connect(&peer).await;
        let session = declared_session(&peer, &client).await;

        let outcome = with_caller_operation(managed_context(), write.run(&client, session))
            .await
            .unwrap_or_else(|error| {
                panic!("{write:?}: managed write must not be refused: {error:?}")
            });
        assert!(matches!(outcome, MutableOutcome::Applied(())), "{write:?}");
        assert_eq!(peer.seen_opcode(write.opcode()).len(), 1, "{write:?}");
    }
}

#[tokio::test]
async fn status_200_is_an_unsupported_client_never_unknown_or_slow_down() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let session = declared_session(&peer, &client).await;
    let (address, _, _) = put_args(0);

    for opcode in [
        Command::Put as u8,
        Command::Copy as u8,
        Command::PutResolved as u8,
        Command::Get as u8,
        Command::Query as u8,
        Command::Verify as u8,
    ] {
        peer.rule(opcode, Reply::Status(200));
    }
    let mut errors = Vec::new();
    for write in Write::ALL {
        errors.push((
            format!("{write:?}"),
            write
                .run(&client, session)
                .await
                .map(|_| ())
                .expect_err("200 is an error"),
        ));
    }
    errors.push((
        "Get".into(),
        client
            .get(session, &address)
            .await
            .map(|_| ())
            .expect_err("200 is an error"),
    ));
    errors.push((
        "Query".into(),
        client
            .query(session, &[address])
            .await
            .map(|_| ())
            .expect_err("200 is an error"),
    ));
    errors.push((
        "Verify".into(),
        client
            .verify(session, &address, false)
            .await
            .map(|_| ())
            .expect_err("200 is an error"),
    ));
    for (name, error) in errors {
        assert!(is_unsupported_client(&error), "{name}: {error:?}");
        assert!(!error.is_outcome_unknown(), "{name}: {error:?}");
        assert!(!error.is_slow_down(), "{name}: {error:?}");
    }
}

#[tokio::test]
async fn status_200_on_a_declared_authorize_stays_a_declaration_refusal() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    peer.rule(Command::Authorize as u8, Reply::Status(200));

    let error = client
        .session_start_declared(partition(), "managed", "outcome_unknown_v1")
        .await
        .expect_err("a refused declaration");
    assert!(is_quic_declaration_refused(&error), "{error:?}");
    assert!(
        !is_unsupported_client(&error),
        "Authorize keeps its slice 2a mapping: {error:?}"
    );
}

#[tokio::test]
async fn a_managed_mutable_key_write_is_refused_before_any_wire_byte() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let session = declared_session(&peer, &client).await;
    let headers_before = peer.seen().len();
    let key = Hash::from([1u8; 32]);
    let value = Hash::from([2u8; 32]);

    let store = with_caller_operation(
        managed_context(),
        client.mutable_store_outcome(session, key, value, KeyType::Untyped),
    )
    .await
    .expect_err("managed MutableStore over QUIC is refused");
    let cas = with_caller_operation(
        managed_context(),
        client.mutable_compare_and_swap_outcome(
            session,
            key,
            Hash::default(),
            value,
            KeyType::Untyped,
        ),
    )
    .await
    .expect_err("managed MutableCas over QUIC is refused");
    for error in [store, cas] {
        assert!(
            error
                .to_string()
                .contains("managed mutable-key writes require gRPC")
                || format!("{error:?}").contains("managed mutable-key writes require gRPC"),
            "{error:?}"
        );
    }
    settle().await;
    assert_eq!(
        peer.seen().len(),
        headers_before,
        "a refused write puts nothing on the wire"
    );

    // Positive controls: the same verbs outside a scope go out, and a managed read is untouched.
    client
        .mutable_store(session, key, value, KeyType::Untyped)
        .await
        .expect("unmanaged mutable store");
    assert_eq!(peer.seen_opcode(Command::MutableStore as u8).len(), 1);
}

// ---------------------------------------------------------------------------------------------
// The three-phase send bound
// ---------------------------------------------------------------------------------------------

/// Short enough to keep the cases fast, long enough to span two keep-alive intervals (500 ms),
/// so a stall that outlasts the bound is also one the keep-alive PINGs did not break.
const BOUND: Duration = Duration::from_millis(1200);

/// A managed `Put` of `payload_len` bytes, timed.
async fn managed_put(
    client: &StorageClient,
    session: u32,
    address: Address,
    fragment: Fragment,
    payload: Bytes,
) -> (Result<MutableOutcome<()>, ProtocolError>, Duration) {
    let started = Instant::now();
    // A missing bound must fail red, not hang: cut the call off at ten times the shortened bound.
    let result = tokio::time::timeout(
        BOUND * 10,
        with_caller_operation(
            managed_context(),
            client.put_outcome(session, address, fragment, Some(payload)),
        ),
    )
    .await
    .expect("the managed Put outlasted ten times the idle bound: the send is unbounded");
    (result, started.elapsed())
}

/// Which proof of "no byte left" a not-dispatched managed write must carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotSent {
    /// Phase 1: the stream's writer lock never freed (`QuicClientError::WriterLockTimeout`).
    WriterLockTimeout,
    /// Phase 2 before any byte: the stream took none (`QuicClientError::WriteTimeout`).
    WriteTimeout,
    /// The write boundary refused a session id from a replaced connection (the rebind proof the
    /// session layer resends on).
    RebindRequired,
}

impl NotSent {
    const ALL: [NotSent; 3] = [
        NotSent::WriterLockTimeout,
        NotSent::WriteTimeout,
        NotSent::RebindRequired,
    ];

    /// The text only this proof renders. `SessionRebindRequired` is `pub(crate)` and cannot be
    /// named from here, so the proof is read off the message the transport gives it.
    fn marker(self) -> &'static str {
        match self {
            NotSent::WriterLockTimeout => {
                "No progress on the stream writer within the managed idle bound"
            }
            NotSent::WriteTimeout => {
                "The stream accepted no byte of the command within the managed idle bound"
            }
            NotSent::RebindRequired => "storage command was not dispatched",
        }
    }
}

/// The error is exactly the not-dispatched proof `expected`, and is neither a lost answer nor an
/// unknown outcome. A bare "is not a lost answer" would pass for any unrelated failure.
fn assert_not_dispatched(error: &ProtocolError, expected: NotSent, what: &str) {
    let text = format!("{error} | {error:?}");
    assert!(
        text.contains(expected.marker()),
        "{what}: expected {expected:?} ({:?}), got {text}",
        expected.marker()
    );
    for other in NotSent::ALL.into_iter().filter(|other| *other != expected) {
        assert!(
            !text.contains(other.marker()),
            "{what}: expected only {expected:?}, but it also reads as {other:?}: {text}"
        );
    }
    assert!(!is_unjournaled_answer_lost(error), "{what}: {error:?}");
    assert!(!error.is_outcome_unknown(), "{what}: {error:?}");
    assert!(!error.is_disconnected(), "{what}: {error:?}");
    assert!(!text.contains("lost its answer"), "{what}: {text}");
}

/// Phase 3. The write completes, the peer reads it and never answers.
#[tokio::test]
async fn a_managed_put_whose_answer_never_comes_is_a_lost_answer_after_the_bound() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let session = declared_session(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    peer.rule(PUT, Reply::Silent);

    let (address, fragment, payload) = put_args(64);
    let (result, elapsed) = managed_put(&client, session, address, fragment, payload).await;

    let error = result.expect_err("a silent peer ends a managed Put");
    assert!(is_unjournaled_answer_lost(&error), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(
        elapsed >= BOUND - Duration::from_millis(100),
        "fired early: {elapsed:?}"
    );
    assert!(
        elapsed < BOUND + Duration::from_secs(5),
        "fired late: {elapsed:?}"
    );
    settle().await;
    assert_eq!(peer.seen_opcode(PUT).len(), 1, "never resent");
}

/// Phase 3 keeps the command's entry in the reader's pending map, so the answer that arrives
/// after the bound is only dropped: it does not kill the reader and with it the connection.
#[tokio::test]
async fn a_late_answer_after_the_bound_leaves_the_connection_usable() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let session = declared_session(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    peer.rule(PUT, Reply::Hold(Vec::new()));

    let (address, fragment, payload) = put_args(64);
    let (result, _) = managed_put(&client, session, address, fragment, payload).await;
    assert!(is_unjournaled_answer_lost(&result.expect_err("bounded")));

    assert_eq!(peer.release_held().await, 1, "the held answer is sent late");
    settle().await;
    // The connection that carried the late answer still serves the next command.
    let (address, fragment, payload) = put_args(64);
    peer.rule(PUT, Reply::Ok(Vec::new()));
    let (second, _) = managed_put(&client, session, address, fragment, payload).await;
    second.expect("the same connection serves the next managed Put");
    assert_eq!(peer.accepted_connections(), 1, "no reconnect");
    assert_eq!(
        peer.closed_connections(),
        0,
        "the late answer closed nothing"
    );
}

/// Phase 2 before any byte: the stream has no credit, so this command's `write_chunks` accepts
/// nothing. Nothing was dispatched, the connection stays, and sending it again is safe.
#[tokio::test]
async fn a_write_stalled_before_its_first_byte_is_not_dispatched_and_keeps_the_connection() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let (session, stream) = warm_up(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    fill_stream_credit(&peer, &client, session, stream).await;
    let puts_before = peer.seen_opcode(PUT).len();

    let (address, fragment, payload) = put_args(64);
    let (result, elapsed) = managed_put(&client, session, address, fragment, payload.clone()).await;
    let error = result.expect_err("no credit, no progress");
    assert_not_dispatched(&error, NotSent::WriteTimeout, "zero-byte write stall");
    assert!(
        elapsed >= BOUND - Duration::from_millis(100),
        "fired early: {elapsed:?}"
    );
    assert_eq!(peer.closed_connections(), 0, "the connection stays open");
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        puts_before,
        "no header of this command left"
    );

    // Safe to retry: the peer reads again and the retried command is the only copy.
    peer.open_gate();
    let (retried, _) = managed_put(&client, session, address, fragment, payload).await;
    retried.expect("the retry is served on the same connection");
    peer.wait_until("the retried Put to be read", |peer| {
        peer.done_heads(PUT)
            .iter()
            .any(|head| head.as_slice() == address.as_bytes())
    })
    .await;
    let copies = peer
        .done_heads(PUT)
        .iter()
        .filter(|head| head.as_slice() == address.as_bytes())
        .count();
    assert_eq!(
        copies, 1,
        "exactly one copy of the command reached the peer"
    );
    assert_eq!(peer.accepted_connections(), 1);
    assert_eq!(peer.closed_connections(), 0);
}

/// Phase 2 after a partial write: some of the frame is out and the peer stops reading while the
/// keep-alive PINGs keep flowing. The client closes the connection that carried the send, the
/// result is a lost answer, and the command is never sent again.
#[tokio::test]
async fn a_write_stalled_after_a_partial_write_closes_the_connection_and_is_never_replayed() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let (session, _stream) = warm_up(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    peer.close_gate();

    // Larger than the stream's credit, so part of the frame is accepted and the rest is not.
    let (address, fragment, payload) = put_args(4 * WINDOW as usize);
    let (result, elapsed) = managed_put(&client, session, address, fragment, payload).await;

    let error = result.expect_err("the stalled write ends");
    assert!(is_unjournaled_answer_lost(&error), "{error:?}");
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(
        elapsed >= BOUND - Duration::from_millis(100),
        "keep-alive traffic must not count as progress: {elapsed:?}"
    );
    peer.wait_until("the connection to be closed", |peer| {
        peer.closed_connections() == 1
    })
    .await;
    settle().await;
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        1,
        "the command is never replayed"
    );
    assert_eq!(
        peer.accepted_connections(),
        1,
        "and no replacement was needed to try"
    );
}

/// The same stall without a managed scope: no timer runs. The write waits as long as the peer
/// does, whatever the bound was set to.
#[tokio::test]
async fn an_unmanaged_write_has_no_send_bound() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let (session, stream) = warm_up(&peer, &client).await;
    client
        .quic()
        .set_managed_idle_for_test(Duration::from_millis(300));
    fill_stream_credit(&peer, &client, session, stream).await;

    let (address, fragment, payload) = put_args(64);
    let waiting = tokio::time::timeout(
        Duration::from_millis(1500),
        client.put_outcome(session, address, fragment, Some(payload)),
    )
    .await;
    assert!(
        waiting.is_err(),
        "an unmanaged write is not cut: {waiting:?}"
    );
    assert_eq!(peer.closed_connections(), 0);
}

/// Occupy the streams so a managed Put queues behind a stalled writer on one stream.
///
/// A sequential caller sits on the lowest stream outside the two metadata streams (`stream`).
/// Selection balances on commands outstanding, ties to the lowest index, so: six held reads put
/// one outstanding command on each of streams `2..8`, the one on `stream` is answered, and the
/// writer that then stalls lands on `stream` too. Every stream is now at one, and the next normal
/// command ties to `stream`, behind that writer.
async fn queue_behind_a_stalled_writer(
    peer: &Arc<Peer>,
    client: &Arc<StorageClient>,
    session: u32,
    stream: usize,
    writer_payload: usize,
    close_gate_for_writer: bool,
    managed_writer: bool,
) -> tokio::task::JoinHandle<Result<(), ProtocolError>> {
    peer.rule(Command::Query as u8, Reply::Hold(vec![0]));
    for round in 1..=6usize {
        let client = client.clone();
        let (address, _, _) = put_args(0);
        lore_base::lore_spawn!(async move {
            let _ = client.query(session, &[address]).await;
        });
        peer.wait_until("a held read to arrive", |peer| {
            peer.seen_opcode(Command::Query as u8).len() == round
        })
        .await;
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        peer.release_held_on_stream(stream).await,
        1,
        "one read on the target stream {stream}: {:?}",
        peer.seen_opcode(Command::Query as u8)
    );
    if close_gate_for_writer {
        peer.close_gate();
    }
    // The answered read finishes on its own task; give it a moment to drop its in-flight count.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let writer = {
        let client = client.clone();
        let (address, fragment, payload) = put_args(writer_payload);
        lore_base::lore_spawn!(async move {
            if managed_writer {
                with_caller_operation(
                    managed_context(),
                    client.put_outcome(session, address, fragment, Some(payload)),
                )
                .await
                .map(|_| ())
            } else {
                client.put(session, address, fragment, Some(payload)).await
            }
        })
    };
    peer.wait_until("the writer's header to arrive", |peer| {
        peer.seen_opcode(PUT)
            .iter()
            .any(|seen| seen.stream == stream)
    })
    .await;
    writer
}

/// Phase 1: the stream's writer lock is held by a writer that has stopped making progress. The
/// managed command that queues behind it is not dispatched: no byte of it was written.
#[tokio::test]
async fn a_managed_put_queued_behind_a_stalled_writer_is_not_dispatched() {
    let peer = Arc::new(Peer::start());
    let client = Arc::new(connect(&peer).await);
    let (session, stream) = warm_up(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    let writer = queue_behind_a_stalled_writer(
        &peer,
        &client,
        session,
        stream,
        4 * WINDOW as usize,
        true,
        false,
    )
    .await;

    let (address, fragment, payload) = put_args(64);
    let (result, elapsed) = managed_put(&client, session, address, fragment, payload).await;
    let error = result.expect_err("the lock never frees");
    assert_not_dispatched(&error, NotSent::WriterLockTimeout, "writer-lock wait");
    assert!(
        elapsed >= BOUND - Duration::from_millis(100),
        "fired early: {elapsed:?}"
    );
    assert_eq!(peer.closed_connections(), 0, "classify gives no reconnect");
    assert_eq!(peer.accepted_connections(), 1);
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        1,
        "only the stalled writer's header reached the peer"
    );

    peer.open_gate();
    tokio::time::timeout(BOUND * 10, writer)
        .await
        .expect("the stalled writer never finished")
        .expect("writer task")
        .expect("the stalled writer completes once read");
}

/// A lock holder that keeps writing is progress for its waiters, however long its upload takes.
#[tokio::test]
async fn a_managed_put_queued_behind_a_writer_that_keeps_writing_is_not_cut() {
    a_waiter_behind_a_trickling_writer_is_served(false).await;
}

/// The same, with the lock holder itself a managed write. A managed writer takes the lock through
/// `send_bounded`, which stamps the stream's progress on its own; if that stamp stopped moving, a
/// waiter behind a long managed upload would read the stream as dead and get a false
/// `WriterLockTimeout`, which is safe (not dispatched) but fails the push.
#[tokio::test]
async fn a_managed_put_queued_behind_a_managed_writer_that_keeps_writing_is_not_cut() {
    a_waiter_behind_a_trickling_writer_is_served(true).await;
}

async fn a_waiter_behind_a_trickling_writer_is_served(managed_writer: bool) {
    let peer = Arc::new(Peer::start());
    let client = Arc::new(connect(&peer).await);
    let (session, stream) = warm_up(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    // Trickle: the peer reads 2 KiB every 50 ms, and quinn grants more credit each 2 KiB, so the
    // writer advances about every 50-200 ms for a few seconds, well past BOUND in total but
    // never silent for BOUND.
    let writer = {
        peer.throttle(2048, Duration::from_millis(50));
        queue_behind_a_stalled_writer(
            &peer,
            &client,
            session,
            stream,
            200 * 1024,
            false,
            managed_writer,
        )
        .await
    };

    let started = Instant::now();
    let (address, fragment, payload) = put_args(64);
    let (result, elapsed) = managed_put(&client, session, address, fragment, payload).await;
    let served = result.unwrap_or_else(|error| {
        panic!(
            "a waiter behind a live {} writer was cut after {elapsed:?}, the false timeout a \
             stalled stamp gives: {error:?}",
            if managed_writer {
                "managed"
            } else {
                "unmanaged"
            }
        )
    });
    assert!(matches!(served, MutableOutcome::Applied(())), "{served:?}");
    assert!(
        started.elapsed() > BOUND,
        "the case is only meaningful if the wait outlasted the bound: {elapsed:?}"
    );
    tokio::time::timeout(BOUND * 10, writer)
        .await
        .expect("the trickling writer never finished")
        .expect("writer task")
        .expect("a writer that keeps being read is never cut");
    assert_eq!(peer.closed_connections(), 0);
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        2,
        "the writer and the waiter each reached the peer once"
    );
}

// ---------------------------------------------------------------------------------------------
// Healing Verify inside a managed scope is journaled through `dispatch`
// ---------------------------------------------------------------------------------------------

const HEAL_SCHEME: &str = "wp124-heal-stub";
const HEAL_IDENTITY: &str = "wp124-heal-identity";

fn base64_url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::new();
    for chunk in input.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(ALPHABET[((bits >> 18) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((bits >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[((bits >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(bits & 0x3f) as usize] as char);
        }
    }
    encoded
}

/// An unsigned far-future JWT carrying the issuer and subject a journal row binds.
fn unsigned_jwt(subject: &str) -> String {
    let header = base64_url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = format!(
        r#"{{"iss":"auth.example.com","sub":"{subject}","name":"Test User","exp":4102444800,"aud":["127.0.0.1","localhost"]}}"#
    );
    format!("{header}.{}.", base64_url(payload.as_bytes()))
}

/// Grants every repository exchange with a token for `HEAL_IDENTITY`.
struct GrantingAuthentication;

#[async_trait::async_trait]
impl Authentication for GrantingAuthentication {
    async fn start_auth_session(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<AuthSession, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn poll_auth_session(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn exchange_external_token(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn refresh_authentication(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }

    async fn exchange_for_repository(
        &self,
        _: &str,
        _: &str,
        _: RepositoryId,
        _: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Ok(AuthorizationToken {
            token: unsigned_jwt(HEAL_IDENTITY),
            expires_ms: u64::MAX,
            acceptable_root_domains: Vec::new(),
        })
    }

    async fn exchange_for_custom_resource(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Err(ProtocolError::internal("repository exchanges only"))
    }
}

async fn authenticated_client(peer: &Peer) -> StorageClient {
    // Process-global registry: a second registration of the same scheme is an error we ignore.
    let _ = authentication::add(HEAL_SCHEME, Arc::new(GrantingAuthentication));
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        &format!("{HEAL_SCHEME}://auth.example.com"),
        HEAL_IDENTITY,
        partition(),
        &Arc::new(SuppliedCredentials::new(&unsigned_jwt(HEAL_IDENTITY), "")),
        None,
    )
    .await
    .expect("connect with a stub authentication")
}

/// A journal that accepts managed intents and keeps them, over the volatile store.
#[derive(Default)]
struct ManagedJournal {
    inner: VolatileAttemptStore,
    intents: parking_lot::Mutex<Vec<ManagedAttemptIntent>>,
}

#[async_trait::async_trait]
impl AttemptStore for ManagedJournal {
    async fn record_managed(
        &self,
        record: &AttemptRecord,
        intent: &ManagedAttemptIntent,
    ) -> Result<(), ProtocolError> {
        self.inner.record(record).await?;
        self.intents.lock().push(intent.clone());
        Ok(())
    }
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        self.inner.record(record).await
    }
    async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        self.inner.lookup(id).await
    }
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        self.inner.unresolved().await
    }
    async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
        self.inner.record_ownership(ownership).await
    }
    async fn ownership_for(
        &self,
        context: &Context,
        hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        self.inner.ownership_for(context, hash).await
    }
    async fn clear_ownership(&self, context: &Context, hash: &Hash) -> Result<(), ProtocolError> {
        self.inner.clear_ownership(context, hash).await
    }
    async fn resolve(
        &self,
        id: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        self.inner.resolve(id, resolution).await
    }
}
fn scope_over(store: &Arc<ManagedJournal>) -> CallerOperationContext {
    CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        store.clone(),
    )
}

#[tokio::test]
async fn a_healing_verify_in_a_scope_is_journaled_as_storage_verify_and_settles_applied() {
    let peer = Peer::start();
    let client = authenticated_client(&peer).await;
    let session = declared_session(&peer, &client).await;
    peer.rule(Command::Verify as u8, Reply::Ok(vec![1, 1]));
    let store = Arc::new(ManagedJournal::default());
    let scope = scope_over(&store);
    let (address, _, _) = put_args(0);

    let outcome = with_caller_operation(
        scope.clone(),
        client.verify_outcome(session, &address, true),
    )
    .await
    .expect("a journaled healing verify");
    assert!(matches!(outcome, MutableOutcome::Applied(_)));

    let attempt = scope
        .latest_attempt()
        .expect("the dispatch recorded an attempt");
    let record = store
        .lookup(&attempt)
        .await
        .expect("lookup")
        .expect("a journal row");
    assert_eq!(record.operation, "StorageService.Verify");
    assert_eq!(
        record.state,
        AttemptState::Resolved(AttemptResolution::Applied)
    );
    assert!(store.unresolved().await.expect("unresolved").is_empty());
    assert_eq!(peer.seen_opcode(Command::Verify as u8).len(), 1);
}

#[tokio::test]
async fn a_healing_verify_whose_answer_is_lost_stays_outcome_unknown_and_unresolved() {
    let peer = Peer::start();
    let client = authenticated_client(&peer).await;
    let session = declared_session(&peer, &client).await;
    peer.rule(Command::Verify as u8, Reply::Disconnect);
    let store = Arc::new(ManagedJournal::default());
    let scope = scope_over(&store);
    let (address, _, _) = put_args(0);

    let error = with_caller_operation(
        scope.clone(),
        client.verify_outcome(session, &address, true),
    )
    .await
    .expect_err("a lost healing verify is an error in a scope");
    assert!(error.is_outcome_unknown(), "{error:?}");
    assert!(!is_unjournaled_answer_lost(&error), "{error:?}");
    let unresolved = store.unresolved().await.expect("unresolved");
    assert_eq!(unresolved.len(), 1, "{unresolved:?}");
    assert_eq!(unresolved[0].operation, "StorageService.Verify");
    settle().await;
    assert_eq!(
        peer.seen_opcode(Command::Verify as u8).len(),
        1,
        "never resent"
    );
}

#[tokio::test]
async fn a_non_healing_verify_in_a_scope_is_not_journaled() {
    let peer = Peer::start();
    let client = authenticated_client(&peer).await;
    let session = declared_session(&peer, &client).await;
    peer.rule(Command::Verify as u8, Reply::Ok(vec![0, 0]));
    let store = Arc::new(ManagedJournal::default());
    let scope = scope_over(&store);
    let (address, _, _) = put_args(0);

    with_caller_operation(
        scope.clone(),
        client.verify_outcome(session, &address, false),
    )
    .await
    .expect("read-only verify");
    assert!(scope.latest_attempt().is_none());
    assert!(store.unresolved().await.expect("unresolved").is_empty());
}

#[tokio::test]
async fn a_healing_verify_that_cannot_bind_a_namespace_sends_nothing() {
    let peer = Peer::start();
    let client = connect(&peer).await; // auth_url empty: no authorization to bind
    let session = declared_session(&peer, &client).await;
    let (address, _, _) = put_args(0);

    let error = with_caller_operation(
        managed_context(),
        client.verify_outcome(session, &address, true),
    )
    .await
    .expect_err("journal admission fails closed");
    assert!(
        error
            .to_string()
            .contains("cannot bind credential namespace"),
        "{error:?}"
    );
    settle().await;
    assert!(peer.seen_opcode(Command::Verify as u8).is_empty());
}

/// Review fix 1. While a managed Put waits for its answer, answers to other commands on the same
/// connection keep arriving for longer than the idle bound. The connection is alive, so the Put
/// is not cut.
#[tokio::test]
async fn other_answers_on_the_connection_keep_a_waiting_managed_put_alive() {
    let peer = Arc::new(Peer::start());
    let client = Arc::new(connect(&peer).await);
    let session = declared_session(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    peer.rule(PUT, Reply::Hold(Vec::new()));

    let started = Instant::now();
    let put = {
        let client = client.clone();
        let (address, fragment, payload) = put_args(64);
        lore_base::lore_spawn!(async move {
            managed_put(&client, session, address, fragment, payload).await
        })
    };
    peer.wait_until("the Put to be read", |peer| {
        peer.seen_opcode(PUT).len() == 1
    })
    .await;
    // Traffic from other commands, spaced under the bound, for well over the bound in total.
    while started.elapsed() < BOUND * 2 + Duration::from_millis(600) {
        client
            .session_start(partition(), "keep-alive-traffic")
            .await
            .expect("another command is answered");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        !put.is_finished(),
        "the Put was cut while the connection was answering"
    );
    assert_eq!(peer.release_held().await, 1);
    let (result, elapsed) = tokio::time::timeout(BOUND * 10, put)
        .await
        .expect("the Put finishes once answered")
        .expect("put task");
    result.expect("the Put is answered, not timed out");
    assert!(
        elapsed > BOUND,
        "the wait must outlast the bound: {elapsed:?}"
    );
    assert_eq!(peer.closed_connections(), 0);
}

/// Review fix 2. A phase-2 close kills the connection under a sibling managed write that has
/// written no byte. That write was never dispatched, so it must not read as a lost answer.
#[tokio::test]
async fn a_sibling_that_wrote_nothing_before_a_phase_two_close_is_not_a_lost_answer() {
    let peer = Arc::new(Peer::start());
    let client = Arc::new(connect(&peer).await);
    let (session, stream) = warm_up(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    // A managed writer stalls after a partial write and will close the connection.
    let writer = queue_behind_a_stalled_writer(
        &peer,
        &client,
        session,
        stream,
        4 * WINDOW as usize,
        true,
        true,
    )
    .await;

    // The sibling joins well after the writer last made progress, so the writer's idle bound fires
    // first and the sibling is still queued for the lock when the connection closes. Joining at
    // once leaves the two timers a few milliseconds apart, and under load the sibling's own
    // writer-lock timeout (also not dispatched, but a different proof) can win the race.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let (address, fragment, payload) = put_args(64);
    let (sibling, _) = managed_put(&client, session, address, fragment, payload).await;
    let writer_result = tokio::time::timeout(BOUND * 10, writer)
        .await
        .expect("the stalled writer ends")
        .expect("writer task");

    let writer_error = writer_result.expect_err("the stalled writer is cut");
    assert!(
        is_unjournaled_answer_lost(&writer_error),
        "{writer_error:?}"
    );
    let sibling_error = sibling.expect_err("the sibling cannot be served on a closed connection");
    // The dead connection is replaced, and the id issued on it is then refused at the write
    // boundary: that is the proof a session layer resends on.
    assert_not_dispatched(
        &sibling_error,
        NotSent::RebindRequired,
        "sibling that wrote no byte",
    );
    assert_eq!(
        peer.seen_opcode(PUT).len(),
        1,
        "the sibling's bytes never reached the peer"
    );
}

/// Review fix 3. A healing verify journals under the partition the session was started for, and
/// a session this client did not start is refused before anything is sent.
#[tokio::test]
async fn a_healing_verify_journals_under_the_sessions_partition_and_refuses_a_foreign_session() {
    let peer = Peer::start();
    let client = authenticated_client(&peer).await;
    let session = declared_session(&peer, &client).await;
    peer.rule(Command::Verify as u8, Reply::Ok(vec![0, 0]));
    let store = Arc::new(ManagedJournal::default());
    let scope = scope_over(&store);
    let (address, _, _) = put_args(0);

    let foreign = with_caller_operation(scope.clone(), client.verify_outcome(4242, &address, true))
        .await
        .expect_err("a session this client did not start");
    assert!(
        foreign
            .to_string()
            .contains("managed healing verify on a session this client did not start"),
        "{foreign:?}"
    );
    assert!(peer.seen_opcode(Command::Verify as u8).is_empty());

    // A session started for another partition than the scope's repository is not the scope's.
    let other = client
        .session_start_declared(Partition::from([0x55u8; 16]), "other", "outcome_unknown_v1")
        .await
        .expect("a declared session for another partition")
        .0;
    let mismatch =
        with_caller_operation(scope.clone(), client.verify_outcome(other, &address, true))
            .await
            .expect_err("journaled under the session's partition, which is not the scope's");
    assert!(
        mismatch.to_string().contains("repository mismatch"),
        "{mismatch:?}"
    );
    assert!(peer.seen_opcode(Command::Verify as u8).is_empty());
    assert!(store.intents.lock().is_empty(), "nothing was journaled");

    // The scope's own session still journals.
    with_caller_operation(
        scope.clone(),
        client.verify_outcome(session, &address, true),
    )
    .await
    .expect("a healing verify on the scope's own session");
    assert_eq!(store.intents.lock().len(), 1);
}

/// A healing verify on a session id issued before a reconnect. The partition record outlives the
/// reconnect, so the verify is not refused locally as "a session this client did not start": it
/// is journaled under the session's own partition and reaches the write boundary, which refuses
/// the stale id with the rebind proof. Nothing is sent, and the attempt settles not applied, so a
/// session layer may resend it on a rebound session.
#[tokio::test]
async fn a_healing_verify_on_a_stale_session_after_a_reconnect_gets_the_rebind_proof() {
    let peer = Peer::start();
    let client = authenticated_client(&peer).await;
    let stale = declared_session(&peer, &client).await;
    let generation = client.quic().connection_generation();
    peer.rule(Command::Verify as u8, Reply::Ok(vec![0, 0]));
    let store = Arc::new(ManagedJournal::default());
    let scope = scope_over(&store);
    let (address, _, _) = put_args(0);

    // A real reconnect: the peer closes the connection with nothing in flight, then a command
    // that carries no session id replaces it.
    peer.close_connections();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == 1
    })
    .await;
    client
        .session_start(partition(), "reconnect-trigger")
        .await
        .expect("a session start replaces the connection");
    assert_eq!(
        peer.accepted_connections(),
        2,
        "the connection was replaced"
    );
    assert_ne!(
        client.quic().connection_generation(),
        generation,
        "the generation moved"
    );
    // The trigger's own id is bound to the generation its start was framed on (the replacement),
    // so it is current. Only `stale`, issued on the dead connection, is refused below.
    let current = client
        .session_start(partition(), "after-reconnect")
        .await
        .expect("a session on the replacement connection");
    assert_ne!(current, stale);
    let starts_on_replacement = peer
        .done()
        .iter()
        .filter(|done| done.opcode == Command::Authorize as u8 && done.connection == 1)
        .count();
    assert!(
        starts_on_replacement >= 2,
        "both starts ran on the replacement connection: {starts_on_replacement}"
    );

    let error = with_caller_operation(scope.clone(), client.verify_outcome(stale, &address, true))
        .await
        .expect_err("a stale id must be refused");
    assert_not_dispatched(&error, NotSent::RebindRequired, "stale healing verify");
    assert!(
        !error
            .to_string()
            .contains("managed healing verify on a session this client did not start"),
        "the id is known; the write boundary refuses it, not the local partition check: {error:?}"
    );
    assert!(
        peer.seen_opcode(Command::Verify as u8).is_empty(),
        "the stale id never reached the wire"
    );

    // It was journaled first, under the session's own partition, and settled not applied.
    let attempt = scope
        .latest_attempt()
        .expect("the heal was journaled before the boundary refused it");
    let record = store
        .lookup(&attempt)
        .await
        .expect("lookup")
        .expect("a journal row");
    assert_eq!(record.operation, "StorageService.Verify");
    assert_eq!(
        record.state,
        AttemptState::Resolved(AttemptResolution::NotApplied),
        "a command that never left is settled not applied, never left unknown"
    );
    assert!(store.unresolved().await.expect("unresolved").is_empty());
    let intents = store.intents.lock().clone();
    assert_eq!(intents.len(), 1, "{intents:?}");
    assert_eq!(intents[0].repository, RepositoryId::from([0x24u8; 16]));
    assert_eq!(intents[0].rpc, "StorageService.Verify");

    // Positive control: the same scope heals on a session the replacement connection issued.
    let outcome = with_caller_operation(
        scope.clone(),
        client.verify_outcome(current, &address, true),
    )
    .await
    .expect("a healing verify on the current session");
    assert!(matches!(outcome, MutableOutcome::Applied(_)));
    let verifies = peer.seen_opcode(Command::Verify as u8);
    assert_eq!(verifies.len(), 1);
    assert_eq!(verifies[0].session_id, current, "sent on the current id");
    assert_eq!(verifies[0].connection, 1, "on the replacement connection");
    assert_eq!(store.intents.lock().len(), 2);
}

// ---------------------------------------------------------------------------------------------
// The managed reconnect deadline and the journal settlement of a healing Verify
// ---------------------------------------------------------------------------------------------

/// Close every connection and the endpoint, and wait until the client's connection is gone.
async fn heal_make_unreachable(peer: &Peer) {
    peer.stop();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;
}

/// A healing `Verify` is the only journaled QUIC command. When its first send fails BEFORE
/// dispatch and the managed reconnect then hits the deadline, the transport raises the not-sent
/// marker (`RequestNotSent`), and `caller_operation::dispatch_recorded_result` settles the attempt
/// `NotApplied` and hands the caller `Disconnected` carrying the marker's text in its trace (the
/// caller may resend under a fresh attempt). `is_request_not_sent` is crate-private, so the proof
/// that the marker was the cause is the settlement itself plus the trace text.
#[tokio::test]
async fn a_heal_not_dispatched_when_the_reconnect_deadline_hits_settles_not_applied() {
    let peer = Peer::start();
    let client = authenticated_client(&peer).await;
    let session = declared_session(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    heal_make_unreachable(&peer).await;
    let store = Arc::new(ManagedJournal::default());
    let scope = scope_over(&store);
    let (address, _, _) = put_args(0);

    let started = Instant::now();
    let error = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        with_caller_operation(
            scope.clone(),
            client.verify_outcome(session, &address, true),
        ),
    )
    .await
    .expect("the managed heal never ended: the reconnect loop is unbounded")
    .expect_err("an unreachable server ends the heal");

    assert!(started.elapsed() < BOUND + Duration::from_secs(8));
    assert!(
        error.is_disconnected(),
        "the caller is told Disconnected: {error:?}"
    );
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(
        format!("{error:?}").contains("was not sent"),
        "the trace carries the not-sent marker's text: {error:?}"
    );
    let attempt = scope
        .latest_attempt()
        .expect("the heal was journaled first");
    let record = store
        .lookup(&attempt)
        .await
        .expect("lookup")
        .expect("a journal row");
    assert_eq!(
        record.state,
        AttemptState::Resolved(AttemptResolution::NotApplied),
        "a heal that never left is settled not applied"
    );
    assert!(store.unresolved().await.expect("unresolved").is_empty());
    assert!(peer.seen_opcode(Command::Verify as u8).is_empty());
}

/// The same heal, but DISPATCHED: the peer read it and the connection then died, so the answer is
/// lost and the reconnect hits the deadline. A write that may have applied is not "not sent": it is
/// never the managed expiry, it settles nothing, and it stays outcome unknown and unresolved.
#[tokio::test]
async fn a_heal_dispatched_when_the_reconnect_deadline_hits_stays_unknown_and_unresolved() {
    let peer = Peer::start();
    let client = authenticated_client(&peer).await;
    let session = declared_session(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    peer.rule(Command::Verify as u8, Reply::Silent);
    let store = Arc::new(ManagedJournal::default());
    let scope = scope_over(&store);
    let (address, _, _) = put_args(0);

    let started = Instant::now();
    let heal = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        with_caller_operation(
            scope.clone(),
            client.verify_outcome(session, &address, true),
        ),
    );
    let kill = async {
        peer.wait_until("the heal to be read", |peer| {
            !peer.seen_opcode(Command::Verify as u8).is_empty()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        heal_make_unreachable(&peer).await;
    };
    let (result, ()) = tokio::join!(heal, kill);
    let error = result
        .expect("the managed heal never ended: the reconnect loop is unbounded")
        .expect_err("a lost heal is an error in a scope");

    assert!(started.elapsed() < BOUND + Duration::from_secs(8));
    assert!(
        !lore_transport::is_managed_reconnect_expired(&error),
        "a dispatched write must not read as the managed expiry: {error:?}"
    );
    assert!(error.is_outcome_unknown(), "{error:?}");
    let attempt = scope
        .latest_attempt()
        .expect("the heal was journaled first");
    let record = store
        .lookup(&attempt)
        .await
        .expect("lookup")
        .expect("a journal row");
    assert!(
        !matches!(
            record.state,
            AttemptState::Resolved(AttemptResolution::NotApplied)
        ),
        "a dispatched heal must not settle not applied: {:?}",
        record.state
    );
    assert_eq!(store.unresolved().await.expect("unresolved").len(), 1);
    assert_eq!(
        peer.seen_opcode(Command::Verify as u8).len(),
        1,
        "never resent"
    );
}

/// The READ expiry (a dispatched `ReadRetryable` command that hit the deadline) is a marker for
/// the bound, but it is not the not-sent proof: its text names a read that was sent, and the
/// not-sent text is absent. Nothing journals a read, so it can never settle an attempt
/// `NotApplied`; `is_request_not_sent` itself is crate-private, so the distinction is pinned by
/// the two messages, which the transport builds from the two distinct marker structs.
#[tokio::test]
async fn the_read_expiry_is_the_bound_marker_but_carries_no_not_sent_proof() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let session = declared_session(&peer, &client).await;
    client.quic().set_managed_idle_for_test(BOUND);
    peer.rule(Command::Get as u8, Reply::Silent);
    let (address, _, _) = put_args(0);
    let operation = CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    );

    let read = tokio::time::timeout(
        BOUND + Duration::from_secs(40),
        with_caller_operation(operation, client.get(session, &address)),
    );
    let kill = async {
        peer.wait_until("the read to be read", |peer| {
            !peer.seen_opcode(Command::Get as u8).is_empty()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        heal_make_unreachable(&peer).await;
    };
    let (result, ()) = tokio::join!(read, kill);
    let error = result
        .expect("the managed read never ended")
        .expect_err("a lost read ends in an error");

    assert!(
        lore_transport::is_managed_reconnect_expired(&error),
        "{error:?}"
    );
    let text = format!("{error} | {error:?}");
    assert!(text.contains("after the read was sent"), "{text}");
    assert!(!text.contains("before the command was sent"), "{text}");
    assert!(!text.contains("command was not sent"), "{text}");
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124 slice 4: a sibling's phase-2 close, end to end through `StorageSession::attempt`.
//!
//! [CLIENT]-class (`lore-transport`). `tests/unit/quic/managed_send_bound.rs` proves the transport
//! half against a bare `StorageClient`: a managed write whose `write_chunks` fails before its
//! first byte is not dispatched, and the id it carried is refused at the write boundary. This file
//! joins that to the session layer that acts on it, through the public [`lore_transport::connect`]
//! seam, so the claim is the whole chain's: **one** rebind and **one** resend on the rebound
//! declared session, and no other write is repeated.
//!
//! # Why its own binary
//!
//! The managed idle bound is read from `LORE_QUIC_MANAGED_IDLE_TIMEOUT` when a `QuicConnection` is
//! built, and a `Connection` hands out no handle to shorten it afterwards (the unit binary's
//! `set_managed_idle_for_test` needs the `StorageClient`). A process-wide variable in the unit
//! binary would shorten the bound under every other test, so this one lives alone. The scripted
//! peer is the unit binary's, included by path.
//!
//! # Wiring
//!
//! A fake loreserver answers `EnvironmentService` over TCP and advertises the scripted QUIC peer
//! as the storage endpoint, so `connect` builds its real storage connection to the peer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_base::types::RepositoryId;
use lore_proto::lore::environment::v1 as environment_v1;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentService as EnvironmentServiceV1;
use lore_proto::lore::environment::v1::environment_service_server::EnvironmentServiceServer;
use lore_transport::CallerOperationContext;
use lore_transport::VolatileAttemptStore;
use lore_transport::is_unjournaled_answer_lost;
use lore_transport::quic::storage_service::Command;
use lore_transport::replay::MutableOutcome;
use lore_transport::with_caller_operation;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use uuid::Uuid;
use zerocopy::IntoBytes;

// The unit binary's peer, unchanged. Not every helper is used here.
#[allow(dead_code)]
#[path = "unit/quic/scripted_storage_peer.rs"]
mod scripted_storage_peer;

use scripted_storage_peer::Peer;
use scripted_storage_peer::Reply;
use scripted_storage_peer::WINDOW;

const PUT: u8 = Command::Put as u8;
const QUERY: u8 = Command::Query as u8;
const AUTHORIZE: u8 = Command::Authorize as u8;
const ACTION_START: u8 = 0;
const ACTION_START_DECLARED: u8 = 2;

/// The managed idle bound, as `LORE_QUIC_MANAGED_IDLE_TIMEOUT` takes it: whole seconds.
const BOUND: Duration = Duration::from_secs(1);

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

/// Set the bound before this binary builds its first QUIC connection. Every test here sets the
/// same value, so the order they run in does not matter.
fn bound_the_managed_send() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: called first in each test, before any connection exists in this process, and
        // every caller writes the same value.
        unsafe {
            std::env::set_var(
                "LORE_QUIC_MANAGED_IDLE_TIMEOUT",
                BOUND.as_secs().to_string(),
            );
        }
    });
}

/// Advertises the scripted peer as the storage endpoint.
struct Environment {
    storage_url: String,
}

#[tonic::async_trait]
impl EnvironmentServiceV1 for Environment {
    async fn environment_get(
        &self,
        _request: Request<environment_v1::EnvironmentGetRequest>,
    ) -> Result<Response<environment_v1::EnvironmentGetResponse>, Status> {
        Ok(Response::new(environment_v1::EnvironmentGetResponse {
            environment: Some(environment_v1::Environment {
                endpoint: Some(environment_v1::Endpoint {
                    storage_url: self.storage_url.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }))
    }
}

/// A fake loreserver answering only `EnvironmentService`, on a TCP port of its own. The remote
/// URL is its address; the storage endpoint comes from the environment it serves.
async fn serve_environment(peer: &Peer) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let environment = Environment {
        storage_url: peer.url(),
    };
    lore_base::lore_spawn!(async move {
        tonic::transport::Server::builder()
            .add_service(EnvironmentServiceServer::new(environment))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("the environment server must not fail to serve");
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    addr
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

/// Actions of the `Authorize` commands the peer read in full on `connection`, in order.
fn authorize_actions(peer: &Peer, connection: usize) -> Vec<u8> {
    peer.done()
        .into_iter()
        .filter(|done| done.opcode == AUTHORIZE && done.connection == connection)
        .filter_map(|done| done.head.first().copied())
        .collect()
}

/// A managed write on a session, the way a push issues it.
async fn managed_put(
    context: &CallerOperationContext,
    session: &lore_transport::session::StorageSession,
    payload_len: usize,
) -> (
    Address,
    Result<MutableOutcome<()>, lore_transport::error::ProtocolError>,
) {
    let (address, fragment, payload) = put_args(payload_len);
    let result = with_caller_operation(
        context.clone(),
        session.put_outcome(address, fragment, Some(payload)),
    )
    .await;
    (address, result)
}

/// Phase 2 closes the connection under a managed write stalled after a partial write. A sibling
/// managed write queued behind it wrote no byte, so it was never dispatched: the transport says
/// so with the rebind proof, and `StorageSession::attempt` answers with exactly one rebind of the
/// scope's declared session and exactly one resend of that write on it. The stalled writer was
/// dispatched, so it is a lost answer and is never resent.
#[tokio::test]
async fn a_sibling_closed_under_a_managed_write_rebinds_once_and_resends_once() {
    bound_the_managed_send();
    let peer = Arc::new(Peer::start());
    let addr = serve_environment(&peer).await;
    let connection = lore_transport::connect(
        &format!("lore://{addr}"),
        "",
        RepositoryId::default(),
        1,
        "",
        "",
    )
    .await
    .expect("connect builds its storage connection to the scripted peer");
    let storage = connection.storage().await.expect("storage connection");
    let session = connection
        .session(partition(), "managed-attempt")
        .await
        .expect("a storage session");
    let context = CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    );

    // Control for the counters below: an ordinary managed write opens the scope's declared
    // session once and sends once. Nothing is rebound.
    let (_, first) = managed_put(&context, &session, 64).await;
    assert!(
        matches!(first, Ok(MutableOutcome::Applied(()))),
        "{first:?}"
    );
    assert_eq!(context.declared_session_count(), 1);
    assert_eq!(
        authorize_actions(&peer, 0)
            .iter()
            .filter(|action| **action == ACTION_START_DECLARED)
            .count(),
        1,
        "one declared start on the first connection"
    );
    let first_put = peer.seen_opcode(PUT);
    assert_eq!(first_put.len(), 1);
    let declared_before = first_put[0].session_id;
    assert_ne!(declared_before, 0, "the write rode a session");

    // Open all eight streams and settle a sequential caller on one of them.
    for _ in 0..9 {
        storage
            .session_start(partition(), "warm-up")
            .await
            .expect("session start");
    }
    let stream = peer.seen().last().expect("a command was seen").stream;

    // Occupy every other stream with a held read, so the next two writes share `stream`.
    peer.rule(QUERY, Reply::Hold(vec![0]));
    for round in 1..=6usize {
        let storage = storage.clone();
        let (address, _, _) = put_args(0);
        lore_base::lore_spawn!(async move {
            let _ = storage.query(0, &[address]).await;
        });
        peer.wait_until("a held read to arrive", |peer| {
            peer.seen_opcode(QUERY).len() == round
        })
        .await;
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        peer.release_held_on_stream(stream).await,
        1,
        "one read on the target stream {stream}"
    );
    peer.close_gate();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The writer: larger than the stream's credit, so it stalls after a partial write.
    let puts_before = peer.seen_opcode(PUT).len();
    let writer = {
        let session = session.clone();
        let context = context.clone();
        lore_base::lore_spawn!(
            async move { managed_put(&context, &session, 4 * WINDOW as usize).await }
        )
    };
    peer.wait_until("the writer's header to arrive", |peer| {
        peer.seen_opcode(PUT).len() == puts_before + 1
    })
    .await;
    // The sibling joins well after the writer last made progress, so the writer's idle bound
    // fires first and the sibling is still waiting for the lock when the connection closes.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let sibling = {
        let session = session.clone();
        let context = context.clone();
        lore_base::lore_spawn!(async move { managed_put(&context, &session, 64).await })
    };

    // The replacement connection must be able to read, or the resend would wait on the gate.
    peer.wait_until("the stalled writer's connection to close", |peer| {
        peer.closed_connections() == 1
    })
    .await;
    peer.open_gate();

    let (writer_address, writer_result) = tokio::time::timeout(BOUND * 20, writer)
        .await
        .expect("the stalled writer ends")
        .expect("writer task");
    let (sibling_address, sibling_result) = tokio::time::timeout(BOUND * 20, sibling)
        .await
        .expect("the sibling is served")
        .expect("sibling task");

    // The writer was dispatched and lost its answer: a retryable failure, never resent.
    let writer_error = writer_result.expect_err("the stalled writer is cut");
    assert!(
        is_unjournaled_answer_lost(&writer_error),
        "{writer_error:?}"
    );
    // The sibling was served by the one resend.
    assert!(
        matches!(sibling_result, Ok(MutableOutcome::Applied(()))),
        "{sibling_result:?}"
    );

    assert_eq!(peer.accepted_connections(), 2, "one replacement connection");
    // Exactly one rebind: one declared start on the replacement connection, no undeclared one.
    assert_eq!(
        authorize_actions(&peer, 1),
        vec![ACTION_START_DECLARED],
        "one rebind, on a declared session, with no downgrade to an undeclared start"
    );
    assert!(
        !authorize_actions(&peer, 1).contains(&ACTION_START),
        "a managed write never falls back to an undeclared session"
    );
    // Exactly one resend: three Put headers in all. The first write, the stalled writer, and the
    // sibling once, on the replacement connection, under the rebound session's id.
    let puts = peer.seen_opcode(PUT);
    assert_eq!(puts.len(), 3, "{puts:?}");
    assert_eq!(
        puts.iter().filter(|put| put.connection == 0).count(),
        2,
        "the sibling's first attempt never reached the peer"
    );
    let resent: Vec<_> = puts.iter().filter(|put| put.connection == 1).collect();
    assert_eq!(resent.len(), 1, "exactly one resend: {puts:?}");
    assert_ne!(resent[0].session_id, 0);
    assert_ne!(
        resent[0].session_id, declared_before,
        "the resend rode the rebound session, not the id issued on the dead connection"
    );
    let copies = |address: &Address| {
        peer.done_heads(PUT)
            .iter()
            .filter(|head| head.as_slice() == address.as_bytes())
            .count()
    };
    assert_eq!(
        copies(&sibling_address),
        1,
        "the sibling's bytes arrived once"
    );
    assert_eq!(
        copies(&writer_address),
        0,
        "the stalled writer was not resent either"
    );
    assert_eq!(
        context.declared_session_count(),
        1,
        "the scope still owns one declared binding"
    );
}

/// Connect through the public seam, with the scripted peer as the storage endpoint.
async fn connect_to(peer: &Peer) -> Arc<lore_transport::Connection> {
    let addr = serve_environment(peer).await;
    lore_transport::connect(
        &format!("lore://{addr}"),
        "",
        RepositoryId::default(),
        1,
        "",
        "",
    )
    .await
    .expect("connect builds its storage connection to the scripted peer")
}

/// Close the connection from the peer's side and wait for it. The client sees it die with nothing
/// in flight; the next command reconnects.
async fn kill_the_connection(peer: &Peer) {
    peer.close_connections();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == 1
    })
    .await;
}

/// WP-124, through `SessionBinding::resolve`: the first managed write after the connection died
/// starts exactly ONE declared session. The start's own send reconnects, so the id is bound to the
/// replacement's generation; a binding that kept a generation sampled before the start would be
/// refused at the write boundary and start a second declared session, orphaning the first.
#[tokio::test]
async fn the_first_managed_write_after_a_reconnect_starts_exactly_one_declared_session() {
    bound_the_managed_send();
    let peer = Arc::new(Peer::start());
    let connection = connect_to(&peer).await;
    let session = connection
        .session(partition(), "managed-reconnect-one-start")
        .await
        .expect("a storage session");
    kill_the_connection(&peer).await;
    let context = CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    );

    let (_, result) = managed_put(&context, &session, 64).await;

    assert!(
        matches!(result, Ok(MutableOutcome::Applied(()))),
        "{result:?}"
    );
    assert_eq!(peer.accepted_connections(), 2, "one replacement connection");
    assert_eq!(
        authorize_actions(&peer, 1),
        vec![ACTION_START_DECLARED],
        "exactly one declared start on the replacement, and no undeclared one"
    );
    let puts = peer.seen_opcode(PUT);
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert_eq!(puts[0].connection, 1, "the Put went to the replacement");

    // The binding recorded the generation the start was framed on, so the next write in the same
    // scope reuses the session. A binding left on the pre-start generation would pass the first
    // write (the write boundary checks the transport's registry) and then rebind here, orphaning
    // the session the first write rode.
    let (_, second) = managed_put(&context, &session, 64).await;
    assert!(
        matches!(second, Ok(MutableOutcome::Applied(()))),
        "{second:?}"
    );
    assert_eq!(
        authorize_actions(&peer, 1),
        vec![ACTION_START_DECLARED],
        "the second write reused the declared session"
    );
    let puts = peer.seen_opcode(PUT);
    assert_eq!(puts.len(), 2, "{puts:?}");
    assert_eq!(
        puts[0].session_id, puts[1].session_id,
        "both writes rode one session"
    );
    assert_eq!(context.declared_session_count(), 1);
}

/// WP-124, the undeclared pool path: a pool started after the connection died makes exactly ONE
/// undeclared start on the replacement, and its first use is not refused and rebound.
#[tokio::test]
async fn the_first_use_of_a_pool_started_after_a_reconnect_starts_exactly_one_session() {
    bound_the_managed_send();
    let peer = Arc::new(Peer::start());
    let connection = connect_to(&peer).await;
    connection.storage().await.expect("storage connection");
    kill_the_connection(&peer).await;

    let session = connection
        .session(partition(), "pool-reconnect-one-start")
        .await
        .expect("a pool started on a dead connection reconnects");
    let (address, fragment, payload) = put_args(64);
    session
        .put(address, fragment, Some(payload))
        .await
        .expect("the first use of the session is not refused");

    assert_eq!(peer.accepted_connections(), 2, "one replacement connection");
    assert_eq!(
        authorize_actions(&peer, 1),
        vec![ACTION_START],
        "exactly one undeclared start on the replacement"
    );
    let puts = peer.seen_opcode(PUT);
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert_eq!(puts[0].connection, 1);
}

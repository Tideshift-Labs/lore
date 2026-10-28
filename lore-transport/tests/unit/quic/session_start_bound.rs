// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124: a QUIC session start reports the connection generation its `Authorize` was FRAMED on.
//!
//! [CLIENT]-class (`lore-transport`). A start whose own send reconnects frames the request on the
//! replacement connection. An id registered against a generation sampled before the call names the
//! dead connection, so the write boundary refuses the id on its first use, the session layer starts
//! a second session, and the first is never stopped.
//!
//! Every case drives the real `StorageClient` against the scripted peer, so the generation is
//! compared with the one the client's own connection reports after the call, and "not refused" is
//! the peer receiving the command, not a client-side flag.
use std::sync::Arc;
use std::sync::Weak;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const AUTHORIZE: u8 = Command::Authorize as u8;
const PUT: u8 = Command::Put as u8;
const ACTION_START: u8 = 0;
const ACTION_START_DECLARED: u8 = 2;

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

async fn connect(peer: &Peer) -> StorageClient {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "",
        "session-start-bound",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer")
}

/// Close the client's only connection from the peer's side and wait for it. The client sees it die
/// with nothing in flight; the next command reconnects.
async fn kill_the_connection(peer: &Peer) {
    assert_eq!(
        peer.accepted_connections(),
        1,
        "one live connection to kill"
    );
    peer.close_connections();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == 1
    })
    .await;
}

/// Actions of the `Authorize` commands the peer read in full on accepted connection `connection`.
fn authorize_actions(peer: &Peer, connection: usize) -> Vec<u8> {
    peer.done()
        .into_iter()
        .filter(|done| done.opcode == AUTHORIZE && done.connection == connection)
        .filter_map(|done| done.head.first().copied())
        .collect()
}

/// A `Put` on `session`. The peer answers it without looking at the bytes, so what it proves is
/// that the client's write boundary let the id through and the peer saw it on the wire.
async fn put_on(client: &StorageClient, session: u32) {
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
        .put(
            session,
            address,
            fragment,
            Some(Bytes::from_static(&[7u8; 8])),
        )
        .await
        .expect("a session bound to the generation it was framed on is not refused");
}

/// The peer saw exactly one `Put`, on connection `connection`, under session `session`.
fn assert_one_put_on(peer: &Peer, session: u32, connection: usize) {
    let puts = peer.seen_opcode(PUT);
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert_eq!(puts[0].session_id, session, "{puts:?}");
    assert_eq!(puts[0].connection, connection, "{puts:?}");
}

/// The core pin. The start reconnects, so the id belongs to the replacement connection: the
/// returned generation is the one the client's connection reports AFTER the call, not the one it
/// reported before, and the very next command on the id is not refused.
#[tokio::test]
async fn session_start_bound_returns_the_post_reconnect_generation_not_the_pre_call_one() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let before = client.quic().connection_generation();
    kill_the_connection(&peer).await;

    let (session, generation) = client
        .session_start_bound(partition(), "bound-after-reconnect")
        .await
        .expect("a start that reconnects");

    assert_eq!(peer.accepted_connections(), 2, "the start reconnected");
    let after = client.quic().connection_generation();
    assert_ne!(after, before, "the reconnect moved the generation");
    assert_eq!(
        generation, after,
        "the start's generation must be the one its request was framed on"
    );
    assert_ne!(
        generation, before,
        "the pre-call sample names the dead connection"
    );
    put_on(&client, session).await;
    assert_one_put_on(&peer, session, 1);
    assert_eq!(
        authorize_actions(&peer, 1),
        vec![ACTION_START],
        "exactly one undeclared start on the replacement"
    );
}

/// The declared form of the core pin, on the method the managed binding calls.
#[tokio::test]
async fn session_start_declared_returns_the_post_reconnect_generation_not_the_pre_call_one() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let before = client.quic().connection_generation();
    kill_the_connection(&peer).await;

    let (session, generation) = client
        .session_start_declared(
            partition(),
            "declared-after-reconnect",
            "outcome_unknown_v1",
        )
        .await
        .expect("a declared start that reconnects");

    assert_eq!(peer.accepted_connections(), 2, "the start reconnected");
    let after = client.quic().connection_generation();
    assert_ne!(after, before, "the reconnect moved the generation");
    assert_eq!(
        generation, after,
        "the declared start's generation must be the one its request was framed on"
    );
    put_on(&client, session).await;
    assert_one_put_on(&peer, session, 1);
    assert_eq!(
        authorize_actions(&peer, 1),
        vec![ACTION_START_DECLARED],
        "exactly one declared start on the replacement"
    );
}

/// The first dispatch is framed on the old generation and its answer is lost; the retry is framed
/// on the replacement. The generation reported is the retry's, because that is the connection that
/// answered. A report of the FIRST framing would bind the id to a connection that never issued it.
#[tokio::test]
async fn session_start_bound_reports_the_retrys_generation_when_the_first_dispatch_loses_its_answer()
 {
    let peer = Peer::start();
    let client = connect(&peer).await;
    // The first Authorize reaches the peer on the live connection, which closes without
    // answering. The retry on the replacement is answered with this id.
    let issued = 4242u32;
    peer.rule(
        AUTHORIZE,
        Reply::DisconnectThenOk(issued.to_le_bytes().to_vec()),
    );
    let before = client.quic().connection_generation();

    let (session, generation) = client
        .session_start_bound(partition(), "bound-after-lost-answer")
        .await
        .expect("an Authorize is replayable, so the lost answer is retried");

    assert_eq!(session, issued, "the replacement's answer");
    assert_eq!(peer.accepted_connections(), 2);
    assert_eq!(
        peer.seen_opcode(AUTHORIZE).len(),
        2,
        "one framing per connection"
    );
    let after = client.quic().connection_generation();
    assert_ne!(after, before);
    assert_eq!(
        generation, after,
        "the generation of the dispatch that was answered, not the first one framed"
    );
    put_on(&client, session).await;
    assert_one_put_on(&peer, session, 1);
}

/// Control for the three cases above: with no reconnect the reported generation is the one the
/// connection already has, before and after, on one connection.
#[tokio::test]
async fn session_start_bound_without_a_reconnect_reports_the_unchanged_generation() {
    let peer = Peer::start();
    let client = connect(&peer).await;
    let before = client.quic().connection_generation();

    let (session, generation) = client
        .session_start_bound(partition(), "bound-steady")
        .await
        .expect("a start on a live connection");
    let (declared, declared_generation) = client
        .session_start_declared(partition(), "declared-steady", "outcome_unknown_v1")
        .await
        .expect("a declared start on a live connection");

    assert_eq!(peer.accepted_connections(), 1, "no reconnect");
    assert_eq!(generation, before);
    assert_eq!(declared_generation, before);
    assert_eq!(client.quic().connection_generation(), before);
    assert_eq!(
        authorize_actions(&peer, 0),
        vec![ACTION_START, ACTION_START_DECLARED],
        "one start each"
    );
    put_on(&client, session).await;
    put_on(&client, declared).await;
}

/// Hold the `Authorize` answer, move the generation while it is owed, then let it through.
///
/// Returns the start's result and the generation before and after the move.
async fn start_whose_answer_is_owed_across_a_generation_move(
    peer: &Peer,
    client: &StorageClient,
    declared: bool,
) -> ((u32, u32), u32, u32) {
    let issued = 5151u32;
    peer.rule(AUTHORIZE, Reply::Hold(issued.to_le_bytes().to_vec()));
    let framed = client.quic().connection_generation();
    let start = async {
        if declared {
            client
                .session_start_declared(partition(), "owed-answer", "outcome_unknown_v1")
                .await
        } else {
            client.session_start_bound(partition(), "owed-answer").await
        }
        .expect("the start is answered")
    };
    let mover = async {
        peer.wait_until("the Authorize to be held", |peer| {
            !peer.seen_opcode(AUTHORIZE).is_empty()
        })
        .await;
        // The request is framed on `framed`; the generation moves while its answer is owed.
        client.quic().advance_generation_for_test();
        let mut released = 0;
        while released == 0 {
            released = peer.release_held().await;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    let (result, ()) = tokio::join!(start, mover);
    assert_eq!(result.0, issued);
    (result, framed, client.quic().connection_generation())
}

/// INV-EO P0-1 direction. A generation sampled AFTER the answer would mark an id current on a
/// connection that never issued it. The start reports the generation its request was framed on,
/// which is older than the one now current, so the id is not current: the very next command on it
/// is refused at the write boundary with the not-dispatched rebind proof, no byte is sent, and the
/// session layer rebinds.
#[tokio::test]
async fn a_session_whose_answer_arrives_after_a_generation_move_is_bound_to_the_framed_generation_and_refused()
 {
    for declared in [false, true] {
        let peer = Peer::start();
        let client = connect(&peer).await;

        let ((session, generation), framed, after) =
            start_whose_answer_is_owed_across_a_generation_move(&peer, &client, declared).await;

        assert_ne!(
            framed, after,
            "the generation moved while the answer was owed"
        );
        assert_eq!(
            generation, framed,
            "declared={declared}: the framed generation, not the one sampled after the answer"
        );
        let address = Address {
            hash: Hash::from(rand::random::<[u8; 32]>()),
            context: Context::from(rand::random::<[u8; 16]>()),
        };
        let fragment = Fragment {
            flags: 0,
            size_payload: 8,
            size_content: 8,
        };
        let error = client
            .put(
                session,
                address,
                fragment,
                Some(Bytes::from_static(&[7u8; 8])),
            )
            .await
            .expect_err("an id issued on a generation that has moved is not current");
        let text = format!("{error} | {error:?}");
        assert!(
            text.contains("storage command was not dispatched"),
            "declared={declared}: the rebind proof, got {text}"
        );
        assert!(
            !error.is_outcome_unknown(),
            "declared={declared}: {error:?}"
        );
        assert!(
            peer.seen_opcode(PUT).is_empty(),
            "declared={declared}: the stale id never reached the wire"
        );
    }
}

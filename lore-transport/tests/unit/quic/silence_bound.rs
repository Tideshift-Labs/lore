// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The unmanaged silence bound (`bound_unmanaged_silence`): an embedder opt-in that makes an
//! unmanaged command waiting for its answer take the progress-based `send_bounded`, so a server
//! that took the request and went silent cannot hold the caller forever on a live connection.
//!
//! These cases opt in per connection (`set_silence_bound_for_test(Some(true))`). None of them
//! calls the process-wide `bound_unmanaged_silence()`: it is one-way, and this binary runs many
//! other tests in the same process.
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
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::MutableOutcome;
use zerocopy::IntoBytes;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const GET: u8 = Command::Get as u8;
const PUT: u8 = Command::Put as u8;

/// Short enough to keep the cases fast, long enough to span two keep-alive intervals (500 ms).
const BOUND: Duration = Duration::from_millis(1200);

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

async fn connect(peer: &Peer) -> Arc<StorageClient> {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
        lore_transport::quic::client::CongestionAlgorithm::default(),
    )
    .await
    .expect("connect to the scripted peer")
}

/// A client on `peer` with a declared session, the silence bound set to `silence` and a short idle.
async fn client_with_bound(peer: &Peer, silence: Option<bool>) -> (Arc<StorageClient>, u32) {
    let client = connect(peer).await;
    let session = client
        .session_start_declared(partition(), "silence", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    client.quic().set_managed_idle_for_test(BOUND);
    client.quic().set_silence_bound_for_test(silence);
    (client, session)
}

fn address() -> Address {
    Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    }
}

/// A well-formed `Get` answer: the fragment header and `payload_len` payload bytes.
fn get_answer(payload_len: usize) -> (Vec<u8>, Vec<u8>) {
    let fragment = Fragment {
        flags: 0,
        size_payload: payload_len as u32,
        size_content: payload_len as u64,
    };
    let payload = vec![0x5Au8; payload_len];
    let mut body = fragment.as_bytes().to_vec();
    body.extend_from_slice(&payload);
    (body, payload)
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// A silent peer ends an unmanaged Get that opted in at about one bound with the typed read
/// expiry: no reconnect, one dispatch. Without the opt-in condition the Get waits for ever.
#[tokio::test]
async fn an_opted_in_unmanaged_get_whose_answer_never_comes_ends_at_one_bound() {
    let peer = Peer::start();
    let (client, session) = client_with_bound(&peer, Some(true)).await;
    peer.rule(GET, Reply::Silent);
    let generation = client.quic().connection_generation();

    let started = Instant::now();
    let result = tokio::time::timeout(BOUND * 10, client.get(session, &address())).await;
    let elapsed = started.elapsed();
    let result = result.expect("the unmanaged Get outlasted ten bounds: the silence is unbounded");

    let error = result.map(|_| ()).expect_err("a silent peer ends the Get");
    assert!(
        lore_transport::is_managed_reconnect_expired(&error),
        "{error:?}"
    );
    let text = format!("{error} | {error:?}");
    assert!(text.contains("after the read was sent"), "{text}");
    assert!(!text.contains("command was not sent"), "{text}");
    assert!(
        elapsed >= BOUND - Duration::from_millis(100),
        "fired early: {elapsed:?}"
    );
    assert!(elapsed < BOUND * 2, "more than one bound: {elapsed:?}");
    settle().await;
    assert_eq!(
        client.quic().connection_generation(),
        generation,
        "the connection was replaced"
    );
    assert_eq!(peer.accepted_connections(), 1, "no reconnect");
    assert_eq!(peer.closed_connections(), 0);
    assert_eq!(peer.seen_opcode(GET).len(), 1, "exactly one dispatch");
}

/// Control: an explicit opt-out (`Some(false)`) keeps the stock wait, whatever the process says.
#[tokio::test]
async fn an_opted_out_unmanaged_get_whose_answer_never_comes_keeps_waiting() {
    let peer = Peer::start();
    let (client, session) = client_with_bound(&peer, Some(false)).await;
    peer.rule(GET, Reply::Silent);

    let waiting = tokio::time::timeout(BOUND * 3, client.get(session, &address())).await;
    assert!(waiting.is_err(), "an opted-out Get must keep waiting");
    assert_eq!(peer.seen_opcode(GET).len(), 1);
}

/// The answer arrives in small pieces with gaps well under the bound and takes more than three
/// bounds in total. The bound is measured from the last byte received, not from the send, so the
/// Get succeeds. `managed` runs the same Get inside a managed workflow scope.
async fn a_trickled_answer_is_not_cut(managed: bool) {
    let peer = Peer::start();
    let (client, session) = client_with_bound(&peer, Some(true)).await;
    let (body, payload) = get_answer(256);
    // About 270 bytes in 8 byte pieces, 120 ms apart: over four seconds, gaps a tenth of a bound.
    peer.rule(
        GET,
        Reply::Trickle {
            body,
            piece: 8,
            every: Duration::from_millis(120),
        },
    );
    let address = address();

    let started = Instant::now();
    let get = client.get(session, &address);
    let result = tokio::time::timeout(BOUND * 10, async {
        if managed {
            lore_transport::with_managed_workflow(get).await
        } else {
            get.await
        }
    })
    .await
    .expect("the trickled Get never ended");
    let elapsed = started.elapsed();

    let (fragment, received) = result.expect("a slow but moving answer must succeed");
    assert_eq!(fragment.size_payload as usize, payload.len());
    assert_eq!(received.as_ref(), payload.as_slice());
    assert!(
        elapsed >= BOUND * 3,
        "the answer must outlast three bounds to prove the bound follows progress: {elapsed:?}"
    );
    assert_eq!(peer.seen_opcode(GET).len(), 1, "one dispatch");
    assert_eq!(peer.accepted_connections(), 1, "no reconnect");
}

#[tokio::test]
async fn an_opted_in_unmanaged_get_with_a_slow_but_moving_answer_succeeds() {
    a_trickled_answer_is_not_cut(false).await;
}

#[tokio::test]
async fn a_managed_get_with_a_slow_but_moving_answer_succeeds() {
    a_trickled_answer_is_not_cut(true).await;
}

/// A dispatched unmanaged write whose answer never comes is an unknown outcome, dispatched once,
/// never resent and never reconnected, and the silence bound makes it end.
#[tokio::test]
async fn an_opted_in_unmanaged_put_whose_answer_never_comes_is_unknown_with_one_dispatch() {
    let peer = Peer::start();
    let (client, session) = client_with_bound(&peer, Some(true)).await;
    peer.rule(PUT, Reply::Silent);
    let payload = Bytes::from(vec![0xA5u8; 64]);
    let fragment = Fragment {
        flags: 0,
        size_payload: 64,
        size_content: 64,
    };

    let started = Instant::now();
    let result = tokio::time::timeout(
        BOUND * 10,
        client.put_outcome(session, address(), fragment, Some(payload)),
    )
    .await;
    let elapsed = started.elapsed();
    let outcome = result
        .expect("the unmanaged Put outlasted ten bounds: the silence is unbounded")
        .expect("an unmanaged lost answer is an Unknown outcome, not an Err");

    assert!(
        matches!(outcome, MutableOutcome::Unknown(_)),
        "an unmanaged dispatched Put with no answer is Unknown"
    );
    assert!(
        elapsed >= BOUND - Duration::from_millis(100),
        "fired early: {elapsed:?}"
    );
    settle().await;
    assert_eq!(peer.seen_opcode(PUT).len(), 1, "never resent");
    assert_eq!(peer.accepted_connections(), 1, "no reconnect");
}

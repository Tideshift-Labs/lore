// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-026 addendum: the typed `ReadResendAllowed` marker `reconnect_and_retry` hands the session
//! layer after a proven reconnect.
//!
//! [CLIENT]-class (`lore-transport`). A session-bearing command whose replay class is
//! `ReadRetryable`, that was dispatched and lost its answer, may be asked again once the connection
//! was replaced: `reconnect_and_retry` reports that with the marker, and `StorageSession::attempt`
//! (covered end to end in `quic_managed_write_proof_test.rs`) acts on it when the generation moved.
//! The marker is a retry proof, so the property that matters most is the negative one: a
//! `MutableNoReplay` command must never produce it, whatever the session id, the failure's origin or
//! the peer. Each case drives the real `StorageClient` against the scripted peer, with the peer's
//! connections closed so the reconnect succeeds.
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::Partition;
use lore_transport::ProtocolError;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::error::is_read_resend_allowed;
use lore_transport::quic::QuicClientError;
use lore_transport::quic::client::RecordOutcome;
use lore_transport::quic::client::SendFailure;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::client::reconnect_and_retry;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::replay::OutcomeUnknown;

use super::scripted_storage_peer::Peer;

/// Let anything a bug would have sent after the call reach the peer before the count is read.
const GRACE: Duration = Duration::from_millis(500);

fn partition() -> Partition {
    Partition::from([0x26u8; 16])
}

/// A client with an open declared session and a live connection.
async fn client_with_session(peer: &Peer) -> (Arc<StorageClient>, u32) {
    let client = StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "read-resend-marker",
        partition(),
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer");
    let session = client
        .session_start_declared(partition(), "read-resend-marker", "outcome_unknown_v1")
        .await
        .expect("declared session")
        .0;
    (client, session)
}

fn raw_body() -> [Bytes; 1] {
    [Bytes::from(vec![0xA5u8; 64])]
}

/// What `reconnect_and_retry` returned for `command` after `failure`, with the connection replaced
/// under it (the peer closed every connection and keeps accepting, so the reconnect succeeds).
struct Recovered {
    error: ProtocolError,
    recorded: Option<OutcomeUnknown>,
    /// How many requests of `command`'s opcode the peer read: the function must send none.
    sent: usize,
    epoch_before: u32,
    epoch_after: u32,
}

async fn recover(
    command: Command,
    session_id_of: impl FnOnce(u32) -> u32,
    failure: SendFailure,
) -> Recovered {
    let peer = Peer::start();
    let (client, session) = client_with_session(&peer).await;
    peer.close_connections();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;

    let sink = parking_lot::Mutex::new(None);
    let epoch_before = client.quic().epoch.load(Ordering::Relaxed);
    let result = tokio::time::timeout(
        Duration::from_secs(40),
        lore_transport::with_managed_workflow(reconnect_and_retry::<_, _, 1, false, true>(
            &*client,
            command,
            session_id_of(session),
            raw_body,
            RecordOutcome(&sink),
            epoch_before,
            failure,
        )),
    )
    .await
    .expect("reconnect_and_retry never returned");
    tokio::time::sleep(GRACE).await;
    let recorded = sink.lock().clone();
    Recovered {
        error: result.expect_err("the failed command is never answered here"),
        recorded,
        sent: peer.seen_opcode(command as u8).len(),
        epoch_before,
        epoch_after: client.quic().epoch.load(Ordering::Relaxed),
    }
}

/// A session-bearing `ReadRetryable` read that was dispatched and lost its answer is reported with
/// the marker once the reconnect succeeded: the connection is a new epoch, the read itself is not
/// sent by this function (the session layer resolves a replacement session first), and the lost
/// answer is not an unknown outcome.
#[tokio::test]
async fn a_dispatched_session_read_with_a_lost_answer_gets_the_marker_after_a_reconnect() {
    for command in [Command::Get, Command::Query, Command::MutableLoad] {
        let recovered = recover(
            command,
            |session| session,
            SendFailure::response_lost(QuicClientError::Terminated),
        )
        .await;

        assert!(
            is_read_resend_allowed(&recovered.error),
            "{command:?}: a dispatched read after a proven reconnect carries the marker: {:?}",
            recovered.error
        );
        assert!(
            !recovered.error.is_outcome_unknown(),
            "{command:?}: a read is never an unknown outcome: {:?}",
            recovered.error
        );
        assert!(recovered.recorded.is_none(), "{command:?}");
        assert_eq!(
            recovered.sent, 0,
            "{command:?}: the resend is the session layer's, never this function's"
        );
        assert_ne!(
            recovered.epoch_after, recovered.epoch_before,
            "{command:?}: the marker is only produced after the connection was replaced"
        );
    }
}

/// The marker never comes from a `MutableNoReplay` command: a dispatched mutation whose answer is
/// lost is an unknown outcome, recorded once, with nothing sent and no replacement connection made
/// on its behalf. The same holds for a peer-reported unknown outcome.
#[tokio::test]
async fn a_dispatched_mutation_with_a_lost_answer_never_gets_the_marker() {
    for command in [
        Command::Put,
        Command::PutResolved,
        Command::Copy,
        Command::MutableStore,
        Command::MutableCas,
        Command::Verify,
    ] {
        for (shape, failure) in [
            (
                "response lost",
                SendFailure::response_lost(QuicClientError::Terminated),
            ),
            (
                "peer reported unknown",
                SendFailure::response_lost(QuicClientError::OutcomeUnknown),
            ),
        ] {
            let recovered = recover(command, |session| session, failure).await;

            assert!(
                !is_read_resend_allowed(&recovered.error),
                "{command:?} ({shape}) must never carry the read marker: {:?}",
                recovered.error
            );
            assert!(
                recovered.recorded.is_some(),
                "{command:?} ({shape}) stays an unknown outcome, recorded in the sink: {:?}",
                recovered.error
            );
            assert_eq!(recovered.sent, 0, "{command:?} ({shape}) is never resent");
            assert_eq!(
                recovered.epoch_after, recovered.epoch_before,
                "{command:?} ({shape}) must not reconnect for a dispatched mutation"
            );
        }
    }
}

/// A mutation that was answered keeps its own error, and no shape of a mutation without a session
/// id (the case that is resent after a reconnect) gets the marker either.
#[tokio::test]
async fn an_answered_or_session_less_mutation_never_gets_the_marker() {
    let answered = recover(
        Command::Put,
        |session| session,
        SendFailure::answered(QuicClientError::NotFound),
    )
    .await;
    assert!(
        !is_read_resend_allowed(&answered.error),
        "{:?}",
        answered.error
    );
    assert_eq!(answered.sent, 0);

    let session_less = recover(
        Command::MutableStore,
        |_| 0,
        SendFailure::response_lost(QuicClientError::Terminated),
    )
    .await;
    assert!(
        !is_read_resend_allowed(&session_less.error),
        "{:?}",
        session_less.error
    );
    assert_eq!(session_less.sent, 0);
}

/// The marker needs a dispatched read that lost its answer. An answered read keeps its own error,
/// and a read that never reached the wire asks for a session rebind, which is the other proof the
/// session layer accepts; neither is the marker.
#[tokio::test]
async fn an_answered_or_undispatched_read_does_not_get_the_marker() {
    let answered = recover(
        Command::Get,
        |session| session,
        SendFailure::answered(QuicClientError::NotFound),
    )
    .await;
    assert!(
        !is_read_resend_allowed(&answered.error),
        "an answered read keeps its own error: {:?}",
        answered.error
    );

    let undispatched = recover(
        Command::Get,
        |session| session,
        SendFailure::not_dispatched(QuicClientError::Terminated),
    )
    .await;
    assert!(
        !is_read_resend_allowed(&undispatched.error),
        "a read that never reached the wire is the rebind proof, not the resend marker: {:?}",
        undispatched.error
    );
}

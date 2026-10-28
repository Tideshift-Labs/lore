// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124 slice 5b: the QUIC client half of the token-expiry re-check. [CLIENT]-class
//! (`lore-transport`).
//!
//! Two pieces live on `StorageClient`, and both are driven here against the scripted peer:
//!
//! - **The typed answer.** Storage status 201 on a non-`Authorize` command becomes the typed
//!   expired-session error ([`lore_transport::error::is_session_expired`]), so the session layer
//!   can start a new session and send once more. Any other status stays an ordinary error.
//! - **The proactive signal.** [`Storage::session_refresh_due`] is true once the client clock
//!   reaches the `exp` of the JWT the session was started with, and false for a token with time
//!   left, an opaque token, an unknown id and a stopped session.
//!
//! The token a session starts with is a supplied access token: `exchange` returns it unchanged,
//! which is how a test chooses its `exp` without an auth service. The session layer's use of both
//! is in `tests/session_expiry_attempt.rs`.
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_base::types::Partition;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::error::ProtocolError;
use lore_transport::error::is_session_expired;
use lore_transport::quic::STORAGE_SESSION_EXPIRED_STATUS;
use lore_transport::quic::STORAGE_UNSUPPORTED_CLIENT_STATUS;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;

use super::scripted_storage_peer::Peer;
use super::scripted_storage_peer::Reply;

const AUTHORIZE: u8 = Command::Authorize as u8;
const PUT: u8 = Command::Put as u8;
const GET: u8 = Command::Get as u8;
const GET_METADATA: u8 = Command::GetMetadata as u8;
const QUERY: u8 = Command::Query as u8;
const MUTABLE_LOAD: u8 = Command::MutableLoad as u8;
const MUTABLE_STORE: u8 = Command::MutableStore as u8;
const MUTABLE_CAS: u8 = Command::MutableCas as u8;
const VERIFY: u8 = Command::Verify as u8;
const COPY: u8 = Command::Copy as u8;

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

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

/// An unsigned JWT with the given `exp` (Unix seconds), the shape `user_info_from_token` decodes.
fn jwt_expiring_at(exp_secs: u64) -> String {
    let header = base64_url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = format!(
        r#"{{"iss":"auth.example.com","sub":"expiry-user","name":"Test User","exp":{exp_secs},"aud":["127.0.0.1","localhost"]}}"#
    );
    format!("{header}.{}.", base64_url(payload.as_bytes()))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// A client whose session starts present `access_token`. The auth URL is non-empty only so the
/// client calls `exchange`, which returns a supplied access token before it reads the URL.
async fn connect(peer: &Peer, access_token: &str) -> StorageClient {
    StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "session-expiry-unused://auth.example.com",
        "session-expiry",
        partition(),
        &Arc::new(SuppliedCredentials::new("", access_token)),
        None,
    )
    .await
    .expect("connect to the scripted peer")
}

fn address() -> Address {
    Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    }
}

fn fragment() -> Fragment {
    Fragment {
        flags: 0,
        size_payload: 8,
        size_content: 8,
    }
}

// ---- the typed 201 answer -----------------------------------------------------------------

/// One send of every non-`Authorize` command a client can issue on a session.
async fn send_every_command(
    client: &StorageClient,
    session: u32,
) -> Vec<(&'static str, ProtocolError)> {
    let key = Hash::from(rand::random::<[u8; 32]>());
    let mut errors = Vec::new();
    let mut push = |name: &'static str, result: Result<(), ProtocolError>| {
        errors.push((name, result.expect_err(name)));
    };
    push(
        "put",
        client
            .put(
                session,
                address(),
                fragment(),
                Some(Bytes::from_static(&[7u8; 8])),
            )
            .await,
    );
    push("get", client.get(session, &address()).await.map(|_| ()));
    push(
        "get_metadata",
        client.get_metadata(session, &address()).await.map(|_| ()),
    );
    push(
        "query",
        client.query(session, &[address()]).await.map(|_| ()),
    );
    push(
        "verify",
        client.verify(session, &address(), false).await.map(|_| ()),
    );
    push(
        "copy",
        client
            .copy(session, partition(), address(), Context::default())
            .await,
    );
    push(
        "mutable_load",
        client
            .mutable_load(session, &key, KeyType::Untyped)
            .await
            .map(|_| ()),
    );
    push(
        "mutable_store",
        client
            .mutable_store(session, key, key, KeyType::Untyped)
            .await,
    );
    push(
        "mutable_cas",
        client
            .mutable_compare_and_swap(session, key, key, key, KeyType::Untyped)
            .await
            .map(|_| ()),
    );
    errors
}

#[tokio::test]
async fn status_201_on_any_storage_command_is_the_typed_session_expired_error() {
    let peer = Peer::start();
    let client = connect(&peer, "opaque-token").await;
    let session = client
        .session_start(partition(), "expired")
        .await
        .expect("session start");
    for opcode in [
        PUT,
        GET,
        GET_METADATA,
        QUERY,
        VERIFY,
        COPY,
        MUTABLE_LOAD,
        MUTABLE_STORE,
        MUTABLE_CAS,
    ] {
        peer.rule(opcode, Reply::Status(STORAGE_SESSION_EXPIRED_STATUS));
    }

    let errors = send_every_command(&client, session).await;

    assert_eq!(errors.len(), 9);
    for (name, error) in &errors {
        assert!(
            is_session_expired(error),
            "{name}: 201 must map to the typed expired-session error, got {error:?}"
        );
        // Positive proof of non-dispatch: it is not an unknown outcome, and a typed expired
        // answer carries no connection-loss meaning.
        assert!(!error.is_outcome_unknown(), "{name}: {error:?}");
    }
    assert_eq!(
        peer.accepted_connections(),
        1,
        "a 201 never reconnects: only the session is stale"
    );
}

/// Control: every other status stays an ordinary error, including its neighbour 200.
#[tokio::test]
async fn other_statuses_are_not_session_expired() {
    let peer = Peer::start();
    let client = connect(&peer, "opaque-token").await;
    let session = client
        .session_start(partition(), "other-status")
        .await
        .expect("session start");
    for status in [1u32, 2, STORAGE_UNSUPPORTED_CLIENT_STATUS, 202, 5] {
        peer.rule(PUT, Reply::Status(status));
        let error = client
            .put(
                session,
                address(),
                fragment(),
                Some(Bytes::from_static(&[7u8; 8])),
            )
            .await
            .expect_err("a refused put");
        assert!(
            !is_session_expired(&error),
            "status {status} must not read as an expired session: {error:?}"
        );
    }
    assert_eq!(STORAGE_UNSUPPORTED_CLIENT_STATUS, 200);
    assert_eq!(STORAGE_SESSION_EXPIRED_STATUS, 201);
}

/// A 201 to the session start itself is not "your session expired": there is no session to
/// replace, so it stays an ordinary error.
#[tokio::test]
async fn status_201_on_authorize_is_not_the_typed_error() {
    let peer = Peer::start();
    let client = connect(&peer, "opaque-token").await;
    peer.rule(AUTHORIZE, Reply::Status(STORAGE_SESSION_EXPIRED_STATUS));

    let error = client
        .session_start(partition(), "authorize-201")
        .await
        .expect_err("the start was refused");

    assert!(!is_session_expired(&error), "{error:?}");
}

// ---- the proactive signal -----------------------------------------------------------------

#[tokio::test]
async fn session_refresh_due_is_true_once_the_token_exp_has_passed() {
    let peer = Peer::start();
    let past = connect(&peer, &jwt_expiring_at(now_secs() - 5)).await;
    let future = connect(&peer, &jwt_expiring_at(4_102_444_800)).await;

    let expired_session = past
        .session_start(partition(), "past")
        .await
        .expect("session start");
    let live_session = future
        .session_start(partition(), "future")
        .await
        .expect("session start");

    assert!(past.session_refresh_due(expired_session));
    assert!(!future.session_refresh_due(live_session));
}

/// The clock decides it, not the mint: a token with a couple of seconds left is not due when the
/// session starts and is due once the client clock reaches its `exp`.
#[tokio::test]
async fn session_refresh_due_flips_when_the_client_clock_reaches_exp() {
    let peer = Peer::start();
    let exp = now_secs() + 3;
    let client = connect(&peer, &jwt_expiring_at(exp)).await;
    let session = client
        .session_start(partition(), "flips")
        .await
        .expect("session start");
    assert!(
        !client.session_refresh_due(session),
        "{exp}: an unexpired token is not due"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !client.session_refresh_due(session) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session never became due"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        now_secs() >= exp,
        "due only once the client clock reached the token's exp"
    );
}

#[tokio::test]
async fn session_refresh_due_is_false_without_a_readable_exp() {
    let peer = Peer::start();
    // An opaque token has no `exp` to read; the empty token is what an auth-less remote presents.
    for token in ["opaque-token", "not.a.jwt", ""] {
        let client = connect(&peer, token).await;
        let session = client
            .session_start(partition(), "opaque")
            .await
            .expect("session start");
        assert!(
            !client.session_refresh_due(session),
            "token {token:?} has no exp and is never rebound early"
        );
    }
    let client = connect(&peer, &jwt_expiring_at(now_secs() - 5)).await;
    assert!(
        !client.session_refresh_due(424_242),
        "an id this client never started is never due"
    );
}

#[tokio::test]
async fn session_refresh_due_forgets_a_stopped_session() {
    let peer = Peer::start();
    let client = connect(&peer, &jwt_expiring_at(now_secs() - 5)).await;
    let session = client
        .session_start(partition(), "stop")
        .await
        .expect("session start");
    assert!(client.session_refresh_due(session));

    client.session_stop(session).await.expect("stop");

    assert!(
        !client.session_refresh_due(session),
        "the stopped id's expiry entry is released with the session"
    );
}

/// Each session is judged by the token it started with. Credentials replaced after the first
/// session do not make the first due, and the second carries the new token's `exp`.
#[tokio::test]
async fn each_session_keeps_the_exp_of_the_token_it_started_with() {
    let peer = Peer::start();
    let credentials = Arc::new(SuppliedCredentials::new(
        "",
        &jwt_expiring_at(now_secs() - 5),
    ));
    let client = StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "session-expiry-unused://auth.example.com",
        "session-expiry",
        partition(),
        &credentials,
        None,
    )
    .await
    .expect("connect");
    let old = client
        .session_start(partition(), "old")
        .await
        .expect("session start");

    credentials.update("", &jwt_expiring_at(4_102_444_800));
    let new = client
        .session_start(partition(), "new")
        .await
        .expect("session start");

    assert!(client.session_refresh_due(old));
    assert!(!client.session_refresh_due(new));
    assert_eq!(
        peer.seen_opcode(AUTHORIZE).len(),
        2,
        "one start per session, and the check itself sends nothing"
    );
}

/// The answer is per request: after one 201 the same client and session carry on when the server
/// says so. The client itself neither retries nor marks the id dead (that is the session layer's
/// job), so a second send on the same id reaches the wire.
#[tokio::test]
async fn the_client_alone_does_not_resend_after_a_201() {
    let peer = Peer::start();
    let client = connect(&peer, "opaque-token").await;
    let session = client
        .session_start(partition(), "no-resend")
        .await
        .expect("session start");
    peer.rule(
        PUT,
        Reply::StatusThenOk {
            status: STORAGE_SESSION_EXPIRED_STATUS,
            times: 1,
            body: Vec::new(),
        },
    );

    let first = client
        .put(
            session,
            address(),
            fragment(),
            Some(Bytes::from_static(&[7u8; 8])),
        )
        .await
        .expect_err("the first put is answered 201");
    assert!(is_session_expired(&first), "{first:?}");
    assert_eq!(peer.seen_opcode(PUT).len(), 1, "one send for one call");

    client
        .put(
            session,
            address(),
            fragment(),
            Some(Bytes::from_static(&[7u8; 8])),
        )
        .await
        .expect("the second put is answered");
    assert_eq!(peer.seen_opcode(PUT).len(), 2);
    assert_eq!(peer.accepted_connections(), 1);
}

/// A 201 that arrives late, after the command has been in flight for a while, maps the same way.
#[tokio::test]
async fn a_held_201_answer_maps_to_the_typed_error_when_it_arrives() {
    let peer = Peer::start();
    let client = Arc::new(connect(&peer, "opaque-token").await);
    let session = client
        .session_start(partition(), "held-201")
        .await
        .expect("session start");
    peer.rule(QUERY, Reply::HoldStatus(STORAGE_SESSION_EXPIRED_STATUS));

    let query = {
        let client = client.clone();
        lore_base::lore_spawn!(async move { client.query(session, &[address()]).await })
    };
    peer.wait_until("the query to be held", |peer| {
        !peer.seen_opcode(QUERY).is_empty()
    })
    .await;
    assert!(!query.is_finished(), "not answered while held");
    assert_eq!(peer.release_held().await, 1);

    let error = query.await.expect("query task").expect_err("answered 201");
    assert!(is_session_expired(&error), "{error:?}");
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124 slice 5b: the session layer's response to token expiry, end to end through
//! `StorageSession::attempt` and `SessionBinding::resolve`. [CLIENT]-class (`lore-transport`).
//!
//! `tests/unit/quic/session_expiry.rs` proves the two pieces on a bare `StorageClient`: a storage
//! status 201 maps to the typed expired-session error, and `session_refresh_due` follows the
//! token's `exp`. This file joins them to the session layer that acts on them, through the public
//! [`lore_transport::connect`] seam, so the claims are the whole chain's:
//!
//! - **Reactive.** A 201 on the first dispatch starts exactly ONE new session and resends exactly
//!   once on it; the command is applied once, on the new id. A second 201 is the caller's error
//!   (the attempt budget). Only a 201 earns the resend: every other answered error does not.
//!   Siblings answered 201 for the same old id cause ONE rebind between them.
//! - **Proactive.** A session whose token `exp` has passed on the client clock is replaced before
//!   its next command, without a 201, and the old id is not stopped. An unexpired or opaque token
//!   is never replaced early.
//!
//! A fake loreserver answers `EnvironmentService` over TCP, advertises the scripted QUIC peer as
//! the storage endpoint and a non-empty auth URL, and the test supplies the access token: a
//! supplied access token is returned by `exchange` unchanged, so a test chooses the `exp` of the
//! token every session start presents.

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
use lore_transport::error::ProtocolError;
use lore_transport::error::is_session_expired;
use lore_transport::quic::STORAGE_SESSION_EXPIRED_STATUS;
use lore_transport::quic::STORAGE_UNSUPPORTED_CLIENT_STATUS;
use lore_transport::quic::storage_service::Command;
use lore_transport::replay::MutableOutcome;
use lore_transport::session::StorageSession;
use lore_transport::with_caller_operation;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use uuid::Uuid;

// The unit binary's peer, unchanged. Not every helper is used here.
#[allow(dead_code)]
#[path = "unit/quic/scripted_storage_peer.rs"]
mod scripted_storage_peer;

use scripted_storage_peer::Peer;
use scripted_storage_peer::Reply;

const PUT: u8 = Command::Put as u8;
const QUERY: u8 = Command::Query as u8;
const AUTHORIZE: u8 = Command::Authorize as u8;
const ACTION_START: u8 = 0;
const ACTION_STOP: u8 = 1;
const ACTION_START_DECLARED: u8 = 2;
const FAR_FUTURE_EXP: u64 = 4_102_444_800;
const OPAQUE_TOKEN: &str = "opaque-token";
const WAIT: Duration = Duration::from_secs(15);

fn partition() -> Partition {
    Partition::from([0x24u8; 16])
}

// ---- tokens -------------------------------------------------------------------------------

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

/// An unsigned JWT with the given `exp` (Unix seconds).
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

// ---- wiring -------------------------------------------------------------------------------

/// Advertises the scripted peer as the storage endpoint, and an auth URL so the client runs
/// `exchange` (which returns a supplied access token before it reads the URL).
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
                    auth_url: "session-expiry-unused://auth.example.com".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }))
    }
}

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

struct Fixture {
    peer: Arc<Peer>,
    url: String,
    identity: String,
    connection: Arc<lore_transport::Connection>,
    session: Arc<StorageSession>,
}

/// A connection whose session starts present `token`, and a session on it. Its own peer,
/// environment, URL and identity, so nothing is shared with a parallel test.
async fn fixture(token: &str) -> Fixture {
    let peer = Arc::new(Peer::start());
    let addr = serve_environment(&peer).await;
    let url = format!("lore://{addr}");
    let identity = format!("session-expiry-{}", Uuid::new_v4());
    let connection =
        lore_transport::connect(&url, &identity, RepositoryId::default(), 1, "", token)
            .await
            .expect("connect builds its storage connection to the scripted peer");
    let session = connection
        .session(partition(), "session-expiry")
        .await
        .expect("a storage session");
    Fixture {
        peer,
        url,
        identity,
        connection,
        session,
    }
}

impl Fixture {
    /// Replace the credentials every later session start presents, the way a refreshed login does.
    async fn rotate_token(&self, token: &str) {
        let same = lore_transport::connect(
            &self.url,
            &self.identity,
            RepositoryId::default(),
            1,
            "",
            token,
        )
        .await
        .expect("reconnect to the same remote");
        assert!(
            Arc::ptr_eq(&same, &self.connection),
            "the same identity and remote adopt the new credentials on the one connection"
        );
    }

    /// Actions of the `Authorize` commands the peer read in full, in order.
    fn actions(&self) -> Vec<u8> {
        self.peer
            .done()
            .into_iter()
            .filter(|done| done.opcode == AUTHORIZE)
            .filter_map(|done| done.head.first().copied())
            .collect()
    }

    fn count(&self, action: u8) -> usize {
        self.actions().iter().filter(|a| **a == action).count()
    }

    /// The session ids of every `Put` header the peer has read, in order.
    fn put_sessions(&self) -> Vec<u32> {
        self.peer
            .seen_opcode(PUT)
            .into_iter()
            .map(|seen| seen.session_id)
            .collect()
    }

    fn assert_no_reconnect(&self) {
        assert_eq!(self.peer.accepted_connections(), 1, "no reconnect");
        assert_eq!(self.peer.closed_connections(), 0, "no connection closed");
    }
}

fn put_args() -> (Address, Fragment, Bytes) {
    let address = Address {
        hash: Hash::from(rand::random::<[u8; 32]>()),
        context: Context::from(rand::random::<[u8; 16]>()),
    };
    let fragment = Fragment {
        flags: 0,
        size_payload: 8,
        size_content: 8,
    };
    (address, fragment, Bytes::from_static(&[7u8; 8]))
}

async fn put(session: &StorageSession) -> Result<(), ProtocolError> {
    let (address, fragment, payload) = put_args();
    session.put(address, fragment, Some(payload)).await
}

async fn query(session: &StorageSession) -> Result<Bytes, ProtocolError> {
    let (address, _, _) = put_args();
    session.query(&[address]).await
}

fn expired_then_ok(times: usize) -> Reply {
    Reply::StatusThenOk {
        status: STORAGE_SESSION_EXPIRED_STATUS,
        times,
        body: vec![0],
    }
}

// ---- reactive: a 201 answer ---------------------------------------------------------------

/// A 201 on the first dispatch: one new session, one resend on it. The write is dispatched twice
/// in total, but the first copy was refused before the handler, so it is applied once, on the new
/// id. The connection never moves.
#[tokio::test]
async fn a_201_on_a_put_starts_one_new_session_and_resends_once() {
    let f = fixture(OPAQUE_TOKEN).await;
    // Control: an ordinary put binds the session and sends once. Nothing is rebound.
    put(&f.session).await.expect("an ordinary put");
    assert_eq!(f.count(ACTION_START), 1, "one start");
    let first_session = f.put_sessions()[0];
    assert_ne!(first_session, 0);

    f.peer.rule(PUT, expired_then_ok(1));
    put(&f.session)
        .await
        .expect("the 201 is absorbed by one rebind and one resend");

    assert_eq!(
        f.count(ACTION_START),
        2,
        "exactly one extra AuthorizeStart, {:?}",
        f.actions()
    );
    assert_eq!(f.count(ACTION_STOP), 0, "the superseded id is not stopped");
    assert_eq!(f.count(ACTION_START_DECLARED), 0);
    let sessions = f.put_sessions();
    assert_eq!(
        sessions.len(),
        3,
        "control + the refused send + one resend: {sessions:?}"
    );
    assert_eq!(
        sessions[1], first_session,
        "the refused send rode the old id"
    );
    assert_ne!(
        sessions[2], first_session,
        "the resend rode the NEW session id: {sessions:?}"
    );
    f.assert_no_reconnect();

    // The new session is the binding now: a following put rides it with no further start.
    f.peer.rule(PUT, Reply::Ok(Vec::new()));
    put(&f.session).await.expect("a later put");
    assert_eq!(f.count(ACTION_START), 2);
    assert_eq!(*f.put_sessions().last().unwrap(), sessions[2]);
}

/// The same for a read.
#[tokio::test]
async fn a_201_on_a_read_starts_one_new_session_and_resends_once() {
    let f = fixture(OPAQUE_TOKEN).await;
    f.peer.rule(QUERY, Reply::Ok(vec![0]));
    query(&f.session).await.expect("an ordinary query");
    assert_eq!(f.count(ACTION_START), 1);
    let first_session = f.peer.seen_opcode(QUERY)[0].session_id;

    f.peer.rule(QUERY, expired_then_ok(1));
    query(&f.session)
        .await
        .expect("the 201 is absorbed by one rebind and one resend");

    assert_eq!(f.count(ACTION_START), 2, "{:?}", f.actions());
    let queries = f.peer.seen_opcode(QUERY);
    assert_eq!(queries.len(), 3, "{queries:?}");
    assert_eq!(queries[1].session_id, first_session);
    assert_ne!(queries[2].session_id, first_session);
    f.assert_no_reconnect();
}

/// A second 201 after the resend is the caller's error: the attempt budget is spent and nothing
/// is sent a third time.
#[tokio::test]
async fn a_second_201_after_the_resend_is_returned_as_the_error() {
    let f = fixture(OPAQUE_TOKEN).await;
    put(&f.session).await.expect("an ordinary put");
    let puts_before = f.put_sessions().len();

    f.peer
        .rule(PUT, Reply::Status(STORAGE_SESSION_EXPIRED_STATUS));
    let error = put(&f.session)
        .await
        .expect_err("both dispatches are refused");

    assert!(is_session_expired(&error), "{error:?}");
    assert_eq!(
        f.put_sessions().len() - puts_before,
        2,
        "exactly two dispatches, never a third: {:?}",
        f.put_sessions()
    );
    assert_eq!(f.count(ACTION_START), 2, "one rebind, no more");
    f.assert_no_reconnect();

    let query_error = {
        f.peer
            .rule(QUERY, Reply::Status(STORAGE_SESSION_EXPIRED_STATUS));
        query(&f.session)
            .await
            .expect_err("a read is bounded the same way")
    };
    assert!(is_session_expired(&query_error), "{query_error:?}");
    assert_eq!(f.peer.seen_opcode(QUERY).len(), 2);
}

/// Control: only a 201 earns the resend. Every other answered error is returned as it was, with
/// one dispatch and no new session.
#[tokio::test]
async fn an_answered_error_other_than_201_is_not_resent() {
    let f = fixture(OPAQUE_TOKEN).await;
    put(&f.session).await.expect("an ordinary put");
    let puts_before = f.put_sessions().len();

    for status in [1u32, 2, STORAGE_UNSUPPORTED_CLIENT_STATUS, 202] {
        f.peer.rule(PUT, Reply::Status(status));
        let error = put(&f.session).await.expect_err("a refused put");
        assert!(!is_session_expired(&error), "status {status}: {error:?}");
    }
    assert_eq!(
        f.put_sessions().len() - puts_before,
        4,
        "one dispatch per call, none resent"
    );
    assert_eq!(f.count(ACTION_START), 1, "no rebind for a non-201 answer");
    f.assert_no_reconnect();
}

/// Two commands in flight on one session are both answered 201 for it. The first rebinds; the
/// second finds the binding already moved and must not throw the fresh session away. Their
/// answers are released one at a time so the order is the test's, not the scheduler's: an
/// unconditional unbind would make the second 201 discard the new session and start a third.
#[tokio::test]
async fn two_commands_answered_201_for_one_old_session_cause_one_rebind() {
    let f = fixture(OPAQUE_TOKEN).await;
    put(&f.session)
        .await
        .expect("an ordinary put binds the session");
    let first_session = f.put_sessions()[0];
    assert_eq!(f.count(ACTION_START), 1);

    f.peer
        .rule(PUT, Reply::HoldStatus(STORAGE_SESSION_EXPIRED_STATUS));
    let spawn_put = || {
        let session = f.session.clone();
        lore_base::lore_spawn!(async move { put(&session).await })
    };
    let first = spawn_put();
    let second = spawn_put();
    f.peer
        .wait_until("both puts to be in flight", |peer| {
            peer.seen_opcode(PUT).len() == 3
        })
        .await;
    let held = f.peer.seen_opcode(PUT);
    assert_eq!(held[1].session_id, first_session);
    assert_eq!(
        held[2].session_id, first_session,
        "both ride the one old id"
    );
    assert_ne!(held[1].stream, held[2].stream);
    // From here the peer accepts puts.
    f.peer.rule(PUT, Reply::Ok(Vec::new()));

    // The first answer: rebind and resend.
    assert_eq!(f.peer.release_held_on_stream(held[1].stream).await, 1);
    let (first_task, second_task) = (first, second);
    let resolved = tokio::time::timeout(WAIT, async {
        loop {
            if f.put_sessions().len() == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    resolved.expect("the first command's resend arrives");
    let new_session = f.put_sessions()[3];
    assert_ne!(new_session, first_session);
    assert_eq!(f.count(ACTION_START), 2, "the first 201 rebinds once");

    // The second answer, for the old id, after the binding already moved.
    assert_eq!(f.peer.release_held().await, 1);
    for task in [first_task, second_task] {
        tokio::time::timeout(WAIT, task)
            .await
            .expect("a command ends")
            .expect("task")
            .expect("both commands succeed after one rebind");
    }
    assert_eq!(
        f.count(ACTION_START),
        2,
        "the second 201 must not unbind the fresh session: {:?}",
        f.actions()
    );
    let sessions = f.put_sessions();
    assert_eq!(sessions.len(), 5, "{sessions:?}");
    assert_eq!(
        sessions[4], new_session,
        "the second command's resend rode the session the first one started"
    );
    f.assert_no_reconnect();
}

/// The managed (declared) path: the rebind declares again (action 2), never falls back to an
/// undeclared start, and the scope still owns one declared binding.
#[tokio::test]
async fn a_201_on_a_managed_write_rebinds_a_declared_session_and_resends_once() {
    let f = fixture(OPAQUE_TOKEN).await;
    let context = CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    );
    let managed_put = || async {
        let (address, fragment, payload) = put_args();
        with_caller_operation(
            context.clone(),
            f.session.put_outcome(address, fragment, Some(payload)),
        )
        .await
    };

    // Control: the first managed write opens the scope's declared session once.
    let first = managed_put().await;
    assert!(
        matches!(first, Ok(MutableOutcome::Applied(()))),
        "{first:?}"
    );
    assert_eq!(f.count(ACTION_START_DECLARED), 1);
    let undeclared_starts = f.count(ACTION_START);
    let declared_session = *f.put_sessions().last().unwrap();

    f.peer.rule(PUT, expired_then_ok(1));
    let result = managed_put().await;

    assert!(
        matches!(result, Ok(MutableOutcome::Applied(()))),
        "the 201 is absorbed by one declared rebind: {result:?}"
    );
    assert_eq!(
        f.count(ACTION_START_DECLARED),
        2,
        "the rebind re-declares: {:?}",
        f.actions()
    );
    assert_eq!(
        f.count(ACTION_START),
        undeclared_starts,
        "a managed write never falls back to an undeclared start"
    );
    let sessions = f.put_sessions();
    assert_eq!(sessions.len(), 3, "{sessions:?}");
    assert_eq!(sessions[1], declared_session, "the refused send");
    assert_ne!(
        sessions[2], declared_session,
        "the resend, on the new session"
    );
    assert_eq!(context.declared_session_count(), 1);
    f.assert_no_reconnect();
}

// ---- proactive: the client clock passes the token's exp -----------------------------------

/// Wait until the client clock is past `exp_secs`, the instant `session_refresh_due` turns true.
async fn wait_past(exp_secs: u64) {
    tokio::time::timeout(WAIT, async {
        while now_secs() <= exp_secs {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the clock passes the token exp");
}

/// A session whose token `exp` passed on the client clock is replaced BEFORE its next command,
/// with no 201 involved, and the old id is not stopped. The credentials were refreshed in the
/// meantime, so the replacement carries a live token and the next command does not rebind again.
#[tokio::test]
async fn a_session_past_its_token_exp_is_rebound_before_the_next_command() {
    let exp = now_secs() + 3;
    let f = fixture(&jwt_expiring_at(exp)).await;
    put(&f.session)
        .await
        .expect("a put before the token expires");
    assert_eq!(f.count(ACTION_START), 1);
    assert!(
        now_secs() < exp,
        "the fixture started its session inside the token's life"
    );
    let first_session = f.put_sessions()[0];

    wait_past(exp).await;
    f.rotate_token(&jwt_expiring_at(FAR_FUTURE_EXP)).await;
    assert_eq!(
        f.count(ACTION_START),
        1,
        "rotating credentials starts nothing"
    );
    put(&f.session).await.expect("the put after expiry");

    assert_eq!(
        f.count(ACTION_START),
        2,
        "exactly one start, before the command: {:?}",
        f.actions()
    );
    let sessions = f.put_sessions();
    assert_eq!(sessions.len(), 2, "the command was sent once: {sessions:?}");
    assert_ne!(sessions[1], first_session, "it rode the replacement");
    assert_eq!(f.count(ACTION_STOP), 0, "the superseded id is not stopped");
    // The start was observed before the command: the peer read the Authorize before the Put.
    let seen = f.peer.seen();
    let start_at = seen
        .iter()
        .rposition(|s| s.opcode == AUTHORIZE)
        .expect("a start");
    let put_at = seen.iter().rposition(|s| s.opcode == PUT).expect("a put");
    assert!(start_at < put_at, "{seen:?}");

    // The replacement carries the refreshed token: later commands do not rebind.
    for _ in 0..3 {
        put(&f.session).await.expect("a later put");
    }
    assert_eq!(f.count(ACTION_START), 2, "{:?}", f.actions());
    f.assert_no_reconnect();
}

/// Control: a token with time left is never rebound early, however many commands run.
#[tokio::test]
async fn a_session_with_an_unexpired_token_is_not_rebound() {
    let f = fixture(&jwt_expiring_at(FAR_FUTURE_EXP)).await;
    for _ in 0..4 {
        put(&f.session).await.expect("a put");
    }
    assert_eq!(f.count(ACTION_START), 1, "{:?}", f.actions());
    let sessions = f.put_sessions();
    assert!(sessions.iter().all(|id| *id == sessions[0]), "{sessions:?}");
}

/// An opaque (non-JWT) token has no `exp` to read, so its session is never rebound early, even
/// past the point a JWT with the same lifetime would have been.
#[tokio::test]
async fn a_session_with_an_opaque_token_is_never_rebound_early() {
    let f = fixture(OPAQUE_TOKEN).await;
    put(&f.session).await.expect("a put");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    for _ in 0..3 {
        put(&f.session).await.expect("a put");
    }
    assert_eq!(f.count(ACTION_START), 1, "{:?}", f.actions());
    f.assert_no_reconnect();
}

/// A token past its `exp` that is NOT rotated comes back identical from every session start (a
/// supplied token, or one the authz cache still serves). The proactive rebind must happen once
/// for that `exp`, not once per command: otherwise every command costs a start and a server
/// session that is never stopped.
#[tokio::test]
async fn a_token_past_exp_that_is_not_rotated_is_rebound_once_not_per_command() {
    let exp = now_secs() + 2;
    let f = fixture(&jwt_expiring_at(exp)).await;
    put(&f.session)
        .await
        .expect("a put before the token expires");
    assert_eq!(f.count(ACTION_START), 1);
    assert!(
        now_secs() < exp,
        "the first session started inside the token's life"
    );
    let first_session = f.put_sessions()[0];

    wait_past(exp).await;
    for _ in 0..5 {
        put(&f.session).await.expect("a put after expiry");
    }

    assert_eq!(
        f.count(ACTION_START),
        2,
        "exactly one proactive rebind, then none: {:?}",
        f.actions()
    );
    assert_eq!(f.count(ACTION_STOP), 0);
    let sessions = f.put_sessions();
    assert_eq!(sessions.len(), 6, "{sessions:?}");
    assert_ne!(
        sessions[1], first_session,
        "the first put after expiry rebound"
    );
    assert!(
        sessions[1..].iter().all(|id| *id == sessions[1]),
        "all five rode the one replacement: {sessions:?}"
    );
    f.assert_no_reconnect();
}

/// A rotated token (a later `exp`) re-arms the check: the replacement is due again when ITS token
/// passes its own `exp`, and a further rotation is picked up by that second refresh.
#[tokio::test]
async fn a_rotated_token_is_refreshed_again_when_it_also_passes_its_exp() {
    let first_exp = now_secs() + 2;
    let f = fixture(&jwt_expiring_at(first_exp)).await;
    put(&f.session).await.expect("a put");
    assert_eq!(f.count(ACTION_START), 1);

    // First refresh: rotate to a token that itself expires soon.
    wait_past(first_exp).await;
    let second_exp = now_secs() + 2;
    f.rotate_token(&jwt_expiring_at(second_exp)).await;
    put(&f.session).await.expect("the first refresh");
    put(&f.session)
        .await
        .expect("no second start while the new token lives");
    assert_eq!(f.count(ACTION_START), 2, "{:?}", f.actions());

    // Second refresh: the new token passes its exp too.
    wait_past(second_exp).await;
    f.rotate_token(&jwt_expiring_at(FAR_FUTURE_EXP)).await;
    for _ in 0..3 {
        put(&f.session)
            .await
            .expect("a put after the second expiry");
    }
    assert_eq!(
        f.count(ACTION_START),
        3,
        "exactly one more rebind for the second token: {:?}",
        f.actions()
    );
    let sessions = f.put_sessions();
    assert_eq!(sessions.len(), 6, "{sessions:?}");
    assert_ne!(sessions[2], sessions[0]);
    assert_ne!(sessions[5], sessions[2]);
    assert_eq!(f.count(ACTION_STOP), 0);
    f.assert_no_reconnect();
}

/// A 201 whose replacement start is refused (status 2: the user can no longer authorize) fails
/// the operation with `NotAuthorized`. The command is not sent a second time and nothing loops.
#[tokio::test]
async fn a_201_followed_by_a_refused_replacement_start_fails_with_not_authorized_and_stops() {
    let f = fixture(OPAQUE_TOKEN).await;
    put(&f.session).await.expect("an ordinary put");
    let puts_before = f.put_sessions().len();
    let starts_before = f.peer.seen_opcode(AUTHORIZE).len();
    assert_eq!(starts_before, 1);

    f.peer.rule(PUT, expired_then_ok(1));
    f.peer.rule(AUTHORIZE, Reply::Status(2));
    let error = put(&f.session)
        .await
        .expect_err("the replacement session is refused");

    assert!(
        matches!(error, ProtocolError::NotAuthorized(_)),
        "{error:?}"
    );
    assert!(!is_session_expired(&error));
    assert_eq!(
        f.put_sessions().len() - puts_before,
        1,
        "the put was not resent"
    );
    // Let any stray retry loop show itself before counting.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let starts_after = f.peer.seen_opcode(AUTHORIZE).len();
    assert_eq!(
        starts_after - starts_before,
        1,
        "one refused start, no loop"
    );
    assert_eq!(f.put_sessions().len() - puts_before, 1);
    f.assert_no_reconnect();
}

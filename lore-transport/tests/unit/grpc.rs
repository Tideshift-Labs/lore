// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use lore_base::error::AddressNotFound;
use lore_base::types::Hash;
use lore_transport::error::ProtocolError;
use lore_transport::error::branch_push_error;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Status;
use tonic::service::Routes;
use tower::ServiceBuilder;

mod attempt_id_wire_tests;
mod auth_tests;
mod branch_push_wire_tests;
mod call_failure_vs_refusal_wire_tests;
mod domain_operation_client;
mod environment_client;
mod fenced_lock_token_wire_tests;
mod goaway_wire_tests;
mod lock_client;
mod managed_not_prepared_proof_tests;
mod not_prepared_proof_wire_tests;
mod repository_scoped_get;
mod revision_client;
mod session_start_declared_wire_tests;
mod storage_client;

use std::sync::atomic::AtomicUsize;

use lore_transport::grpc::*;

/// A connection that reaches nothing. `with_reconnect` never dials — it only reads the epoch
/// and defers to the supplied rebuild — so the tests drive it entirely offline.
fn test_connection() -> GRPCConnection {
    let endpoint = tonic::transport::Endpoint::from_shared("http://127.0.0.1:1".to_string())
        .expect("test endpoint");
    let channel = ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(endpoint.connect_lazy());
    GRPCConnection::for_test("http://127.0.0.1:1".parse().expect("test url"), channel)
}

/// Serves `routes` on a loopback listener for the rest of the test, and returns the listener's
/// address.
pub(crate) async fn serve_on_loopback(routes: Routes) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let address = listener.local_addr().expect("the listener's address");
    lore_base::lore_spawn!(
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(TcpListenerStream::new(listener))
    );
    address
}

/// Serves `routes` as [`serve_on_loopback`] does, and returns the listener's address and a
/// channel connected to it through [`RequestLoggerLayer`].
pub(crate) async fn serve_logged(routes: Routes) -> (SocketAddr, Channel) {
    let address = serve_on_loopback(routes).await;
    let channel = tonic::transport::Channel::from_shared(format!("http://{address}"))
        .expect("the server's URL")
        .connect()
        .await
        .expect("connect to the test server");
    (
        address,
        ServiceBuilder::new()
            .layer(RequestLoggerLayer {})
            .service(channel),
    )
}

/// An operation the remote answers is returned as-is, without reconnecting.
///
/// Matching the QUIC client, where `NotFound` and friends bubble rather than provoking a
/// reconnect: only a lost channel is the transport's business.
#[tokio::test]
async fn a_server_verdict_is_returned_without_reconnecting() {
    let connection = test_connection();
    let rebuilds = AtomicUsize::new(0);

    let result: Result<(), ProtocolError> = with_reconnect(
        &connection,
        || async { Err(ProtocolError::from(lore_base::error::NotFound)) },
        |_| async {
            rebuilds.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
    )
    .await;

    assert!(
        result.is_err_and(|err| err.is_not_found()),
        "the remote's verdict must reach the caller unchanged",
    );
    assert_eq!(
        rebuilds.load(Ordering::Relaxed),
        0,
        "a verdict is not a lost channel, so nothing should reconnect",
    );
}

/// A remote that keeps reporting a lost channel is given up on rather than retried forever.
///
/// `GRPCConnection::reconnect` only gives up permanently when it cannot reach the remote at
/// all. One that accepts connections while failing every RPC rebuilds successfully every
/// round, so without this bound the loop would never terminate.
#[tokio::test]
async fn attempts_are_bounded_when_the_channel_never_recovers() {
    let connection = test_connection();
    let attempts = AtomicUsize::new(0);
    let rebuilds = AtomicUsize::new(0);

    let result: Result<(), ProtocolError> = with_reconnect(
        &connection,
        || async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(ProtocolError::from(lore_base::error::Disconnected))
        },
        |_| async {
            rebuilds.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
    )
    .await;

    assert!(
        result.is_err_and(|err| err.is_disconnected()),
        "giving up must report a disconnect",
    );
    assert_eq!(attempts.load(Ordering::Relaxed), MAX_RECONNECTS_PER_OP);
    assert_eq!(rebuilds.load(Ordering::Relaxed), MAX_RECONNECTS_PER_OP);
}

/// A failed rebuild ends the call with its error, without another attempt.
#[tokio::test]
async fn a_failed_rebuild_returns_its_error() {
    let connection = test_connection();
    let attempts = AtomicUsize::new(0);
    let rebuilds = AtomicUsize::new(0);

    let result: Result<(), ProtocolError> = with_reconnect(
        &connection,
        || async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(ProtocolError::from(lore_base::error::Disconnected))
        },
        |_| async {
            rebuilds.fetch_add(1, Ordering::Relaxed);
            Err(ProtocolError::from(
                lore_base::error::NotAuthenticated::new("the rebuild was refused"),
            ))
        },
    )
    .await;

    assert!(
        matches!(&result, Err(err) if err.is_not_authenticated()),
        "{result:?}"
    );
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    assert_eq!(rebuilds.load(Ordering::Relaxed), 1);
}

/// Each attempt reads the epoch afresh, so a later attempt still drives a real reconnect.
///
/// Capturing it once outside the loop is the defect this pins: after the first rebuild the
/// epoch has moved, so every later attempt would hand `reconnect` a stale id, which it reads
/// as "somebody else already reconnected" and returns from without doing anything — no
/// reconnect, no backoff, and no route to giving up.
#[tokio::test]
async fn the_epoch_is_read_afresh_for_every_attempt() {
    let connection = test_connection();
    let seen = parking_lot::Mutex::new(Vec::new());

    let _: Result<(), ProtocolError> = with_reconnect(
        &connection,
        || async { Err(ProtocolError::from(lore_base::error::Disconnected)) },
        |reconnect_id| {
            let (seen, connection) = (&seen, &connection);
            async move {
                seen.lock().push(reconnect_id);
                connection.reconnect.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        },
    )
    .await;

    let seen = seen.lock().clone();
    assert_eq!(
        seen,
        (1..=MAX_RECONNECTS_PER_OP as u32).collect::<Vec<_>>(),
        "each attempt must observe the epoch left by the previous rebuild",
    );
}

/// A request's future does not hold the rebuild it runs only after a lost channel.
#[tokio::test]
async fn a_request_does_not_hold_its_rebuild() {
    let connection = test_connection();

    let request = with_reconnect(
        &connection,
        || async { Ok::<(), ProtocolError>(()) },
        |_| async {
            let state = [0u8; 4096];
            tokio::task::yield_now().await;
            std::hint::black_box(state);
            Ok(())
        },
    );

    assert!(
        size_of_val(&request) < 4096,
        "a request holds {} bytes, its rebuild among them",
        size_of_val(&request)
    );
}

fn missing_address() -> AddressNotFound {
    AddressNotFound {
        address: std::array::from_fn(|index| index as u8),
    }
}

/// The address survives the round trip, so a caller can name the fragment
/// the peer is missing.
#[test]
fn a_missing_address_round_trips_through_a_status() {
    let status = Status::from(ProtocolError::from(missing_address()));
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);

    let error = ProtocolError::from(status);
    assert_eq!(
        error.as_address_not_found().map(|error| error.address),
        Some(missing_address().address),
    );
}

/// The details are a trailer, so the round trip has to hold across the
/// headers a peer actually reads.
#[test]
fn a_missing_address_round_trips_through_the_headers() {
    let mut headers = http::HeaderMap::new();
    Status::from(ProtocolError::from(missing_address()))
        .add_header(&mut headers)
        .expect("encode the status");

    let status = Status::from_header_map(&headers).expect("decode the status");
    let error = ProtocolError::from(status);
    assert_eq!(
        error.as_address_not_found().map(|error| error.address),
        Some(missing_address().address),
    );
}

/// `Unauthenticated` maps to `NotAuthenticated`.
#[test]
fn unauthenticated_maps_to_not_authenticated() {
    let error = ProtocolError::from(Status::unauthenticated("authorization header required"));
    assert!(error.is_not_authenticated(), "{error:?}");
}

/// A refusal keeps the remote's reason for it on its trace.
#[test]
fn a_refusal_keeps_the_remotes_reason_on_its_trace() {
    for status in [
        Status::unauthenticated("the token expired"),
        Status::permission_denied("the token expired"),
    ] {
        let error = ProtocolError::from(status);
        assert!(
            error.trace().locations().iter().any(|location| location
                .context()
                .is_some_and(|context| context.contains("the token expired"))),
            "{error:?}"
        );
    }
}

/// A slow down keeps the remote's reason on its trace, as a refusal does.
#[test]
fn a_slow_down_keeps_the_remotes_reason_on_its_trace() {
    let error = ProtocolError::from(Status::resource_exhausted("use branch info"));
    assert!(error.is_slow_down(), "{error:?}");
    assert!(
        error.trace().locations().iter().any(|location| location
            .context()
            .is_some_and(|context| context.contains("use branch info"))),
        "{error:?}"
    );
}

/// A refusal the remote gives no reason for adds no context to the trace.
#[test]
fn a_refusal_without_a_reason_adds_no_context() {
    for status in [Status::unauthenticated(""), Status::permission_denied("")] {
        let error = ProtocolError::from(status);
        assert!(
            error
                .trace()
                .locations()
                .iter()
                .all(|location| location.context().is_none()),
            "{error:?}"
        );
    }
}

/// `NotFound` names an absent object, which a caller recovers from by
/// creating it, and never an address.
#[test]
fn a_not_found_is_never_read_as_an_address() {
    let status = Status::with_details(
        tonic::Code::NotFound,
        "Branch not found",
        Bytes::copy_from_slice(&missing_address().address),
    );

    let error = ProtocolError::from(status);
    assert!(error.is_not_found(), "{error:?}");
}

/// A rejection naming no address is one of the other conditions the code
/// carries, so it stays an opaque failure.
#[test]
fn a_failed_precondition_without_details_is_not_an_address() {
    let error = ProtocolError::from(Status::failed_precondition(
        "Branch push is not a fast-forward",
    ));
    assert!(error.is_internal(), "{error:?}");
}

/// A branch push the remote refuses as not a fast-forward, or as a fast-forward merge that
/// conflicts, and marks so, is `BranchAdvanced`. One it refuses for a missing fragment names the
/// fragment, and another status maps as any call's does.
#[test]
fn a_refused_branch_push_is_branch_advanced() {
    let refused = branch_push_error(branch_advanced_status(
        Hash::from([3; 32]),
        "Branch push is not a fast-forward",
    ));
    let missing = branch_push_error(Status::from(ProtocolError::from(missing_address())));
    let unavailable = branch_push_error(Status::unavailable("restarting"));

    assert!(
        refused.is_branch_advanced()
            && missing.is_address_not_found()
            && unavailable.is_disconnected(),
        "{refused:?}; {missing:?}; {unavailable:?}"
    );
}

/// A branch push refused with `FAILED_PRECONDITION` and no mark, as a pre-push hook or an older
/// Lore Server refuses it, is no `BranchAdvanced`.
#[test]
fn an_unmarked_refusal_of_a_branch_push_is_internal() {
    let refused = branch_push_error(Status::failed_precondition("refused by a hook"));

    assert!(refused.is_internal(), "{refused:?}");
}

/// FORK-LOCAL (Tideshift, WP-120): the details of a `BranchAdvanced` refusal do not outrank the
/// fork's own markers. A `FAILED_PRECONDITION` with 32-byte details that also marks its outcome
/// unknown is `OutcomeUnknown` (the push may have applied), never a refusal.
#[test]
fn an_unknown_outcome_marker_outranks_the_branch_advanced_details() {
    let mut marked =
        branch_advanced_status(Hash::from([3; 32]), "Branch push is not a fast-forward");
    marked.metadata_mut().insert(
        lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
        lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_VALUE
            .parse()
            .unwrap(),
    );
    let error = branch_push_error(marked);
    assert!(
        error.is_outcome_unknown() && !error.is_branch_advanced(),
        "{error:?}"
    );

    // Without the marker, the same details are the refusal.
    let unmarked = branch_push_error(branch_advanced_status(
        Hash::from([3; 32]),
        "Branch push is not a fast-forward",
    ));
    assert!(
        unmarked.is_branch_advanced() && !unmarked.is_outcome_unknown(),
        "{unmarked:?}"
    );
}

/// FORK-LOCAL (Tideshift, CR-019): the server's marked lock refusal is `LockNotOwned` and keeps
/// the server's message on its trace; the same code without the marker stays `NotAuthorized`.
#[test]
fn a_marked_lock_refusal_of_a_branch_push_is_lock_not_owned_with_the_servers_message() {
    let message =
        "push blocked: 1 file(s) changed are locked by another user: 'a.bin' is locked by alice";
    let error = branch_push_error(push_lock_refused_status(message));

    assert!(
        matches!(error, lore_transport::BranchPushError::LockNotOwned(_)),
        "{error:?}"
    );
    assert!(
        !error.is_outcome_unknown() && !error.is_not_authorized(),
        "{error:?}"
    );
    assert!(
        error.trace().locations().iter().any(|location| location
            .context()
            .is_some_and(|context| context.contains(message))),
        "{error:?}"
    );
    // The marker is the documented wire contract, pinned by value.
    let status = push_lock_refused_status("x");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        status
            .metadata()
            .get("lore-push-refusal-v1")
            .map(|value| value.as_bytes()),
        Some(b"lock-not-owned".as_slice())
    );

    // Negative control: an unmarked `PERMISSION_DENIED` is still `NotAuthorized`.
    let unmarked = branch_push_error(Status::permission_denied("protected branch"));
    assert!(
        matches!(unmarked, lore_transport::BranchPushError::NotAuthorized(_)),
        "{unmarked:?}"
    );
}

/// FORK-LOCAL (Tideshift, CR-019): the marker is read only on `PERMISSION_DENIED`.
#[test]
fn the_lock_refusal_marker_on_another_code_is_ignored() {
    for code in [
        tonic::Code::FailedPrecondition,
        tonic::Code::Aborted,
        tonic::Code::Internal,
        tonic::Code::Unauthenticated,
    ] {
        let mut status = Status::new(code, "locked");
        status.metadata_mut().insert(
            PUSH_REFUSAL_HEADER,
            PUSH_REFUSAL_LOCK_NOT_OWNED.parse().unwrap(),
        );
        let error = branch_push_error(status);
        assert!(
            !matches!(error, lore_transport::BranchPushError::LockNotOwned(_)),
            "{code:?}: {error:?}"
        );
    }
}

/// FORK-LOCAL (Tideshift, CR-019): another marker value is not the lock refusal.
#[test]
fn another_push_refusal_marker_value_is_not_a_lock_refusal() {
    let mut status = Status::permission_denied("refused");
    status
        .metadata_mut()
        .insert(PUSH_REFUSAL_HEADER, "something-else".parse().unwrap());
    let error = branch_push_error(status);
    assert!(
        matches!(error, lore_transport::BranchPushError::NotAuthorized(_)),
        "{error:?}"
    );
}

/// FORK-LOCAL (Tideshift, CR-019): a fork outcome marker outranks the lock refusal, so a push
/// that may have applied is never reported as refused.
#[test]
fn an_unknown_outcome_marker_outranks_the_lock_refusal_marker() {
    let mut status = push_lock_refused_status("locked");
    status.metadata_mut().insert(
        lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
        lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_VALUE
            .parse()
            .unwrap(),
    );
    let error = branch_push_error(status);
    assert!(
        error.is_outcome_unknown()
            && !matches!(error, lore_transport::BranchPushError::LockNotOwned(_)),
        "{error:?}"
    );
}

/// The other fork markers that `ProtocolError`'s mapping reads before any branch on the code also
/// win over the details: a tonic lost response (the server produced a message this client could
/// not read) and a client-admission refusal.
#[test]
fn a_lost_response_or_an_admission_refusal_outranks_the_branch_advanced_details() {
    let lost = branch_push_error(Status::with_details(
        tonic::Code::FailedPrecondition,
        "Missing response message.",
        Bytes::copy_from_slice(&[3; 32]),
    ));
    assert!(!lost.is_branch_advanced(), "{lost:?}");
    assert!(lost.is_internal(), "{lost:?}");

    let mut refused = branch_advanced_status(Hash::from([3; 32]), "unsupported client");
    refused.metadata_mut().insert(
        "lore-client-admission-v1",
        "unsupported-client".parse().unwrap(),
    );
    let refused = branch_push_error(refused);
    assert!(!refused.is_branch_advanced(), "{refused:?}");
    assert!(refused.is_internal(), "{refused:?}");
}

/// Details of any other length are not guessed at.
#[test]
fn details_of_another_length_are_not_read_as_an_address() {
    let status = Status::with_details(
        tonic::Code::FailedPrecondition,
        "Missing fragment",
        Bytes::from_static(&[1, 2, 3]),
    );

    let error = ProtocolError::from(status);
    assert!(error.is_internal(), "{error:?}");
}

/// WP-124 slice 2b: `lore(s)://` and `grpc(s)://` name the same gRPC endpoint, so a managed
/// journal never records a `lore(s)://` namespace and `recovery_dial_url` keeps working.
#[test]
fn lore_and_grpc_schemes_normalize_to_the_same_http_endpoint() {
    for (lore, grpc, expected) in [
        (
            "lore://h.example:41337",
            "grpc://h.example:41337",
            "http://h.example:41337/",
        ),
        (
            "lores://h.example:41337",
            "grpcs://h.example:41337",
            "https://h.example:41337/",
        ),
        (
            "lore://127.0.0.1:8080",
            "grpc://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
        ),
        (
            "lores://[::1]:9443",
            "grpcs://[::1]:9443",
            "https://[::1]:9443/",
        ),
    ] {
        let from_lore = grpc_endpoint(lore).expect("lore url");
        let from_grpc = grpc_endpoint(grpc).expect("grpc url");
        assert_eq!(from_lore, from_grpc, "{lore} vs {grpc}");
        assert_eq!(from_lore.as_str(), expected, "{lore}");
        assert!(
            !from_lore.scheme().starts_with("lore"),
            "a journal namespace never records lore(s)://: {from_lore}"
        );
    }
}

/// A missing port takes the same default whichever of the two schemes spelled the remote.
#[test]
fn lore_and_grpc_schemes_take_the_same_default_port() {
    for (lore, grpc) in [
        ("lore://h.example", "grpc://h.example"),
        ("lores://h.example", "grpcs://h.example"),
    ] {
        assert_eq!(
            grpc_endpoint(lore).expect("lore url"),
            grpc_endpoint(grpc).expect("grpc url"),
            "{lore} vs {grpc}"
        );
    }
}

#[test]
fn grpc_endpoint_refuses_a_remote_it_cannot_dial() {
    for remote in ["", "not a url", "lore://", "lores:///only-a-path"] {
        assert!(grpc_endpoint(remote).is_err(), "must refuse {remote:?}");
    }
}

fn authorization_header(auth: GRPCAuth) -> Option<String> {
    let mut interceptor = AuthnInterceptor {
        auth: std::sync::Arc::new(parking_lot::RwLock::new(auth)),
    };
    let request = tonic::service::Interceptor::call(&mut interceptor, tonic::Request::new(()))
        .expect("the interceptor accepts the request");
    request
        .metadata()
        .get("authorization")
        .map(|value| value.to_str().expect("an ASCII header").to_string())
}

/// The repository service sends the authentication token, and the authorization token when there
/// is none: a caller that supplied only an access token presents it.
#[test]
fn the_authn_interceptor_falls_back_to_the_authorization_token() {
    let both = GRPCAuth {
        authentication_token: "identity".to_string(),
        authorization_token: "access".to_string(),
        ..Default::default()
    };
    let access_only = GRPCAuth {
        authorization_token: "access".to_string(),
        ..Default::default()
    };

    assert_eq!(
        authorization_header(both).as_deref(),
        Some("Bearer identity")
    );
    assert_eq!(
        authorization_header(access_only).as_deref(),
        Some("Bearer access")
    );
    assert_eq!(authorization_header(GRPCAuth::default()), None);
}

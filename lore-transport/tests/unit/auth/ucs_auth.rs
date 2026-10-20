// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::convert::Infallible;
use std::future::Ready;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;

use lore_base::types::RepositoryId;
use lore_proto::auth::RefreshAuthSessionRequest;
use lore_proto::auth::UserToken;
use lore_proto::auth::urc_auth_api_client::UrcAuthApiClient;
use lore_transport::Authentication;
use lore_transport::auth::ucs_auth::*;

#[derive(Clone, Default)]
struct CaptureGrpcPath {
    path: Arc<Mutex<Option<String>>>,
}

impl tower::Service<http::Request<tonic::body::Body>> for CaptureGrpcPath {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        *self.path.lock().expect("path lock") = Some(request.uri().path().to_string());
        std::future::ready(Ok(http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("grpc-status", tonic::Code::Unimplemented as i32)
            .body(tonic::body::Body::empty())
            .expect("valid gRPC response")))
    }
}

fn wire_user_token(refresh_token: Option<&str>) -> UserToken {
    UserToken {
        user_token: "authn-token".to_string(),
        expires_at: 1_234,
        user_id: "user-1".to_string(),
        user_name: "User One".to_string(),
        refresh_token: refresh_token.map(str::to_string),
    }
}
#[test]
fn grpc_endpoint_ucs_auth() {
    assert_eq!(
        grpc_endpoint("ucs-auth://auth.example.com"),
        "https://auth.example.com"
    );
}

#[test]
fn grpc_endpoint_https() {
    assert_eq!(
        grpc_endpoint("https://auth.example.com"),
        "https://auth.example.com"
    );
}

#[test]
fn grpc_endpoint_http_to_loopback_is_preserved() {
    assert_eq!(
        grpc_endpoint("http://127.0.0.1:41339"),
        "http://127.0.0.1:41339"
    );
    assert_eq!(
        grpc_endpoint("http://localhost:41339"),
        "http://localhost:41339"
    );
    // A parsed loopback IP literal counts, IPv6 included.
    assert_eq!(grpc_endpoint("http://[::1]:41339"), "http://[::1]:41339");
}

/// The downgrade defence: a rogue server advertising a plaintext variant
/// of a real auth host must not steer login and exchange tokens onto an
/// unencrypted channel. Any non-loopback http URL is upgraded to https.
#[test]
fn grpc_endpoint_http_to_remote_host_is_upgraded() {
    assert_eq!(
        grpc_endpoint("http://auth.example.com"),
        "https://auth.example.com"
    );
    assert_eq!(
        grpc_endpoint("http://auth.example.com:8080/path"),
        "https://auth.example.com:8080/path"
    );
    // A crafted host that merely starts with a local name is not local.
    assert_eq!(
        grpc_endpoint("http://localhost.evil.example"),
        "https://localhost.evil.example"
    );
}

/// Userinfo in the authority is the classic trick against hand-rolled
/// host extraction: the URL's host below is `auth.example.com`, and a
/// splitter taking the first `:`/`/` segment reads `localhost`. Such a
/// URL must never keep plaintext — and any URL carrying userinfo is
/// refused the loopback exemption outright.
#[test]
fn grpc_endpoint_userinfo_cannot_spoof_loopback() {
    assert_eq!(
        grpc_endpoint("http://localhost:password@auth.example.com"),
        "https://localhost:password@auth.example.com"
    );
    assert_eq!(
        grpc_endpoint("http://localhost@auth.example.com"),
        "https://localhost@auth.example.com"
    );
    // Even a genuine loopback host gets no plaintext with userinfo present.
    assert_eq!(
        grpc_endpoint("http://user:password@127.0.0.1:41339"),
        "https://user:password@127.0.0.1:41339"
    );
}

#[test]
fn grpc_endpoint_no_scheme() {
    assert_eq!(
        grpc_endpoint("auth.example.com"),
        "https://auth.example.com"
    );
}

#[test]
fn grpc_endpoint_custom_scheme() {
    assert_eq!(
        grpc_endpoint("custom://auth.example.com:8443/path"),
        "https://auth.example.com:8443/path"
    );
}

#[test]
fn resource_id_format() {
    let repo_id = RepositoryId::default();
    let rid = resource_id(repo_id);
    assert!(rid.starts_with("urc-"));
    // Default RepositoryId is all zeros, displayed as hex
    assert_eq!(rid, "urc-00000000000000000000000000000000");
}

#[test]
fn authentication_token_maps_refresh_credential() {
    let token = authentication_token(wire_user_token(Some("refresh-1")));

    assert_eq!(token.refresh_token.as_deref(), Some("refresh-1"));
}

#[test]
fn authentication_token_preserves_absent_refresh_credential() {
    let token = authentication_token(wire_user_token(None));

    assert!(token.refresh_token.is_none());
}

#[test]
fn authentication_token_treats_empty_refresh_credential_as_absent() {
    let token = authentication_token(wire_user_token(Some("")));

    assert!(token.refresh_token.is_none());
}

#[test]
fn authentication_token_maps_identity_and_expiry() {
    let token = authentication_token(wire_user_token(Some("refresh-1")));

    assert_eq!(
        (
            token.token.as_str(),
            token.user_id.as_str(),
            token.user_name.as_str(),
            token.expires_ms,
        ),
        ("authn-token", "user-1", "User One", 1_234)
    );
}

#[test]
fn authentication_token_clamps_negative_expiry_to_zero() {
    let mut wire = wire_user_token(None);
    wire.expires_at = -1;

    assert_eq!(authentication_token(wire).expires_ms, 0);
}

#[test]
fn refresh_request_is_empty_and_bearer_is_sensitive() {
    let mut request = tonic::Request::new(RefreshAuthSessionRequest {});

    set_auth_header(&mut request, "opaque refresh").expect("valid metadata");

    let header = request
        .metadata()
        .get("authorization")
        .expect("authorization header");
    assert_eq!(
        header.to_str().expect("ASCII header"),
        "Bearer opaque refresh"
    );
    assert!(header.is_sensitive());
    assert_eq!(request.into_inner(), RefreshAuthSessionRequest {});
}

#[tokio::test]
async fn generated_refresh_client_uses_exact_rpc_path() {
    let service = CaptureGrpcPath::default();
    let path = Arc::clone(&service.path);
    let mut client = UrcAuthApiClient::new(service);

    let error = client
        .refresh_auth_session(RefreshAuthSessionRequest {})
        .await
        .expect_err("stub returns unimplemented");

    assert_eq!(error.code(), tonic::Code::Unimplemented);
    assert_eq!(
        path.lock().expect("path lock").as_deref(),
        Some("/epic_urc.UrcAuthApi/RefreshAuthSession")
    );
}

#[test]
fn required_authentication_token_reports_empty_exchange_response() {
    let error = required_authentication_token(None, "exchange")
        .expect_err("missing exchange token must fail");

    assert!(
        error
            .to_string()
            .contains("empty user token in exchange response")
    );
}

#[test]
fn required_authentication_token_reports_empty_refresh_response() {
    let error = required_authentication_token(None, "refresh")
        .expect_err("missing refresh token must fail");

    assert!(
        error
            .to_string()
            .contains("empty user token in refresh response")
    );
}

/// Holds a TCP connection open without ever speaking HTTP/2, so the client's handshake can
/// never complete. Returns the url.
async fn mute_listener() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    url
}

/// An HTTP/2 server that completes the handshake and accepts requests but never answers them.
async fn unanswering_h2_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    #[allow(clippy::disallowed_methods)] // Test-local server task.
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            #[allow(clippy::disallowed_methods)] // Test-local connection task.
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::handshake(socket).await else {
                    return;
                };
                let mut held = Vec::new();
                while let Some(Ok(request)) = conn.accept().await {
                    held.push(request);
                }
            });
        }
    });
    url
}

/// Nothing listening: the connect fails fast with an error rather than hanging.
#[tokio::test]
async fn auth_call_against_a_closed_port_errors_promptly() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        UcsAuthentication.exchange_for_custom_resource(&url, "token", "urc-x", "corr"),
    )
    .await
    .expect("a refused connection must not hang");
    assert!(result.is_err(), "no server cannot yield a token");
}

/// An endpoint that accepts the TCP connection and never completes the HTTP/2 handshake must
/// produce an error, not block its caller (and a session rebind's lock) forever.
///
/// Measured: the 5 s `connect_timeout` does NOT end this wait (tonic's `connect()` returns
/// before the HTTP/2 handshake finishes); the 30 s per-RPC timeout does, as `Cancelled` /
/// `TimeoutExpired`. Ignored by default only because the bound is 30 s of real time.
#[tokio::test]
#[ignore = "waits out the 30 s per-RPC timeout in real time"]
async fn auth_call_against_an_endpoint_that_never_handshakes_errors_at_the_rpc_timeout() {
    let url = mute_listener().await;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        UcsAuthentication.exchange_for_custom_resource(&url, "token", "urc-x", "corr"),
    )
    .await
    .expect("the auth channel must bound a handshake that never completes");
    assert!(result.is_err(), "no answer cannot be a token");
    let took = started.elapsed();
    assert!(
        took >= std::time::Duration::from_secs(25) && took < std::time::Duration::from_secs(40),
        "expected the 30 s RPC bound, took {took:?}"
    );
}

/// A server that handshakes but never answers the RPC is cut by the 30 s per-RPC timeout.
/// Ignored by default only because the bound is real wall time.
#[tokio::test]
#[ignore = "waits out the 30 s per-RPC timeout in real time"]
async fn auth_call_against_an_unanswering_server_errors_at_the_rpc_timeout() {
    let url = unanswering_h2_server().await;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        UcsAuthentication.exchange_for_custom_resource(&url, "token", "urc-x", "corr"),
    )
    .await
    .expect("the per-RPC timeout must end the call");
    assert!(result.is_err(), "no answer cannot be a token");
    let took = started.elapsed();
    assert!(
        took >= std::time::Duration::from_secs(25) && took < std::time::Duration::from_secs(40),
        "expected the 30 s RPC bound, took {took:?}"
    );
}

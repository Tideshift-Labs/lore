// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the shared auth channel over real TLS, when its
//! idle connection drops and the peer then accepts TCP but never answers the
//! TLS handshake. tonic re-dials under the next call by itself, so only the
//! per-call timeout bounds that call.
//!
//! A binary of its own: the fake's CA is trusted through `SSL_CERT_FILE`,
//! which `rustls-native-certs` reads and which is process-wide.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use futures::future::join_all;
use lore_proto::auth::CheckUserPermissionRequest;
use lore_server::authnz::auth::AUTH_CONNECT_TIMEOUT;
use lore_server::authnz::auth::AUTH_DEADLINE;
use lore_server::authnz::auth::AUTH_OUTAGE_HOLD;
use lore_server::authnz::auth::AuthChannel;
use lore_server::authnz::auth::is_auth_unavailable;
use tonic::codegen::*;

#[derive(Clone)]
struct AllowAll {
    /// Never answers `CheckUserPermission`.
    hang: bool,
}

impl tonic::server::NamedService for AllowAll {
    const NAME: &'static str = "epic_urc.UrcAuthApi";
}

struct CheckUserPermission {
    hang: bool,
}

impl tonic::server::UnaryService<CheckUserPermissionRequest> for CheckUserPermission {
    type Response = lore_proto::auth::CheckUserPermissionResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<CheckUserPermissionRequest>) -> Self::Future {
        let hang = self.hang;
        Box::pin(async move {
            if hang {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            Ok(tonic::Response::new(
                lore_proto::auth::CheckUserPermissionResponse {
                    allowed_resource_permission: request
                        .into_inner()
                        .resource_id
                        .into_iter()
                        .map(|resource_id| lore_proto::auth::ResourcePermission {
                            resource_id,
                            permission: vec!["read".to_string()],
                        })
                        .collect(),
                    denied_resource_permission: vec![],
                },
            ))
        })
    }
}

impl<B> Service<http::Request<B>> for AllowAll
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
        let hang = self.hang;
        Box::pin(async move { Ok(grpc.unary(CheckUserPermission { hang }, request).await) })
    }
}

/// A CA trusted through `SSL_CERT_FILE` and a server identity for
/// `127.0.0.1` it signed.
fn trust_a_test_ca() -> tonic::transport::Identity {
    // One CA per process: `SSL_CERT_FILE` is process-wide and tests run in parallel.
    static CA: std::sync::OnceLock<(lore_base::test_util::TempDir, tonic::transport::Identity)> =
        std::sync::OnceLock::new();
    CA.get_or_init(|| {
        let dir = lore_base::test_util::TempDir::new("lore-auth-channel-tls-");
        let identity = make_test_ca(dir.path());
        (dir, identity)
    })
    .1
    .clone()
}

fn make_test_ca(dir: &std::path::Path) -> tonic::transport::Identity {
    use rcgen::BasicConstraints;
    use rcgen::CertificateParams;
    use rcgen::IsCa;
    use rcgen::Issuer;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_path = dir.join("ca.crt");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&server_key, &issuer)
        .unwrap();

    // SAFETY: runs once, under the `OnceLock`, before any test dials.
    unsafe { std::env::set_var("SSL_CERT_FILE", &ca_path) };
    tonic::transport::Identity::from_pem(server_cert.pem(), server_key.serialize_pem())
}

/// Starts the TLS fake on an ephemeral port and returns its address.
async fn start_tls_auth(identity: tonic::transport::Identity, hang: bool) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    lore_base::lore_spawn!(async move {
        let _ = tonic::transport::Server::builder()
            .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))
            .unwrap()
            .add_service(AllowAll { hang })
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });
    address
}

/// A TCP front that relays to the fake, or accepts and holds connections
/// without a byte (a stalled TLS handshake), and can drop every relay.
struct Front {
    address: SocketAddr,
    stall: Arc<AtomicBool>,
    /// Milliseconds each new connection is held before it is relayed.
    delay_ms: Arc<AtomicU64>,
    relays: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Front {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = Front {
            address: listener.local_addr().unwrap(),
            stall: Arc::default(),
            delay_ms: Arc::default(),
            relays: Arc::default(),
        };
        let stall = front.stall.clone();
        let delay_ms = front.delay_ms.clone();
        let relays = front.relays.clone();
        lore_base::lore_spawn!(async move {
            let mut held = Vec::new();
            while let Ok((mut down, _)) = listener.accept().await {
                if stall.load(Ordering::SeqCst) {
                    held.push(down);
                    continue;
                }
                let delay = Duration::from_millis(delay_ms.load(Ordering::SeqCst));
                let relay = lore_base::lore_spawn!(async move {
                    tokio::time::sleep(delay).await;
                    if let Ok(mut up) = tokio::net::TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                });
                relays.lock().unwrap().push(relay);
            }
        });
        front
    }

    /// Drops every relayed connection.
    async fn drop_connections(&self) {
        let relays: Vec<_> = self.relays.lock().unwrap().drain(..).collect();
        for relay in relays {
            relay.abort();
            let _ = relay.await;
        }
    }
}

fn permission_request() -> tonic::Request<CheckUserPermissionRequest> {
    tonic::Request::new(CheckUserPermissionRequest {
        resource_id: vec!["urc-0194b726b34e72b0b45550b88a967076".to_string()],
        target_user: None,
    })
}

async fn call(channel: &AuthChannel) -> Result<(), tonic::Status> {
    channel
        .client()
        .await?
        .check_user_permission(permission_request())
        .await
        .map(|_| ())
}

/// P6: the idle connection drops, then the peer stalls TLS. The call on the
/// cached channel fails within the call timeout, the channel is discarded,
/// a wave after it shares one bounded dial, and once the peer answers again
/// the next call passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_drop_then_a_tls_stall_is_bounded_and_recovers() {
    let identity = trust_a_test_ca();
    let upstream = start_tls_auth(identity, false).await;
    let front = Front::start(upstream).await;
    let channel = AuthChannel::new(format!("https://{}", front.address));

    call(&channel).await.expect("first call over TLS");
    assert_eq!(channel.dial_attempts(), 1);

    // The idle connection drops; from now on the peer stalls TLS.
    front.stall.store(true, Ordering::SeqCst);
    front.drop_connections().await;
    // Let the client see the close while idle, so the next call re-dials
    // rather than racing the close on the old connection.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let margin = Duration::from_secs(3);
    let started = Instant::now();
    let status = tokio::time::timeout(AUTH_DEADLINE * 3, call(&channel))
        .await
        .expect("the call on the dropped channel hung")
        .unwrap_err();
    let elapsed = started.elapsed();
    assert!(elapsed < AUTH_DEADLINE + margin, "{elapsed:?}");
    assert_eq!(status.code(), tonic::Code::Internal, "{status:?}");
    assert!(is_auth_unavailable(&status), "{status:?}");
    assert!(
        status
            .message()
            .contains("did not answer check_user_permission within"),
        "{status:?}"
    );
    assert_eq!(
        channel.dial_attempts(),
        1,
        "the re-dial was tonic's own, under the call"
    );

    // The timeout started a hold: a wave right after it fails at once and
    // dials nothing.
    let started = Instant::now();
    let held = join_all((0..10).map(|_| call(&channel))).await;
    assert!(
        held.iter()
            .all(|result| matches!(result, Err(status) if is_auth_unavailable(status)))
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(channel.dial_attempts(), 1);
    tokio::time::sleep(AUTH_OUTAGE_HOLD + Duration::from_millis(300)).await;

    // The channel was discarded: a wave shares one fresh, bounded dial.
    let started = Instant::now();
    let wave = tokio::time::timeout(AUTH_DEADLINE * 3, join_all((0..10).map(|_| call(&channel))))
        .await
        .expect("the wave hung");
    let elapsed = started.elapsed();
    assert!(wave.iter().all(Result::is_err));
    assert!(elapsed < AUTH_CONNECT_TIMEOUT + margin, "{elapsed:?}");
    assert_eq!(channel.dial_attempts(), 2);

    // The stalled dial timed out, which started another hold: wait it out.
    // The peer answers again: the next call dials and passes.
    tokio::time::sleep(AUTH_OUTAGE_HOLD + Duration::from_millis(300)).await;
    front.stall.store(false, Ordering::SeqCst);
    call(&channel).await.expect("call after the peer recovered");
    assert_eq!(channel.dial_attempts(), 3);
}

/// The dial and the call share ONE deadline. Over TLS the handshake is part
/// of the dial, so a front that holds each new connection for 3 s delays
/// `client()` itself; the service then never answers. The request fails at
/// about the deadline, not at the dial delay plus a deadline (a per-call
/// deadline would give about 11 s, the old dial-plus-call timeouts about 13 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_tls_dial_then_a_hanging_call_fail_together_within_one_deadline() {
    let identity = trust_a_test_ca();
    let upstream = start_tls_auth(identity, true).await;
    let front = Front::start(upstream).await;
    front.delay_ms.store(3000, Ordering::SeqCst);
    let channel = AuthChannel::new(format!("https://{}", front.address));

    let started = Instant::now();
    let mut client = tokio::time::timeout(AUTH_DEADLINE * 3, channel.client())
        .await
        .expect("the slow dial hung")
        .expect("a 3 s dial is within the deadline");
    let dialled = started.elapsed();
    assert!(
        dialled >= Duration::from_millis(2500),
        "the delay did not land in the dial: {dialled:?}"
    );

    let status = tokio::time::timeout(
        AUTH_DEADLINE * 3,
        client.check_user_permission(permission_request()),
    )
    .await
    .expect("an unanswered RPC was not bounded")
    .unwrap_err();
    let elapsed = started.elapsed();
    eprintln!("tls: client() took {dialled:?}, total {elapsed:?}");
    assert!(
        elapsed >= AUTH_DEADLINE - Duration::from_millis(200),
        "{elapsed:?}"
    );
    assert!(
        elapsed < AUTH_DEADLINE + Duration::from_millis(1500),
        "dial delay plus a fresh deadline: {elapsed:?}"
    );
    assert_eq!(status.code(), tonic::Code::Internal, "{status:?}");
    assert!(is_auth_unavailable(&status), "{status:?}");
    assert!(
        status
            .message()
            .contains(&format!("within {AUTH_DEADLINE:?}")),
        "{status:?}"
    );
}

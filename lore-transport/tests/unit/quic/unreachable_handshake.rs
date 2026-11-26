// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! A QUIC handshake that gets no answer fails as `Disconnected`, and says where it went.
//!
//! [CLIENT]-class (`lore-transport`). A front that drops UDP while it passes TCP leaves sign-in
//! and every gRPC call working, and only the QUIC storage path dead. The handshake gives up after
//! its own 5 s timeout; the error names the host and UDP port and why it may have failed, rather
//! than only "Disconnected".
//!
//! The "server" here is a bound UDP socket that never reads or answers, so the handshake times
//! out for real.
use std::net::UdpSocket;
use std::sync::Weak;
use std::time::Duration;
use std::time::Instant;

use lore_base::types::Partition;
use lore_transport::SuppliedCredentials;
use lore_transport::error::ProtocolError;
use lore_transport::quic::client::CertificateSettings;
use lore_transport::quic::client::CongestionAlgorithm;
use lore_transport::quic::client::DEFAULT_EXPECTED_RTT_MS;
use lore_transport::quic::client::EndpointConfig;
use lore_transport::quic::client::TransportConfig;
use lore_transport::quic::client::connect;
use lore_transport::quic::client::quic_unreachable_message;
use lore_transport::quic::storage_service::client::StorageClient;

/// The handshake timeout is 5 s. Anything near quinn's 30 s idle timeout means the handshake was
/// not bounded by it.
const HANDSHAKE_FLOOR: Duration = Duration::from_secs(4);
const HANDSHAKE_CEILING: Duration = Duration::from_secs(12);

/// A UDP socket on loopback that is bound, so no ICMP port-unreachable comes back, and never
/// answers.
fn black_hole() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
    let port = socket.local_addr().expect("local address").port();
    (socket, port)
}

fn has_context(error: &ProtocolError, needle: &str) -> bool {
    error.trace().locations().iter().any(|location| {
        location
            .context()
            .is_some_and(|context| context.contains(needle))
    })
}

fn assert_names_where_it_went(error: &ProtocolError, port: u16) {
    assert_names_where_it_went_over(error, port, "grpcs");
}

/// The error names the endpoint in its trace and carries it typed: host, UDP port, and the TCP URL
/// (`grpcs://` for a `lores://` remote, `grpc://` for `lore://`) to clone again with.
fn assert_names_where_it_went_over(error: &ProtocolError, port: u16, tcp_scheme: &str) {
    assert!(error.is_disconnected(), "{error:?}");
    // The trace carries the short fact. The firewall hint lives in the message only: the CLI
    // prints both, and would print the hint twice.
    let short = format!("no QUIC handshake answered from 127.0.0.1 on UDP port {port} within 5 s");
    assert!(has_context(error, &short), "missing {short:?}: {error:?}");
    assert!(
        !has_context(error, "firewall"),
        "the hint must not repeat in the trace: {error:?}"
    );
    let unreachable = error
        .quic_unreachable()
        .unwrap_or_else(|| panic!("the error carries no typed unreachable detail: {error:?}"));
    assert_eq!(unreachable.host, "127.0.0.1");
    assert_eq!(unreachable.port, port);
    assert_eq!(
        unreachable.tcp_url,
        format!("{tcp_scheme}://127.0.0.1:{port}")
    );
    // The message the caller reads carries the hint (the first connect logs no warning of its own).
    let message = error.to_string();
    for needle in ["UDP port", "firewall or VPN", unreachable.tcp_url.as_str()] {
        assert!(
            message.contains(needle),
            "message lacks {needle:?}: {message}"
        );
    }
}

fn assert_one_handshake_bound(elapsed: Duration) {
    assert!(
        elapsed >= HANDSHAKE_FLOOR && elapsed < HANDSHAKE_CEILING,
        "expected about one 5 s handshake timeout, took {elapsed:?}"
    );
}

#[tokio::test]
async fn a_quic_connect_that_gets_no_answer_is_disconnected_after_one_handshake_timeout() {
    let (_socket, port) = black_hole();
    let config = EndpointConfig {
        remote_url: format!("lores://127.0.0.1:{port}"),
        default_port: 1,
        sni_override: None,
    };

    let start = Instant::now();
    let result = connect(
        &config,
        CertificateSettings {
            custom_ca: None,
            client: None,
        },
        "lore-storage/1",
        TransportConfig {
            max_bytes_bandwidth_per_second: (1024 * 1024 * 1024) / 8,
            expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
            congestion_algorithm: CongestionAlgorithm::default(),
            initial_cwnd: None,
        },
    )
    .await;
    let elapsed = start.elapsed();

    let Err(error) = result else {
        panic!("a socket that never answers cannot complete a handshake");
    };
    assert_names_where_it_went(&error, port);
    assert_one_handshake_bound(elapsed);
}

#[tokio::test]
async fn a_storage_connect_that_gets_no_answer_is_disconnected_and_names_the_port() {
    let (_socket, port) = black_hole();

    let start = Instant::now();
    let result = StorageClient::connect(
        Weak::new(),
        &format!("lores://127.0.0.1:{port}"),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "unreachable-handshake",
        Partition::from([0x24u8; 16]),
        &std::sync::Arc::new(SuppliedCredentials::default()),
        None,
        CongestionAlgorithm::default(),
    )
    .await;
    let elapsed = start.elapsed();

    let Err(error) = result else {
        panic!("a socket that never answers cannot complete a handshake");
    };
    assert_names_where_it_went(&error, port);
    assert_one_handshake_bound(elapsed);
}

#[tokio::test]
async fn a_plain_lore_remote_maps_to_a_grpc_tcp_url() {
    let (_socket, port) = black_hole();

    let result = StorageClient::connect(
        Weak::new(),
        &format!("lore://127.0.0.1:{port}"),
        "127.0.0.1".to_string(),
        &lore_transport::auth::AuthEndpoint::none(),
        "unreachable-handshake-plain",
        Partition::from([0x24u8; 16]),
        &std::sync::Arc::new(SuppliedCredentials::default()),
        None,
        CongestionAlgorithm::default(),
    )
    .await;

    let Err(error) = result else {
        panic!("a socket that never answers cannot complete a handshake");
    };
    assert_names_where_it_went_over(&error, port, "grpc");
}
#[test]
fn the_unreachable_message_names_host_and_port_and_never_the_credentials() {
    let message = quic_unreachable_message("lores://user:secret@example.test:1234", 41337, true);

    assert!(message.contains("example.test"), "{message}");
    assert!(message.contains("UDP port 1234"), "{message}");
    assert!(!message.contains("41337"), "{message}");
    assert!(!message.contains("secret"), "{message}");
    assert!(!message.contains("user"), "{message}");
    assert!(message.contains("5 s"), "{message}");
    assert!(message.contains("firewall or VPN"), "{message}");
}

#[test]
fn the_unreachable_message_falls_back_to_the_default_port() {
    let message = quic_unreachable_message("lores://example.test", 41337, true);

    assert!(message.contains("example.test"), "{message}");
    assert!(message.contains("UDP port 41337"), "{message}");
}

#[test]
fn the_unreachable_message_for_an_unparseable_url_leaks_nothing() {
    for timed_out in [true, false] {
        let message = quic_unreachable_message("not a url with secret", 41337, timed_out);

        assert!(message.contains("UDP port 41337"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }
}

/// The timed-out text ends with how to use TCP by hand: the remote's own TLS choice, host and
/// port, never the URL's userinfo.
#[test]
fn the_timed_out_message_gives_the_tcp_url_with_the_remotes_tls_choice() {
    let tls = quic_unreachable_message("lores://user:secret@example.test:1234", 41337, true);
    let plain = quic_unreachable_message("lore://example.test:1234", 41337, true);
    let unparseable = quic_unreachable_message("not a url with secret", 41337, true);

    assert!(
        tls.ends_with("clone again with grpcs://example.test:1234/<repository>"),
        "{tls}"
    );
    assert!(
        plain.ends_with("clone again with grpc://example.test:1234/<repository>"),
        "{plain}"
    );
    assert!(!tls.contains("secret") && !tls.contains("user"), "{tls}");
    assert!(
        unparseable.ends_with("clone again with grpcs://<host>:41337/<repository>"),
        "{unparseable}"
    );
    assert!(!unparseable.contains("secret"), "{unparseable}");
}

/// A handshake that was answered and failed is not a blocked-UDP case, so its message does not
/// send the user to their firewall.
#[test]
fn the_failed_handshake_message_names_the_endpoint_and_gives_no_firewall_hint() {
    let message = quic_unreachable_message("lores://user:secret@example.test:1234", 41337, false);

    assert!(message.contains("example.test"), "{message}");
    assert!(message.contains("UDP port 1234"), "{message}");
    assert!(message.contains("the handshake failed"), "{message}");
    assert!(!message.contains("secret"), "{message}");
    assert!(!message.contains("firewall"), "{message}");
    assert!(!message.contains("VPN"), "{message}");
    assert!(!message.contains("clone again"), "{message}");
    assert!(!message.contains("grpc"), "{message}");
    assert!(!message.contains("within"), "{message}");
}

/// A server that answers the handshake with a certificate the client does not trust: the
/// handshake fails at once, not after the timeout, and says so without the firewall hint.
#[tokio::test]
async fn a_handshake_the_server_answers_and_fails_says_so_without_the_firewall_hint() {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::PemObject;

    const ALPN: &str = "lore-storage/1";

    let cert = lore_transport::tls::generate_self_signed(vec!["127.0.0.1".to_string()])
        .expect("self-signed cert");
    let cert_der = CertificateDer::from_pem_slice(cert.cert_pem.as_bytes())
        .expect("parse cert")
        .into_owned();
    let key_der = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).expect("parse key");
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server crypto config");
    server_crypto.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .expect("quic server crypto"),
    ));
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().expect("address"))
        .expect("bind the server");
    let port = server.local_addr().expect("local address").port();
    let accepting = lore_base::lore_spawn!(async move {
        // Drives the handshake; the client abandons it, so its result is not the test's.
        while let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    let start = Instant::now();
    let result = connect(
        &EndpointConfig {
            remote_url: format!("lores://127.0.0.1:{port}"),
            default_port: 1,
            sni_override: None,
        },
        CertificateSettings {
            custom_ca: None,
            client: None,
        },
        ALPN,
        TransportConfig {
            max_bytes_bandwidth_per_second: (1024 * 1024 * 1024) / 8,
            expected_rtt_ms: DEFAULT_EXPECTED_RTT_MS,
            congestion_algorithm: CongestionAlgorithm::default(),
            initial_cwnd: None,
        },
    )
    .await;
    let elapsed = start.elapsed();
    accepting.abort();

    let Err(error) = result else {
        panic!("an untrusted certificate cannot complete a handshake");
    };
    assert!(error.is_disconnected(), "{error:?}");
    assert!(
        elapsed < HANDSHAKE_FLOOR,
        "an answered handshake fails before the timeout, took {elapsed:?}"
    );
    assert!(has_context(&error, "the handshake failed"), "{error:?}");
    assert!(
        has_context(&error, &format!("UDP port {port}")),
        "{error:?}"
    );
    assert!(!has_context(&error, "firewall"), "{error:?}");
    assert!(error.quic_unreachable().is_none(), "{error:?}");
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::ServerName;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

pub struct ProxyTlsMaterial {
    pub root_ca_pem: String,
    pub maintenance_certificate_chain_pem: String,
    pub maintenance_private_key_pem: String,
    pub server_certificate_chain_pem: String,
    pub server_private_key_pem: String,
    pub expected_client_common_name: String,
}

pub struct RetentionFaultProxy {
    port: u16,
    stall_next_response: Arc<AtomicBool>,
    drop_next_commit_response: Arc<AtomicBool>,
    commit_fault_fired: Arc<AtomicBool>,
    commit_fault_notify: Arc<Notify>,
    shutdown: CancellationToken,
    task: Option<AbortOnDropHandle<()>>,
}

#[derive(Clone)]
struct ConnectionFaults {
    stall_next_response: Arc<AtomicBool>,
    drop_next_commit_response: Arc<AtomicBool>,
    commit_fault_fired: Arc<AtomicBool>,
    commit_fault_notify: Arc<Notify>,
}

impl RetentionFaultProxy {
    pub async fn start(upstream_host: String, upstream_port: u16, tls: ProxyTlsMaterial) -> Self {
        let listener = TcpListener::bind(("localhost", 0))
            .await
            .expect("bind retention fault proxy");
        let port = listener.local_addr().expect("proxy local address").port();
        let expected_client_common_name = Arc::new(tls.expected_client_common_name.clone());
        let acceptor = downstream_acceptor(&tls);
        let connector = upstream_connector(&tls);
        let stall_next_response = Arc::new(AtomicBool::new(false));
        let drop_next_commit_response = Arc::new(AtomicBool::new(false));
        let commit_fault_fired = Arc::new(AtomicBool::new(false));
        let commit_fault_notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let task_faults = ConnectionFaults {
            stall_next_response: Arc::clone(&stall_next_response),
            drop_next_commit_response: Arc::clone(&drop_next_commit_response),
            commit_fault_fired: Arc::clone(&commit_fault_fired),
            commit_fault_notify: Arc::clone(&commit_fault_notify),
        };
        let task_expected_client_common_name = Arc::clone(&expected_client_common_name);
        let task =
            AbortOnDropHandle::new(lore_base::lore_spawn!("retention-live-proxy", async move {
                let mut connection_tasks = Vec::new();
                loop {
                    let accepted = tokio::select! {
                        () = task_shutdown.cancelled() => break,
                        accepted = listener.accept() => accepted,
                    };
                    let Ok((downstream, _)) = accepted else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let connector = connector.clone();
                    let upstream_host = upstream_host.clone();
                    let faults = task_faults.clone();
                    let expected_client_common_name = Arc::clone(&task_expected_client_common_name);
                    connection_tasks.push(AbortOnDropHandle::new(lore_base::lore_spawn!(
                        "retention-live-proxy-connection",
                        async move {
                            let _ = serve_connection(
                                downstream,
                                &upstream_host,
                                upstream_port,
                                acceptor,
                                connector,
                                faults,
                                expected_client_common_name,
                            )
                            .await;
                        }
                    )));
                }
                drop(connection_tasks);
            }));
        Self {
            port,
            stall_next_response,
            drop_next_commit_response,
            commit_fault_fired,
            commit_fault_notify,
            shutdown,
            task: Some(task),
        }
    }

    pub fn postgres_url(&self, direct_url: &str) -> String {
        let config = direct_url
            .parse::<tokio_postgres::Config>()
            .expect("parse direct retention PostgreSQL URL");
        let user = config.get_user().expect("retention URL user");
        let database = config.get_dbname().expect("retention URL database");
        let [tokio_postgres::config::Host::Tcp(host)] = config.get_hosts() else {
            panic!("retention URL has one TCP host")
        };
        format!(
            "postgresql://{user}@{host}:{}/{database}?sslmode=require",
            self.port
        )
    }

    pub fn stall_next_response(&self) {
        self.stall_next_response.store(true, Ordering::Release);
    }

    pub fn drop_next_commit_response(&self) {
        self.commit_fault_fired.store(false, Ordering::Release);
        self.drop_next_commit_response
            .store(true, Ordering::Release);
    }

    pub async fn wait_for_commit_fault(&self, maximum: std::time::Duration) -> bool {
        if self.commit_fault_fired.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::timeout(maximum, self.commit_fault_notify.notified())
            .await
            .is_ok()
            && self.commit_fault_fired.load(Ordering::Acquire)
    }

    pub async fn shutdown(mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        }
    }
}

impl Drop for RetentionFaultProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn downstream_acceptor(tls: &ProxyTlsMaterial) -> TlsAcceptor {
    let certificates = certificates(&tls.server_certificate_chain_pem);
    let private_key = private_key(&tls.server_private_key_pem);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(tls.root_ca_pem.as_bytes())) {
        client_roots
            .add(certificate.expect("valid downstream client root CA"))
            .expect("usable downstream client root CA");
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("downstream client certificate verifier");
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("supported proxy server TLS versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .expect("proxy server certificate matches its key");
    TlsAcceptor::from(Arc::new(config))
}

fn upstream_connector(tls: &ProxyTlsMaterial) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(tls.root_ca_pem.as_bytes())) {
        roots
            .add(certificate.expect("valid retention root CA"))
            .expect("usable retention root CA");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("supported proxy client TLS versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certificates(&tls.maintenance_certificate_chain_pem),
            private_key(&tls.maintenance_private_key_pem),
        )
        .expect("maintenance certificate matches its key");
    TlsConnector::from(Arc::new(config))
}

fn certificates(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .expect("valid certificate-chain PEM")
}

fn private_key(pem: &str) -> rustls::pki_types::PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut Cursor::new(pem.as_bytes()))
        .expect("valid private-key PEM")
        .expect("private-key PEM is not empty")
}

fn assert_client_common_name(
    stream: &TlsStream<TcpStream>,
    expected_common_name: &str,
) -> std::io::Result<()> {
    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "downstream client certificate missing",
            )
        })?;
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "downstream client certificate malformed",
        )
    })?;
    let common_name = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok());
    if common_name != Some(expected_common_name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "downstream client certificate identity mismatch",
        ));
    }
    Ok(())
}

async fn serve_connection(
    mut downstream: TcpStream,
    upstream_host: &str,
    upstream_port: u16,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    faults: ConnectionFaults,
    expected_client_common_name: Arc<String>,
) -> std::io::Result<()> {
    let mut ssl_request = [0u8; 8];
    downstream.read_exact(&mut ssl_request).await?;
    if ssl_request != POSTGRES_SSL_REQUEST {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected PostgreSQL SSLRequest",
        ));
    }
    downstream.write_all(b"S").await?;
    let downstream = acceptor.accept(downstream).await?;
    assert_client_common_name(&downstream, &expected_client_common_name)?;

    let mut upstream = TcpStream::connect((upstream_host, upstream_port)).await?;
    upstream.write_all(&POSTGRES_SSL_REQUEST).await?;
    let mut ssl_response = [0u8; 1];
    upstream.read_exact(&mut ssl_response).await?;
    if ssl_response != *b"S" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "upstream PostgreSQL refused TLS",
        ));
    }
    let server_name = ServerName::try_from(upstream_host.to_string()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid upstream DNS name",
        )
    })?;
    let upstream = connector.connect(server_name, upstream).await?;

    let (downstream_read, downstream_write) = tokio::io::split(downstream);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let connection_closed = Arc::new(Notify::new());
    let commit_pending = Arc::new(AtomicBool::new(false));
    let frontend = forward_frontend(
        downstream_read,
        upstream_write,
        Arc::clone(&commit_pending),
        Arc::clone(&connection_closed),
    );
    let backend = forward_backend(
        upstream_read,
        downstream_write,
        commit_pending,
        faults,
        connection_closed,
    );
    let _ = tokio::join!(frontend, backend);
    Ok(())
}

async fn forward_frontend<R, W>(
    mut source: R,
    mut destination: W,
    commit_pending: Arc<AtomicBool>,
    connection_closed: Arc<Notify>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16_384];
    let mut frames = FrontendFrameParser::default();
    loop {
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            connection_closed.notify_waiters();
            return Ok(());
        }
        if frames.observe(&buffer[..read])? {
            commit_pending.store(true, Ordering::Release);
        }
        destination.write_all(&buffer[..read]).await?;
        destination.flush().await?;
    }
}

async fn forward_backend<R, W>(
    mut source: R,
    mut destination: W,
    commit_pending: Arc<AtomicBool>,
    faults: ConnectionFaults,
    connection_closed: Arc<Notify>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16_384];
    let mut frames = PgFrameParser::default();
    let mut held_response = Vec::new();
    let mut commit_response = CommitResponseTracker::default();
    loop {
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        if faults.stall_next_response.swap(false, Ordering::AcqRel) {
            connection_closed.notified().await;
            return Ok(());
        }
        let parsed = frames.push(&buffer[..read])?;
        if commit_pending.load(Ordering::Acquire)
            && faults.drop_next_commit_response.load(Ordering::Acquire)
        {
            held_response.extend_from_slice(&buffer[..read]);
            for frame in parsed {
                match commit_response.observe(&frame) {
                    CommitResponseOutcome::Pending => {}
                    CommitResponseOutcome::Fire => {
                        faults
                            .drop_next_commit_response
                            .store(false, Ordering::Release);
                        faults.commit_fault_fired.store(true, Ordering::Release);
                        faults.commit_fault_notify.notify_waiters();
                        return Ok(());
                    }
                    CommitResponseOutcome::Reject => {
                        commit_pending.store(false, Ordering::Release);
                        commit_response = CommitResponseTracker::default();
                        destination.write_all(&held_response).await?;
                        destination.flush().await?;
                        held_response.clear();
                        break;
                    }
                }
            }
            continue;
        }
        destination.write_all(&buffer[..read]).await?;
        destination.flush().await?;
    }
}

const MAX_POSTGRES_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct PgFrame {
    tag: u8,
    payload: Vec<u8>,
}

#[derive(Default)]
struct PgFrameParser {
    buffered: Vec<u8>,
}

impl PgFrameParser {
    fn push(&mut self, bytes: &[u8]) -> std::io::Result<Vec<PgFrame>> {
        self.buffered.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            if self.buffered.len() < 5 {
                break;
            }
            let length = u32::from_be_bytes(
                self.buffered[1..5]
                    .try_into()
                    .expect("four-byte PostgreSQL frame length"),
            ) as usize;
            if !(4..=MAX_POSTGRES_FRAME_BYTES).contains(&length) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid PostgreSQL frame length",
                ));
            }
            let total = length + 1;
            if self.buffered.len() < total {
                break;
            }
            let frame = self.buffered.drain(..total).collect::<Vec<_>>();
            frames.push(PgFrame {
                tag: frame[0],
                payload: frame[5..].to_vec(),
            });
        }
        Ok(frames)
    }
}

#[derive(Default)]
struct FrontendFrameParser {
    startup_buffered: Vec<u8>,
    startup_complete: bool,
    frames: PgFrameParser,
}

impl FrontendFrameParser {
    fn observe(&mut self, bytes: &[u8]) -> std::io::Result<bool> {
        let mut remaining = bytes;
        if !self.startup_complete {
            self.startup_buffered.extend_from_slice(bytes);
            if self.startup_buffered.len() < 4 {
                return Ok(false);
            }
            let length = u32::from_be_bytes(
                self.startup_buffered[..4]
                    .try_into()
                    .expect("four-byte PostgreSQL startup length"),
            ) as usize;
            if !(8..=MAX_POSTGRES_FRAME_BYTES).contains(&length) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid PostgreSQL startup length",
                ));
            }
            if self.startup_buffered.len() < length {
                return Ok(false);
            }
            let tail = self.startup_buffered.split_off(length);
            self.startup_buffered.clear();
            self.startup_complete = true;
            remaining = &[];
            if !tail.is_empty() {
                return self.observe_typed(&tail);
            }
        }
        self.observe_typed(remaining)
    }

    fn observe_typed(&mut self, bytes: &[u8]) -> std::io::Result<bool> {
        Ok(self
            .frames
            .push(bytes)?
            .into_iter()
            .any(|frame| frame.tag == b'Q' && frame.payload == b"COMMIT\0"))
    }
}

#[derive(Default)]
enum CommitResponseTracker {
    #[default]
    AwaitCommandComplete,
    AwaitIdleReady,
}

enum CommitResponseOutcome {
    Pending,
    Fire,
    Reject,
}

impl CommitResponseTracker {
    fn observe(&mut self, frame: &PgFrame) -> CommitResponseOutcome {
        match self {
            Self::AwaitCommandComplete if frame.tag == b'C' && frame.payload == b"COMMIT\0" => {
                *self = Self::AwaitIdleReady;
                CommitResponseOutcome::Pending
            }
            Self::AwaitCommandComplete if frame.tag == b'E' || frame.tag == b'Z' => {
                CommitResponseOutcome::Reject
            }
            Self::AwaitCommandComplete => CommitResponseOutcome::Pending,
            Self::AwaitIdleReady if frame.tag == b'Z' && frame.payload == b"I" => {
                CommitResponseOutcome::Fire
            }
            Self::AwaitIdleReady => CommitResponseOutcome::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(
            &(u32::try_from(payload.len()).expect("payload length") + 4).to_be_bytes(),
        );
        bytes.extend_from_slice(payload);
        bytes
    }

    fn startup() -> Vec<u8> {
        vec![0, 0, 0, 8, 0, 3, 0, 0]
    }

    #[test]
    fn frontend_parser_arms_only_after_a_fragmented_exact_simple_commit() {
        let mut parser = FrontendFrameParser::default();
        assert!(!parser.observe(&startup()[..3]).expect("startup prefix"));
        assert!(!parser.observe(&startup()[3..]).expect("startup suffix"));
        let commit = frame(b'Q', b"COMMIT\0");
        assert!(!parser.observe(&commit[..6]).expect("commit prefix"));
        assert!(parser.observe(&commit[6..]).expect("commit suffix"));
    }

    #[test]
    fn frontend_parser_handles_coalesced_frames_without_substring_false_positives() {
        let mut parser = FrontendFrameParser::default();
        parser.observe(&startup()).expect("startup");
        let mut coalesced = frame(b'Q', b"SELECT 'COMMIT'\0");
        coalesced.extend_from_slice(&frame(b'P', b"statement\0COMMIT\0"));
        assert!(!parser.observe(&coalesced).expect("false-positive frames"));
        let mut queries = frame(b'Q', b"SELECT 1\0");
        queries.extend_from_slice(&frame(b'Q', b"COMMIT\0"));
        assert!(parser.observe(&queries).expect("coalesced exact commit"));
    }

    #[test]
    fn backend_parser_accepts_fragmented_command_complete_then_idle_ready() {
        let mut parser = PgFrameParser::default();
        let mut bytes = frame(b'C', b"COMMIT\0");
        bytes.extend_from_slice(&frame(b'Z', b"I"));
        let mut tracker = CommitResponseTracker::default();
        assert!(parser.push(&bytes[..4]).expect("prefix").is_empty());
        let frames = parser.push(&bytes[4..]).expect("suffix");
        assert!(matches!(
            tracker.observe(&frames[0]),
            CommitResponseOutcome::Pending
        ));
        assert!(matches!(
            tracker.observe(&frames[1]),
            CommitResponseOutcome::Fire
        ));
    }

    #[test]
    fn backend_tracker_rejects_failed_commit_and_nonidle_ready_sequences() {
        let mut parser = PgFrameParser::default();
        let mut failed = frame(b'E', b"failed COMMIT\0");
        failed.extend_from_slice(&frame(b'Z', b"I"));
        let failed_frames = parser
            .push(&failed)
            .expect("coalesced failed commit frames");
        let mut tracker = CommitResponseTracker::default();
        assert!(matches!(
            tracker.observe(&failed_frames[0]),
            CommitResponseOutcome::Reject
        ));
        assert!(
            !failed_frames
                .iter()
                .skip(1)
                .any(|frame| matches!(tracker.observe(frame), CommitResponseOutcome::Fire))
        );
        let mut tracker = CommitResponseTracker::default();
        assert!(matches!(
            tracker.observe(&PgFrame {
                tag: b'C',
                payload: b"COMMIT\0".to_vec(),
            }),
            CommitResponseOutcome::Pending
        ));
        assert!(matches!(
            tracker.observe(&PgFrame {
                tag: b'Z',
                payload: b"E".to_vec(),
            }),
            CommitResponseOutcome::Reject
        ));
    }
}

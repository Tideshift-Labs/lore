// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! A scripted `lore-storage/0.4` peer on raw quinn, for the WP-124 slice 2b send-bound tests.
//!
//! The stock client needs a peer that can do what a healthy server never does: stop reading,
//! never answer, or answer late. This one speaks just enough of the protocol (a command header,
//! a payload, an answer) and takes its behavior from the test:
//!
//! - **Rules** decide the answer per opcode ([`Reply`]). `Authorize` is built in: a start (action
//!   0 or 2) is answered with a fresh session id and a stop with an empty answer.
//! - **The gate** ([`Peer::close_gate`]) stops the peer reading payload bytes. The peer's flow
//!   control then stops granting the client credit, so the client's `write_chunks` stops
//!   accepting bytes while the connection stays alive and keep-alive PINGs keep flowing.
//!   Command headers are still read, and the peer's stream window is far above the bytes read
//!   before the gate closes, so quinn never raises the client's credit while it is closed. The
//!   client's remaining credit on a stream is then exactly `WINDOW` minus the bytes it sent on
//!   that stream, which is what [`Peer::bytes_read_on_stream`] reports.
//! - **The throttle** ([`Peer::throttle`]) reads a few bytes per interval instead of stopping,
//!   so a writer makes slow but steady progress.
//!
//! Streams are numbered in the order the peer accepts them, which is the order the client opened
//! them (it opens them lazily, lowest first, and a stream a higher id implies counts as opened).
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_transport::quic::command_header::COMMAND_HEADER_SIZE_V4;
use lore_transport::quic::command_header::CommandHeader;
use parking_lot::Mutex;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use tokio::sync::Notify;

const AUTHORIZE: u8 = 0;
const CLIENT_IDENTIFY: u8 = 14;
const ACTION_STOP: u8 = 1;

/// The peer's per-stream receive window: the credit a client has on a stream before the peer
/// reads anything. quinn raises it again only after the peer has read a further `WINDOW / 8` on
/// that stream, which is why tests keep the bytes read before closing the gate far below that.
pub const WINDOW: u64 = 16 * 1024;

/// How the peer answers a command, by opcode.
#[derive(Clone, Debug)]
pub enum Reply {
    /// Answer success with this payload once the whole request is read.
    Ok(Vec<u8>),
    /// Answer an error status once the whole request is read.
    Status(u32),
    /// Read the request and never answer it.
    Silent,
    /// Read the request, keep the answer back, and send it on [`Peer::release_held`].
    Hold(Vec<u8>),
    /// Read the request, then close the connection without answering: the answer is lost.
    Disconnect,
    /// As [`Reply::Disconnect`] for the first request of this opcode, and from then on answer
    /// success with this payload. The rule is swapped before the connection is closed, so the
    /// retry on the replacement connection always finds the second behavior.
    DisconnectThenOk(Vec<u8>),
    /// Answer success as soon as the header is read, before the payload. The payload is read
    /// later, when the gate allows it. This is how a test fills a stream's credit with a write
    /// that has completed.
    EarlyOk,
}

/// One request header the peer has read.
#[derive(Clone, Debug)]
pub struct Seen {
    pub opcode: u8,
    pub stream: usize,
    /// The session id in the header. Zero for a command sent outside a session.
    pub session_id: u32,
    /// Which accepted connection carried it, from 0 in the order the peer accepted them.
    pub connection: usize,
}

/// One request the peer has read in full.
#[derive(Clone, Debug)]
pub struct Done {
    pub opcode: u8,
    /// The first 48 payload bytes. For a `Put` this is the `Address`; for an `Authorize` the
    /// first byte is the action (0 start, 1 stop, 2 declared start).
    pub head: Vec<u8>,
    /// Which accepted connection carried it, from 0 in the order the peer accepted them.
    pub connection: usize,
}

struct Held {
    stream: usize,
    send: Arc<tokio::sync::Mutex<quinn::SendStream>>,
    header: CommandHeader,
    payload: Vec<u8>,
}

struct Shared {
    rules: Mutex<HashMap<u8, Reply>>,
    seen: Mutex<Vec<Seen>>,
    done: Mutex<Vec<Done>>,
    read_on: Mutex<HashMap<usize, u64>>,
    held: Mutex<Vec<Held>>,
    gate_open: AtomicBool,
    gate: Notify,
    throttle: Mutex<Option<(usize, Duration)>>,
    next_session: AtomicU32,
    accepted: AtomicUsize,
    closed: AtomicUsize,
    stream_count: AtomicUsize,
    /// Every connection the peer has accepted, so a test can close them from the peer's side.
    connections: Mutex<Vec<quinn::Connection>>,
}

pub struct Peer {
    pub port: u16,
    shared: Arc<Shared>,
    _endpoint: quinn::Endpoint,
    accept: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl Peer {
    pub fn start() -> Peer {
        let cert = lore_transport::tls::generate_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_der = CertificateDer::from_pem_slice(cert.cert_pem.as_bytes())
            .expect("parse cert")
            .into_owned();
        let key_der = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).expect("parse key");
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server crypto");
        crypto.alpn_protocols = vec![b"lore-storage/0.4".to_vec()];
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("quic crypto"),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(quinn::VarInt::from_u64(WINDOW).expect("window"))
            .receive_window(quinn::VarInt::from_u32(256 * 1024 * 1024))
            .max_concurrent_bidi_streams(16_u8.into())
            .max_concurrent_uni_streams(0_u8.into());
        config.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().expect("addr"))
            .expect("bind peer");
        let port = endpoint.local_addr().expect("local addr").port();
        let shared = Arc::new(Shared {
            rules: Mutex::new(HashMap::new()),
            seen: Mutex::new(Vec::new()),
            done: Mutex::new(Vec::new()),
            read_on: Mutex::new(HashMap::new()),
            held: Mutex::new(Vec::new()),
            gate_open: AtomicBool::new(true),
            gate: Notify::new(),
            throttle: Mutex::new(None),
            next_session: AtomicU32::new(1000),
            accepted: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
            stream_count: AtomicUsize::new(0),
            connections: Mutex::new(Vec::new()),
        });
        let accept = {
            let shared = shared.clone();
            let endpoint = endpoint.clone();
            lore_base::lore_spawn!(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(connection) = incoming.await else {
                        continue;
                    };
                    let index = shared.accepted.fetch_add(1, Ordering::SeqCst);
                    shared.connections.lock().push(connection.clone());
                    let shared = shared.clone();
                    lore_base::lore_spawn!(serve_connection(shared, connection, index));
                }
            })
        };
        Peer {
            port,
            shared,
            _endpoint: endpoint,
            accept,
        }
    }

    pub fn url(&self) -> String {
        format!("lore://127.0.0.1:{}", self.port)
    }

    pub fn rule(&self, opcode: u8, reply: Reply) {
        self.shared.rules.lock().insert(opcode, reply);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.shared.seen.lock().clone()
    }

    /// Every opcode-`opcode` header the peer has read.
    pub fn seen_opcode(&self, opcode: u8) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|seen| seen.opcode == opcode)
            .collect()
    }

    pub fn done(&self) -> Vec<Done> {
        self.shared.done.lock().clone()
    }

    /// Addresses (the first 48 payload bytes) of every opcode-`opcode` request read in full.
    pub fn done_heads(&self, opcode: u8) -> Vec<Vec<u8>> {
        self.done()
            .into_iter()
            .filter(|done| done.opcode == opcode)
            .map(|done| done.head)
            .collect()
    }

    pub fn bytes_read_on_stream(&self, stream: usize) -> u64 {
        self.shared
            .read_on
            .lock()
            .get(&stream)
            .copied()
            .unwrap_or(0)
    }

    pub fn accepted_connections(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    pub fn closed_connections(&self) -> usize {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Close every connection the peer has accepted so far, from the peer's side. The client sees
    /// its connection die with nothing in flight; a later command reconnects.
    pub fn close_connections(&self) {
        for connection in self.shared.connections.lock().iter() {
            connection.close(quinn::VarInt::from_u32(7), b"scripted close");
        }
    }

    /// Stop reading payload bytes. Headers are still read.
    pub fn close_gate(&self) {
        self.shared.gate_open.store(false, Ordering::SeqCst);
    }

    pub fn open_gate(&self) {
        self.shared.gate_open.store(true, Ordering::SeqCst);
        self.shared.gate.notify_waiters();
    }

    /// Read `bytes` per `every` instead of everything available.
    pub fn throttle(&self, bytes: usize, every: Duration) {
        *self.shared.throttle.lock() = Some((bytes, every));
    }

    /// Send every answer a [`Reply::Hold`] kept back.
    pub async fn release_held(&self) -> usize {
        self.release_held_where(|_| true).await
    }

    /// Send the kept-back answers of requests that arrived on `stream`.
    pub async fn release_held_on_stream(&self, stream: usize) -> usize {
        self.release_held_where(|held| held == stream).await
    }

    async fn release_held_where(&self, mut select: impl FnMut(usize) -> bool) -> usize {
        let held: Vec<Held> = {
            let mut all = self.shared.held.lock();
            let (selected, kept): (Vec<Held>, Vec<Held>) = std::mem::take(&mut *all)
                .into_iter()
                .partition(|held| select(held.stream));
            *all = kept;
            selected
        };
        let count = held.len();
        for held in held {
            respond(&held.send, &held.header, &held.payload).await;
        }
        count
    }

    pub async fn wait_until(&self, what: &str, mut condition: impl FnMut(&Peer) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !condition(self) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn serve_connection(shared: Arc<Shared>, connection: quinn::Connection, index: usize) {
    let mut next_stream = 0usize;
    let watcher = {
        let shared = shared.clone();
        let connection = connection.clone();
        lore_base::lore_spawn!(async move {
            let _ = connection.closed().await;
            shared.closed.fetch_add(1, Ordering::SeqCst);
        })
    };
    // Stream indices restart per connection, so a replacement connection is numbered from 0.
    while let Ok((send, recv)) = connection.accept_bi().await {
        let stream = next_stream;
        next_stream += 1;
        shared.stream_count.fetch_max(next_stream, Ordering::SeqCst);
        let shared = shared.clone();
        lore_base::lore_spawn!(serve_stream(
            shared,
            connection.clone(),
            index,
            stream,
            send,
            recv
        ));
    }
    let _ = watcher.await;
}

async fn read_header(
    recv: &mut quinn::RecvStream,
    shared: &Shared,
    stream: usize,
) -> Option<[u8; 12]> {
    let mut header = [0u8; COMMAND_HEADER_SIZE_V4];
    recv.read_exact(&mut header).await.ok()?;
    *shared.read_on.lock().entry(stream).or_default() += header.len() as u64;
    Some(header)
}

/// Read `len` payload bytes, honoring the gate and the throttle.
async fn read_payload(
    recv: &mut quinn::RecvStream,
    shared: &Shared,
    stream: usize,
    len: usize,
) -> Option<Vec<u8>> {
    let mut payload = vec![0u8; len];
    let mut offset = 0;
    while offset < len {
        while !shared.gate_open.load(Ordering::SeqCst) {
            let opened = shared.gate.notified();
            if shared.gate_open.load(Ordering::SeqCst) {
                break;
            }
            // Wake on a notify or poll: a notify between the check and the await is not lost to
            // `notify_waiters`, because the poll catches it within the interval.
            let _ = tokio::time::timeout(Duration::from_millis(20), opened).await;
        }
        let throttle = *shared.throttle.lock();
        let step = throttle.map_or(len - offset, |(bytes, _)| bytes.min(len - offset));
        let read = recv
            .read(&mut payload[offset..offset + step])
            .await
            .ok()??;
        offset += read;
        *shared.read_on.lock().entry(stream).or_default() += read as u64;
        if let Some((_, every)) = throttle {
            tokio::time::sleep(every).await;
        }
    }
    Some(payload)
}

async fn respond(
    send: &Arc<tokio::sync::Mutex<quinn::SendStream>>,
    request: &CommandHeader,
    payload: &[u8],
) {
    let header = request.response_success(payload.len() as u32);
    let (bytes, len) = header.response_bytes();
    let mut send = send.lock().await;
    let _ = send.write_all(&bytes[..len]).await;
    let _ = send.write_all(payload).await;
}

async fn respond_status(
    send: &Arc<tokio::sync::Mutex<quinn::SendStream>>,
    request: &CommandHeader,
    status: u32,
) {
    let header = request.response_error(status);
    let (bytes, len) = header.response_bytes();
    let _ = send.lock().await.write_all(&bytes[..len]).await;
}

async fn serve_stream(
    shared: Arc<Shared>,
    connection: quinn::Connection,
    connection_index: usize,
    stream: usize,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let send = Arc::new(tokio::sync::Mutex::new(send));
    loop {
        let Some(raw) = read_header(&mut recv, &shared, stream).await else {
            return;
        };
        let header = CommandHeader::from_bytes_v4(&raw);
        let len = header.size_or_status as usize;
        shared.seen.lock().push(Seen {
            opcode: header.cmd,
            stream,
            session_id: header.session_id,
            connection: connection_index,
        });
        let rule = shared.rules.lock().get(&header.cmd).cloned();
        if matches!(rule, Some(Reply::EarlyOk)) {
            respond(&send, &header, &[]).await;
        }
        let Some(payload) = read_payload(&mut recv, &shared, stream, len).await else {
            return;
        };
        shared.done.lock().push(Done {
            opcode: header.cmd,
            head: payload.iter().take(48).copied().collect(),
            connection: connection_index,
        });
        if header.cmd == CLIENT_IDENTIFY {
            continue;
        }
        match rule {
            Some(Reply::EarlyOk | Reply::Silent) => {}
            Some(Reply::Disconnect) => connection.close(quinn::VarInt::from_u32(9), b"scripted"),
            Some(Reply::DisconnectThenOk(body)) => {
                shared.rules.lock().insert(header.cmd, Reply::Ok(body));
                connection.close(quinn::VarInt::from_u32(9), b"scripted");
            }
            Some(Reply::Ok(body)) => respond(&send, &header, &body).await,
            Some(Reply::Status(status)) => respond_status(&send, &header, status).await,
            Some(Reply::Hold(body)) => shared.held.lock().push(Held {
                stream,
                send: send.clone(),
                header,
                payload: body,
            }),
            None if header.cmd == AUTHORIZE => {
                if payload.first() == Some(&ACTION_STOP) {
                    respond(&send, &header, &[]).await;
                } else {
                    let id = shared.next_session.fetch_add(1, Ordering::SeqCst);
                    respond(&send, &header, &id.to_le_bytes()).await;
                }
            }
            None => respond(&send, &header, &[]).await,
        }
    }
}

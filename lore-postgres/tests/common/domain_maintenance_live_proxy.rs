// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
// Adapted from lore-object-dispatch/tests/common/retention_live_proxy.rs.
// The PostgreSQL frame parsers and COMMIT-response state machine are kept
// identical; only the TLS/mTLS envelope is omitted for local LORE_TEST_PG_URL.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

pub struct DomainMaintenanceFaultProxy {
    port: u16,
    drop_next_commit_response: Arc<AtomicBool>,
    commit_fault_fired: Arc<AtomicBool>,
    commit_fault_notify: Arc<Notify>,
    shutdown: CancellationToken,
    task: Option<AbortOnDropHandle<()>>,
}

#[derive(Clone)]
struct ConnectionFaults {
    drop_next_commit_response: Arc<AtomicBool>,
    commit_fault_fired: Arc<AtomicBool>,
    commit_fault_notify: Arc<Notify>,
}

impl DomainMaintenanceFaultProxy {
    pub async fn start(upstream_host: String, upstream_port: u16) -> Self {
        let listener = TcpListener::bind(("localhost", 0))
            .await
            .expect("bind domain-maintenance fault proxy");
        let port = listener.local_addr().expect("proxy local address").port();
        let drop_next_commit_response = Arc::new(AtomicBool::new(false));
        let commit_fault_fired = Arc::new(AtomicBool::new(false));
        let commit_fault_notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let faults = ConnectionFaults {
            drop_next_commit_response: Arc::clone(&drop_next_commit_response),
            commit_fault_fired: Arc::clone(&commit_fault_fired),
            commit_fault_notify: Arc::clone(&commit_fault_notify),
        };
        let task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "domain-maintenance-live-proxy",
            async move {
                let mut connections = Vec::new();
                loop {
                    let accepted = tokio::select! {
                        () = task_shutdown.cancelled() => break,
                        accepted = listener.accept() => accepted,
                    };
                    let Ok((downstream, _)) = accepted else {
                        break;
                    };
                    let upstream_host = upstream_host.clone();
                    let faults = faults.clone();
                    connections.push(AbortOnDropHandle::new(lore_base::lore_spawn!(
                        "domain-maintenance-live-proxy-connection",
                        async move {
                            let _ =
                                serve_connection(downstream, &upstream_host, upstream_port, faults)
                                    .await;
                        }
                    )));
                }
                drop(connections);
            }
        ));
        Self {
            port,
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
            .expect("parse direct PostgreSQL URL");
        let user = config.get_user().expect("PostgreSQL URL user");
        let database = config.get_dbname().expect("PostgreSQL URL database");
        let password = config
            .get_password()
            .map(|value| String::from_utf8_lossy(value).into_owned());
        let credentials =
            password.map_or_else(|| user.to_owned(), |password| format!("{user}:{password}"));
        format!(
            "postgresql://{credentials}@localhost:{}/{database}?sslmode=disable",
            self.port
        )
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

impl Drop for DomainMaintenanceFaultProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn serve_connection(
    downstream: TcpStream,
    upstream_host: &str,
    upstream_port: u16,
    faults: ConnectionFaults,
) -> std::io::Result<()> {
    let upstream = TcpStream::connect((upstream_host, upstream_port)).await?;
    let (downstream_read, downstream_write) = tokio::io::split(downstream);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let commit_pending = Arc::new(AtomicBool::new(false));
    let frontend = forward_frontend(downstream_read, upstream_write, Arc::clone(&commit_pending));
    let backend = forward_backend(upstream_read, downstream_write, commit_pending, faults);
    let _ = tokio::join!(frontend, backend);
    Ok(())
}

async fn forward_frontend<R, W>(
    mut source: R,
    mut destination: W,
    commit_pending: Arc<AtomicBool>,
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
            return self.observe_typed(&tail);
        }
        self.observe_typed(bytes)
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

    #[test]
    fn fragmented_exact_commit_and_idle_response_fire_the_fault() {
        let mut frontend = FrontendFrameParser::default();
        let startup = [0, 0, 0, 8, 0, 3, 0, 0];
        assert!(!frontend.observe(&startup).expect("startup"));
        let commit = frame(b'Q', b"COMMIT\0");
        assert!(!frontend.observe(&commit[..6]).expect("commit prefix"));
        assert!(frontend.observe(&commit[6..]).expect("commit suffix"));

        let mut backend = PgFrameParser::default();
        let mut response = frame(b'C', b"COMMIT\0");
        response.extend_from_slice(&frame(b'Z', b"I"));
        let frames = backend.push(&response).expect("backend frames");
        let mut tracker = CommitResponseTracker::default();
        assert!(matches!(
            tracker.observe(&frames[0]),
            CommitResponseOutcome::Pending
        ));
        assert!(matches!(
            tracker.observe(&frames[1]),
            CommitResponseOutcome::Fire
        ));
    }
}

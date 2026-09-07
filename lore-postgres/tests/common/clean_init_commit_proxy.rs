// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Plaintext test-only PostgreSQL proxy. Drops an actual COMMIT CommandComplete exactly once.
//! Adapted from lore-object-dispatch/tests/dispatch_client_live.rs; no production transport hook.
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::task::AbortOnDropHandle;
pub(super) struct LostCommitProxy {
    pub(super) port: u16,
    arm: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
    _task: AbortOnDropHandle<()>,
}

impl LostCommitProxy {
    pub(super) async fn start(upstream: String) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind lost-commit proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let arm = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let task_arm = Arc::clone(&arm);
        let task_fired = Arc::clone(&fired);
        let task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "clean-init-lost-commit-proxy",
            async move {
                let mut connections = Vec::new();
                while let Ok((downstream, _)) = listener.accept().await {
                    let upstream = upstream.clone();
                    let arm = Arc::clone(&task_arm);
                    let fired = Arc::clone(&task_fired);
                    connections.push(AbortOnDropHandle::new(lore_base::lore_spawn!(
                        "clean-init-lost-commit-connection",
                        async move {
                            if let Ok(server) = TcpStream::connect(&upstream).await {
                                relay(downstream, server, arm, fired).await;
                            }
                        }
                    )));
                }
            }
        ));
        Self {
            port,
            arm,
            fired,
            _task: task,
        }
    }

    /// Drop the next `COMMIT` response instead of forwarding it, once.
    pub(super) fn drop_next_commit_response(&self) {
        self.fired.store(false, Ordering::Release);
        self.arm.store(true, Ordering::Release);
    }

    pub(super) fn fault_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }
}

async fn relay(
    downstream: TcpStream,
    upstream: TcpStream,
    arm: Arc<AtomicBool>,
    fired: Arc<AtomicBool>,
) {
    let (mut downstream_read, mut downstream_write) = downstream.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let forward = async move {
        // Client to server is copied verbatim; nothing about the fault depends on it.
        let _ = tokio::io::copy(&mut downstream_read, &mut upstream_write).await;
    };
    let backward = async move {
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let read = match upstream_read.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            buffer.extend_from_slice(&chunk[..read]);
            let mut offset = 0usize;
            while buffer.len() - offset >= 5 {
                let tag = buffer[offset];
                let Ok(length) = <[u8; 4]>::try_from(&buffer[offset + 1..offset + 5]) else {
                    return;
                };
                let length = u32::from_be_bytes(length) as usize;
                if length < 4 {
                    return;
                }
                let total = 1 + length;
                if buffer.len() - offset < total {
                    break;
                }
                let is_commit_complete = tag == b'C'
                    && &buffer[offset + 5..offset + total] == b"COMMIT\0"
                    && arm.swap(false, Ordering::AcqRel);
                if is_commit_complete {
                    // The server committed. Close without forwarding, so the client's `COMMIT`
                    // never completes and its outcome is genuinely unknown to it.
                    fired.store(true, Ordering::Release);
                    return;
                }
                if downstream_write
                    .write_all(&buffer[offset..offset + total])
                    .await
                    .is_err()
                {
                    return;
                }
                offset += total;
            }
            buffer.drain(..offset);
            if downstream_write.flush().await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        () = forward => {}
        () = backward => {}
    }
}

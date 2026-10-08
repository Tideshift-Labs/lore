// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_transport::error::ProtocolError;
use lore_transport::session::*;

/// A lazy session whose resolver counts its calls and always fails with `error`, so how
/// often it is asked is what the test reads and what it resolves to is out of the way.
fn counting_session(calls: Arc<AtomicUsize>, error: ProtocolError) -> StorageSession {
    StorageSession::pending(move || {
        let calls = calls.clone();
        let error = error.clone();
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
    })
}

/// One resolution serves every operation, a failure the caller cannot retry past being
/// held like a success.
#[tokio::test]
async fn a_lazy_session_resolves_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = counting_session(calls.clone(), ProtocolError::internal("nothing to resolve"));

    assert!(session.is_lazy());
    assert!(session.partition().await.is_err());
    assert!(session.partition().await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

/// The read path recovers a rotated server session map by invalidating the
/// session and retrying that same session, which only gets a `session_id` the
/// server knows about where the session resolves again.
#[tokio::test]
async fn an_invalidated_lazy_session_resolves_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = counting_session(calls.clone(), ProtocolError::internal("nothing to resolve"));

    assert!(session.partition().await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    session.invalidate().await;

    assert!(session.partition().await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// The read and write paths back off on `SlowDown` and retry the same session without
/// invalidating it, so a throttled `session_start` has to be asked again for the retry to
/// reach the server at all.
#[tokio::test]
async fn a_throttled_lazy_session_resolves_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let session = counting_session(
        calls.clone(),
        ProtocolError::from(lore_base::error::SlowDown),
    );

    let first = session.partition().await;
    let second = session.partition().await;

    assert!(first.is_err_and(|err| err.is_slow_down()));
    assert!(second.is_err_and(|err| err.is_slow_down()));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

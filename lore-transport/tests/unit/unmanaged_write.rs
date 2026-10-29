// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 follow-up (b)): the per-session unmanaged-write latch.

use lore_transport::unmanaged_write::UnmanagedWriteLatch;

#[test]
fn a_new_latch_is_not_refused() {
    assert!(!UnmanagedWriteLatch::default().is_refused());
}

#[test]
fn refuse_sets_the_latch() {
    let latch = UnmanagedWriteLatch::default();
    latch.refuse();
    assert!(latch.is_refused());
}

#[test]
fn refusal_is_final_and_repeatable() {
    let latch = UnmanagedWriteLatch::default();
    latch.refuse();
    latch.refuse();
    assert!(latch.is_refused(), "nothing reopens a refused latch");
}

/// Every session owns its own latch: a lazy session does not share one with the session it
/// resolves to, and two sessions never share one.
#[tokio::test]
async fn a_pending_session_owns_its_own_latch() {
    use std::sync::Arc;

    use lore_base::error::NoRemote;
    use lore_transport::StorageSession;
    use lore_transport::error::ProtocolError;

    let first = Arc::new(StorageSession::pending(|| async {
        Err(ProtocolError::from(NoRemote))
    }));
    let second = Arc::new(StorageSession::pending(|| async {
        Err(ProtocolError::from(NoRemote))
    }));
    first.unmanaged_writes().refuse();
    assert!(first.unmanaged_writes().is_refused());
    assert!(!second.unmanaged_writes().is_refused());
}

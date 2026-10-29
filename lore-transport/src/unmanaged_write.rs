// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 follow-up (b)): whether a session's server has refused a write
//! made outside a managed caller operation.
//!
//! An unmanaged command such as `lore commit` uploads each fragment as it writes it. A strict
//! server refuses every one of those writes (`unsupported-client`), and the refusal is not fatal:
//! the fragment stays local and the next push uploads it. Nothing tells the client ahead of time
//! that a server is strict, so a commit sent every payload once only to be refused (117-977
//! refusals per commit on a strict dev cell).
//!
//! Unmanaged writes start exactly as before. The first typed refusal latches; a write that has not
//! been sent yet then skips its upload, which leaves the fragment exactly where a refusal would
//! have. Writes already in flight finish normally. Only the typed refusal latches: a transient or
//! network failure says nothing about the server's policy. The latch is final for the session:
//! a long-lived session on a cell that later turns compatible keeps unmanaged writes local, and
//! push uploads them as it does after any refusal.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// The unmanaged-write latch for one session. See the module docs.
#[derive(Default)]
pub struct UnmanagedWriteLatch {
    refused: AtomicBool,
}

impl UnmanagedWriteLatch {
    /// Record that the server refused an unmanaged write as an unsupported client.
    pub fn refuse(&self) {
        self.refused.store(true, Ordering::Relaxed);
    }

    /// Whether an unmanaged write on this session has been refused.
    pub fn is_refused(&self) -> bool {
        self.refused.load(Ordering::Relaxed)
    }
}

// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 K10): a commit's uploads as declared, best-effort writes.
//!
//! Stock Lore uploads a commit's fragments unmanaged and best effort. A strict cell refuses
//! every such upload, so the fragments stay local and the push uploads them. A managed client
//! (our CLI's `lore commit`, the desktop with "Upload while committing" on) asks for the uploads
//! to run declared instead, by running the commit inside [`with_managed_commit_uploads`]. The
//! commit then installs a [`ManagedUploads`] scope on its execution context once it has enabled
//! uploads, and the write path runs each fragment's remote legs in it. See
//! [`lore_storage::managed_uploads`] for what the scope does and does not change.
//!
//! Without the request, a commit runs exactly as stock Lore's does.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use lore_storage::managed_uploads::ManagedUploads;

use crate::interface::ExecutionContext;
use crate::repository::RepositoryContext;

tokio::task_local! {
    static REQUESTED: ();
}

/// Run `future` (a commit) with its uploads declared and best effort. Entered by the embedder in
/// the task that calls the commit. Does nothing for a commit that does not upload, or that runs
/// inside a managed caller operation (whose uploads are already managed).
pub fn with_managed_commit_uploads<F: Future>(future: F) -> impl Future<Output = F::Output> {
    REQUESTED.scope((), future)
}

/// Whether the current task runs inside [`with_managed_commit_uploads`].
pub fn managed_commit_uploads_requested() -> bool {
    REQUESTED.try_with(|_| ()).is_ok()
}

/// The scope [`install`] put on the current call, removed when dropped.
pub struct InstalledUploads {
    context: Arc<ExecutionContext>,
    uploads: Arc<ManagedUploads>,
}

impl InstalledUploads {
    /// The scope, for a test to read its diagnostics.
    pub fn uploads(&self) -> &Arc<ManagedUploads> {
        &self.uploads
    }
}

impl Drop for InstalledUploads {
    fn drop(&mut self) {
        // Only the scope this guard installed. The declared sessions stop when the last write
        // holding the scope drops it.
        let current = self.context.set_managed_uploads(None);
        if let Some(current) = current
            && !Arc::ptr_eq(&current, &self.uploads)
        {
            self.context.set_managed_uploads(Some(current));
        }
    }
}

/// Install a declared, best-effort upload scope on the current call, for a commit on
/// `repository` that has just enabled its uploads. `None` when the commit did not ask for one
/// ([`with_managed_commit_uploads`]), does not upload, already runs in a managed caller operation,
/// or runs outside a call.
///
/// The scope's uploads wait for the repository's connect, at most one managed bound, and start
/// only if it resolved in time and its session-pool pre-warm did not expire. So a dead QUIC path,
/// or an endpoint that never answers, costs the commit one managed bound and no more.
pub fn install(repository: &Arc<RepositoryContext>) -> Option<InstalledUploads> {
    if !managed_commit_uploads_requested()
        || repository.disable_upload()
        || repository.is_offline()
        || lore_transport::current_caller_operation().is_some()
    {
        return None;
    }
    let context = crate::runtime::try_execution_context()?;
    let remote = repository.remote_handle();
    let prewarm_expired = context.prewarm_expired_flag();
    let bound = lore_transport::quic::client::managed_wait_bound();
    let uploads = ManagedUploads::new(async move {
        // The outcome does not matter here: a failed connect fails each upload's session fast.
        // A connect that does not resolve within the managed bound (an endpoint that takes the
        // connection and never answers) skips the uploads too. Waiting on the shared connect
        // future is drop-safe: the connect runs in its own task and is not cancelled.
        if tokio::time::timeout(bound, remote.remote()).await.is_err() {
            return false;
        }
        !prewarm_expired.load(Ordering::Relaxed)
    });
    context.set_managed_uploads(Some(uploads.clone()));
    Some(InstalledUploads { context, uploads })
}

// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Durable file finalization for one staged fragment.
//!
//! # The ordering is the contract
//!
//! ADR-00027's acknowledgement boundary requires the payload to be flushed,
//! atomically finalized under its content-derived identity, and the directory
//! durability operation completed, all **before** the authoritative `Staged`
//! commit. This module performs, in exactly this order:
//!
//! 1. ensure the fan-out directories exist and fsync **their** parents,
//!    including directories created by another writer;
//! 2. write the payload to a temporary file under `incoming/`;
//! 3. fsync the temporary file;
//! 4. rename it onto its staged path;
//! 5. fsync the leaf directory that now holds the entry.
//!
//! Step 1 comes before step 4 and that is not cosmetic. If the fan-out
//! directories were created and fsynced only after the rename, a crash between
//! the rename and those fsyncs could lose the directory entries that make the
//! leaf entry reachable, leaving a `Staged` row whose file cannot be found. A
//! `Staged` row without a readable, valid staged file is corruption under
//! ADR-00027 and must fail closed; producing one is worse than refusing the
//! write.
//!
//! `sync_all` rather than `sync_data` on the temporary file: the rename target's
//! metadata is part of what must survive, not just its contents.
//!
//! # What a crash leaves at each point
//!
//! - before step 4: an identified temporary file under `incoming/`.
//! - between step 4 and the caller's `commit_staged`: a finalized file under
//!   `staged/` whose publication may still be in flight.
//!
//! Both remain under coordinator custody. The bounded cleanup pass requests an
//! exact reclaim grant after preparation expires and ownership/readers permit
//! it. Missing epoch rows alone never authorize unlinking either kind of file.
//! A paused finalizer can leave late residue after fencing; retained custody
//! markers allow a later pass to remove it without releasing capacity twice.

use bytes::Bytes;
use lore_base::lore_spawn_blocking;
use tokio::sync::OwnedSemaphorePermit;

use super::WriteBehindError;
use super::root::ConfinedRoot;
use super::root::ResolvedStagedPath;
use super::root::StagedLeaf;

/// [`finalize_reserved`] that takes its own I/O slot. Test-only: production
/// reserves the slot before allocating an epoch.
#[cfg(all(test, unix))]
pub(crate) async fn finalize(
    root: &ConfinedRoot,
    resolved: &ResolvedStagedPath,
    payload: &Bytes,
) -> Result<(), WriteBehindError> {
    let permit = root.try_io_permit(super::StageIoPath::Put)?;
    finalize_reserved(permit, root, resolved, payload).await
}

/// Durably place one payload at its resolved staged path, using an I/O slot
/// the caller reserved before allocating its epoch, so a capacity refusal
/// never leaves a live preparation behind.
///
/// # Errors
///
/// Returns [`WriteBehindError::UnsupportedPlatform`] off Unix and `Io` for any
/// filesystem failure. Temporary-file removal on an I/O failure is best
/// effort; coordinator-fenced cleanup handles residue.
pub(crate) async fn finalize_reserved(
    permit: OwnedSemaphorePermit,
    root: &ConfinedRoot,
    resolved: &ResolvedStagedPath,
    payload: &Bytes,
) -> Result<(), WriteBehindError> {
    let root = root.clone();
    let resolved = resolved.clone();
    let payload = payload.clone();
    let handle = lore_spawn_blocking!(move || {
        let _permit = permit;
        root.verify_device()?;
        finalize_blocking(&root, &resolved, &payload)
    });
    match handle.await {
        Ok(result) => result,
        Err(_) => Err(WriteBehindError::Io {
            operation: "finalize join",
            kind: std::io::ErrorKind::Interrupted,
        }),
    }
}

pub(super) fn finalize_blocking(
    root: &ConfinedRoot,
    resolved: &ResolvedStagedPath,
    payload: &Bytes,
) -> Result<(), WriteBehindError> {
    use std::fs;
    use std::io::Write as _;

    // Step 1, and it must precede the rename. See the module header. The leaf
    // stays held so steps 4 and 5 act on the directory step 1 synced.
    let mut leaf = ensure_parent_retrying(root, resolved)?;

    let key = resolved
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(WriteBehindError::KeyMismatch)?;
    let temporary = root.incoming().join(format!("{key}.tmp"));

    // A failed create grants no ownership of an existing deterministic temp.
    // Return before the cleanup arm so a retry cannot unlink another writer.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| WriteBehindError::io("staging temp create", &error))?;
    let outcome = (|| -> Result<(), WriteBehindError> {
        file.write_all(payload.as_ref())
            .map_err(|error| WriteBehindError::io("staging temp write", &error))?;
        // Step 3. Contents and metadata, because the rename publishes both.
        file.sync_all()
            .map_err(|error| WriteBehindError::io("staging temp fsync", &error))?;
        #[cfg(feature = "failure_generator")]
        blocking_failpoint(async { crate::domain::fragments::failpoint!("stage.temp.synced") })
            .map_err(|_| WriteBehindError::Io {
                operation: "staging temp synced failpoint",
                kind: std::io::ErrorKind::Interrupted,
            })?;
        drop(file);
        // Step 4. Atomic within one filesystem, which the recorded device
        // guarantees. The target cannot already exist: `(hash, epoch)` is unique
        // by construction and an epoch row is immutable.
        let mut attempt = 1;
        loop {
            match root.rename_into(&temporary, resolved, &leaf) {
                Ok(()) => break,
                // Purge removes an empty fan-out directory, so the leaf step 1
                // synced can be gone by now, and a path might name a newer,
                // unsynced one. Redo step 1, so the rename lands in a directory
                // whose entry is durable.
                Err(WriteBehindError::Io {
                    kind: std::io::ErrorKind::NotFound,
                    ..
                }) if attempt < PLACEMENT_ATTEMPTS => {
                    attempt += 1;
                    leaf = ensure_parent_retrying(root, resolved)?;
                }
                // Out of attempts, `NotFound` stays an `Io` error, and
                // `WriteBehindError::store_error` maps every `Io` to `SlowDown`:
                // the PUT is retryable, not failed hard.
                Err(error) => return Err(error),
            }
        }
        #[cfg(feature = "failure_generator")]
        blocking_failpoint(async { crate::domain::fragments::failpoint!("stage.final.renamed") })
            .map_err(|_| WriteBehindError::Io {
            operation: "staging final renamed failpoint",
            kind: std::io::ErrorKind::Interrupted,
        })?;
        // Step 5.
        root.sync_leaf(&leaf, resolved)
    })();

    if outcome.is_err() {
        // Best effort. The rename either happened or it did not; if it did, this
        // removes nothing, and if it did not, this is the orphan that would
        // otherwise wait for the sweep.
        let _ = root.remove_placement_blocking(resolved, true);
    }
    outcome
}

/// Bounded attempts at a step whose fan-out directory a concurrent purge removed.
const PLACEMENT_ATTEMPTS: usize = 3;

/// Step 1, retried when a concurrent purge removed a directory it just made or
/// found. Each attempt syncs every level again, so the durability order holds.
fn ensure_parent_retrying(
    root: &ConfinedRoot,
    resolved: &ResolvedStagedPath,
) -> Result<StagedLeaf, WriteBehindError> {
    let mut attempt = 1;
    loop {
        match root.ensure_parent(resolved) {
            Err(WriteBehindError::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) if attempt < PLACEMENT_ATTEMPTS => attempt += 1,
            result => return result,
        }
    }
}

/// Finalization runs on a retained blocking worker. Its failpoint can wait on
/// the runtime without blocking an asynchronous executor thread.
#[cfg(feature = "failure_generator")]
fn blocking_failpoint(
    future: impl std::future::Future<Output = Result<(), crate::domain::DomainError>>,
) -> Result<(), crate::domain::DomainError> {
    let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
        crate::domain::DomainError::Internal(format!("staging failpoint runtime: {error}"))
    })?;
    runtime.block_on(future)
}

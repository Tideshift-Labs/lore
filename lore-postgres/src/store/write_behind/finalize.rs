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
//! 1. create the fan-out directories and fsync **their** parents;
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
//! - before step 4: an orphan under `incoming/`. Reclaimed by the orphan sweep
//!   (owned by `lore-server`, per the 2026-09-16 lane split).
//! - between step 4 and the caller's `commit_staged`: a finalized, valid,
//!   **unreferenced** file under `staged/`. It is not swept. `cleanup.rs`'s rule
//!   removes a `staged/` file only on a coordinator-computed purge target, and a
//!   file with no epoch row is indistinguishable from one whose `commit_staged`
//!   is still in flight on another replica. It therefore **leaks** until the same
//!   fragment is pushed again, which re-derives the same `(hash, epoch)` only if
//!   the epoch is reused — it is not — so in practice it leaks until an operator
//!   or a future reconciliation pass removes it. This is a known, accepted cost
//!   of never guessing that bytes are unreferenced; it is recorded here because
//!   an earlier draft of this plan wrongly claimed the sweep covered it.

use bytes::Bytes;
use lore_base::lore_spawn_blocking;

use super::WriteBehindError;
use super::root::ConfinedRoot;
use super::root::ResolvedStagedPath;
use super::root::sync_directory;

/// Durably place one payload at its resolved staged path.
///
/// # Errors
///
/// Returns [`WriteBehindError::UnsupportedPlatform`] off Unix and `Io` for any
/// filesystem failure. The temporary file is removed on every failure arm.
pub(crate) async fn finalize(
    root: &ConfinedRoot,
    resolved: &ResolvedStagedPath,
    payload: &Bytes,
) -> Result<(), WriteBehindError> {
    root.verify_device()?;
    let root = root.clone();
    let resolved = resolved.clone();
    let payload = payload.clone();
    let handle = lore_spawn_blocking!(move || finalize_blocking(&root, &resolved, &payload));
    match handle.await {
        Ok(result) => result,
        Err(_) => Err(WriteBehindError::Io {
            operation: "finalize join",
            kind: std::io::ErrorKind::Interrupted,
        }),
    }
}

fn finalize_blocking(
    root: &ConfinedRoot,
    resolved: &ResolvedStagedPath,
    payload: &Bytes,
) -> Result<(), WriteBehindError> {
    use std::fs;
    use std::io::Write as _;

    // Step 1, and it must precede the rename. See the module header.
    root.ensure_parent(resolved)?;

    let token = uuid::Uuid::now_v7().simple().to_string();
    let temporary = root.incoming().join(format!("{token}.tmp"));

    let outcome = (|| -> Result<(), WriteBehindError> {
        // `create_new` rather than `create`: a UUIDv7 collision is not expected,
        // and if one ever happened, silently truncating another in-flight
        // fragment's temporary file is the worst available response.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| WriteBehindError::io("staging temp create", &error))?;
        file.write_all(payload.as_ref())
            .map_err(|error| WriteBehindError::io("staging temp write", &error))?;
        // Step 3. Contents and metadata, because the rename publishes both.
        file.sync_all()
            .map_err(|error| WriteBehindError::io("staging temp fsync", &error))?;
        drop(file);
        // Step 4. Atomic within one filesystem, which the recorded device
        // guarantees. The target cannot already exist: `(hash, epoch)` is unique
        // by construction and an epoch row is immutable.
        fs::rename(&temporary, resolved.path())
            .map_err(|error| WriteBehindError::io("staging rename", &error))?;
        // Step 5.
        sync_directory(resolved.parent())
    })();

    if outcome.is_err() {
        // Best effort. The rename either happened or it did not; if it did, this
        // removes nothing, and if it did not, this is the orphan that would
        // otherwise wait for the sweep.
        let _ = fs::remove_file(&temporary);
    }
    outcome
}

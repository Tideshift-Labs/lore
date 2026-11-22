// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): whether a working copy is at its remote tip and clean.
//!
//! This answers a question about the working copy NOW. It does not say whether any one sync or
//! clone attempt applied: another sync, from this client or a different one, reaches the same
//! state. It is the evidence a caller uses to clear doubt about a sync or clone that ended without
//! a known outcome, because a sync owes the remote nothing. Only the local result matters, and
//! this is a direct read of that result.
//!
//! The verdict is decided here so every client of the engine (the `lore` CLI and in-process
//! embedders) reads the same rule. The reads that feed it live in `lore::sync_settled`, except
//! [`remote_branch`], the one direct remote read the rule needs.

use std::sync::Arc;

use lore_error_set::prelude::*;

use crate::branch;
use crate::branch::BranchError;
use crate::repository::RepositoryContext;

/// What a direct `BranchGet` said about the working copy's current branch on the remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteBranch {
    /// The server answered: the branch does not exist, or it exists with no revisions.
    Empty,
    /// The server answered with a branch record that has a tip.
    HasTip,
}

/// Ask the remote directly about the working copy's current branch.
///
/// This exists because push treats every failed remote branch lookup as "no remote branch"
/// (`branch/push.rs`, the `load_remote` match), so push's zero remote tip cannot tell an empty
/// branch from a failed read. Here only the server's `NotFound` answer reads as
/// [`RemoteBranch::Empty`]. Every other failure is an `Err`.
pub async fn remote_branch(
    repository: Arc<RepositoryContext>,
) -> Result<RemoteBranch, BranchError> {
    let (_latest, branch) = crate::instance::load_current_anchor(&repository)
        .await
        .forward::<BranchError>("reading the current branch")?;
    let remote = repository
        .remote()
        .await
        .forward::<BranchError>("acquiring remote")?;
    match branch::load_remote(remote, repository.id, branch).await {
        Ok(status) if status.latest.is_zero() => Ok(RemoteBranch::Empty),
        Ok(_status) => Ok(RemoteBranch::HasTip),
        Err(error) if error.is_branch_not_found() => Ok(RemoteBranch::Empty),
        Err(error) => Err(error),
    }
}

/// The state of a working copy against its remote tip, read after a sync or clone.
///
/// Only [`SyncSettled::Settled`] clears doubt. The other two keep it. A caller must never read
/// [`SyncSettled::Behind`] or [`SyncSettled::Dirty`] as "the attempt did not apply": current state
/// cannot tell an attempt that never landed from one that landed and was later overtaken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncSettled {
    /// Nothing on the remote branch tip is missing locally, and no file has a pending change.
    Settled,
    /// The remote branch tip has revisions the working copy does not have.
    Behind,
    /// At least one file has a pending change, a conflict, or content that differs from the
    /// recorded state.
    ///
    /// This includes a torn file: sync's realize path truncates a small file in place, so the
    /// revision pointer can be right while the bytes on disk are not. It also includes the
    /// user's own edits, which is the conservative direction: a dirty tree never clears doubt.
    Dirty,
}

impl SyncSettled {
    /// Decide the verdict from the two observations.
    ///
    /// `behind` is the count of remote revisions not present locally. `changed_files` is the
    /// count of non-directory nodes a full status scan reported. Revisions the working copy has
    /// and the remote does not (ahead) do not matter here: a sync never removes them.
    pub fn from_observation(behind: u64, changed_files: usize) -> Self {
        if behind > 0 {
            Self::Behind
        } else if changed_files > 0 {
            Self::Dirty
        } else {
            Self::Settled
        }
    }

    /// True only for [`SyncSettled::Settled`].
    pub fn is_settled(self) -> bool {
        self == Self::Settled
    }
}

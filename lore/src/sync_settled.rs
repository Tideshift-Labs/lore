// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): read whether a working copy is at its remote tip and clean.
//!
//! The rule lives in [`lore_revision::revision::sync_settled`]. This module makes the two reads
//! that feed it, through the same public calls any client makes:
//!
//! 1. A dry-run [`crate::branch::push`] of the current branch. Lore has no ahead/behind RPC; the
//!    counts are side output of push's `BranchPush` event, and `dry_run` gates off every mutation.
//!    `fast_forward_merge` is set so a behind or diverged branch returns status 0 rather than
//!    "Branch has diverged". The event is emitted before push's final status, so the event, not
//!    the status, decides whether the read succeeded.
//! 2. Only when that event shows a zero remote tip: one direct `BranchGet`
//!    ([`lore_revision::revision::sync_settled::remote_branch`]). Push reads a failed remote
//!    branch lookup as "no remote branch", so its zero tip cannot tell an empty branch from a
//!    failed read. Only the server's `NotFound` answer (or an empty record), with no local
//!    revisions ahead, continues. Anything else is an error.
//! 3. A full-scan, offline [`crate::repository::status`] with staged state included. The scan is
//!    load-bearing: without it, unstaged changes (a torn file among them) never appear.
//!
//! Every read that runs must succeed. A failed read is an error, never a verdict: "we could not
//! ask" is not "there is nothing there".

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;

use lore_revision::branch::BranchError;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEvent;
use lore_revision::interface::LoreEventCallback;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::interface::LoreNodeType;
use lore_revision::interface::LoreString;
use lore_revision::revision::sync_settled::RemoteBranch;
pub use lore_revision::revision::sync_settled::SyncSettled;
use lore_revision::revision::sync_settled::remote_branch;

use crate::branch::LoreBranchPushArgs;
use crate::repository::LoreRepositoryStatusArgs;

/// Why [`sync_settled`] could not produce a verdict. Every variant means "unknown".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncSettledError {
    /// The dry-run push emitted no `BranchPush` event, so there are no counts to read.
    #[error("dry-run push emitted no BranchPush event (status {status})")]
    RemoteReadFailed { status: i32 },
    /// The dry-run push did not finish inside the caller's budget.
    #[error("dry-run push did not finish within {seconds}s")]
    RemoteReadTimedOut { seconds: u64 },
    /// The dry-run push saw no remote tip, and a direct `BranchGet` did not confirm that the
    /// remote branch is empty.
    ///
    /// Push reads a failed remote branch lookup (a transient error, denied access) as "no
    /// remote branch" and reports zero remote history. Zero history against an unknown tip is
    /// not "at the remote tip", so this is an error, not a verdict.
    #[error("no remote tip, and the remote did not confirm an empty branch")]
    RemoteTipUnknown,
    /// The remote branch is empty, but the working copy has revisions the remote lacks.
    #[error("the remote branch is empty but the working copy has local revisions")]
    EmptyRemoteWithLocalHistory,
    /// The status scan returned a non-zero status.
    #[error("status scan failed (status {status})")]
    StatusFailed { status: i32 },
}

/// Read whether the working copy named by `globals.repository_path` is at its remote tip and
/// clean. See the module documentation for the two reads.
///
/// `callback` receives every event both reads emit, so a caller's error and telemetry taps still
/// see them. `remote_read_budget` bounds each remote read separately (the dry-run push, and the
/// direct `BranchGet` when it runs), so the remote half can take up to twice the budget; `None`
/// leaves them unbounded. The status scan is never bounded here.
///
/// The empty-branch case trusts the server's `NotFound`. A fork server maps only a missing key to
/// `NotFound`; an older or upstream server may also send it for a failed store read, and against
/// such a server a never-finished clone of a non-empty repository can read `Settled`.
///
/// The answer is about the working copy now, never about one attempt. See [`SyncSettled`].
pub async fn sync_settled(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    remote_read_budget: Option<Duration>,
) -> Result<SyncSettled, SyncSettledError> {
    let forward = Arc::new(callback);

    // Pin the flags that change what a read means. A caller's `force`, `local`, `remote` or
    // dispatch attempt must not reshape any read.
    let globals = LoreGlobalArgs {
        attempt_id: LoreString::default(),
        force: 0,
        local: 0,
        remote: 0,
        dry_run: 0,
        offline: 0,
        ..globals
    };

    // (remote history count, local history count, remote tip is zero)
    let observed = Arc::new(Mutex::new(None::<(u64, u64, bool)>));
    let push_globals = LoreGlobalArgs {
        dry_run: 1,
        ..globals.clone()
    };
    let push_args = LoreBranchPushArgs {
        branch: LoreString::default(),
        fast_forward_merge: 1,
    };
    let push = crate::branch::push(
        push_globals,
        push_args,
        tee(&forward, {
            let observed = observed.clone();
            move |event| {
                if let LoreEvent::BranchPush(data) = event {
                    *observed.lock().unwrap_or_else(PoisonError::into_inner) = Some((
                        data.remote_history,
                        data.local_history,
                        data.remote_revision.is_zero(),
                    ));
                }
            }
        }),
    );
    let push_status = match remote_read_budget {
        Some(budget) => match tokio::time::timeout(budget, push).await {
            Ok(status) => status,
            Err(_elapsed) => {
                return Err(SyncSettledError::RemoteReadTimedOut {
                    seconds: budget.as_secs(),
                });
            }
        },
        None => push.await,
    };
    let observed = *observed.lock().unwrap_or_else(PoisonError::into_inner);
    let Some((behind, ahead, remote_tip_is_zero)) = observed else {
        return Err(SyncSettledError::RemoteReadFailed {
            status: push_status,
        });
    };
    if remote_tip_is_zero {
        if ahead > 0 {
            return Err(SyncSettledError::EmptyRemoteWithLocalHistory);
        }
        let read = read_remote_branch(globals.clone(), &forward);
        let remote = match remote_read_budget {
            Some(budget) => tokio::time::timeout(budget, read)
                .await
                .map_err(|_elapsed| SyncSettledError::RemoteReadTimedOut {
                    seconds: budget.as_secs(),
                })?,
            None => read.await,
        };
        if remote != Some(RemoteBranch::Empty) {
            return Err(SyncSettledError::RemoteTipUnknown);
        }
    }

    let changed_files = Arc::new(Mutex::new(0usize));
    let status_globals = LoreGlobalArgs {
        offline: 1,
        ..globals
    };
    let status_args = LoreRepositoryStatusArgs {
        staged: 1,
        scan: 1,
        check_dirty: 0,
        reset: 0,
        sync_point: 0,
        revision_only: 0,
        count: 1,
        paths: LoreArray::default(),
    };
    let status = crate::repository::status(
        status_globals,
        status_args,
        tee(&forward, {
            let changed_files = changed_files.clone();
            move |event| {
                // Status emits directory nodes too. A directory is never a torn file and never
                // a pending change of its own; the files inside it are.
                if let LoreEvent::RepositoryStatusFile(data) = event
                    && !matches!(data.r#type, LoreNodeType::Directory)
                {
                    *changed_files.lock().unwrap_or_else(PoisonError::into_inner) += 1;
                }
            }
        }),
    )
    .await;
    if status != 0 {
        return Err(SyncSettledError::StatusFailed { status });
    }
    let changed_files = *changed_files.lock().unwrap_or_else(PoisonError::into_inner);

    Ok(SyncSettled::from_observation(behind, changed_files))
}

/// One direct `BranchGet` of the current branch. `None` when the read failed, for any reason;
/// only the server's answer can be `Some`.
async fn read_remote_branch(
    globals: LoreGlobalArgs,
    forward: &Arc<LoreEventCallback>,
) -> Option<RemoteBranch> {
    let out = Arc::new(Mutex::new(None::<RemoteBranch>));
    let sink = out.clone();
    let status = crate::call::repository_call_read(
        globals,
        tee(forward, |_event| {}),
        (),
        remote_branch,
        move |repository, ()| async move {
            let remote = remote_branch(repository).await?;
            *sink.lock().unwrap_or_else(PoisonError::into_inner) = Some(remote);
            Ok::<(), BranchError>(())
        },
    )
    .await;
    let remote = *out.lock().unwrap_or_else(PoisonError::into_inner);
    if status == 0 { remote } else { None }
}

/// A callback that runs the caller's callback, then `fold`.
fn tee<F>(forward: &Arc<LoreEventCallback>, fold: F) -> LoreEventCallback
where
    F: Fn(&LoreEvent) + Send + Sync + 'static,
{
    let forward = forward.clone();
    Some(Box::new(move |event| {
        if let Some(callback) = forward.as_ref() {
            callback(event);
        }
        fold(event);
    }))
}

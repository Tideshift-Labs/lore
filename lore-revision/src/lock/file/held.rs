// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! FORK-LOCAL (Tideshift): find the locks another user holds on the files a commit or a push
//! would change, so a caller can refuse before the change is made.
//!
//! Locks stay advisory on the server: a push over another user's lock is accepted there. This is
//! the client's own check. It refuses only on a positive answer. When the answer cannot be had
//! (offline, the lock service is unavailable, the caller's identity is unknown, the base revision
//! is not local), the check reports [`HeldLocks::Unknown`] and the caller goes on with a warning,
//! so an offline commit still works.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use lore_base::types::LockData;

use crate::branch;
use crate::filter::FilterMode;
use crate::lock::util::LOCK_BATCH_SIZE;
use crate::lock::util::assemble_resource_for_path;
use crate::lore::BranchId;
use crate::lore::Hash;
use crate::lore::execution_context;
use crate::lore_warn;
use crate::repository::RepositoryContext;
use crate::state;
use crate::state::State;
use crate::util::path::RelativePath;

/// How long finding the change and the whole lookup may take before it is given up as unknown.
pub const LOCK_CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// The holder a server without authentication records for every lock (`lore-server`'s display
/// subject for an unauthenticated caller).
pub const UNATTRIBUTED_LOCK_OWNER: &str = "<unknown>";

/// The answer to "does another user hold a lock on these paths?".
#[derive(Debug, Clone, PartialEq)]
pub enum HeldLocks {
    /// No path carries another user's lock.
    Clear,
    /// These locks, on paths in the change, are held by another user. Sorted by path.
    ByOthers(Vec<LockData>),
    /// The lookup could not answer, for the reason given.
    Unknown(String),
}

impl HeldLocks {
    /// The refusal message for [`HeldLocks::ByOthers`], naming each path and its holder.
    pub fn refusal_message(locks: &[LockData], override_hint: &str) -> String {
        let listed = locks
            .iter()
            .map(|lock| format!("{} (locked by {})", lock.resource.description, lock.owner))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{} file(s) in this change are locked by another user: {listed}. Ask the holder to \
             release the lock, or pass {override_hint} to go ahead anyway",
            locks.len()
        )
    }
}

/// Refuse `action` when another user holds a lock on one of the paths it would change.
///
/// `change` finds the branch and the paths, as [`staged_change_paths`] or [`push_change_paths`]
/// do; `None` paths means there is nothing to check. Finding the change and the lookup together
/// are bounded by [`LOCK_CHECK_TIMEOUT`]. Returns `LockNotOwned`, with a message naming each path
/// and holder, only on a positive answer. Anything that keeps the question from being answered is
/// logged as a warning and lets the action go ahead.
pub async fn refuse_if_held_by_others<E, F>(
    repository: &Arc<RepositoryContext>,
    change: F,
    action: &str,
    override_hint: &str,
) -> Result<(), E>
where
    E: lore_error_set::ErrorSet + From<lore_base::error::LockNotOwned>,
    F: Future<Output = Result<(BranchId, Option<Vec<String>>), String>>,
{
    match find_held_by_others(repository, change, action).await {
        None => Ok(()),
        Some(locks) => {
            let message = HeldLocks::refusal_message(&locks, override_hint);
            let mut error = E::from(lore_base::error::LockNotOwned);
            lore_error_set::ErrorSet::push_trace(
                &mut error,
                lore_error_set::Location::with_context(
                    file!(),
                    line!(),
                    column!(),
                    Arc::from(message),
                ),
            );
            Err(error)
        }
    }
}

/// The locks another user holds on the paths `change` finds, for a caller that builds its own
/// refusal. `None` when nothing refuses: no such lock, or no answer (logged as a warning, as
/// [`refuse_if_held_by_others`] does).
pub async fn find_held_by_others<F>(
    repository: &Arc<RepositoryContext>,
    change: F,
    action: &str,
) -> Option<Vec<LockData>>
where
    F: Future<Output = Result<(BranchId, Option<Vec<String>>), String>>,
{
    let context = execution_context();
    let globals = context.globals();
    if globals.offline() || globals.local() {
        lore_warn!("Not checking file locks before {action}: running offline or local");
        return None;
    }
    let answer = tokio::time::timeout(LOCK_CHECK_TIMEOUT, async {
        match change.await? {
            (branch, Some(paths)) => query_held_by_others(repository, branch, &paths).await,
            (_, None) => Ok(Vec::new()),
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "the lock lookup did not answer within {} seconds",
            LOCK_CHECK_TIMEOUT.as_secs()
        ))
    });
    let held = match answer {
        Ok(locks) if locks.is_empty() => HeldLocks::Clear,
        Ok(locks) => HeldLocks::ByOthers(locks),
        Err(reason) => HeldLocks::Unknown(reason),
    };
    match held {
        HeldLocks::Clear => None,
        HeldLocks::Unknown(reason) => {
            lore_warn!(
                "Could not check file locks before {action} ({reason}); going ahead without the \
                 check"
            );
            None
        }
        HeldLocks::ByOthers(locks) => Some(locks),
    }
}

/// The paths the staged change would commit, and the branch it commits to.
///
/// Every path the diff between the current and the staged revision names, including both ends of
/// a move. An empty list when nothing is staged.
pub async fn staged_change_paths(
    repository: &Arc<RepositoryContext>,
) -> Result<(BranchId, Vec<String>), String> {
    let (current, branch) = crate::instance::load_current_anchor(repository)
        .await
        .map_err(|error| format!("reading the current revision: {error}"))?;
    let staged = match crate::instance::load_staged_revision(repository).await {
        Ok(Some(staged)) if staged != current => staged,
        Ok(_) => return Ok((branch, Vec::new())),
        Err(error) => return Err(format!("reading the staged revision: {error}")),
    };
    let paths = changed_paths(repository, current, staged).await?;
    Ok((branch, paths))
}

/// The current branch and `user_paths` (as a caller names them) as repository paths, for a commit
/// of an explicit selection. A path that does not normalize is left out: the selection's own
/// validation refuses it.
pub async fn selection_change_paths(
    repository: &Arc<RepositoryContext>,
    user_paths: &[String],
) -> Result<(BranchId, Vec<String>), String> {
    let (_, branch) = crate::instance::load_current_anchor(repository)
        .await
        .map_err(|error| format!("reading the current revision: {error}"))?;
    let root = repository
        .require_path()
        .map_err(|error| format!("reading the working copy root: {error}"))?;
    // Selection paths are repository-relative: joined to the root first, as the selection's own
    // normalization does, since a bare relative path would resolve against the working directory.
    let paths = user_paths
        .iter()
        .filter_map(|path| {
            let joined = root.join(path);
            RelativePath::new_from_user_path(root, &joined.to_string_lossy()).ok()
        })
        .map(|path| path.as_str().to_string())
        .collect();
    Ok((branch, paths))
}

/// The branch a push would update and the local revision it would push: `branch` resolved when
/// given, else the current branch and revision, as [`crate::branch::push`] reads them.
pub async fn push_target(
    repository: &Arc<RepositoryContext>,
    branch: Option<&str>,
) -> Result<(BranchId, Hash), String> {
    if let Some(identifier) = branch {
        let status = branch::resolve(repository.clone(), identifier)
            .await
            .map_err(|error| format!("resolving branch {identifier}: {error}"))?;
        return Ok((status.id, status.latest));
    }
    let (latest, branch) = crate::instance::load_current_anchor(repository)
        .await
        .map_err(|error| format!("reading the current revision: {error}"))?;
    Ok((branch, latest))
}

/// The paths a push of `local_latest` to `branch` would change on the remote.
///
/// `Ok(None)` when the remote branch has no revisions yet: nobody can hold a lock on a branch the
/// server has never seen a revision of, so there is nothing to check.
pub async fn push_change_paths(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    local_latest: Hash,
) -> Result<Option<Vec<String>>, String> {
    let remote = repository
        .remote()
        .await
        .map_err(|error| format!("connecting to the remote: {error}"))?;
    let remote_latest = branch::load_remote_latest(remote, repository.id, branch)
        .await
        .map_err(|error| format!("reading the remote branch: {error}"))?;
    if remote_latest.is_zero() {
        return Ok(None);
    }
    if remote_latest == local_latest {
        return Ok(Some(Vec::new()));
    }
    // From the branch point, not the remote tip: a local copy that is behind (a fast-forward
    // merge push) would otherwise count the other users' own remote changes as this push's.
    let (branch_point, _, _) =
        crate::history::find_branch_point(repository.clone(), remote_latest, local_latest)
            .await
            .map_err(|error| format!("finding where the local and remote branch part: {error}"))?;
    let base = if branch_point.is_zero() {
        remote_latest
    } else {
        branch_point
    };
    if base == local_latest {
        return Ok(Some(Vec::new()));
    }
    changed_paths(repository, base, local_latest)
        .await
        .map(Some)
}

async fn changed_paths(
    repository: &Arc<RepositoryContext>,
    from: Hash,
    to: Hash,
) -> Result<Vec<String>, String> {
    let state_from = State::deserialize(repository.clone(), from)
        .await
        .map_err(|error| format!("reading revision {from}: {error}"))?;
    let state_to = State::deserialize(repository.clone(), to)
        .await
        .map_err(|error| format!("reading revision {to}: {error}"))?;
    let changes = state::diff_collect(
        repository.clone(),
        state_from,
        repository.clone(),
        state_to,
        None,
        FilterMode::Full,
    )
    .await
    .map_err(|error| format!("comparing revisions {from} and {to}: {error}"))?;

    let mut paths = BTreeSet::new();
    let mut moves = Vec::new();
    for change in &changes {
        paths.insert(change.path().as_str().to_string());
        if let Some(source) = change.move_source() {
            paths.insert(source.as_str().to_string());
            moves.push((
                source.as_str().to_string(),
                change.path().as_str().to_string(),
            ));
        }
    }
    // A moved directory reports its files at their new place only. Name each one at its old
    // place too, where a lock taken before the move sits.
    let mut moved_from = Vec::new();
    for path in &paths {
        for (source, target) in &moves {
            if let Some(rest) = path
                .strip_prefix(target.as_str())
                .and_then(|rest| rest.strip_prefix('/'))
            {
                moved_from.push(format!("{source}/{rest}"));
            }
        }
    }
    paths.extend(moved_from);
    paths.remove("");
    Ok(paths.into_iter().collect())
}

/// The locks on `paths` in `branch` that a user other than the caller holds.
///
/// The caller is the identity the remote connection resolved, the same subject the server records
/// as a lock's owner. The whole lookup is bounded by [`LOCK_CHECK_TIMEOUT`].
pub async fn held_by_others(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    paths: &[String],
) -> HeldLocks {
    if paths.is_empty() {
        return HeldLocks::Clear;
    }
    match tokio::time::timeout(
        LOCK_CHECK_TIMEOUT,
        query_held_by_others(repository, branch, paths),
    )
    .await
    {
        Ok(Ok(locks)) if locks.is_empty() => HeldLocks::Clear,
        Ok(Ok(locks)) => HeldLocks::ByOthers(locks),
        Ok(Err(reason)) => HeldLocks::Unknown(reason),
        Err(_) => HeldLocks::Unknown(format!(
            "the lock lookup did not answer within {} seconds",
            LOCK_CHECK_TIMEOUT.as_secs()
        )),
    }
}

async fn query_held_by_others(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    paths: &[String],
) -> Result<Vec<LockData>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let remote = repository
        .remote()
        .await
        .map_err(|error| format!("connecting to the remote: {error}"))?;
    let me = remote.identity().to_string();
    if me.is_empty() {
        return Err(
            "the signed-in identity is not known, so a lock's holder cannot be told \
                    apart from the caller"
                .to_string(),
        );
    }

    let mut held = Vec::new();
    for chunk in paths.chunks(LOCK_BATCH_SIZE) {
        let resources = chunk
            .iter()
            .map(|path| assemble_resource_for_path(path, branch))
            .collect::<Vec<_>>();
        let mut answer = remote
            .lock(repository.id)
            .await
            .map_err(|error| format!("connecting to the lock service: {error}"))?
            .status(&resources)
            .await
            .map_err(|error| format!("reading lock status: {error}"))?;
        held.append(&mut answer);
    }

    held.retain(|lock| lock.owner != me);
    // A server without authentication records every holder as the same placeholder, so such a
    // lock may well be the caller's own: it settles nothing either way.
    let unattributed = held
        .iter()
        .filter(|lock| lock.owner == UNATTRIBUTED_LOCK_OWNER)
        .count();
    held.retain(|lock| lock.owner != UNATTRIBUTED_LOCK_OWNER);
    if held.is_empty() && unattributed > 0 {
        return Err(format!(
            "{unattributed} file(s) carry a lock whose holder the server does not record \
             (authentication is off), so it cannot be told apart from the caller's own"
        ));
    }
    held.sort_by(|a, b| a.resource.description.cmp(&b.resource.description));
    Ok(held)
}

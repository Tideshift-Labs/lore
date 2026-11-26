// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): settle a journalled local commit that provably did not apply, from the
//! repository's own anchors.
//!
//! A local commit has no server receipt, so a managed workflow that lost the answer to one (a
//! crash, or a failure the caller could not classify) used to block every later write to the
//! working copy. The child journals, before the commit runs, the anchors the commit would move.
//! Recovery reads them again and settles `NotApplied` only when the branch, current, branch
//! latest, staged anchor and commit intent are all exactly as recorded: a commit publishes its
//! anchors only at its end, so nothing moved. Anything else stays unknown, including a commit
//! that did apply (settling that needs proof the revision is this attempt's; a follow-up).
//!
//! While the attempt is unresolved the repository's write fence refuses every other write of a
//! fork build, so the anchors move only by the attempt itself. A build without the fence (a
//! stock `lore`) writing the same working copy is outside this guarantee. A repository with links
//! or layers has no evidence: its commit publishes the inner repository's anchors first, which
//! the outer anchors do not show. Nor has one on a shared store: its branch latest is every
//! instance's, and the fence covers one working copy.
//!
//! The parent closes on this evidence only if every step with an effect records its child before
//! the effect; a caller must keep to that.

use std::sync::Arc;

use lore_base::types::Hash;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::error::ProtocolError;
use serde::Deserialize;
use serde::Serialize;

use crate::repository::RepositoryContext;
use crate::state::State;

/// The anchors a local commit would move, read before it runs. Strict reads only: a store that
/// fails a read fails the capture, never reads as zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalCommitEvidence {
    /// The current branch, as `Hash::from_context`.
    pub branch: Hash,
    pub current: Hash,
    pub branch_latest: Hash,
    /// Zero where nothing is staged.
    pub staged: Hash,
    /// Zero unless a commit of this instance was cut short; see `instance::store_commit_intent`.
    pub committing: Hash,
}

/// Reads the anchors of `repository` as [`LocalCommitEvidence`].
pub async fn capture(
    repository: &Arc<RepositoryContext>,
) -> Result<LocalCommitEvidence, ProtocolError> {
    let (current, branch) = crate::instance::load_own_current_anchor(repository)
        .await
        .map_err(|error| internal("reading the current anchor", error))?;
    // The local store alone: a branch with no latest reads zero, and nothing goes remote.
    let branch_latest = match crate::branch::load_latest_local(repository.clone(), branch).await {
        Ok(latest) => latest,
        Err(error) if error.is_branch_not_found() => Hash::default(),
        Err(error) => return Err(internal("reading the branch latest", error)),
    };
    let staged = crate::instance::load_own_staged_revision(repository)
        .await
        .map_err(|error| internal("reading the staged anchor", error))?
        .unwrap_or_default();
    let committing = crate::instance::load_commit_intent(repository)
        .await
        .map_err(|error| internal("reading the commit intent", error))?;
    // A shared store holds the branch latest for every instance on it, while the write fence
    // covers this working copy alone: another instance could move it, or move it back.
    // An instance with no working copy on disk has no config and no shared store.
    let shared = match repository.require_path() {
        Ok(root) => {
            let config = crate::repository::load_repository_config(root)
                .map_err(|error| internal("reading the repository config", error))?;
            crate::shared_store::get_shared_store_path_for_repo(&config)
                .await
                .map_err(|error| internal("locating the shared store", error))?
                .is_some()
        }
        Err(_) => false,
    };
    if shared {
        return Err(internal(
            "capturing",
            "a repository on a shared store has no evidence",
        ));
    }
    // A commit of a linked or layered repository publishes the inner repository's anchors before
    // the outer one's, with no commit intent, so the outer anchors alone could read a published
    // link as nothing moved. Such a repository has no local commit evidence.
    if !crate::layer::list(repository.clone())
        .await
        .map_err(|error| internal("reading the layers", error))?
        .is_empty()
    {
        return Err(internal(
            "capturing",
            "a repository with layers has no evidence",
        ));
    }
    for revision in [current, staged] {
        if revision.is_zero() {
            continue;
        }
        let state = State::deserialize(repository.clone(), revision)
            .await
            .map_err(|error| internal("reading a state", error))?;
        if !state
            .link_list(repository.clone())
            .await
            .map_err(|error| internal("reading the links", error))?
            .is_empty()
        {
            return Err(internal(
                "capturing",
                "a repository with links has no evidence",
            ));
        }
    }
    Ok(LocalCommitEvidence {
        branch: Hash::from_context(branch),
        current,
        branch_latest,
        staged,
        committing,
    })
}

/// `NotApplied` where the anchors of `repository` are exactly `recorded`, else `None`. A read
/// that fails is an error, which settles nothing.
pub async fn decide(
    repository: &Arc<RepositoryContext>,
    recorded: &LocalCommitEvidence,
) -> Result<Option<AttemptResolution>, ProtocolError> {
    let now = capture(repository).await?;
    Ok(decide_from(recorded, &now))
}

/// [`decide`] on anchors already read.
pub fn decide_from(
    recorded: &LocalCommitEvidence,
    now: &LocalCommitEvidence,
) -> Option<AttemptResolution> {
    (now == recorded).then_some(AttemptResolution::NotApplied)
}

fn internal(action: &str, error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::internal(format!("local commit evidence: {action}: {error}"))
}

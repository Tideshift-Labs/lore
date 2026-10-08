// Copyright 2026 Khurram Virani
// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

//! Push-time advisory-lock enforcement (CR-019, naive present-tense model).
//!
//! Lore locks are advisory by design: the storage/push/merge paths never
//! consult them, so a client that ignores the lock protocol (e.g. the stock
//! `lore` CLI, or any tool bypassing Lorehub's own clients) can push a change
//! to a file another user has locked. This guard makes an **opt-in** server
//! check: on push, diff the pushed revision against the branch's current tip
//! and, if any changed path is locked on that branch by a *different* user,
//! reject the push.
//!
//! Deliberately naive (present-tense) for a first cut: it answers "is a changed
//! file locked by someone else *right now*", not the causal question the
//! upstream successor-locks LEP targets (has this branch seen every prior edit).
//! It is gated behind `[feature] enforce_locks_on_push` (default **off**), so
//! enabling it is an explicit operator choice after live verification.

use std::collections::HashMap;
use std::sync::Arc;

use lore_base::types::Hash;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_revision::branch::load_latest;
use lore_revision::change::NodeChange;
use lore_revision::diff::diff_revision_paths;
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lock::util::assemble_resource_for_path;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::State;
use lore_revision::util::collect_stream::collect_stream_with_summary;
use tonic::Status;
use tracing::debug;
use tracing::warn;

/// The verified owner pair a push is authorized under.
///
/// Push-lock authority is the `(verified_issuer, authenticated_subject)` pair
/// (CR-030), so an enforcing cell has nothing to compare against when the
/// request carries no verified token, and must refuse rather than fall back to
/// the shared `"<unknown>"` display subject.
pub(crate) fn verified_push_owner(
    authorization: Option<&crate::auth::jwt::AuthorizationToken>,
) -> Result<VerifiedLockOwner, Status> {
    let token = authorization.ok_or_else(|| {
        Status::unauthenticated("Push-lock enforcement requires a verified caller")
    })?;
    Ok(VerifiedLockOwner {
        verified_issuer: token.issuer.clone(),
        authenticated_subject: token.user_id.clone(),
    })
}

/// A single lock that blocks the push: the changed path and who holds the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockConflict {
    pub path: String,
    pub owner: String,
}

/// How this cell resolves the verified issuer behind a stored lock owner.
///
/// The legacy `LockStore` records an owner as a bare subject string, which is
/// display data, never authority (CR-030). Turning it back into the verified
/// `(issuer, subject)` pair the comparison needs is only possible when the cell
/// pins one issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockOwnerIssuerPolicy {
    /// The cell pins one verified issuer, so every token it accepts — and
    /// therefore every lock row it admitted — carries exactly this issuer. A
    /// stored subject plus this issuer is a provable owner pair.
    Pinned(String),
    /// The cell accepts more than one issuer (or any issuer its JWK service
    /// can verify), so a stored subject names no provable pair: `mallory`
    /// under issuer B and `mallory` under issuer A are indistinguishable in
    /// storage. Nothing can be proved to be the pusher's own lock, so every
    /// lock on a changed path blocks.
    Unprovable,
}

impl LockOwnerIssuerPolicy {
    /// Derive the policy from the verifier's configured `jwt_issuer` list.
    ///
    /// Since upstream v0.10.0 `jwt_issuer` is a list, so a cell can accept two
    /// issuers during an issuer cutover. A stored subject is a provable owner
    /// pair only when the cell accepts exactly ONE non-empty issuer; with two,
    /// a row could have been admitted under either, so the policy is
    /// `Unprovable` (fail closed) — never "pin the first one".
    pub fn from_configured_issuers(issuers: Option<&[String]>) -> Self {
        match issuers {
            Some([issuer]) if !issuer.is_empty() => Self::Pinned(issuer.clone()),
            _ => Self::Unprovable,
        }
    }

    /// Whether a stored owner subject provably names the pushing owner pair.
    ///
    /// Under `Pinned` the issuer half is proved by configuration rather than by
    /// storage: the verifier rejects every token from another issuer, so a row
    /// this cell admitted cannot have been acquired under one.
    fn proves_own(&self, stored_owner: &str, pusher: &VerifiedLockOwner) -> bool {
        match self {
            Self::Pinned(issuer) => {
                stored_owner == pusher.authenticated_subject
                    && issuer.as_str() == pusher.verified_issuer.as_str()
            }
            Self::Unprovable => false,
        }
    }
}

/// The legacy push-lock authority: a lock store plus the issuer policy needed
/// to read its subject-only owners as verified pairs.
#[derive(Clone)]
pub struct PushLockEnforcement {
    pub lock_store: Arc<dyn LockStore>,
    pub issuer_policy: LockOwnerIssuerPolicy,
}

/// Map an internal engine error to a `Status::internal` that fails the push
/// closed, logging via the house `warn_mapped_error_status` convention.
fn to_internal<E: std::error::Error>(error: &E, message: &'static str) -> Status {
    let status = Status::internal(message);
    crate::grpc::warn_mapped_error_status(error, &status);
    status
}

/// Enforce advisory locks against a push. Returns `Ok(())` when the push is
/// clear; returns a `permission_denied` `Status` naming the first blocking lock
/// when a changed path is locked by another user on this branch.
///
/// `new_revision` is the revision being pushed; the prior branch tip is loaded
/// here (before `push()` advances it). A push that creates the branch (no prior
/// tip) diffs against the empty tree, so a brand-new file locked by someone else
/// would still be caught.
pub async fn enforce_push_locks(
    repository: Arc<RepositoryContext>,
    enforcement: &PushLockEnforcement,
    branch: BranchId,
    new_revision: Hash,
    pusher: &VerifiedLockOwner,
) -> Result<(), Status> {
    let repository_id = repository.id;
    let conflicts = collect_push_lock_conflicts(
        repository,
        &enforcement.lock_store,
        repository_id,
        branch,
        new_revision,
        pusher,
        &enforcement.issuer_policy,
    )
    .await?;

    if let Some(first) = conflicts.first() {
        warn!(
            path = %first.path,
            owner = %first.owner,
            conflict_count = conflicts.len(),
            "Rejecting push: changed path is locked by another user",
        );
        return Err(Status::permission_denied(
            match &enforcement.issuer_policy {
                LockOwnerIssuerPolicy::Pinned(_) => format!(
                    "push blocked: {} file(s) changed are locked by another user; \
                 e.g. '{}' is locked by {}",
                    conflicts.len(),
                    first.path,
                    first.owner,
                ),
                LockOwnerIssuerPolicy::Unprovable => format!(
                    "push blocked: {} file(s) changed are locked and this cell cannot prove who \
                 holds them; e.g. '{}' is locked by subject '{}' under an unverified issuer. \
                 Set [server.auth] jwt_issuer so lock ownership is a verified issuer/subject \
                 pair.",
                    conflicts.len(),
                    first.path,
                    first.owner,
                ),
            },
        ));
    }

    Ok(())
}

/// The pure core: compute the set of changed paths on this push that are locked
/// by a different user. Split out from `enforce_push_locks` so the conflict
/// computation is unit-testable without the tonic `Status` mapping.
#[lore_macro::test_pub]
pub(crate) async fn collect_push_lock_conflicts(
    repository: Arc<RepositoryContext>,
    lock_store: &Arc<dyn LockStore>,
    repository_id: RepositoryId,
    branch: BranchId,
    new_revision: Hash,
    pusher: &VerifiedLockOwner,
    issuer_policy: &LockOwnerIssuerPolicy,
) -> Result<Vec<LockConflict>, Status> {
    // Locks held by OTHERS on this branch, keyed by resource hash. If nobody
    // else holds a lock on this branch, there is nothing to enforce — skip the
    // (potentially expensive) revision diff entirely.
    let other_locks =
        others_locks_by_hash(lock_store, repository_id, branch, pusher, issuer_policy).await?;
    if other_locks.is_empty() {
        debug!(%branch, "No foreign locks on branch; skipping push-lock diff");
        return Ok(Vec::new());
    }

    let prior_tip = load_latest(repository.clone(), branch)
        .await
        .map_err(|err| to_internal(&err, "failed to load branch tip for lock check"))?;

    let changed_paths = changed_paths(repository, prior_tip, new_revision).await?;

    Ok(conflicts_for_changed_paths(changed_paths, branch, |hash| {
        other_locks.get(hash).cloned()
    }))
}

/// Map changed paths onto the locks that block them.
///
/// `owner_of` answers "who holds the lock on this resource, if anyone" for
/// whichever lock authority the caller consulted — the legacy `LockStore` here,
/// the fenced coordinator in `branch_push`. Sharing this keeps the two callers
/// from drifting on path-to-resource mapping, which is the part that must
/// agree with what a client used to acquire the lock.
pub(crate) fn conflicts_for_changed_paths(
    changed_paths: Vec<String>,
    branch: BranchId,
    owner_of: impl Fn(&Hash) -> Option<String>,
) -> Vec<LockConflict> {
    let mut conflicts = Vec::new();
    for path in changed_paths {
        let resource = assemble_resource_for_path(&path, branch);
        if let Some(owner) = owner_of(&resource.hash) {
            conflicts.push(LockConflict { path, owner });
        }
    }
    conflicts
}

/// Map of `resource.hash -> owner` for every lock on `branch` this cell cannot
/// prove belongs to the pushing owner pair.
///
/// The old comparison was `lock.owner != pusher_user_id` — a bare subject
/// against a bare subject, which reads `mallory` under two different issuers as
/// one owner and lets the second push over the first's lock (CR-030's named
/// fail-open). A lock is now the pusher's own only when the issuer policy can
/// prove the pair; anything unprovable stays foreign.
#[lore_macro::test_pub]
async fn others_locks_by_hash(
    lock_store: &Arc<dyn LockStore>,
    repository_id: RepositoryId,
    branch: BranchId,
    pusher: &VerifiedLockOwner,
    issuer_policy: &LockOwnerIssuerPolicy,
) -> Result<HashMap<Hash, String>, Status> {
    let locks = lock_store
        .query_locks(LockQuery::RepositoryBranch(repository_id, branch))
        .await
        .map_err(|err| to_internal(&err, "failed to query locks for lock check"))?;

    Ok(locks
        .into_iter()
        .filter(|lock| !issuer_policy.proves_own(&lock.owner, pusher))
        .map(|lock| (lock.resource.hash, lock.owner))
        .collect())
}

/// The set of file paths that differ between `source` and `target` revisions.
pub(crate) async fn changed_paths(
    repository: Arc<RepositoryContext>,
    source: Hash,
    target: Hash,
) -> Result<Vec<String>, Status> {
    let state_source = State::deserialize(repository.clone(), source)
        .await
        .map_err(|err| to_internal(&err, "failed to read source revision for lock check"))?;
    let state_target = State::deserialize(repository.clone(), target)
        .await
        .map_err(|err| to_internal(&err, "failed to read target revision for lock check"))?;

    let (_, changes): (_, Vec<NodeChange>) = collect_stream_with_summary(|tx| {
        diff_revision_paths(repository.clone(), state_source, state_target, None, tx)
    })
    .await
    .map_err(|err| to_internal(&err, "failed to diff revisions for lock check"))?;

    let mut paths = Vec::with_capacity(changes.len());
    for change in changes {
        // The path in the target tree. A rename also carries a move source (the
        // old path) — both endpoints are "changed" for lock purposes, since a
        // lock is on either the source or destination path.
        paths.push(change.path().as_str().to_string());
        if let Some(from_path) = change.move_source() {
            let from = from_path.as_str().to_string();
            if from != change.path().as_str() {
                paths.push(from);
            }
        }
    }
    Ok(paths)
}

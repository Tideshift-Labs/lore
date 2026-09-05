// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use lore_base::error::OutcomeUnknown;
use lore_base::lore_spawn;
use lore_base::types::LockResource;
use lore_error_set::prelude::*;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::FencedLockResource;
use lore_transport::connection::Connection;
use serde::Deserialize;
use serde::Serialize;
use tokio::task::JoinSet;

use crate::attempt_store::held_tokens;
use crate::auth;
use crate::branch;
use crate::errors::*;
use crate::event;
use crate::event::EventError;
use crate::filter::FilterMode;
use crate::interface::LoreArray;
use crate::interface::LoreError;
use crate::interface::LoreString;
use crate::lock;
use crate::lock::util::LOCK_BATCH_SIZE;
use crate::lock::util::assemble_resource_for_path;
use crate::lore::execution_context;
use crate::lore_debug;
use crate::lore_error;
use crate::lore_trace;
use crate::repository::RepositoryContext;
use crate::state;
use crate::util::path::RelativePath;

#[derive(Clone, Debug)]
pub struct ReleaseOptions {
    pub paths: LoreArray<LoreString>,
    pub branch: String,
    pub owner: String,
    pub owner_id: String,
}

#[error_set]
pub enum ReleaseError {
    Disconnected,
    InvalidArguments,
    SlowDown,
    NotAuthorized,
    NotAuthenticated,
    Maintenance,
    NotFound,
    NoRemote,
    NotSupported,
    AddressNotFound,
    InvalidNodeHierarchy,
    InvalidPath,
    LinkNotFound,
    NodeNotFound,
    Oversized,
    RevisionNotFound,
    WriteRequired,
    NotConnected,
    PayloadNotFound,
    AlreadyLinked,
    BranchAdvanced,
    BranchAlreadyExists,
    BranchNotFound,
    Conflict,
    DeleteCurrent,
    DeleteDefault,
    DeleteProtected,
    Divergent,
    FileNotFound,
    IdenticalMetadata,
    LayerNotFound,
    LinkPathNotFound,
    LocalModifications,
    LockNotFound,
    LockNotOwned,
    MaxHistorySearchDepth,
    NotALayer,
    NotALink,
    NothingStaged,
    RepositoryAlreadyExists,
    RepositoryNotFound,
    SharedStoreNotFound,
    TokenNotFound,
    MissingIdentity,
    /// A dispatched mutable request whose outcome is not known (WP-120).
    ///
    /// Declared so the ambiguity survives this layer. Collapsing it into a
    /// connectivity error here would tell the caller the write did not happen.
    OutcomeUnknown,
}

impl EventError for ReleaseError {
    fn translated(&self) -> LoreError {
        match self {
            // An unresolved attempt keeps its own code all the way to the FFI
            // boundary (WP-120). Reported as `Internal` it is indistinguishable
            // from an operation that provably did not happen, which is the one
            // reading a caller must never be given.
            ReleaseError::OutcomeUnknown(_) => LoreError::OutcomeUnknown,
            _ => LoreError::Internal,
        }
    }

    fn inner(&self) -> String {
        self.to_string()
    }
}

/// Data for an event that marks the start of a lock release report.
#[repr(C)]
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreLockFileReleaseBeginEventData {
    /// Number of release entries that follow.
    pub count: u64,
    /// Whether no matching lock was found to release.
    pub not_found: u8,
}

/// Data for an event reporting a path whose lock is being released.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreLockFileReleaseEventData {
    /// The path whose lock is being released.
    pub path: LoreString,
}

/// Release file locks, presenting whatever ownership this client holds for them.
///
/// `ownership` is the same durable store [`crate::lock::file::acquire::acquire`] wrote to; see
/// that function for why it is a parameter rather than derived from the repository.
///
/// A resource this client holds no token for is still sent, tokenless. A cell that is not routing
/// through the fenced authority issues no tokens at all, so a client that withheld tokenless
/// resources could release nothing on one. A fenced cell refuses such a request and says so, in a
/// message that names the only remedy that works.
pub async fn release(
    repository: Arc<RepositoryContext>,
    options: ReleaseOptions,
    ownership: Arc<dyn AttemptStore>,
) -> Result<(), ReleaseError> {
    let remote = repository
        .remote()
        .await
        .forward::<ReleaseError>("Unable to release lock while offline")?;

    let (current_revision, current_branch) = crate::instance::load_current_anchor(&repository)
        .await
        .forward::<ReleaseError>("Failed to deserialize current revision anchor")?;
    let staged_revision = crate::instance::load_staged_revision(&repository)
        .await
        .ok()
        .flatten()
        .unwrap_or(current_revision);

    let branch = if options.branch.is_empty() {
        current_branch
    } else {
        let resolved = branch::resolve(repository.clone(), options.branch.as_str())
            .await
            .forward::<ReleaseError>("Invalid branch")?;
        resolved.id
    };

    let owner = if !options.owner_id.is_empty() {
        Some(options.owner_id)
    } else if !options.owner.is_empty() {
        let owner_id = auth::userinfo::user_id(repository.clone(), &options.owner)
            .await
            .forward::<ReleaseError>("Failed to resolve user id from user name")?;

        Some(owner_id)
    } else {
        None
    };

    let mut resources = HashSet::<lock::LockResource>::with_capacity(options.paths.len());
    // Owners are known only where the set was rebuilt from a `Query`, which is the one release
    // shape that can escalate to an administrative takeover: `ForceUnlock` names the owner it
    // believes it is releasing, and there is nowhere else on this path to learn one.
    let mut queried_owners = HashMap::<lock::LockResource, String>::new();
    let force = execution_context().globals().force();
    if !options.paths.is_empty() {
        // When --force flag IS enabled we attempt to release a lock on all paths passed
        // When --force flag ISN'T enabled we attempt to release a lock considering the following
        // a)   If the path is excluded by the filter, discard it from operation
        //      This happens when file was excluded by --view or .urcignore
        // b)   Otherwise we verify the path is a valid node in the repository
        // REMARK: since locks are treated as an atomic operation if anything here fails we abort

        let state = state::State::deserialize(repository.clone(), staged_revision)
            .await
            .forward::<ReleaseError>("Failed to deserialize state")?;

        lore_debug!("Inspecting {} path(s)", options.paths.len());
        for path in options.paths.as_slice().iter() {
            let relative_path = RelativePath::new_from_user_path(
                repository.require_path()?,
                path.as_str(),
            )
            .forward_with::<ReleaseError, _>(|| format!("Invalid path: {}", path.as_str()))?;
            if !force {
                if repository
                    .filter
                    .emit_excludes(&relative_path, true, FilterMode::Full)
                {
                    lore_trace!("Path excluded by filter: {}", relative_path.as_str());
                    continue;
                }

                let node_link = state
                    .find_node_link(repository.clone(), relative_path.as_str())
                    .await
                    .unwrap_or_default();

                if !node_link.is_valid() {
                    lore_error!(
                        "Path not found in repository. Use --force if file was deleted while being locked."
                    );
                    return Err(ReleaseError::internal(format!(
                        "Invalid path: {}",
                        path.as_str()
                    )));
                }
            }

            let resource = assemble_resource_for_path(relative_path.as_str(), branch);
            resources.insert(resource);
        }
    } else if force {
        // If there are no paths and --force flag IS enabled we attempt to release all locks for
        // i) the current branch or the branch passed in by the --branch option
        // ii) the current user or the user passed in by the --owner option

        let response = remote
            .lock(repository.id)
            .await
            .forward_with::<ReleaseError, _>(|| {
                format!("Failed to connect to remote {}", remote.remote_url())
            })?
            .query(Some(branch), owner.as_deref(), None)
            .await
            .forward::<ReleaseError>("Failed to query the locks")?;

        for lock in response.iter() {
            let relative_path = &lock.resource.description;
            let resource = assemble_resource_for_path(relative_path.as_str(), branch);
            queried_owners.insert(resource.clone(), lock.owner.clone());
            resources.insert(resource);
        }
    }

    if resources.is_empty() {
        lore_debug!("No paths to release lock on");
        return Ok(());
    }

    // We cannot know which locks are going to be released without contacting the server, so every path is reported as a would-be release.
    if execution_context().globals().dry_run() {
        let mut paths = resources
            .iter()
            .map(|resource| resource.description.clone())
            .collect::<Vec<_>>();
        paths.sort();

        event::LoreEvent::LockFileReleaseBegin(LoreLockFileReleaseBeginEventData {
            count: paths.len() as u64,
            not_found: 0,
        })
        .send();

        for path in paths {
            event::LoreEvent::LockFileRelease(LoreLockFileReleaseEventData {
                path: LoreString::from(&path),
            })
            .send();
        }

        return Ok(());
    }

    lore_debug!("Unlocking {} path(s)", resources.len());

    let resources_count = resources.len();

    // Attach the ownership this client holds, then split on whether it holds any.
    //
    // The split is what lets one release cover both cells. Rows with a token go through `Unlock`,
    // which is the owner's own verb and works on a fenced cell and an unfenced one alike. Rows
    // without one are the interesting case: on an unfenced cell that is every row and `Unlock` is
    // correct, while on a fenced cell it means the token was never issued or has been lost, and
    // only an administrator can clear the row. Sending them together would let the second kind
    // fail the batch that carried the first.
    let requested = Vec::from_iter(resources);
    let keys = requested
        .iter()
        .map(|resource| (resource.branch, resource.hash))
        .collect::<Vec<_>>();
    let tokens = held_tokens(&ownership, &keys)
        .await
        .forward::<ReleaseError>("Failed to read the held lock ownership")?;

    let mut held = Vec::with_capacity(resources_count);
    let mut unheld = Vec::with_capacity(resources_count);
    for (resource, token) in requested.into_iter().zip(tokens) {
        match token {
            Some(token) => held.push(FencedLockResource::with_token(resource, Some(token))),
            None => unheld.push(FencedLockResource::tokenless(resource)),
        }
    }

    let mut unlocks = Vec::with_capacity(resources_count);
    // The first wholesale failure of either set. The release fails on it even when the other set
    // succeeded: the two are one user request split on an implementation detail — which rows this
    // client happens to hold a token for — so reporting success because the other half worked
    // would tell someone their locks are released when their own are not.
    let mut first_failure: Option<ReleaseError> = None;

    if !held.is_empty()
        && let Err(error) = unlock_batches(&remote, repository.id, &held, &mut unlocks).await
    {
        first_failure = Some(error);
    }

    if !unheld.is_empty()
        // `Unlock` first, escalate second, and in that order deliberately. An unfenced cell
        // releases these on the first call, so its behaviour is unchanged; a fenced cell refuses
        // them before it mutates anything, which makes the retry safe. Escalating first would
        // instead break every unfenced cell, because `ForceUnlock` does not exist there.
        && let Err(unlock_error) =
            unlock_batches(&remote, repository.id, &unheld, &mut unlocks).await
        && let Err(error) = force_release(
            &remote,
            repository.id,
            &unheld,
            &queried_owners,
            unlock_error,
            &mut unlocks,
        )
        .await
    {
        first_failure = first_failure.or(Some(error));
    }

    // Clearing comes before the failure is raised, never after. Whatever the server confirmed is
    // released whether or not something else in the same request failed, and a token kept for a
    // lock that is gone will one day be presented against a row somebody else holds.
    //
    // Only on a confirmed release, and only for what the server named. A release whose outcome is
    // unknown must leave the token exactly where it is: discarding it on a maybe strands a lock
    // that is still held with nothing left to release it.
    let cleared = unlocks
        .iter()
        .map(|resource| (resource.branch, resource.hash))
        .collect::<Vec<_>>();
    ownership
        .clear_ownership_batch(&cleared)
        .await
        .forward::<ReleaseError>("Failed to clear the released lock ownership")?;

    if let Some(failure) = first_failure {
        return Err(failure);
    }

    if unlocks.is_empty() {
        event::LoreEvent::LockFileReleaseBegin(LoreLockFileReleaseBeginEventData {
            count: 0,
            not_found: 1,
        })
        .send();
    } else {
        unlocks
            .sort_by(|resource_a, resource_b| resource_a.description.cmp(&resource_b.description));

        // Generate structured output for locks successfully released
        lore_debug!("Unlocked {} path(s)", unlocks.len());
        event::LoreEvent::LockFileReleaseBegin(LoreLockFileReleaseBeginEventData {
            count: unlocks.len() as u64,
            not_found: 0,
        })
        .send();
        for unlock in unlocks.iter() {
            event::LoreEvent::LockFileRelease(LoreLockFileReleaseEventData {
                path: LoreString::from(&unlock.description),
            })
            .send();
        }
    }

    Ok(())
}

/// Release one set of resources through `Unlock`, in batches, concurrently.
///
/// Keeps the batch tolerance the single-set version had: a partial failure is logged and the
/// batches that succeeded still count, and only a set where every batch failed is an error. That
/// matters because these are the caller's *own* locks — releasing four hundred of five hundred is
/// strictly better than releasing none.
async fn unlock_batches(
    remote: &Arc<Connection>,
    repository_id: crate::lore::RepositoryId,
    resources: &[FencedLockResource],
    released: &mut Vec<LockResource>,
) -> Result<(), ReleaseError> {
    let batch_iterator = resources.chunks(LOCK_BATCH_SIZE);
    let num_batches = batch_iterator.len();

    let mut batches: JoinSet<Result<Vec<LockResource>, ReleaseError>> = JoinSet::new();
    for batch_resources in batch_iterator {
        let batch_resources = batch_resources.to_vec();
        let remote = remote.clone();
        lore_spawn!(batches, async move {
            let response = remote
                .lock(repository_id)
                .await
                .forward_with::<ReleaseError, _>(|| {
                    format!("Failed to connect to remote {}", remote.remote_url())
                })?
                .unlock(&batch_resources)
                .await
                .forward::<ReleaseError>("Failed to release the lock")?;

            Ok(response)
        });
    }

    let mut batches_results = Vec::with_capacity(num_batches);
    let mut task_error: Result<(), ReleaseError> = Ok(());
    while let Some(task_result) = batches.join_next().await {
        if let Ok(result) = task_result {
            batches_results.push(result);
        } else {
            task_error = Err(ReleaseError::internal("Failed executing batch task"));
        }
    }
    task_error?;

    // Appended as the results are read, so the caller keeps what a partly successful set released
    // even when a later set fails. Those rows are gone on the server, and their tokens have to be
    // cleared whatever else went wrong.
    let mut num_batch_success = 0;
    let mut num_batch_failed = 0;
    let mut first_failure: Option<ReleaseError> = None;
    for batch_result in batches_results {
        match batch_result {
            Ok(mut results) => {
                released.append(&mut results);
                num_batch_success += 1;
            }
            Err(error) => {
                num_batch_failed += 1;
                first_failure = first_failure.or(Some(error));
            }
        }
    }

    if num_batch_failed > 0 {
        lore_error!("Failed to lock-release {num_batch_failed} batch(es) out of {num_batches}");
    }

    if num_batch_success == 0 {
        return Err(
            first_failure.unwrap_or_else(|| ReleaseError::internal("Failed to release the lock"))
        );
    }

    Ok(())
}

/// Escalate a refused release to the administrative takeover (CR-030, WP-120).
///
/// Reached only when `Unlock` refused a set this client holds no token for, which on a fenced cell
/// means the row's token was never issued (a cutover conversion) or has been lost. `ForceUnlock`
/// is the only verb that can clear such a row, it requires no token, and it names the owner it
/// believes it is taking the lock from so a raced takeover is refused rather than silently
/// releasing someone else's lock.
///
/// Two conditions decline the escalation and re-raise the original refusal instead, because in
/// both the escalation would be a guess:
///
/// * **no owner is known.** Only the `--force`-with-no-paths shape rebuilds its set from a
///   `Query`, which is where an owner comes from. A release naming explicit paths has none, and
///   the server's own refusal already names the remedy in that case.
/// * **the escalation itself fails.** A caller with no administrative permission, or a cell with
///   no fenced routing, gets the `Unlock` refusal back — on a fenced cell that message is the
///   actionable one, and on an unfenced cell `ForceUnlock`'s own refusal would be a red herring.
async fn force_release(
    remote: &Arc<Connection>,
    repository_id: crate::lore::RepositoryId,
    resources: &[FencedLockResource],
    owners: &HashMap<lock::LockResource, String>,
    unlock_error: ReleaseError,
    released: &mut Vec<LockResource>,
) -> Result<(), ReleaseError> {
    // Grouped by owner because one `ForceUnlock` names exactly one. A rebuilt set spans several
    // when `--owner` was not given and the branch holds other people's locks.
    let mut by_owner: HashMap<&str, Vec<LockResource>> = HashMap::new();
    for resource in resources {
        let Some(owner) = owners.get(&resource.resource) else {
            return Err(unlock_error);
        };
        by_owner
            .entry(owner.as_str())
            .or_default()
            .push(resource.resource.clone());
    }

    lore_debug!(
        "Escalating {} tokenless release(s) to an administrative force-release",
        resources.len()
    );

    // Each batch appends into the caller's accumulator as it lands, so a takeover that clears
    // three hundred rows and then fails on the fourth batch still tells the caller which three
    // hundred are gone. Collecting locally and returning them only on success would drop that, and
    // their tokens would stay in the store naming rows nobody holds any more.
    for (owner, owned) in by_owner {
        for batch in owned.chunks(LOCK_BATCH_SIZE) {
            let connection = match remote.lock(repository_id).await {
                Ok(connection) => connection,
                Err(_) => return Err(unlock_error),
            };
            match connection.force_unlock(batch, owner).await {
                Ok(mut resources) => released.append(&mut resources),
                Err(_) => return Err(unlock_error),
            }
        }
    }

    Ok(())
}

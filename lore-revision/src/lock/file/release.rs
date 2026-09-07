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
use lore_transport::outcome::GrpcRpc;
use serde::Deserialize;
use serde::Serialize;
use tokio::task::JoinSet;

use crate::attempt_store::held_tokens;
use crate::auth;
use crate::branch;
use crate::dispatch::under_own_attempt;
use crate::errors::*;
use crate::event;
use crate::event::EventError;
use crate::filter::FilterMode;
use crate::interface::LoreArray;
use crate::interface::LoreError;
use crate::interface::LoreString;
use crate::lock;
use crate::lock::util::BatchSetError;
use crate::lock::util::BatchSetLabels;
use crate::lock::util::LOCK_BATCH_SIZE;
use crate::lock::util::SetFailure;
use crate::lock::util::assemble_resource_for_path;
use crate::lock::util::classify_batch_set;
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
    attempts: Option<&Arc<dyn AttemptStore>>,
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
        && let Err(failure) =
            unlock_batches(&remote, repository.id, &held, &mut unlocks, attempts).await
    {
        first_failure = Some(failure.error);
    }

    if !unheld.is_empty()
        // `Unlock` first, escalate second, and in that order deliberately. An unfenced cell
        // releases these on the first call, so its behaviour is unchanged; a fenced cell refuses
        // them before it mutates anything, which makes the retry safe. Escalating first would
        // instead break every unfenced cell, because `ForceUnlock` does not exist there.
        && let Err(failure) =
            unlock_batches(&remote, repository.id, &unheld, &mut unlocks, attempts).await
    {
        // The escalation is a second irreversible mutation, so it may only follow an answer that
        // decisively says the first one did not happen. A lost answer says the opposite of that:
        // the `Unlock` may already have released the row, and a `ForceUnlock` on top of it is a
        // takeover performed on a maybe — against whoever holds the row by then, which after a
        // successful-but-unheard release can be somebody else entirely. A non-decisive set is
        // handed back as it is, so its attempt record stays unresolved for the reconciliation it
        // was written for and the caller learns the outcome is unknown rather than refused.
        let error = if failure.decisive {
            force_release(
                &remote,
                repository.id,
                &unheld,
                &queried_owners,
                failure.error,
                &mut unlocks,
                attempts,
            )
            .await
            .err()
        } else {
            Some(failure.error)
        };
        first_failure = first_failure.or(error);
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
    let accounting = ownership
        .clear_ownership_batch(&cleared)
        .await
        .forward::<ReleaseError>("Failed to clear the released lock ownership");

    // The release failure outranks the accounting one, and the order used to be the other way
    // round because this was a `?` on the line above. It is not a preference between two equal
    // reports. The release error is what happened to the caller's locks, and on a lost answer it
    // is the code a reconciler keys off; an accounting failure means a token row is now stale,
    // which is a real problem and a different one. Raising the accounting failure first replaced
    // an `OutcomeUnknown` with an `Internal`, which tells the caller the release decisively did
    // not happen. Logged rather than discarded, so neither failure is lost.
    if let Some(failure) = first_failure {
        if let Err(accounting_error) = accounting {
            lore_error!("Failed to clear the released lock ownership: {accounting_error}");
        }
        return Err(failure);
    }
    accounting?;

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

/// Whether an `Unlock` failure settles what happened to the request.
///
/// See [`BatchSetError`] for the rule and why it is one `matches!` per verb.
impl BatchSetError for ReleaseError {
    fn is_decisive(&self) -> bool {
        !matches!(self, ReleaseError::OutcomeUnknown(_))
    }

    fn set_failed(message: &'static str) -> Self {
        ReleaseError::internal(message)
    }
}

/// What this verb calls its batched dispatch, in the shared verdict's log line and fallback.
const UNLOCK_SET_LABELS: BatchSetLabels = BatchSetLabels {
    verb: "lock-release",
    fallback: "Failed to release the lock",
};

/// Why one set of `Unlock` batches did not complete, and whether the answer settles anything.
type UnlockSetFailure = SetFailure<ReleaseError>;

/// Turn one `Unlock` set's per-batch outcomes into the set's verdict.
///
/// The rules live in [`classify_batch_set`], which `acquire` uses too — the two verbs decide
/// decisiveness identically, and the second copy of that decision is how `acquire` came to discard
/// the classified errors this one acts on. This wrapper is this verb's labels and nothing else.
///
/// The [`crate::lock::util::SetSuccess`] the shared helper returns is discarded here: `release`
/// tolerates a partly successful set and reports it as a success, and only `acquire` acts on the
/// difference.
fn classify_set(
    outcomes: Vec<Result<Vec<LockResource>, ReleaseError>>,
    task_failure: Option<ReleaseError>,
    num_batches: usize,
    released: &mut Vec<LockResource>,
) -> Result<(), UnlockSetFailure> {
    classify_batch_set(
        outcomes,
        task_failure,
        num_batches,
        &UNLOCK_SET_LABELS,
        released,
    )
    .map(|_| ())
}

/// Release one set of resources through `Unlock`, in batches, concurrently.
///
/// Keeps the batch tolerance the single-set version had for *decisive* failures: a partial failure
/// is logged and the batches that succeeded still count, and only a set where every batch failed
/// is an error. That matters because these are the caller's *own* locks — releasing four hundred
/// of five hundred is strictly better than releasing none, and the hundred that failed are known
/// not to have been released.
///
/// An unknown outcome is the exception, and it ends the set whatever else succeeded. It is not a
/// failure to release: it is an attempt still outstanding, whose record the caller has to
/// reconcile against the server. Reporting the set as a success because the other batches landed
/// would throw that away silently, and would leave the escalation free to run on it.
async fn unlock_batches(
    remote: &Arc<Connection>,
    repository_id: crate::lore::RepositoryId,
    resources: &[FencedLockResource],
    released: &mut Vec<LockResource>,
    attempts: Option<&Arc<dyn AttemptStore>>,
) -> Result<(), UnlockSetFailure> {
    let batch_iterator = resources.chunks(LOCK_BATCH_SIZE);
    let num_batches = batch_iterator.len();

    let mut batches: JoinSet<Result<Vec<LockResource>, ReleaseError>> = JoinSet::new();
    for batch_resources in batch_iterator {
        let batch_resources = batch_resources.to_vec();
        let remote = remote.clone();
        let attempts = attempts.cloned();
        lore_spawn!(batches, async move {
            let connection = remote
                .lock(repository_id)
                .await
                .forward_with::<ReleaseError, _>(|| {
                    format!("Failed to connect to remote {}", remote.remote_url())
                })?;

            // Entered inside the spawned task, and that placement is load-bearing. `lore_spawn!`
            // re-scopes `LORE_CONTEXT` and nothing else, so the attempt task-local does not cross
            // the spawn: a scope opened around this loop would be invisible in here, every batch
            // would mint its own id anyway, and the caller's store would record none of them.
            // Each batch is a separate irreversible dispatch and takes a separate id, for the
            // same reason a push's several dispatches do.
            let response = under_own_attempt(
                attempts.as_ref(),
                repository_id,
                GrpcRpc::LockUnlock,
                connection.unlock(&batch_resources),
            )
            .await
            .forward::<ReleaseError>("Failed to release the lock")?;

            Ok(response)
        });
    }

    let mut outcomes = Vec::with_capacity(num_batches);
    // A task that did not run to completion is not an answer. It panicked or was cancelled, and
    // neither says whether its request reached the server. Collected rather than raised on the
    // spot: the batches that *did* answer still have confirmed releases the caller has to account
    // for, and an early return here discarded them along with the tokens they would have cleared.
    let mut task_failure: Option<ReleaseError> = None;
    while let Some(task_result) = batches.join_next().await {
        match task_result {
            Ok(result) => outcomes.push(result),
            Err(_) => {
                task_failure = task_failure
                    .or_else(|| Some(ReleaseError::internal("Failed executing batch task")));
            }
        }
    }

    classify_set(outcomes, task_failure, num_batches, released)
}

/// Escalate a refused release to the administrative takeover (CR-030, WP-120).
///
/// Reached only when `Unlock` refused a set this client holds no token for, which on a fenced cell
/// means the row's token was never issued (a cutover conversion) or has been lost. `ForceUnlock`
/// is the only verb that can clear such a row, it requires no token, and it names the owner it
/// believes it is taking the lock from so a raced takeover is refused rather than silently
/// releasing someone else's lock.
///
/// A third condition declines the escalation before this function is entered at all, and it is
/// the caller's because only the caller can see it: a set whose `Unlock` outcome is not decisive
/// is never escalated. See [`UnlockSetFailure`] and [`BatchSetError::is_decisive`].
///
/// Two further conditions decline it from in here and re-raise the original refusal instead,
/// because in both the escalation would be a guess:
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
    attempts: Option<&Arc<dyn AttemptStore>>,
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
            // Journalled like any other irreversible dispatch. A takeover is the most consequential
            // call in this file — it removes a row from whoever holds it — so a caller that
            // reconciles a lost response needs this one recorded most of all.
            match under_own_attempt(
                attempts,
                repository_id,
                GrpcRpc::LockForceUnlock,
                connection.force_unlock(batch, owner),
            )
            .await
            {
                Ok(mut resources) => released.append(&mut resources),
                Err(_) => return Err(unlock_error),
            }
        }
    }

    Ok(())
}

/// The release's two error paths and which one the caller is told about (WP-120).
///
/// These live here rather than in `lore/tests/live_lock_journal.rs` with the rest of the live lock
/// proofs for one reason: the ownership store is a *parameter* of [`release`] and is not a
/// parameter of anything above it. `lore::lock::file_release_with_attempt_store` derives it from
/// the repository it just opened, so a test at that layer has no way to make the accounting fail
/// on demand. This is the lowest layer where it can be injected, so it is where the claim can be
/// proven. The escalation half of the same fix is proven from `lore`'s tier, where the server's
/// own request log is the evidence.
#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use async_trait::async_trait;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_transport::ProtocolError;
    use lore_transport::attempt_store::AttemptRecord;
    use lore_transport::attempt_store::AttemptResolution;
    use lore_transport::attempt_store::LockOwnership;
    use lore_transport::attempt_store::VolatileAttemptStore;
    use lore_transport::outcome::AttemptId;
    use parking_lot::Mutex;

    use super::*;
    use crate::live_fixture::LiveRepository;
    use crate::live_fixture::LockPolicy;
    use crate::live_fixture::LockServer;
    use crate::live_fixture::RpcOutcome;
    use crate::live_fixture::UnlockEcho;
    use crate::live_fixture::fixture_execution_context;
    use crate::lock::file::acquire::AcquireOptions;
    use crate::repository::RepositoryAccess;

    /// An ownership store that works, except that clearing a released lock always fails.
    ///
    /// Everything delegates to a real [`VolatileAttemptStore`], so an acquire mints and stores its
    /// tokens normally and the release reads them back and takes the held path. Only
    /// `clear_ownership_batch` is replaced, and it fails unconditionally — including for an empty
    /// batch, which a real store answers `Ok` to without touching anything.
    ///
    /// That unconditional failure is deliberate, and it is the only way to reach the composition
    /// under test with this fixture. In production both failures coincide readily: one set's
    /// releases are confirmed and cleared while another set's answer is lost, and the store's write
    /// then fails on its own (a full disk, a revoked handle). The stub server's policy is per-RPC,
    /// so it cannot answer the two `Unlock` calls of one release differently, and the composition
    /// cannot be built out of its answers. What is under test is the precedence between two error
    /// paths inside [`release`], and a store that refuses the write is a faithful stand-in for the
    /// one that fails it.
    struct FailingOwnership {
        inner: VolatileAttemptStore,
        /// How many times the accounting was attempted, and with how many resources each time.
        cleared_batches: Mutex<Vec<usize>>,
        clear_calls: AtomicUsize,
    }

    impl FailingOwnership {
        fn new() -> Self {
            Self {
                inner: VolatileAttemptStore::new(),
                cleared_batches: Mutex::new(Vec::new()),
                clear_calls: AtomicUsize::new(0),
            }
        }

        fn clear_calls(&self) -> usize {
            self.clear_calls.load(Ordering::SeqCst)
        }

        fn cleared_batches(&self) -> Vec<usize> {
            self.cleared_batches.lock().clone()
        }
    }

    #[async_trait]
    impl AttemptStore for FailingOwnership {
        async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
            self.inner.record(record).await
        }

        async fn lookup(
            &self,
            attempt: &AttemptId,
        ) -> Result<Option<AttemptRecord>, ProtocolError> {
            self.inner.lookup(attempt).await
        }

        async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
            self.inner.unresolved().await
        }

        async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
            self.inner.record_ownership(ownership).await
        }

        async fn ownership_for(
            &self,
            branch: &Context,
            resource_hash: &Hash,
        ) -> Result<Option<LockOwnership>, ProtocolError> {
            self.inner.ownership_for(branch, resource_hash).await
        }

        async fn clear_ownership(
            &self,
            branch: &Context,
            resource_hash: &Hash,
        ) -> Result<(), ProtocolError> {
            self.inner.clear_ownership(branch, resource_hash).await
        }

        async fn clear_ownership_batch(
            &self,
            resources: &[(Context, Hash)],
        ) -> Result<(), ProtocolError> {
            self.clear_calls.fetch_add(1, Ordering::SeqCst);
            self.cleared_batches.lock().push(resources.len());
            Err(ProtocolError::internal(
                "fixture: the ownership store refuses the write",
            ))
        }

        async fn resolve(
            &self,
            attempt: &AttemptId,
            resolution: AttemptResolution,
        ) -> Result<(), ProtocolError> {
            self.inner.resolve(attempt, resolution).await
        }
    }

    /// Every absolute committed path, in the shape both lock verbs take.
    fn all_paths(fixture: &LiveRepository) -> LoreArray<LoreString> {
        LoreArray::from_vec(
            fixture
                .committed_files_absolute
                .iter()
                .map(LoreString::from)
                .collect(),
        )
    }

    fn release_options(fixture: &LiveRepository) -> ReleaseOptions {
        ReleaseOptions {
            paths: all_paths(fixture),
            branch: String::new(),
            owner: String::new(),
            owner_id: String::new(),
        }
    }

    /// The set verdict, decided from hand-built per-batch outcomes.
    ///
    /// None of these are reachable through the live fixture, and that is why they are here rather
    /// than beside the live proofs. The stub server answers one policy per RPC, so every batch of
    /// one `Unlock` set gets the same answer from it, and a set whose batches *differ* is exactly
    /// what the two rules below are about.
    mod set_verdict {
        use super::*;

        /// A lost answer, shaped as the transport produces one.
        fn unknown() -> ReleaseError {
            ReleaseError::from(OutcomeUnknown {
                operation: "LockService.Unlock".to_owned(),
                attempt_id: "018f5f4c-0000-7000-8000-00000000abcd".to_owned(),
            })
        }

        /// A refusal the server answered with: decisive, and the shape that may escalate.
        fn refusal() -> ReleaseError {
            ReleaseError::internal("the server refused")
        }

        fn resource(description: &str) -> LockResource {
            LockResource {
                branch: Context::from([0x02u8; 16]),
                hash: Hash::from([0x55u8; 32]),
                description: description.to_owned(),
            }
        }

        fn descriptions(released: &[LockResource]) -> Vec<String> {
            released
                .iter()
                .map(|resource| resource.description.clone())
                .collect()
        }

        /// A set every batch of which was refused is decisive, and stays escalatable.
        ///
        /// The negative control for everything below. If this returned a non-decisive verdict the
        /// cutover path would silently stop working: a fenced cell's refusal of a tokenless
        /// `Unlock` is precisely the case `force_release` exists for.
        #[test]
        fn a_set_of_refusals_is_decisive() {
            let mut released = Vec::new();
            let failure =
                classify_set(vec![Err(refusal()), Err(refusal())], None, 2, &mut released)
                    .expect_err("a set where every batch was refused fails");

            assert!(failure.decisive, "a refusal settles what happened");
            assert!(released.is_empty());
        }

        /// One unknown batch outranks a refusal in the same set.
        ///
        /// The escalation re-sends every resource in the set, not only the ones a batch failed on,
        /// so acting on the refusal would force-release resources whose own release may already
        /// have happened. Reporting the refusal and calling the set decisive is what a
        /// first-error-wins accumulator does, and it looks entirely reasonable until you notice
        /// the second batch.
        #[test]
        fn an_unknown_batch_outranks_a_refusal_in_the_same_set() {
            let mut released = Vec::new();
            let failure =
                classify_set(vec![Err(refusal()), Err(unknown())], None, 2, &mut released)
                    .expect_err("a set where every batch failed fails");

            assert!(
                !failure.decisive,
                "one unknown batch makes the whole set unsafe to escalate"
            );
            assert!(
                matches!(failure.error, ReleaseError::OutcomeUnknown(_)),
                "the caller must be told the outcome is unknown, not that it was refused: {:?}",
                failure.error
            );
        }

        /// An unknown batch fails a set that also succeeded, and the successes are still accounted.
        ///
        /// Two claims at once. The batch tolerance elsewhere in this file reports a partly
        /// successful set as `Ok`, which for an unknown outcome would hide an attempt the caller
        /// still has to reconcile. And the confirmed release must survive that failure, because its
        /// row is gone on the server and its token has to be cleared regardless.
        #[test]
        fn an_unknown_batch_fails_a_set_that_also_succeeded_without_losing_the_success() {
            let mut released = Vec::new();
            let failure = classify_set(
                vec![Ok(vec![resource("a.file")]), Err(unknown())],
                None,
                2,
                &mut released,
            )
            .expect_err("an unknown outcome fails the set whatever else succeeded");

            assert!(!failure.decisive);
            assert!(matches!(failure.error, ReleaseError::OutcomeUnknown(_)));
            assert_eq!(
                descriptions(&released),
                vec!["a.file".to_owned()],
                "the batch the server confirmed must still be accounted for"
            );
        }

        /// A lost batch task must not shadow a real lost answer.
        ///
        /// Found in review. Seeding the unknown slot with the join failure and then folding the
        /// batch errors into it with `or` looks equivalent and is not: the join failure arrives
        /// first, so the real `OutcomeUnknown` is discarded and the caller is handed an `Internal`
        /// for an attempt that is sitting unresolved in its own store. That is the exact
        /// contradiction `is_decisive` exists to prevent, reintroduced one layer up.
        #[test]
        fn a_lost_batch_task_does_not_shadow_a_lost_answer() {
            let mut released = Vec::new();
            let failure = classify_set(
                vec![Err(unknown())],
                Some(ReleaseError::internal("Failed executing batch task")),
                2,
                &mut released,
            )
            .expect_err("a set with a lost answer fails");

            assert!(!failure.decisive);
            assert!(
                matches!(failure.error, ReleaseError::OutcomeUnknown(_)),
                "the lost answer names an attempt to reconcile; the lost task names nothing: {:?}",
                failure.error
            );
        }

        /// A lost batch task alone is non-decisive, even beside a batch that succeeded.
        ///
        /// Nothing here knows whether the lost task's request reached the server, so the set may
        /// not be escalated. It is reported as an internal failure rather than as an unknown
        /// outcome on purpose: an `OutcomeUnknown` names an attempt id, and the id that task minted
        /// died with it.
        #[test]
        fn a_lost_batch_task_alone_is_non_decisive() {
            let mut released = Vec::new();
            let failure = classify_set(
                vec![Ok(vec![resource("a.file")])],
                Some(ReleaseError::internal("Failed executing batch task")),
                2,
                &mut released,
            )
            .expect_err("a set with a lost task fails even though a batch succeeded");

            assert!(!failure.decisive);
            assert!(
                !matches!(failure.error, ReleaseError::OutcomeUnknown(_)),
                "no attempt id survived the lost task, so none may be named: {:?}",
                failure.error
            );
            assert_eq!(descriptions(&released), vec!["a.file".to_owned()]);
        }

        /// A set every batch of which succeeded is a success, and every release is accounted.
        #[test]
        fn a_fully_answered_set_succeeds() {
            let mut released = Vec::new();
            classify_set(
                vec![Ok(vec![resource("a.file")]), Ok(vec![resource("b.file")])],
                None,
                2,
                &mut released,
            )
            .expect("a set every batch of which succeeded is a success");

            assert_eq!(
                descriptions(&released),
                vec!["a.file".to_owned(), "b.file".to_owned()]
            );
        }
    }

    /// A lost answer outranks a failing ownership write, and the caller is told the outcome is
    /// unknown rather than that something went wrong internally.
    ///
    /// The accounting used to be a `?` on the line before the release failure was raised, so
    /// whichever error the store produced won. The difference is not cosmetic. `OutcomeUnknown`
    /// tells a caller the release may have happened and names an attempt to reconcile; an
    /// `Internal` in its place says the operation failed, which is the one reading a caller must
    /// never be given for an attempt that is still outstanding.
    ///
    /// The clear-call assertion is what stops this test passing for the wrong reason. Without it
    /// the test would also be green if the accounting had simply never run — which is another way
    /// to return `OutcomeUnknown` here, and not the behaviour being pinned.
    #[test]
    fn a_release_failure_outranks_a_failing_ownership_accounting() {
        let runtime = lore_base::runtime::runtime();
        runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let server = LockServer::start().await;
            let fixture = LiveRepository::create(&server.remote_url()).await;
            let repository = fixture.connect(RepositoryAccess::ReadOnly).await;

            let ownership = Arc::new(FailingOwnership::new());
            let store: Arc<dyn AttemptStore> = ownership.clone();

            crate::lock::file::acquire::acquire(
                repository.clone(),
                AcquireOptions {
                    paths: all_paths(&fixture),
                    branch: String::new(),
                    owner: String::new(),
                },
                store.clone(),
                None,
            )
            .await
            .expect("the acquire must succeed and mint an ownership token");

            server.set_policy(LockPolicy {
                unlock: RpcOutcome::LoseTheAnswer,
                ..LockPolicy::default()
            });

            let error = release(repository, release_options(&fixture), store, None)
                .await
                .expect_err("a lost answer must fail the release");

            assert!(
                matches!(error, ReleaseError::OutcomeUnknown(_)),
                "the release must surface the lost answer, not the accounting failure that \
                 followed it: {error}"
            );
            assert!(
                !error.is_decisive(),
                "the error the caller receives must be the non-decisive one"
            );
            assert_eq!(
                ownership.clear_calls(),
                1,
                "the accounting must actually have run and failed -- an accounting that never ran \
                 would return the same error for a different reason"
            );
        }));
    }

    /// With no release failure to outrank it, the accounting failure is the answer.
    ///
    /// The other half of the same change: the release error was given precedence, not the
    /// accounting error suppressed. A version that simply dropped the accounting result would pass
    /// the test above and fail this one, reporting a clean release while the token for a lock the
    /// server has already released stays in the store — a token that will one day be presented
    /// against a row somebody else holds.
    ///
    /// `UnlockEcho::FirstOnly` also puts a real batch through the accounting: two locks are
    /// released, the server confirms one, and the single entry the store is asked to clear is the
    /// live-fixture proof that this layer clears what the server named rather than the whole
    /// request.
    #[test]
    fn an_accounting_failure_is_raised_when_the_release_itself_succeeded() {
        let runtime = lore_base::runtime::runtime();
        runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let server = LockServer::start().await;
            let fixture =
                LiveRepository::create_with_files(&server.remote_url(), &["a.file", "b.file"])
                    .await;
            let repository = fixture.connect(RepositoryAccess::ReadOnly).await;

            let ownership = Arc::new(FailingOwnership::new());
            let store: Arc<dyn AttemptStore> = ownership.clone();

            crate::lock::file::acquire::acquire(
                repository.clone(),
                AcquireOptions {
                    paths: all_paths(&fixture),
                    branch: String::new(),
                    owner: String::new(),
                },
                store.clone(),
                None,
            )
            .await
            .expect("the acquire must succeed and mint an ownership token per file");

            server.set_policy(LockPolicy {
                unlock_echo: UnlockEcho::FirstOnly,
                ..LockPolicy::default()
            });

            let error = release(repository, release_options(&fixture), store, None)
                .await
                .expect_err("a failing ownership write must fail the release");

            assert!(
                !matches!(error, ReleaseError::OutcomeUnknown(_)),
                "nothing here lost an answer, so the caller must not be told an outcome is \
                 unknown: {error}"
            );
            assert_eq!(
                ownership.cleared_batches(),
                vec![1],
                "the accounting must have been asked to clear exactly the one resource the server \
                 confirmed"
            );
        }));
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use lore_base::error::OutcomeUnknown;
use lore_base::lore_spawn;
use lore_error_set::prelude::*;
use lore_transport::attempt_store::AcquiredLock;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::FencedLockResource;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;
use serde::Deserialize;
use serde::Serialize;
use tokio::task::JoinSet;

use crate::attempt_store::held_tokens;
use crate::branch;
use crate::dispatch::under_named_attempt;
use crate::errors::*;
use crate::event;
use crate::event::EventError;
use crate::filter::FilterMode;
use crate::interface::LoreArray;
use crate::interface::LoreError;
use crate::interface::LoreString;
use crate::lock;
use crate::lock::file::release::ReleaseOptions;
use crate::lock::file::release::release;
use crate::lock::util::BatchSetError;
use crate::lock::util::BatchSetLabels;
use crate::lock::util::LOCK_BATCH_SIZE;
use crate::lock::util::SetSuccess;
use crate::lock::util::assemble_resource_for_path;
use crate::lock::util::classify_batch_set;
use crate::lore::BranchId;
use crate::lore::Hash;
use crate::lore::execution_context;
use crate::lore_debug;
use crate::lore_error;
use crate::lore_trace;
use crate::repository::RepositoryContext;
use crate::state;
use crate::util::path::RelativePath;

#[derive(Clone, Debug)]
pub struct AcquireOptions {
    pub paths: LoreArray<LoreString>,
    pub branch: String,
    pub owner: String,
}

#[error_set]
pub enum AcquireError {
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
    /// The server granted a resource this call never requested, so the rollback
    /// cannot name a path to release it with.
    ///
    /// Its own variant rather than a reused failure, because the state it
    /// describes is neither: a lock is held, the acquire did not succeed, and
    /// nothing local can undo it. It carries no attempt identity on purpose —
    /// see the type's own doc for why a receipt lookup would settle nothing.
    UnnameableResource,
}

impl EventError for AcquireError {
    fn translated(&self) -> LoreError {
        match self {
            // An unresolved attempt keeps its own code all the way to the FFI
            // boundary (WP-120). Reported as `Internal` it is indistinguishable
            // from an operation that provably did not happen, which is the one
            // reading a caller must never be given.
            //
            // A resource this call cannot name shares that coarse translation
            // while keeping its own discrete `ffi_code`, which is what the
            // terminal status carries. `LoreError` is a curated subset, and at
            // its granularity the two say the same actionable thing: the
            // outcome is unresolved, do not retry, read authoritative state.
            AcquireError::OutcomeUnknown(_) | AcquireError::UnnameableResource(_) => {
                LoreError::OutcomeUnknown
            }
            _ => LoreError::Internal,
        }
    }

    fn inner(&self) -> String {
        self.to_string()
    }
}

/// Whether a `Lock` failure settles what happened to the request.
///
/// See [`BatchSetError`] for the rule and why it is one `matches!` per verb.
impl BatchSetError for AcquireError {
    fn is_decisive(&self) -> bool {
        !matches!(
            self,
            AcquireError::OutcomeUnknown(_) | AcquireError::UnnameableResource(_)
        )
    }

    fn set_failed(message: &'static str) -> Self {
        AcquireError::internal(message)
    }
}

/// What this verb calls its batched dispatch, in the shared verdict's log line and fallback.
#[lore_macro::test_pub]
const ACQUIRE_SET_LABELS: BatchSetLabels = BatchSetLabels {
    verb: "lock-acquire",
    fallback: "Failed to acquire the lock",
};

/// Data for an event that marks the start of a lock acquire report.
#[repr(C)]
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreLockFileAcquireBeginEventData {
    /// Number of acquire entries that follow.
    pub count: u64,
    /// Whether the entries that follow were already owned.
    pub ignored: u8,
}

/// Data for an event reporting a path whose lock is being acquired.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreLockFileAcquireEventData {
    /// The path whose lock is being acquired.
    pub path: LoreString,
}

/// Acquire file locks, keeping whatever ownership the server issues for them.
///
/// `ownership` is the client's durable record of what it holds (CR-030, WP-120). It is a
/// parameter rather than something derived from `repository` because two callers need two
/// different stores: the CLI and the embedding library use the repository's own `.lore/` file
/// (see [`crate::attempt_store::repository_attempt_store`]), and the desktop injects its own
/// implementation over the operation journal it already keeps.
///
/// Two things it is used for here, and the second is the one that is easy to miss:
///
/// * every token the server returns is recorded **before** this reports success, because an
///   acquire that returns a token the client then loses has produced a lock only an
///   administrator can release; and
/// * a re-lock of a row this client already holds presents the stored token, because a fenced
///   cell refuses a tokenless acquire over a current row even to that row's own owner.
pub async fn acquire(
    repository: Arc<RepositoryContext>,
    options: AcquireOptions,
    ownership: Arc<dyn AttemptStore>,
    attempts: Option<&Arc<dyn AttemptStore>>,
) -> Result<(), AcquireError> {
    let (current_revision, current_branch) = crate::instance::load_current_anchor(&repository)
        .await
        .forward::<AcquireError>("Failed to deserialize current revision anchor")?;
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
            .forward::<AcquireError>("Invalid branch")?;
        resolved.id
    };

    let owner = if options.owner.is_empty() {
        None
    } else {
        Some(options.owner)
    };

    let mut resources = HashMap::<String, lock::LockResource>::with_capacity(options.paths.len());
    // The path the USER named, per resource, keyed by the resource IDENTITY rather than by its
    // description. Kept so a rollback hands `release` the same strings this acquire was given
    // instead of re-deriving them from what the server echoed back.
    //
    // `(branch, hash)` and not the description, because the description is free text the server
    // chose. Keying on it made every spelling difference — case, separators, a server that
    // normalises — look like a lock this call could not name, which is a state the rollback treats
    // as unresolved. The hash is what `assemble_resource_for_path` derives from the path and what
    // the lock is actually keyed by, so a lookup on it misses only for a resource that was never
    // requested at all.
    let mut requested_paths =
        HashMap::<(BranchId, Hash), String>::with_capacity(options.paths.len());
    let state = state::State::deserialize(repository.clone(), staged_revision)
        .await
        .forward::<AcquireError>("Failed to deserialize state")?;

    lore_debug!("Inspecting {} path(s)", options.paths.len());
    let force = execution_context().globals().force();
    for path in options.paths.as_slice().iter() {
        let relative_path =
            RelativePath::new_from_user_path(repository.require_path()?, path.as_str())
                .forward_with::<AcquireError, _>(|| format!("Invalid path: {}", path.as_str()))?;

        if !force
            && repository
                .filter
                .emit_excludes(&relative_path, true, FilterMode::Full)
        {
            lore_trace!("Path excluded by filter: {}", relative_path.as_str());
            continue;
        }

        let node_link = state
            .find_node_link(repository.clone(), relative_path.as_str())
            .await
            .forward_with::<AcquireError, _>(|| format!("Invalid path: {}", path.as_str()))?;
        if !node_link.is_valid() {
            return Err(AcquireError::internal(format!(
                "Invalid path: {}",
                path.as_str()
            )));
        }

        let resource = assemble_resource_for_path(relative_path.as_str(), branch);
        requested_paths.insert((resource.branch, resource.hash), path.to_string());
        resources.insert(relative_path.to_string(), resource);
    }

    if resources.is_empty() {
        lore_debug!("No paths to acquire lock on");
        return Ok(());
    }

    // We cannot know which locks are going to be acquired or which ones are owned without contacting the server, so every path is reported as a would-be acquisition.
    if execution_context().globals().dry_run() {
        let mut paths = resources.keys().cloned().collect::<Vec<_>>();
        paths.sort();

        event::LoreEvent::LockFileAcquireBegin(LoreLockFileAcquireBeginEventData {
            count: paths.len() as u64,
            ignored: 0,
        })
        .send();

        for path in paths {
            event::LoreEvent::LockFileAcquire(LoreLockFileAcquireEventData { path: path.into() })
                .send();
        }

        return Ok(());
    }

    let remote = repository
        .remote()
        .await
        .forward::<AcquireError>("Unable to acquire lock while offline")?;

    let resources_count = resources.len();

    // Attach the ownership this client already holds. A first acquire carries none; a renewal of a
    // row this client holds carries the token it was issued, which a fenced cell requires even
    // from the row's own owner.
    let requested = resources.values().cloned().collect::<Vec<_>>();
    let keys = requested
        .iter()
        .map(|resource| (resource.branch, resource.hash))
        .collect::<Vec<_>>();
    let tokens = held_tokens(&ownership, &keys)
        .await
        .forward::<AcquireError>("Failed to read the held lock ownership")?;
    // The rows this client already held when the call started, which a rollback must leave alone:
    // releasing one would put the caller BELOW the state it was in before it asked, and clear a
    // token it needs. A granted lock is not proof this call took the row — the fenced coordinator
    // reports a renewal in the same `committed` set as a first acquire — so the request side is
    // the only place the difference is visible.
    //
    // On a cell that issues no tokens at all every entry here is `None`, so a renewal would be
    // indistinguishable from a first acquire and would land in the rollback. That residual is
    // unreachable on both legacy backends today, and for the same reason on each: neither returns
    // an already-owned row in the granted set at all. `lore-server`'s in-memory store `continue`s
    // past a row whose owner already matches (`lore-server/src/lock/store.rs:60`), and `lore-aws`
    // drops one from both the write set and the response (`lore-aws/src/store/lock_store.rs:450`).
    // So a tokenless cell never produces the granted renewal this exclusion would have to catch.
    let pre_held = keys
        .iter()
        .zip(tokens.iter())
        .filter_map(|(key, token)| token.as_ref().map(|_| *key))
        .collect::<HashSet<(BranchId, Hash)>>();
    let resources_values = requested
        .into_iter()
        .zip(tokens)
        .map(|(resource, token)| FencedLockResource::with_token(resource, token))
        .collect::<Vec<_>>();

    let batch_iterator = resources_values.chunks(LOCK_BATCH_SIZE);
    let num_batches = batch_iterator.len();

    let mut batches: JoinSet<Result<Vec<AcquiredLock>, AcquireError>> = JoinSet::new();
    let mut batches_results = Vec::with_capacity(num_batches);
    // Which attempt each batch task dispatches under, keyed by the task's own id.
    //
    // A batch that never runs to completion leaves a `JoinError` and nothing else. If the id were
    // minted inside the task — as `under_own_attempt` mints it, and as this loop used to — it
    // would die with the task, and the join loop below could only report that something went
    // wrong internally for a request that may already have taken the locks. That is the exact
    // reading the doc comment on `AcquireError::OutcomeUnknown` says a caller must never be given.
    let mut batch_attempts = HashMap::<tokio::task::Id, AttemptId>::with_capacity(num_batches);
    for batch_resources in batch_iterator {
        let batch_resources = batch_resources.to_vec();
        let owner = owner.clone();
        let remote = remote.clone();
        let repository_id = repository.id;
        let ownership = ownership.clone();
        let attempts = attempts.cloned();
        // One id per batch, because each batch is a separate irreversible dispatch — the same rule
        // that makes a push's several dispatches take several ids. Only the choice of the VALUE
        // moves out here; the scope it is entered in stays inside the task below.
        let batch_attempt = AttemptId::new();
        let caller_operation = lore_transport::current_caller_operation();
        let handle = lore_spawn!(
            batches,
            lore_transport::with_optional_caller_operation(caller_operation, async move {
                let connection = remote
                    .lock(repository_id)
                    .await
                    .forward_with::<AcquireError, _>(|| {
                        format!("Failed to connect to remote {}", remote.remote_url())
                    })?;

                // Entered inside the spawned task, and that placement is load-bearing. `lore_spawn!`
                // re-scopes `LORE_CONTEXT` and nothing else, so the attempt task-local does not cross
                // the spawn: a scope opened around this loop would be invisible in here, and the
                // caller's store would record none of the batches' attempts.
                let response = under_named_attempt(
                    attempts.as_ref(),
                    batch_attempt,
                    repository_id,
                    GrpcRpc::LockLock,
                    connection.lock(&batch_resources, owner.as_deref()),
                )
                .await
                .forward::<AcquireError>("Failed to acquire the lock")?;

                // Recorded inside the batch task, before this batch is reported as successful, and
                // deliberately not after the join. A partial acquire rolls back by *releasing* what
                // succeeded, and that release needs these tokens; a store written after the join
                // would be written after the rollback had already tried to run without them.
                record_batch_ownership(&ownership, &response).await?;

                Ok(response)
            })
        );
        batch_attempts.insert(handle.id(), batch_attempt);
    }

    // A task that did not run to completion is not an answer. It panicked or was cancelled, and
    // neither says whether its request reached the server. Collected rather than raised on the
    // spot: the batches that *did* answer still hold locks the caller has to be told about, and an
    // early return here discarded them along with the verdict they belong to.
    let mut task_failure: Option<AcquireError> = None;
    while let Some(task_result) = batches.join_next().await {
        match task_result {
            Ok(result) => batches_results.push(result),
            Err(join_error) => {
                // Logged rather than dropped. `JoinError`'s own message is the only thing that
                // separates a panic from a cancellation, and neither the set verdict nor the
                // caller's error can carry it.
                lore_error!("A lock-acquire batch task did not run to completion: {join_error}");
                let attempt = batch_attempts.get(&join_error.id()).copied();
                task_failure = task_failure.or_else(|| Some(lost_batch_task(attempt)));
            }
        }
    }

    let mut locks = Vec::with_capacity(resources_count);

    // The set verdict, decided by the same helper `release` uses. This loop used to count
    // successes and failures and throw each batch's own `Result` away, then report an all-failed
    // set as a flat internal error — so a batch whose ANSWER WAS LOST read to the caller as an
    // ordinary decisive refusal, and a client acting on that would retry a lock that may already
    // have been taken. That is the double mutation WP-120 exists to prevent, and it is the same
    // one `release`'s escalation had.
    //
    // The rollback below rides on the same verdict, for the same reason: it re-sends every
    // requested resource as a release, which is a second irreversible mutation, and performing one
    // over a maybe is exactly what a non-decisive set forbids.
    let SetSuccess {
        num_batch_success,
        first_decisive_failure,
    } = match classify_batch_set(
        batches_results,
        task_failure,
        num_batches,
        &ACQUIRE_SET_LABELS,
        &mut locks,
    ) {
        Ok(verdict) => verdict,
        // Handed back as it is, both when it is decisive (nothing was acquired, and the server's
        // own refusal is more useful than a message this file invented) and when it is not (the
        // caller is told `OutcomeUnknown`, naming the attempt whose journal record
        // `under_named_attempt` deliberately left unresolved for a later authoritative read).
        //
        // Whatever the successful batches did acquire stays acquired and stays recorded in
        // `ownership`: rolling it back would be the mutation-on-a-maybe this guards against, and
        // the caller reconciles from the attempt instead. Those locks are deliberately NOT
        // reported as acquire events — the operation failed, and the event stream is its report —
        // so the record of what this client now holds is the ownership store, which is where the
        // release path reads it from anyway.
        Err(failure) => return Err(failure.error),
    };

    if num_batch_success < num_batches {
        let rollback = rollback_set(&locks, &requested_paths, &pre_held);

        for description in &rollback.unnameable {
            lore_error!(
                "A granted lock names a path this acquire did not request, so it cannot be rolled \
                 back: {description}"
            );
        }

        if rollback.paths.is_empty() {
            lore_debug!("This call took no new lock, so there is nothing to roll back.");
        } else {
            lore_debug!(
                "Releasing the {} lock(s) this partial acquire took.",
                rollback.paths.len()
            );

            let options = ReleaseOptions {
                paths: LoreArray::from_vec(rollback.paths),
                branch: options.branch,
                owner: String::default(),
                owner_id: String::default(),
                all_owners: false,
            };

            // The same store the successful batches just wrote their tokens into, so the rollback
            // presents them. Without this the rollback would release tokenlessly, which a fenced
            // cell refuses — leaving exactly the half-acquired set this branch exists to undo.
            //
            // The rollback's own answer can be lost in turn, and `forward` carries that variant
            // across: the caller is then told `OutcomeUnknown` for the release rather than a
            // decisive failure for the acquire, which is the honest report — some of these locks
            // are held and nothing here knows which.
            release(repository.clone(), options, ownership.clone(), attempts)
                .await
                .forward::<AcquireError>("Failed to acquire the lock")?;
        }

        // A lock this call holds and cannot name is not a decisive failure, whatever the server
        // said about the batch that failed. Reporting the refusal here would tell the caller the
        // acquire is over and nothing is outstanding, while a row it cannot release stays taken —
        // the same wrong reading a lost batch task used to produce, arrived at from the other
        // side. Its own error rather than an `OutcomeUnknown`, because there is no attempt to
        // reconcile: the batch that granted this answered, and what is unresolved is the client's
        // ability to name the row. Every one is named in the message, so a human has the whole
        // set rather than the first of it.
        if !rollback.unnameable.is_empty() {
            return Err(AcquireError::from(UnnameableResource {
                resource: rollback.unnameable.join(", "),
            }));
        }

        // The refusal that failed the set, not a message invented here. A caller told `Internal`
        // for a batch the server turned down with a reason has to guess at the remedy the server
        // already named. `first_decisive_failure` is `Some` for every set that reaches this arm —
        // a set with no failure at all has `num_batch_success == num_batches` — so the fallback is
        // unreachable rather than a second-choice message.
        return Err(first_decisive_failure
            .unwrap_or_else(|| AcquireError::internal("Failed to acquire the lock")));
    }

    locks.sort_by(|lock_a, lock_b| {
        lock_a
            .lock
            .resource
            .description
            .cmp(&lock_b.lock.resource.description)
    });

    // Generate structured output for locks successfully acquired
    lore_debug!("Locked {} path(s)", locks.len());
    if !locks.is_empty() {
        event::LoreEvent::LockFileAcquireBegin(LoreLockFileAcquireBeginEventData {
            count: locks.len() as u64,
            ignored: 0,
        })
        .send();
    }
    for lock in locks {
        let path = lock.lock.resource.description;

        // From the requested paths, remove those successfully locked
        resources.remove(&path);

        event::LoreEvent::LockFileAcquire(LoreLockFileAcquireEventData { path: path.into() })
            .send();
    }

    // Generate structured output for locks already owned by the user.
    if !resources.is_empty() {
        event::LoreEvent::LockFileAcquireBegin(LoreLockFileAcquireBeginEventData {
            count: resources.len() as u64,
            ignored: 1,
        })
        .send();
    }
    for (key, _) in resources {
        event::LoreEvent::LockFileAcquire(LoreLockFileAcquireEventData { path: key.into() }).send();
    }

    Ok(())
}

/// What a partial acquire has to release to undo itself, and what it cannot.
///
/// Two fields rather than a path list, because the second one changes the error the caller is
/// given rather than only what is released.
#[lore_macro::test_pub]
struct RollbackSet {
    /// The user paths to release: the locks the server granted THIS call, minus the ones it
    /// already held.
    paths: Vec<LoreString>,
    /// Descriptions of granted locks no requested path accounts for. Non-empty means the rollback
    /// is incomplete whatever else it managed, so the acquire's own report may not be decisive.
    unnameable: Vec<String>,
}

/// Decide which of a partial acquire's granted locks must be released to undo it.
///
/// Extracted from `acquire` rather than left inline because it is the whole of a destructive
/// decision, and inline it was reachable only against a live server with more than
/// [`LOCK_BATCH_SIZE`] paths and a server that refuses exactly one batch.
///
/// Two exclusions, and both are the difference between undoing this call and damaging the caller:
///
/// * **a row this client already held** is skipped. A granted lock does not say whether the server
///   created the row or renewed it — the fenced coordinator reports both in one `committed` set —
///   so `pre_held`, built from the tokens the client presented on the way in, is the only evidence
///   of the pre-call state. Releasing one would leave the caller worse off than if it had never
///   asked, and clear the token it needs to release the row later.
/// * **a resource that was never requested** cannot be released at all: `release` takes user paths
///   and there is none to give it. Reported rather than dropped, because the row is held. The
///   lookup is on `(branch, hash)`, so this is the only thing that reaches it — a granted lock
///   whose description the server spelled differently still matches the request that produced it.
#[lore_macro::test_pub]
fn rollback_set(
    locks: &[AcquiredLock],
    requested_paths: &HashMap<(BranchId, Hash), String>,
    pre_held: &HashSet<(BranchId, Hash)>,
) -> RollbackSet {
    let mut paths = Vec::with_capacity(locks.len());
    let mut unnameable = Vec::new();
    for lock in locks {
        let resource = &lock.lock.resource;
        let key = (resource.branch, resource.hash);
        if pre_held.contains(&key) {
            continue;
        }
        match requested_paths.get(&key) {
            Some(path) => paths.push(LoreString::from(path)),
            // The description, not the key, because this string is for a human deciding what to do
            // about a row nothing local can release.
            None => unnameable.push(resource.description.clone()),
        }
    }
    RollbackSet { paths, unnameable }
}

/// What the caller is told when one batch task never produced an answer (WP-120).
///
/// A `JoinError` means the task panicked or was cancelled. Neither says whether the batch's
/// request reached the server, so this is an outstanding attempt rather than a failure. Reported
/// as `Internal`, which is what this used to be, it read to a caller as an operation that provably
/// did not happen: `EventError::translated` above maps everything but `OutcomeUnknown` to
/// `LoreError::Internal`, and a desktop that adjudicates on `OutcomeUnknown` would have retried an
/// acquire that may already have taken the locks.
///
/// **What the id does and does not promise.** It is the one the parent minted for that batch, so
/// it is the id the batch dispatched under — `lore-attempt-id` on the request, and the key of the
/// record `under_named_attempt` wrote before dispatching. Neither of those is guaranteed to exist
/// by the time this runs: a caller passing no attempt store journals nothing (the CLI and FFI path
/// in `lore::lock`), and a task that died inside the connect above never reached the dispatch at
/// all. So a reconciler finding nothing under this id has learned that the request cannot be shown
/// to have left, NOT that it did not happen. That is the whole reason the code is non-decisive:
/// the absence is as ambiguous as the id.
///
/// `None` is the one shape that must not claim an unknown outcome. `OutcomeUnknown` is the only
/// error in the registry that names an attempt, and being looked up is its entire purpose; one
/// carrying an empty id would send a reconciler after a receipt it cannot key, which is worse than
/// a plain internal failure rather than better than one. The arm is unreachable, and proven so
/// rather than assumed: every spawned handle's id is recorded here, and `AbortHandle::id` and
/// `JoinError::id` were probed to agree for both a panic and an abort. It is a message rather than
/// a panic if it is ever reached.
#[lore_macro::test_pub]
fn lost_batch_task(attempt: Option<AttemptId>) -> AcquireError {
    match attempt {
        Some(attempt) => AcquireError::from(OutcomeUnknown {
            operation: GrpcRpc::LockLock.wire_name().to_owned(),
            attempt_id: attempt.to_string(),
        }),
        None => AcquireError::internal("Failed executing batch task"),
    }
}

/// Keep every ownership token one batch was issued.
///
/// A cell that is not routing through the fenced authority issues none, and every lock in the
/// response then carries `None`. That is the ordinary case, not a failure: nothing is recorded and
/// the release path later sends a tokenless request, exactly as it always did.
///
/// A failure to record **fails the batch**. It is tempting to treat this as best-effort, since the
/// lock is already held by the time this runs, and that is precisely why it must not be: a lock
/// held with no recorded token is a lock only an administrator can release, so reporting the
/// acquire as successful would hand the caller a resource it cannot give back.
#[lore_macro::test_pub]
async fn record_batch_ownership(
    ownership: &Arc<dyn AttemptStore>,
    locks: &[AcquiredLock],
) -> Result<(), AcquireError> {
    for acquired in locks {
        let Some(token) = acquired.ownership_token.clone() else {
            continue;
        };
        // Minted here rather than read from the dispatch, which does not surface the identity it
        // stamped on the request.
        //
        // PIN(WP-120, 2026-09-05): so this id matches **no** server receipt today. It is not a
        // stale join waiting to be tightened — it is a local identity that no `Unlock` or
        // `Lock` receipt is filed under, and a reconciler reading it as a receipt key would find
        // nothing and could read that absence as "the acquire did not happen". Whoever wires the
        // reconciler must either have the transport return the id it stamped, or scope an id
        // around the dispatch here and record that one; until then nothing may treat this field
        // as a receipt key. It identifies which local acquire took the lock, and no more.
        //
        // **The trap this PIN used to carry is disarmed, and it is worth knowing it existed.**
        // `AttemptStore::resolve` used to settle a record *and* drop every ownership row held by
        // that attempt id. Making the acquire adopt the transport's dispatch attempt — the obvious
        // way to close this PIN — would then have let a decisive `NotApplied` resolution silently
        // delete the token for a lock the caller still held, leaving a row only an administrator
        // can release: the exact failure CR-030's token exists to prevent, reached from the side.
        //
        // `resolve` now settles the record only. Ownership rows are removed by `clear_ownership`
        // alone, on a release the server confirmed, because a lock outlives the attempt that took
        // it. So sharing the id is safe from that angle, and whoever closes this PIN has one
        // problem rather than two.
        let record = LockOwnership {
            attempt_id: AttemptId::new(),
            branch: acquired.lock.resource.branch,
            resource_hash: acquired.lock.resource.hash,
            token,
        };
        ownership
            .record_ownership(&record)
            .await
            .forward::<AcquireError>("Failed to record the lock ownership token")?;
    }
    Ok(())
}

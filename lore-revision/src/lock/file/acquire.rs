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
}

impl EventError for AcquireError {
    fn translated(&self) -> LoreError {
        match self {
            // An unresolved attempt keeps its own code all the way to the FFI
            // boundary (WP-120). Reported as `Internal` it is indistinguishable
            // from an operation that provably did not happen, which is the one
            // reading a caller must never be given.
            AcquireError::OutcomeUnknown(_) => LoreError::OutcomeUnknown,
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
        !matches!(self, AcquireError::OutcomeUnknown(_))
    }

    fn set_failed(message: &'static str) -> Self {
        AcquireError::internal(message)
    }
}

/// What this verb calls its batched dispatch, in the shared verdict's log line and fallback.
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
    // The path the USER named, per resource, kept only so a rollback can hand `release` the same
    // strings this acquire was given rather than re-deriving them from a server-echoed
    // description. `release` resolves a path exactly as the loop below does, so feeding it the
    // original spelling is the one form guaranteed to resolve back to the same resource.
    let mut requested_paths = HashMap::<String, String>::with_capacity(options.paths.len());
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
        requested_paths.insert(relative_path.to_string(), path.to_string());
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
    // On a cell that issues no tokens at all every entry here is `None`, so a renewal is
    // indistinguishable from a first acquire and lands in the rollback. That is what this client
    // can know, and it is still strictly narrower than releasing every requested path.
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
        let handle = lore_spawn!(batches, async move {
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
        });
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

        // A lock this call holds and could not name is not a decisive failure, whatever the
        // server said about the batch that failed. Reporting the refusal here would tell the
        // caller the acquire is over and nothing is outstanding, while a row it cannot release
        // stays taken — the same wrong reading a lost batch task used to produce, arrived at from
        // the other side. Only the code carries that here: the attempt this lock was granted
        // under is a per-batch identity, and `classify_batch_set` flattens the batches before this
        // point, so no id survives to name. An empty one is the truth rather than a placeholder,
        // and a reconciler that cannot key off it has to escalate to the user, which is the
        // correct handling for a row nothing local can name.
        if !rollback.unnameable.is_empty() {
            return Err(AcquireError::from(OutcomeUnknown {
                operation: GrpcRpc::LockLock.wire_name().to_owned(),
                attempt_id: String::new(),
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
/// * **a description no requested path produced** cannot be released at all: `release` takes user
///   paths and there is none to give it. Reported rather than dropped, because the row is held.
fn rollback_set(
    locks: &[AcquiredLock],
    requested_paths: &HashMap<String, String>,
    pre_held: &HashSet<(BranchId, Hash)>,
) -> RollbackSet {
    let mut paths = Vec::with_capacity(locks.len());
    let mut unnameable = Vec::new();
    for lock in locks {
        let resource = &lock.lock.resource;
        if pre_held.contains(&(resource.branch, resource.hash)) {
            continue;
        }
        match requested_paths.get(&resource.description) {
            Some(path) => paths.push(LoreString::from(path)),
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
/// `None` still reports an unknown outcome, with an empty id. It means only that this loop could
/// not say WHICH batch died, which changes nothing about the batch having died: the request may
/// still have left. Falling back to `Internal` here would answer a bookkeeping gap with the one
/// claim this file exists to stop making. The status is the load-bearing half and the id is the
/// convenience — a consumer of `#[ffi_outcome_identity]` reads the two as separate fields, and
/// lorehub-desktop's adjudicator keys off the rows its own `AttemptStore` wrote before the
/// dispatch rather than off this string, so an empty one costs it a label and not a lookup. The
/// arm is unreachable anyway: every spawned handle's id is recorded, and `AbortHandle::id` and
/// `JoinError::id` agree for both a panic and an abort.
fn lost_batch_task(attempt: Option<AttemptId>) -> AcquireError {
    AcquireError::from(OutcomeUnknown {
        operation: GrpcRpc::LockLock.wire_name().to_owned(),
        attempt_id: attempt
            .map(|attempt| attempt.to_string())
            .unwrap_or_default(),
    })
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

/// CR-030, WP-120: `record_batch_ownership` is a private free function reachable only from a
/// same-file test module (see `lore/docs/testing-guide.md`'s note on white-box seams). It needs
/// no live remote or `RepositoryContext` -- only an [`AttemptStore`] -- so these are unit tests
/// against [`lore_transport::attempt_store::VolatileAttemptStore`] rather than an integration
/// fixture. The full `acquire`/`release` orchestration around a real `Connection` (batching,
/// re-lock presenting a stored token, partial-batch rollback, tokenless-vs-held splitting, the
/// `ForceUnlock` fallback in `release.rs`) is NOT covered here: this crate's test harness has no
/// live-connected `RepositoryContext` fixture today (`lore-revision/tests/helper.rs` builds every
/// repository with an offline `Err(NoRemote)` session resolver), and building one is real test
/// infrastructure, not a cheap extension -- see `lore/docs/testing-guide.md`'s `State::tree` entry
/// for the same gap documented previously. `lore_transport::connection::add(scheme, protocol)`
/// registers a custom `Arc<dyn Protocol>` by URL scheme and could be the seam such a fixture is
/// built on, but that is a follow-up, not something to improvise inside this test pass.
#[cfg(test)]
mod tests {
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_base::types::LockData;
    use lore_base::types::LockResource;
    use lore_transport::attempt_store::OwnershipToken;
    use lore_transport::attempt_store::VolatileAttemptStore;

    use super::*;

    fn acquired_lock(
        resource_hash: Hash,
        branch: Context,
        token: Option<OwnershipToken>,
    ) -> AcquiredLock {
        AcquiredLock {
            lock: LockData {
                resource: LockResource {
                    branch,
                    hash: resource_hash,
                    description: "test-resource".to_string(),
                },
                owner: "wp120-test-owner".to_string(),
                locked_at: 0,
            },
            ownership_token: token,
        }
    }

    fn token(fill: u8) -> OwnershipToken {
        OwnershipToken::from_wire(&[fill; OwnershipToken::LEN])
            .expect("32 bytes must decode")
            .expect("32 bytes must produce a token, not None")
    }

    /// The whole reason this helper exists: a granted lock's token must be durably recorded
    /// before the batch is reported as successful, or an acquire could hand back a lock nothing
    /// can later release.
    #[tokio::test]
    async fn every_granted_token_is_recorded() {
        let store: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
        let branch = Context::from([0x11u8; 16]);
        let resource = Hash::from([0x22u8; 32]);
        let locks = vec![acquired_lock(resource, branch, Some(token(0xAB)))];

        record_batch_ownership(&store, &locks)
            .await
            .expect("recording a real token must succeed");

        let held = store
            .ownership_for(&branch, &resource)
            .await
            .unwrap()
            .expect("the granted token must be recorded");
        assert_eq!(held.token, token(0xAB));
    }

    /// An unfenced cell issues no token, and every lock then carries `None` -- that is the
    /// ordinary case, not a failure, and nothing must be recorded for it.
    #[tokio::test]
    async fn a_tokenless_lock_records_nothing_and_still_succeeds() {
        let store: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
        let branch = Context::from([0x11u8; 16]);
        let resource = Hash::from([0x22u8; 32]);
        let locks = vec![acquired_lock(resource, branch, None)];

        record_batch_ownership(&store, &locks)
            .await
            .expect("a tokenless lock must not fail the batch");

        assert_eq!(store.ownership_for(&branch, &resource).await.unwrap(), None);
    }

    /// A mixed batch records only the resources that actually carry a token.
    #[tokio::test]
    async fn a_mixed_batch_records_only_the_tokened_resources() {
        let store: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
        let branch = Context::from([0x11u8; 16]);
        let tokened = Hash::from([0x22u8; 32]);
        let tokenless = Hash::from([0x33u8; 32]);
        let locks = vec![
            acquired_lock(tokened, branch, Some(token(0xCD))),
            acquired_lock(tokenless, branch, None),
        ];

        record_batch_ownership(&store, &locks).await.unwrap();

        assert!(
            store
                .ownership_for(&branch, &tokened)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store.ownership_for(&branch, &tokenless).await.unwrap(),
            None
        );
    }

    /// `lost_batch_task` itself, pinned directly rather than only through `classify_batch_set` or
    /// the live fixture.
    ///
    /// This is the unit-level guard on the exact mapping WP-120 depends on: it must fail if either
    /// arm reverts to `AcquireError::internal(...)` -- `Some(attempt)`'s old fallback, or a
    /// reintroduced special case for `None` -- even if every `set_verdict` case and every live test
    /// happened to be skipped. Both arms return `OutcomeUnknown` now; the pair below shows the
    /// attempt id is what's optional, not the status.
    mod lost_batch_task_mapping {
        use super::*;

        /// `Some(id)` becomes `AcquireError::OutcomeUnknown`, translating to
        /// `LoreError::OutcomeUnknown`, with the attempt id and the RPC's wire name both present in
        /// the rendered message -- the two facts a reconciler reads out of the error.
        #[test]
        fn a_surviving_attempt_id_becomes_outcome_unknown_naming_the_attempt_and_the_rpc() {
            let attempt = AttemptId::new();
            let error = lost_batch_task(Some(attempt));

            assert!(
                matches!(error, AcquireError::OutcomeUnknown(_)),
                "a surviving attempt id must map to the OutcomeUnknown variant: {error:?}"
            );
            assert!(
                error.translated() == LoreError::OutcomeUnknown,
                "the public translation must carry the unknown outcome through, not collapse it \
                 to Internal: {:?}",
                error.translated() as i32
            );

            let rendered = error.to_string();
            assert!(
                rendered.contains(&attempt.to_string()),
                "the attempt id must be readable in the rendered message: {rendered}"
            );
            assert!(
                rendered.contains(GrpcRpc::LockLock.wire_name()),
                "the RPC's wire name must be readable in the rendered message: {rendered}"
            );
        }

        /// `None` -- the join loop could not say WHICH batch died, not that no batch died -- still
        /// becomes `AcquireError::OutcomeUnknown`, with an empty attempt id rather than no claim at
        /// all. The status is the load-bearing half: whether this loop can name the batch changes
        /// nothing about whether the request may have left, so answering `Internal` here would make
        /// the one claim this whole change exists to stop making. The empty id costs a label, not a
        /// lookup -- a reconciler builds its own record from what it journalled before the dispatch,
        /// not by parsing this string.
        #[test]
        fn no_surviving_attempt_id_still_becomes_outcome_unknown_with_an_empty_id() {
            let error = lost_batch_task(None);

            assert!(
                matches!(error, AcquireError::OutcomeUnknown(_)),
                "an unnamed attempt must still surface as OutcomeUnknown: {error:?}"
            );
            assert!(
                error.translated() == LoreError::OutcomeUnknown,
                "the public translation must carry the unknown outcome through, not collapse it \
                 to Internal: {:?}",
                error.translated() as i32
            );

            let rendered = error.to_string();
            assert!(
                rendered.contains(GrpcRpc::LockLock.wire_name()),
                "the RPC's wire name must still be readable in the rendered message: {rendered}"
            );

            let (operation, attempt_id) = error
                .outcome_identity()
                .expect("an OutcomeUnknown error must carry an outcome identity");
            assert_eq!(operation, GrpcRpc::LockLock.wire_name());
            assert_eq!(
                attempt_id, "",
                "no batch id survived, so the identity must carry an empty attempt id rather \
                 than inventing or omitting one"
            );
        }
    }

    /// `rollback_set` itself, pinned directly: the pure destructive decision a partial acquire's
    /// rollback now rides on. No fixture, no batching, no live server -- just the three inputs the
    /// function actually reads.
    mod rollback_set_tests {
        use super::*;

        /// A granted lock, distinguished only by branch/hash/description -- the fields
        /// `rollback_set` reads. Token and owner are irrelevant to the function under test.
        fn lock_named(branch: Context, hash: Hash, description: &str) -> AcquiredLock {
            let mut lock = acquired_lock(hash, branch, Some(token(0x11)));
            lock.lock.resource.description = description.to_owned();
            lock
        }

        /// A granted lock whose resource is in `pre_held` is excluded entirely: it is not in
        /// `paths`, and it is not `unnameable` either -- it is simply not this call's to release.
        #[test]
        fn a_pre_held_resource_is_excluded() {
            let branch = Context::from([0x01u8; 16]);
            let hash = Hash::from([0x02u8; 32]);
            let locks = vec![lock_named(branch, hash, "held.file")];
            let mut requested_paths = HashMap::new();
            requested_paths.insert("held.file".to_owned(), "C:/repo/held.file".to_owned());
            let mut pre_held = HashSet::new();
            pre_held.insert((branch, hash));

            let rollback = rollback_set(&locks, &requested_paths, &pre_held);

            assert!(
                rollback.paths.is_empty(),
                "a row this client already held must never be released: {:?}",
                rollback.paths
            );
            assert!(rollback.unnameable.is_empty());
        }

        /// A granted lock NOT in `pre_held` is included, using the ORIGINAL user path from
        /// `requested_paths` -- never the server-echoed description, which may differ in spelling
        /// (case, separators) from what the user actually typed.
        #[test]
        fn a_newly_granted_resource_is_included_using_the_original_user_path() {
            let branch = Context::from([0x01u8; 16]);
            let hash = Hash::from([0x02u8; 32]);
            let locks = vec![lock_named(branch, hash, "relative/new.file")];
            let mut requested_paths = HashMap::new();
            requested_paths.insert(
                "relative/new.file".to_owned(),
                "C:/repo/relative/new.file".to_owned(),
            );
            let pre_held = HashSet::new();

            let rollback = rollback_set(&locks, &requested_paths, &pre_held);

            assert_eq!(
                rollback.paths,
                vec![LoreString::from("C:/repo/relative/new.file")],
                "the released path must be the user's ORIGINAL spelling, not the description"
            );
            assert!(rollback.unnameable.is_empty());
        }

        /// A description no requested path produced lands in `unnameable`, never in `paths`.
        #[test]
        fn a_description_absent_from_requested_paths_is_unnameable() {
            let branch = Context::from([0x01u8; 16]);
            let hash = Hash::from([0x02u8; 32]);
            let locks = vec![lock_named(branch, hash, "unexpected.file")];
            let requested_paths = HashMap::new();
            let pre_held = HashSet::new();

            let rollback = rollback_set(&locks, &requested_paths, &pre_held);

            assert!(rollback.paths.is_empty());
            assert_eq!(rollback.unnameable, vec!["unexpected.file".to_owned()]);
        }

        /// A mixed set produces both: one pre-held resource excluded, one new resource released
        /// under its original path, and one unnameable description -- all three rules in one pass.
        #[test]
        fn a_mixed_set_produces_both_a_released_path_and_an_unnameable_description() {
            let branch = Context::from([0x01u8; 16]);
            let held_hash = Hash::from([0x02u8; 32]);
            let new_hash = Hash::from([0x03u8; 32]);
            let unnameable_hash = Hash::from([0x04u8; 32]);
            let locks = vec![
                lock_named(branch, held_hash, "held.file"),
                lock_named(branch, new_hash, "new.file"),
                lock_named(branch, unnameable_hash, "unexpected.file"),
            ];
            let mut requested_paths = HashMap::new();
            requested_paths.insert("held.file".to_owned(), "C:/repo/held.file".to_owned());
            requested_paths.insert("new.file".to_owned(), "C:/repo/new.file".to_owned());
            let mut pre_held = HashSet::new();
            pre_held.insert((branch, held_hash));

            let rollback = rollback_set(&locks, &requested_paths, &pre_held);

            assert_eq!(
                rollback.paths,
                vec![LoreString::from("C:/repo/new.file")],
                "only the new, non-held resource may be released"
            );
            assert_eq!(rollback.unnameable, vec!["unexpected.file".to_owned()]);
        }
    }

    /// The set verdict, decided from hand-built per-batch outcomes.
    ///
    /// `acquire` calls [`classify_batch_set`] directly, with its own [`ACQUIRE_SET_LABELS`], rather
    /// than through a `release`-style wrapper -- there is only the one call site here, so a wrapper
    /// would name nothing a reader could not already see. See `release.rs`'s own `mod set_verdict`
    /// for the sibling cases against `ReleaseError`; the rules under test are the same shared
    /// helper, exercised here against `AcquireError` and `AcquiredLock` instead.
    ///
    /// None of these are reachable through the live fixture, and that is why they are here rather
    /// than beside the live proofs in `lore/tests/live_lock_journal.rs`. The stub server answers one
    /// policy per RPC, so every batch of one `Lock` set gets the same answer from it, and a set
    /// whose batches *differ* is exactly what these cases are about.
    ///
    /// These unit tests pin the verdict `classify_batch_set` returns; they do not themselves prove
    /// the rollback arm in `acquire` is skipped end to end -- that proof is the live fixture's exact
    /// `OutcomeUnknown` status plus its surviving unresolved journal record. Case 5 below is the
    /// structural link between the two: it is the returned success count, and only that count being
    /// less than `num_batches`, that triggers the rollback release in `acquire`, and a non-decisive
    /// set never returns `Ok` at all -- which is what makes an unknown batch structurally unable to
    /// reach it.
    mod set_verdict {
        use lore_base::error::OutcomeUnknown;

        use super::*;
        use crate::lock::util::classify_batch_set;

        /// A lost answer, shaped as the transport produces one.
        fn unknown() -> AcquireError {
            AcquireError::from(OutcomeUnknown {
                operation: "LockService.Lock".to_owned(),
                attempt_id: "018f5f4c-0000-7000-8000-00000000abcd".to_owned(),
            })
        }

        /// A refusal the server answered with: decisive.
        fn refusal() -> AcquireError {
            AcquireError::internal("the server refused")
        }

        fn descriptions(locks: &[AcquiredLock]) -> Vec<String> {
            locks
                .iter()
                .map(|lock| lock.lock.resource.description.clone())
                .collect()
        }

        /// A batch's lock, distinguished only by its resource description -- the branch and
        /// resource hash are irrelevant to the verdict under test.
        fn lock_named(description: &str) -> AcquiredLock {
            let mut lock = acquired_lock(
                Hash::from([0x55u8; 32]),
                Context::from([0x02u8; 16]),
                Some(token(0x11)),
            );
            lock.lock.resource.description = description.to_owned();
            lock
        }

        /// A set every batch of which was refused is decisive.
        ///
        /// The negative control for everything below. Without it, an implementation that classified
        /// every acquire failure as non-decisive would still pass every other case here.
        #[test]
        fn a_set_of_refusals_is_decisive() {
            let mut locks: Vec<AcquiredLock> = Vec::new();
            let failure = classify_batch_set(
                vec![Err(refusal()), Err(refusal())],
                None,
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect_err("a set where every batch was refused fails");

            assert!(failure.decisive, "a refusal settles what happened");
            assert!(locks.is_empty());
        }

        /// One unknown batch outranks a refusal in the same set.
        ///
        /// A first-error-wins accumulator would report the refusal and call the set decisive, which
        /// is exactly the shape that used to let `acquire` roll a non-decisive set back.
        #[test]
        fn an_unknown_batch_outranks_a_refusal_in_the_same_set() {
            let mut locks: Vec<AcquiredLock> = Vec::new();
            let failure = classify_batch_set(
                vec![Err(refusal()), Err(unknown())],
                None,
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect_err("a set where every batch failed fails");

            assert!(
                !failure.decisive,
                "one unknown batch makes the whole set unsafe to act on again"
            );
            assert!(
                matches!(failure.error, AcquireError::OutcomeUnknown(_)),
                "the caller must be told the outcome is unknown, not that it was refused: {:?}",
                failure.error
            );
        }

        /// A lost batch task must not shadow a real lost answer.
        #[test]
        fn a_lost_batch_task_does_not_shadow_a_lost_answer() {
            let mut locks: Vec<AcquiredLock> = Vec::new();
            let failure = classify_batch_set(
                vec![Err(unknown())],
                Some(AcquireError::internal("Failed executing batch task")),
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect_err("a set with a lost answer fails");

            assert!(!failure.decisive);
            assert!(
                matches!(failure.error, AcquireError::OutcomeUnknown(_)),
                "the lost answer names an attempt to reconcile; the lost task names nothing: {:?}",
                failure.error
            );
        }

        /// The `lost_batch_task(None)` shape passed through unchanged.
        ///
        /// `None` is the unreachable fallback at `acquire`'s own call site -- every spawned
        /// handle's id is recorded in `batch_attempts` before the join loop runs, so a real lost
        /// batch task always has a surviving id today (see the sibling test below, which pins the
        /// shape `acquire` actually builds). This case is really about `classify_batch_set` itself:
        /// whatever `task_failure` a caller hands in, decisive or not, it must reach the verdict
        /// unchanged rather than reshaped -- proven here against the one shape that is NOT
        /// `OutcomeUnknown`, so a future change that always wraps `task_failure` in `OutcomeUnknown`
        /// regardless of its input would fail this test.
        #[test]
        fn a_lost_batch_task_alone_is_non_decisive() {
            let mut locks = Vec::new();
            let failure = classify_batch_set(
                vec![Ok(vec![lock_named("a.file")])],
                Some(AcquireError::internal("Failed executing batch task")),
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect_err("a set with a lost task fails even though a batch succeeded");

            assert!(!failure.decisive);
            assert!(
                !matches!(failure.error, AcquireError::OutcomeUnknown(_)),
                "no attempt id survived the lost task, so none may be named: {:?}",
                failure.error
            );
            assert_eq!(descriptions(&locks), vec!["a.file".to_owned()]);
        }

        /// The `lost_batch_task(Some(id))` shape -- the one `acquire` actually builds -- passed
        /// through unchanged.
        ///
        /// Sibling to the test above: together they cover both of `lost_batch_task`'s branches at
        /// the `classify_batch_set` boundary, proving the helper reshapes neither. `unknown()` is
        /// exactly the `AcquireError::OutcomeUnknown` shape `lost_batch_task(Some(id))` builds (see
        /// `mod tests`'s own direct pin of that mapping), so passing it as `task_failure` here
        /// stands in for a real panicking batch task without needing a live fixture.
        #[test]
        fn a_lost_batch_task_with_a_surviving_id_is_non_decisive_and_names_it() {
            let mut locks = Vec::new();
            let failure = classify_batch_set(
                vec![Ok(vec![lock_named("a.file")])],
                Some(unknown()),
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect_err("a set with a lost task fails even though a batch succeeded");

            assert!(!failure.decisive);
            assert!(
                matches!(failure.error, AcquireError::OutcomeUnknown(_)),
                "the id the lost task's own record was minted under must reach the caller \
                 unchanged: {:?}",
                failure.error
            );
            assert_eq!(descriptions(&locks), vec!["a.file".to_owned()]);
        }

        /// A partly successful decisive set reports its success count.
        ///
        /// This is the acquire-specific claim: that count, and only that count being less than
        /// `num_batches`, is what triggers `acquire`'s partial-acquire rollback. This test does not
        /// itself prove the rollback runs or is skipped -- it proves the value the rollback's own
        /// condition reads.
        #[test]
        fn a_partly_successful_decisive_set_reports_its_success_count() {
            let mut locks = Vec::new();
            let verdict = classify_batch_set(
                vec![Ok(vec![lock_named("a.file")]), Err(refusal())],
                None,
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect("a set with at least one success is a success");

            assert_eq!(
                verdict.num_batch_success, 1,
                "exactly one of the two batches answered successfully"
            );
            assert!(
                verdict.first_decisive_failure.is_some(),
                "the refused batch's own error must survive into the verdict -- this is what lets \
                 acquire's rollback arm re-raise the server's own refusal instead of inventing an \
                 internal message"
            );
            assert_eq!(descriptions(&locks), vec!["a.file".to_owned()]);
        }

        /// A set every batch of which succeeded returns every batch, in order, with no failure
        /// carried.
        #[test]
        fn a_fully_answered_set_returns_every_batch() {
            let mut locks = Vec::new();
            let verdict = classify_batch_set(
                vec![
                    Ok(vec![lock_named("a.file")]),
                    Ok(vec![lock_named("b.file")]),
                ],
                None::<AcquireError>,
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect("a set every batch of which succeeded is a success");

            assert_eq!(verdict.num_batch_success, 2);
            assert!(
                verdict.first_decisive_failure.is_none(),
                "a set with no failed batch must carry no failure"
            );
            assert_eq!(
                descriptions(&locks),
                vec!["a.file".to_owned(), "b.file".to_owned()]
            );
        }

        /// A set whose `outcomes` hold fewer entries than `num_batches` is non-decisive even when
        /// `task_failure` is `None`.
        ///
        /// The structural guarantee that a non-decisive set can never be acted on again must not
        /// rest on a caller's join loop remembering to report its own `JoinError` into
        /// `task_failure` -- a caller that simply dropped an outcome (rather than reporting it as a
        /// task failure) must still be refused the success arm.
        #[test]
        fn a_short_outcome_list_is_non_decisive_even_with_no_task_failure() {
            let mut locks: Vec<AcquiredLock> = Vec::new();
            let failure = classify_batch_set(
                vec![Ok(vec![lock_named("a.file")])],
                None::<AcquireError>,
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect_err("a set missing an outcome for one of its two batches fails");

            assert!(
                !failure.decisive,
                "a missing outcome is exactly as unsafe to act on again as a reported task \
                 failure or a lost answer"
            );
            assert_eq!(
                descriptions(&locks),
                vec!["a.file".to_owned()],
                "the one batch that did answer must still be accounted for"
            );
        }

        /// A set of zero batches succeeds with a zero count, rather than a fabricated decisive
        /// failure.
        ///
        /// Unreachable from either verb today -- both `resources.is_empty()` early-return before
        /// ever building a set -- but pinned so the helper's own contract for the boundary is
        /// explicit rather than implied by what happens to call it.
        #[test]
        fn a_set_of_zero_batches_succeeds_with_a_zero_count() {
            let mut locks: Vec<AcquiredLock> = Vec::new();
            let outcomes: Vec<Result<Vec<AcquiredLock>, AcquireError>> = Vec::new();
            let verdict = classify_batch_set(outcomes, None, 0, &ACQUIRE_SET_LABELS, &mut locks)
                .expect("a set of zero batches has nothing to fail on");

            assert_eq!(verdict.num_batch_success, 0);
            assert!(verdict.first_decisive_failure.is_none());
            assert!(locks.is_empty());
        }
    }
}

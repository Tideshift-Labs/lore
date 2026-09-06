// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::sync::Arc;

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
use crate::dispatch::under_own_attempt;
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
use crate::lock::util::assemble_resource_for_path;
use crate::lock::util::classify_batch_set;
use crate::lore::execution_context;
use crate::lore_debug;
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
    let resources_values = requested
        .into_iter()
        .zip(tokens)
        .map(|(resource, token)| FencedLockResource::with_token(resource, token))
        .collect::<Vec<_>>();

    let batch_iterator = resources_values.chunks(LOCK_BATCH_SIZE);
    let num_batches = batch_iterator.len();

    let mut batches: JoinSet<Result<Vec<AcquiredLock>, AcquireError>> = JoinSet::new();
    let mut batches_results = Vec::with_capacity(num_batches);
    for batch_resources in batch_iterator {
        let batch_resources = batch_resources.to_vec();
        let owner = owner.clone();
        let remote = remote.clone();
        let repository_id = repository.id;
        let ownership = ownership.clone();
        let attempts = attempts.cloned();
        lore_spawn!(batches, async move {
            let connection = remote
                .lock(repository_id)
                .await
                .forward_with::<AcquireError, _>(|| {
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
    }

    // A task that did not run to completion is not an answer. It panicked or was cancelled, and
    // neither says whether its request reached the server. Collected rather than raised on the
    // spot: the batches that *did* answer still hold locks the caller has to be told about, and an
    // early return here discarded them along with the verdict they belong to.
    let mut task_failure: Option<AcquireError> = None;
    while let Some(task_result) = batches.join_next().await {
        match task_result {
            Ok(result) => batches_results.push(result),
            Err(_) => {
                task_failure = task_failure
                    .or_else(|| Some(AcquireError::internal("Failed executing batch task")));
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
    let num_batch_success = match classify_batch_set(
        batches_results,
        task_failure,
        num_batches,
        &ACQUIRE_SET_LABELS,
        &mut locks,
    ) {
        Ok(num_batch_success) => num_batch_success,
        // Handed back as it is, both when it is decisive (nothing was acquired, and the server's
        // own refusal is more useful than a message this file invented) and when it is not (the
        // caller is told `OutcomeUnknown`, naming the attempt whose journal record
        // `under_own_attempt` deliberately left unresolved for a later authoritative read).
        // Whatever the successful batches did acquire stays acquired and stays recorded in
        // `ownership`: rolling it back would be the mutation-on-a-maybe this guards against, and
        // the caller reconciles from the attempt instead.
        Err(failure) => return Err(failure.error),
    };

    if num_batch_success < num_batches {
        lore_debug!("Attempting releasing partial acquired locks.");

        let options = ReleaseOptions {
            paths: options.paths,
            branch: options.branch,
            owner: String::default(),
            owner_id: String::default(),
        };

        // The same store the successful batches just wrote their tokens into, so the rollback
        // presents them. Without this the rollback would release tokenlessly, which a fenced cell
        // refuses — leaving exactly the half-acquired set this branch exists to undo.
        //
        // The rollback's own answer can be lost in turn, and `forward` carries that variant
        // across: the caller is then told `OutcomeUnknown` for the release rather than a decisive
        // failure for the acquire, which is the honest report — some of these locks are held and
        // nothing here knows which.
        release(repository.clone(), options, ownership.clone(), attempts)
            .await
            .forward::<AcquireError>("Failed to acquire the lock")?;

        return Err(AcquireError::internal("Failed to acquire the lock"));
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

        /// A lost batch task alone is non-decisive, even beside a batch that succeeded, and the
        /// successful batch's locks are still accounted for.
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

        /// A partly successful decisive set reports its success count.
        ///
        /// This is the acquire-specific claim: that count, and only that count being less than
        /// `num_batches`, is what triggers `acquire`'s partial-acquire rollback. This test does not
        /// itself prove the rollback runs or is skipped -- it proves the value the rollback's own
        /// condition reads.
        #[test]
        fn a_partly_successful_decisive_set_reports_its_success_count() {
            let mut locks = Vec::new();
            let num_batch_success = classify_batch_set(
                vec![Ok(vec![lock_named("a.file")]), Err(refusal())],
                None,
                2,
                &ACQUIRE_SET_LABELS,
                &mut locks,
            )
            .expect("a set with at least one success is a success");

            assert_eq!(
                num_batch_success, 1,
                "exactly one of the two batches answered successfully"
            );
            assert_eq!(descriptions(&locks), vec!["a.file".to_owned()]);
        }

        /// A set every batch of which succeeded returns every batch, in order.
        #[test]
        fn a_fully_answered_set_returns_every_batch() {
            let mut locks = Vec::new();
            let num_batch_success = classify_batch_set(
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

            assert_eq!(num_batch_success, 2);
            assert_eq!(
                descriptions(&locks),
                vec!["a.file".to_owned(), "b.file".to_owned()]
            );
        }
    }
}

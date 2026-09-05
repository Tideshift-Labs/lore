// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
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
use serde::Deserialize;
use serde::Serialize;
use tokio::task::JoinSet;

use crate::attempt_store::held_tokens;
use crate::branch;
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
        lore_spawn!(batches, async move {
            let response = remote
                .lock(repository_id)
                .await
                .forward_with::<AcquireError, _>(|| {
                    format!("Failed to connect to remote {}", remote.remote_url())
                })?
                .lock(&batch_resources, owner.as_deref())
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

    let mut task_error: Result<(), AcquireError> = Ok(());
    while let Some(task_result) = batches.join_next().await {
        if let Ok(result) = task_result {
            batches_results.push(result);
        } else {
            task_error = Err(AcquireError::internal("Failed executing batch task"));
        }
    }
    task_error?;

    let mut locks = Vec::with_capacity(resources_count);

    let mut num_batch_success = 0;
    let mut num_batch_failed = 0;
    for batch_result in batches_results {
        if let Ok(mut results) = batch_result {
            locks.append(&mut results);
            num_batch_success += 1;
        } else {
            num_batch_failed += 1;
        }
    }

    if num_batch_failed > 0 {
        lore_error!("Failed to lock-acquire {num_batch_failed} batch(es) out of {num_batches}");
    }

    if num_batch_success == 0 {
        return Err(AcquireError::internal("Failed to acquire the lock"));
    }

    if num_batch_success > 0 && num_batch_success < num_batches {
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
        release(repository.clone(), options, ownership.clone())
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
        // stamped on the request. PIN(WP-120, 2026-09-05): the reconciler lane that reads a
        // receipt back under a client-minted attempt id has to join these two, either by
        // returning the transport's id or by passing one in.
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
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Moved from `src/lock/file/release.rs` when the crate's lib test harness was turned off.
// The release's two error paths and which one the caller is told about (WP-120).
//
// These live here rather than in `lore/tests/live_lock_journal.rs` with the rest of the live lock
// proofs for one reason: the ownership store is a *parameter* of [`release`] and is not a
// parameter of anything above it. `lore::lock::file_release_with_attempt_store` derives it from
// the repository it just opened, so a test at that layer has no way to make the accounting fail
// on demand. This is the lowest layer where it can be injected, so it is where the claim can be
// proven. The escalation half of the same fix is proven from `lore`'s tier, where the server's
// own request log is the evidence.
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use lore_base::error::OutcomeUnknown;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockPolicy;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::RpcOutcome;
use lore_revision::live_fixture::UnlockEcho;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::lock::file::acquire::AcquireOptions;
use lore_revision::lock::file::release::*;
use lore_revision::lock::util::BatchSetError;
use lore_revision::repository::RepositoryAccess;
use lore_transport::ProtocolError;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::outcome::AttemptId;
use parking_lot::Mutex;
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

    async fn lookup(&self, attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
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
        all_owners: false,
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
        let failure = classify_set(vec![Err(refusal()), Err(refusal())], None, 2, &mut released)
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
        let failure = classify_set(vec![Err(refusal()), Err(unknown())], None, 2, &mut released)
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

        lore_revision::lock::file::acquire::acquire(
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
            LiveRepository::create_with_files(&server.remote_url(), &["a.file", "b.file"]).await;
        let repository = fixture.connect(RepositoryAccess::ReadOnly).await;

        let ownership = Arc::new(FailingOwnership::new());
        let store: Arc<dyn AttemptStore> = ownership.clone();

        lore_revision::lock::file::acquire::acquire(
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

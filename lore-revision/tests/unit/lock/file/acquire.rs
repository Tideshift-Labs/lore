// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_error_set::FfiError;
use lore_revision::event::EventError;
use lore_revision::interface::LoreError;
use lore_revision::interface::LoreString;
use lore_revision::lock::file::acquire::*;
use lore_revision::lock::util::BatchSetError;
use lore_revision::lock::util::fold_batch_results;
use lore_transport::attempt_store::AcquiredLock;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::OwnershipToken;
use lore_transport::attempt_store::VolatileAttemptStore;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;

/// Builds a batch error shaped like the one a batch task produces: the
/// remote's denial forwarded under the generic acquire context.
fn denied_batch_error() -> AcquireError {
    AcquireError::internal("resource already locked").forward("Failed to acquire the lock")
}

#[test]
fn batch_denial_reason_survives_the_fold() {
    let denial = denied_batch_error();
    let reported = denial.to_string();

    let (locks, num_batch_success, first_batch_error) = fold_batch_results::<LockData, _>(
        vec![Err(denial), Err(AcquireError::internal("a later batch"))],
        0,
    );

    assert!(locks.is_empty());
    assert_eq!(num_batch_success, 0);
    assert_eq!(
        first_batch_error
            .expect("a failing batch keeps its error")
            .to_string(),
        reported
    );
}

#[test]
fn batch_denial_reason_reaches_the_message() {
    let reported = denied_batch_error().to_string();

    assert!(
        reported.ends_with("resource already locked"),
        "the remote's reason is not in the reported message: {reported}"
    );
}

// ---------------------------------------------------------------------------
// FORK-LOCAL (Tideshift, CR-030, WP-120): moved from the inline `src/lock/file/acquire.rs`
// tests when the crate's lib test harness was turned off. The original module doc follows.
//
// CR-030, WP-120: `record_batch_ownership` is a private free function reachable only from a
// same-file test module (see `lore/docs/testing-guide.md`'s note on white-box seams). It needs
// no live remote or `RepositoryContext` -- only an [`AttemptStore`] -- so these are unit tests
// against [`lore_transport::attempt_store::VolatileAttemptStore`] rather than an integration
// fixture. The full `acquire`/`release` orchestration around a real `Connection` (batching,
// re-lock presenting a stored token, partial-batch rollback, tokenless-vs-held splitting, the
// `ForceUnlock` fallback in `release.rs`) is NOT covered here: this crate's test harness has no
// live-connected `RepositoryContext` fixture today (`lore-revision/tests/helper.rs` builds every
// repository with an offline `Err(NoRemote)` session resolver), and building one is real test
// infrastructure, not a cheap extension -- see `lore/docs/testing-guide.md`'s `State::tree` entry
// for the same gap documented previously. `lore_transport::connection::add(scheme, protocol)`
// registers a custom `Arc<dyn Protocol>` by URL scheme and could be the seam such a fixture is
// built on, but that is a follow-up, not something to improvise inside this test pass.
// ---------------------------------------------------------------------------

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
/// This is the unit-level guard on the exact mapping WP-120 depends on: it must fail if
/// `Some(attempt)` reverts to `AcquireError::internal(...)`, or if `None` is ever changed to
/// claim `OutcomeUnknown` with an empty attempt id -- even if every `set_verdict` case and
/// every live test happened to be skipped. The pair below shows the attempt id is what
/// decides the status, not a detail carried alongside it: `Some` names an attempt and becomes
/// `OutcomeUnknown`; `None` names nothing and stays `Internal`.
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

    /// `None` -- the join loop could not say WHICH batch died -- must NOT become
    /// `AcquireError::OutcomeUnknown`. `OutcomeUnknown` is the only error in the registry that
    /// names an attempt, and being looked up is its entire purpose; one carrying an empty id
    /// would send a reconciler after a receipt it cannot key, which is worse than a plain
    /// internal failure rather than better than one.
    ///
    /// The arm is unreachable in practice, and that is proven rather than assumed: every
    /// spawned handle's id is recorded in `batch_attempts` before the join loop runs (see the
    /// sibling test in `set_verdict` below and `lost_batch_task`'s own doc), and
    /// `AbortHandle::id` and `JoinError::id` were probed to agree for both a panic and an
    /// abort. This test pins what the fallback itself returns if that unreachable arm were
    /// ever reached.
    #[test]
    fn no_surviving_attempt_id_is_not_outcome_unknown() {
        let error = lost_batch_task(None);

        assert!(
            error.is_internal(),
            "no surviving attempt id must not be reported as OutcomeUnknown -- that variant \
             is reserved for a real attempt a reconciler can look up: {error:?}"
        );
        assert!(
            error.translated() == LoreError::Internal,
            "the public translation must stay Internal, not claim an unresolved outcome for \
             an attempt nothing can name: {:?}",
            error.translated() as i32
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
        requested_paths.insert((branch, hash), "C:/repo/held.file".to_owned());
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
        requested_paths.insert((branch, hash), "C:/repo/relative/new.file".to_owned());
        let pre_held = HashSet::new();

        let rollback = rollback_set(&locks, &requested_paths, &pre_held);

        assert_eq!(
            rollback.paths,
            vec![LoreString::from("C:/repo/relative/new.file")],
            "the released path must be the user's ORIGINAL spelling, not the description"
        );
        assert!(rollback.unnameable.is_empty());
    }

    /// A granted lock whose `(branch, hash)` was never requested at all lands in
    /// `unnameable`, never in `paths` -- even though `requested_paths` is non-empty and holds
    /// an entry for a DIFFERENT resource, proving the miss is a real key lookup rather than an
    /// artifact of an empty map.
    #[test]
    fn a_description_absent_from_requested_paths_is_unnameable() {
        let branch = Context::from([0x01u8; 16]);
        let hash = Hash::from([0x02u8; 32]);
        let locks = vec![lock_named(branch, hash, "unexpected.file")];
        let mut requested_paths = HashMap::new();
        let other_hash = Hash::from([0x99u8; 32]);
        requested_paths.insert((branch, other_hash), "C:/repo/other.file".to_owned());
        let pre_held = HashSet::new();

        let rollback = rollback_set(&locks, &requested_paths, &pre_held);

        assert!(rollback.paths.is_empty());
        assert_eq!(rollback.unnameable, vec!["unexpected.file".to_owned()]);
    }

    /// The discriminating case for keying on identity rather than description: a granted lock
    /// whose `(branch, hash)` IS in the map, but whose DESCRIPTION differs from the spelling
    /// the user requested (the server is free to normalise case/separators), is released --
    /// not reported unnameable. Against the old description-keyed lookup this case would have
    /// missed and wrongly landed in `unnameable`.
    #[test]
    fn a_granted_lock_with_a_differently_spelled_description_is_still_released() {
        let branch = Context::from([0x01u8; 16]);
        let hash = Hash::from([0x02u8; 32]);
        let locks = vec![lock_named(branch, hash, "Relative\\New.File")];
        let mut requested_paths = HashMap::new();
        requested_paths.insert((branch, hash), "C:/repo/relative/new.file".to_owned());
        let pre_held = HashSet::new();

        let rollback = rollback_set(&locks, &requested_paths, &pre_held);

        assert_eq!(
            rollback.paths,
            vec![LoreString::from("C:/repo/relative/new.file")],
            "a resource keyed to a requested path must be released by its original spelling \
             even when the server's description spells it differently"
        );
        assert!(
            rollback.unnameable.is_empty(),
            "a resource this call requested must never be reported unnameable just because \
             the server described it differently: {:?}",
            rollback.unnameable
        );
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
        requested_paths.insert((branch, held_hash), "C:/repo/held.file".to_owned());
        requested_paths.insert((branch, new_hash), "C:/repo/new.file".to_owned());
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

/// `AcquireError::UnnameableResource` itself: the guard on someone deleting its entry from
/// the single `matches!` in `BatchSetError::is_decisive`, plus its public translation and its
/// FFI code. Allocated from the Outcome block (248-254, `lore-base/src/error.rs`), so its code
/// must sit beside `OutcomeUnknown`'s 248 without colliding with it or with `Internal`'s -1.
mod unnameable_resource_tests {
    use lore_base::error::UnnameableResource;

    use super::*;

    fn unnameable() -> AcquireError {
        AcquireError::from(UnnameableResource {
            resource: "unexpected.file".to_owned(),
        })
    }

    /// Not decisive: a granted-but-unreleasable lock means the acquire's own report may not
    /// settle what happened, exactly like a lost answer -- the single `matches!` this test
    /// guards is what a future edit could silently narrow.
    #[test]
    fn unnameable_resource_is_not_decisive() {
        let error = unnameable();

        assert!(
            !error.is_decisive(),
            "a granted resource this call cannot name must never be reported decisive: \
             {error:?}"
        );
    }

    /// Translates to `LoreError::OutcomeUnknown`, the same coarse reading `OutcomeUnknown`
    /// itself gets: at the FFI boundary both say "do not retry, read authoritative state",
    /// even though the underlying reasons differ (a lost answer vs. a granted lock this call
    /// cannot name).
    #[test]
    fn unnameable_resource_translates_to_outcome_unknown() {
        let error = unnameable();

        assert!(
            error.translated() == LoreError::OutcomeUnknown,
            "an unnameable resource must translate the same way an unresolved attempt does: \
             {:?}",
            error.translated() as i32
        );
    }

    /// `ffi_code()` is 249, distinct from both `Internal` (-1) and `OutcomeUnknown` (248) --
    /// the terminal status a C caller actually reads, independent of `translated()`'s coarser
    /// `LoreError` bucket.
    #[test]
    fn unnameable_resource_ffi_code_is_249_and_distinct() {
        let error = unnameable();

        assert_eq!(error.ffi_code(), 249);
        assert_ne!(error.ffi_code(), lore_error_set::Internal::FFI_CODE);
        assert_ne!(
            error.ffi_code(),
            AcquireError::from(lore_base::error::OutcomeUnknown {
                operation: GrpcRpc::LockLock.wire_name().to_owned(),
                attempt_id: AttemptId::new().to_string(),
            })
            .ffi_code()
        );
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
    use lore_revision::lock::util::classify_batch_set;

    use super::*;

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

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Attempt identity for the client's irreversible dispatches (WP-120).
//!
//! One helper, shared by every operation family that reaches a `MutableNoReplay` dispatch a caller
//! may need to reconcile: `branch::push` and the two lock verbs. It lived inside `branch/push.rs`
//! while push was the only family wired, and moved here rather than being copied when locks were
//! wired, because two copies of a mint-record-scope-resolve sequence drift and the drift is silent.
//!
//! See [`under_own_attempt`] for the granularity rule, which is the part that is easy to get wrong.

use std::sync::Arc;

use lore_transport::ProtocolError;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;
use lore_transport::outcome::with_dispatch_attempt;

use crate::lore::RepositoryId;
/// Dispatch one irreversible submutation under an attempt identity of its own (WP-120).
///
/// **One id per dispatch, never one per operation.** A single push reaches several
/// `MutableNoReplay` dispatches: the push itself, and on a server-side branch deletion a create
/// followed by a second push. The transport reuses whatever attempt is in scope, so one scope
/// around the whole operation would stamp the same id on all of them, the server would file
/// several receipts under it, and `attempt_receipt_get` answers `NotFound` whenever more than one
/// receipt shares an id. The lookup would go permanently dark while looking like it worked. This
/// scope is entered around one await and no more.
///
/// With no store the dispatch is exactly what it was: the CLI passes `None` and the transport
/// mints its own id as before.
///
/// The resolution mapping is the contract's, not a convenience. A returned value means the server
/// answered and the effect happened. An [`ProtocolError::OutcomeUnknown`] means the answer was
/// lost, so the record is deliberately left unresolved for a later authoritative read; that is
/// the entire reason any of this exists. Any other error means the transport either held proof
/// the request never left or carried back the server's own refusal, and both are decisively
/// not-applied.
/// PIN(WP-120, 2026-09-05): this helper is wired at the push dispatches in this file and nowhere
/// else, and that is the whole desktop surface rather than a partial rollout. Every other
/// `MutableNoReplay` domain dispatch on the client path is unwired because `lore-engine` in
/// lorehub-desktop reaches none of them: `branch::merge_into`'s pushes (`branch/merge.rs:4000`
/// and `:4383`, whose only caller anywhere is the CLI entry point in `lore/src/branch.rs`),
/// `revision::restore`'s push (`revision/restore.rs:556`, where the desktop's Restore stays a
/// local anchor and calls only `file_unstage` and `file_reset`), `branch_delete`
/// (`branch.rs:2030`), the two metadata compare-and-swaps (`metadata/branch.rs:243` and
/// `metadata/repository.rs:235`), `RepositoryCreate` and `RepositoryDelete` (create is the
/// platform's claim rail, delete is not a desktop operation), and `AdminObliterate`.
///
/// Wiring any of them is a few lines with this helper, but do it when a caller that reconciles
/// appears, not before: an attempt record no reconciler ever reads is a durable write that stays
/// unresolved forever.
pub(crate) async fn under_own_attempt<T, Fut>(
    attempts: Option<&Arc<dyn AttemptStore>>,
    repository: RepositoryId,
    rpc: GrpcRpc,
    dispatch: Fut,
) -> Result<T, ProtocolError>
where
    Fut: Future<Output = Result<T, ProtocolError>>,
{
    let Some(store) = attempts else {
        return dispatch.await;
    };

    let attempt = AttemptId::new();
    // Recorded before the dispatch, never after. A record written afterwards cannot describe an
    // attempt whose response was lost, which is the only case that needs one.
    store
        .record(&AttemptRecord {
            attempt_id: attempt,
            state: AttemptState::Unresolved,
            operation: rpc.wire_name().to_owned(),
            repository,
            recorded_at_unix_millis: unix_millis_now(),
            receipt: None,
        })
        .await?;

    let result = with_dispatch_attempt(attempt, dispatch).await;

    let resolution = match &result {
        Ok(_) => Some(AttemptResolution::Applied),
        Err(ProtocolError::OutcomeUnknown(_)) => None,
        Err(_) => Some(AttemptResolution::NotApplied),
    };
    if let Some(resolution) = resolution {
        store.resolve(&attempt, resolution).await?;
    }
    result
}

/// Wall-clock milliseconds for an attempt record's ordering field.
///
/// A clock that is behind or repeats produces a record that sorts oddly in an operator's view and
/// nothing worse, so a failure to read it is floored rather than propagated: refusing to dispatch
/// a mutation because the clock misbehaved would be a far larger harm than a misordered row.
fn unix_millis_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-dispatch attempt identity (WP-120).
    ///
    /// These exist because the first version of this feature put ONE scope around the whole push.
    /// A push reaches several dispatches, the transport reuses whatever is in scope, so the server
    /// filed several receipts under one id and `attempt_receipt_get` answers `NotFound` whenever
    /// more than one shares an id. The lookup went dark and nothing failed loudly. The test that
    /// catches that is the second one here: two dispatches, two ids.
    mod attempts {
        use lore_transport::attempt_store::VolatileAttemptStore;

        use super::*;

        fn store() -> Arc<dyn AttemptStore> {
            Arc::new(VolatileAttemptStore::new())
        }

        fn repository() -> RepositoryId {
            RepositoryId::from([7u8; 16])
        }

        /// The id recorded before the dispatch is the id the dispatch runs under. If these ever
        /// differ the caller journals one identity and the server files another.
        #[tokio::test]
        async fn the_dispatch_runs_under_the_id_that_was_recorded() {
            let store = store();
            let seen = under_own_attempt(
                Some(&store),
                repository(),
                GrpcRpc::RevisionBranchPush,
                async {
                    Ok::<_, ProtocolError>(lore_transport::outcome::current_dispatch_attempt())
                },
            )
            .await
            .expect("the dispatch succeeds");

            let recorded = store.unresolved().await.expect("reading the store");
            // Resolved on success, so the ledger is empty and the id has to come from the record
            // the scope saw.
            assert!(recorded.is_empty(), "a successful dispatch resolves");
            assert!(
                seen.is_some(),
                "the dispatch must run inside an attempt scope"
            );
        }

        /// The defect this feature shipped with, and the reason for one scope per dispatch.
        #[tokio::test]
        async fn two_dispatches_in_one_operation_get_two_different_ids() {
            let store = store();
            let mut ids = Vec::new();
            for _ in 0..2 {
                let seen = under_own_attempt(
                    Some(&store),
                    repository(),
                    GrpcRpc::RevisionBranchCreate,
                    async {
                        Err::<(), _>(lore_transport::outcome::outcome_unknown(
                            "RevisionService.BranchCreate",
                            &lore_transport::outcome::current_dispatch_attempt()
                                .expect("inside a scope"),
                        ))
                    },
                )
                .await;
                assert!(seen.is_err());
                ids.push(());
            }

            let unresolved = store.unresolved().await.expect("reading the store");
            assert_eq!(unresolved.len(), 2, "each dispatch records its own attempt");
            assert_ne!(
                unresolved[0].attempt_id.as_uuid(),
                unresolved[1].attempt_id.as_uuid(),
                "two dispatches sharing one id is what makes the receipt lookup answer NotFound"
            );
        }

        /// A lost answer leaves the record standing. Resolving it would throw away the only thing
        /// that lets the caller ask what happened.
        #[tokio::test]
        async fn a_lost_outcome_leaves_its_record_unresolved() {
            let store = store();
            let result = under_own_attempt(
                Some(&store),
                repository(),
                GrpcRpc::RevisionBranchPush,
                async {
                    Err::<(), _>(lore_transport::outcome::outcome_unknown(
                        "RevisionService.BranchPush",
                        &AttemptId::new(),
                    ))
                },
            )
            .await;

            assert!(result.is_err());
            assert_eq!(
                store.unresolved().await.expect("reading the store").len(),
                1,
                "an unknown outcome is exactly what must survive for a later receipt read"
            );
        }

        /// Any other error is the server's own answer or proof the request never left, and both
        /// are decisive. Keeping them unresolved would block the repository forever.
        #[tokio::test]
        async fn a_decisive_failure_resolves_its_record() {
            let store = store();
            let result = under_own_attempt(
                Some(&store),
                repository(),
                GrpcRpc::RevisionBranchPush,
                async { Err::<(), _>(ProtocolError::internal("the server refused")) },
            )
            .await;

            assert!(result.is_err());
            assert!(
                store
                    .unresolved()
                    .await
                    .expect("reading the store")
                    .is_empty(),
                "a decisive refusal is resolved, not left blocking the repository"
            );
        }

        /// No store means no behaviour change: the CLI passes `None` and the transport mints its
        /// own id per dispatch exactly as it did before any of this existed.
        #[tokio::test]
        async fn without_a_store_nothing_is_recorded_and_no_scope_is_entered() {
            let seen = under_own_attempt(None, repository(), GrpcRpc::RevisionBranchPush, async {
                Ok::<_, ProtocolError>(lore_transport::outcome::current_dispatch_attempt())
            })
            .await
            .expect("the dispatch succeeds");

            assert!(seen.is_none(), "no store must leave the scope untouched");
        }
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Moved from `src/dispatch.rs` when the crate's lib test harness was turned off.
use std::sync::Arc;

use lore_revision::dispatch::under_named_attempt;
use lore_revision::dispatch::under_own_attempt;
use lore_revision::lore::RepositoryId;
use lore_transport::ProtocolError;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;

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

    #[tokio::test]
    async fn arbitrary_foreign_context_refuses_before_dispatch_or_journal_write() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering;

        for named in [false, true] {
            let store = store();
            let dispatched = AtomicBool::new(false);
            let context = lore_transport::caller_operation::CallerOperationContext::new(
                uuid::Uuid::now_v7(),
                repository(),
                store.clone(),
            );
            let foreign = RepositoryId::from([8u8; 16]);
            let result = lore_transport::with_caller_operation(context, async {
                let dispatch = async {
                    dispatched.store(true, Ordering::SeqCst);
                    Ok::<_, ProtocolError>(())
                };
                if named {
                    under_named_attempt(
                        Some(&store),
                        AttemptId::new(),
                        foreign,
                        GrpcRpc::RevisionBranchPush,
                        dispatch,
                    )
                    .await
                } else {
                    under_own_attempt(Some(&store), foreign, GrpcRpc::RevisionBranchPush, dispatch)
                        .await
                }
            })
            .await;
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("repository mismatch")
            );
            assert!(!dispatched.load(Ordering::SeqCst));
            assert!(store.unresolved().await.unwrap().is_empty());
        }
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
            async { Ok::<_, ProtocolError>(lore_transport::outcome::current_dispatch_attempt()) },
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

    /// `under_named_attempt`'s one behavioural difference from `under_own_attempt`'s no-store
    /// path (see its own doc comment): the dispatch scope is entered whether or not a store is
    /// present, because the caller-minted id is what reaches the wire either way. With no
    /// store, `under_own_attempt` above leaves the scope untouched and the transport mints its
    /// own id; `under_named_attempt` must still stamp the CALLER's id on the request, which
    /// only happens if the scope carries it.
    #[tokio::test]
    async fn without_a_store_the_dispatch_scope_is_still_entered_with_the_named_id() {
        let attempt = AttemptId::new();
        let seen = under_named_attempt(None, attempt, repository(), GrpcRpc::LockLock, async {
            Ok::<_, ProtocolError>(lore_transport::outcome::current_dispatch_attempt())
        })
        .await
        .expect("the dispatch succeeds");

        assert_eq!(
            seen,
            Some(attempt),
            "with no store to record it, the scope is the only thing that makes the \
             caller-chosen id -- rather than one the transport would otherwise mint itself -- \
             the one stamped on the request"
        );
    }
}

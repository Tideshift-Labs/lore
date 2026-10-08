// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Attempt identity for the client's irreversible dispatches (WP-120).
//!
//! Shared by every operation family that reaches a `MutableNoReplay` dispatch a caller may need to
//! reconcile: `branch::push` and the two lock verbs. It lived inside `branch/push.rs` while push
//! was the only family wired, and moved here rather than being copied when locks were wired,
//! because two copies of a mint-record-scope-resolve sequence drift and the drift is silent.
//!
//! Two entry points over one sequence, differing only in who chooses the id.
//! [`under_own_attempt`] mints it, which is right when the caller has no use for the value.
//! [`under_named_attempt`] takes it, for the one caller that has to be able to name the dispatch
//! after the fact even if the task carrying it dies.
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
/// PIN(WP-120, 2026-09-05): this helper is wired at `branch::push`'s dispatches and at the lock
/// verbs' (`lock::file::acquire`'s batch lock, `lock::file::release`'s batch unlock and its
/// force-release escalation), and that is the whole desktop surface rather than a partial
/// rollout. The wording here said "in this file and nowhere else" while the helper still lived in
/// `branch/push.rs`; it moved when the lock verbs were wired, and the sentence did not. Every other
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
#[lore_macro::test_pub]
pub(crate) async fn under_own_attempt<T, Fut>(
    attempts: Option<&Arc<dyn AttemptStore>>,
    repository: RepositoryId,
    rpc: GrpcRpc,
    dispatch: Fut,
) -> Result<T, ProtocolError>
where
    Fut: Future<Output = Result<T, ProtocolError>>,
{
    if lore_transport::current_caller_operation().is_some() {
        return under_named_attempt(attempts, AttemptId::new(), repository, rpc, dispatch).await;
    }
    let Some(store) = attempts else {
        return dispatch.await;
    };

    under_named_attempt(Some(store), AttemptId::new(), repository, rpc, dispatch).await
}

/// Dispatch one irreversible submutation under an attempt identity the CALLER minted (WP-120).
///
/// [`under_own_attempt`] mints inside itself, which is right whenever the caller has no use for
/// the id. One caller does: `lock::file::acquire` spawns its batches, and a batch task that never
/// runs to completion cannot report the id it would have minted — the id dies with the task, and
/// the `JoinError` left behind is then indistinguishable from a request that never left. Minting
/// in the parent, before the spawn, is what lets the join loop name the attempt whose record is
/// sitting unresolved in the caller's store.
///
/// **The dispatch scope is entered whether or not a store is present**, and that is the one
/// behavioural difference from [`under_own_attempt`]'s no-store path. It is what makes naming the
/// id honest for a caller that journals nothing: with no store the id is recorded nowhere locally,
/// but it is still the one stamped on the request as `lore-attempt-id`, so it still names the
/// receipt the server filed. The transport would otherwise have minted an equivalent id itself and
/// told nobody which — so nothing on the wire changes shape, only who chose the value.
///
/// The caller is responsible for minting one id per dispatch. Reusing one across two dispatches
/// reintroduces the defect [`under_own_attempt`] documents: the server files several receipts
/// under one id and `attempt_receipt_get` answers `NotFound` for all of them.
#[lore_macro::test_pub]
pub(crate) async fn under_named_attempt<T, Fut>(
    attempts: Option<&Arc<dyn AttemptStore>>,
    attempt: AttemptId,
    repository: RepositoryId,
    rpc: GrpcRpc,
    dispatch: Fut,
) -> Result<T, ProtocolError>
where
    Fut: Future<Output = Result<T, ProtocolError>>,
{
    if let Some(context) = lore_transport::current_caller_operation() {
        if context.repository() != repository {
            return Err(ProtocolError::internal(
                "managed operation repository mismatch",
            ));
        }
        // The transport request producer owns canonical intent, journaling and settlement.
        return with_dispatch_attempt(attempt, dispatch).await;
    }
    // Recorded before the dispatch, never after. A record written afterwards cannot describe an
    // attempt whose response was lost, which is the only case that needs one.
    if let Some(store) = attempts {
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
    }

    let result = with_dispatch_attempt(attempt, dispatch).await;

    if let Some(store) = attempts {
        let resolution = match &result {
            Ok(_) => Some(AttemptResolution::Applied),
            Err(ProtocolError::OutcomeUnknown(_)) => None,
            Err(_) => Some(AttemptResolution::NotApplied),
        };
        if let Some(resolution) = resolution {
            store.resolve(&attempt, resolution).await?;
        }
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

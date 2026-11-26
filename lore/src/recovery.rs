// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Rust-only original-namespace receipt reads. Stored requests are never replayed.
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptStore;
use lore_transport::DomainAttemptReceipt;
use lore_transport::ProtocolError;
use uuid::Uuid;

pub async fn receipt_get(
    store: &RepositoryAttemptStore,
    attempt: &AttemptId,
) -> Result<DomainAttemptReceipt, ProtocolError> {
    let binding = store.recovery_context(attempt).await?;
    let dial_url = lore_transport::caller_operation::recovery_dial_url(&binding.endpoint)?;
    lore_transport::with_caller_recovery(binding.clone(), async {
        let connection = lore_transport::connection::connect(
            &dial_url,
            "",
            binding.repository,
            lore_transport::connection::MAX_STORAGE_CONNECTIONS,
            "",
            "",
            // A receipt read has no caller globals; follow the server's preference, as a call
            // that leaves `auth_mode` zeroed does.
            lore_transport::auth::AuthMode::Auto,
            // No caller globals either: the transport's default congestion control.
            None,
        )
        .await?;
        connection
            .domain_operations(binding.repository)
            .await?
            .attempt_receipt_get(attempt)
            .await
    })
    .await
}

/// Write admission for a managed command. When an earlier crash left the repository blocked,
/// run the same read-only reconcile `lore operation reconcile` runs, then admit again, so the
/// user does not have to know about reconcile. A child whose receipt stays nondecisive still
/// blocks, with the reconcile detail in the error.
pub async fn admit(root: &Path) -> Result<RepositoryMutationGuard, ProtocolError> {
    admit_with(root, |store, attempt| async move {
        receipt_get(&store, &attempt).await
    })
    .await
}

/// [`admit`] with an injected receipt reader.
pub async fn admit_with<F, Fut>(
    root: &Path,
    lookup: F,
) -> Result<RepositoryMutationGuard, ProtocolError>
where
    F: Fn(Arc<RepositoryAttemptStore>, AttemptId) -> Fut,
    Fut: Future<Output = Result<DomainAttemptReceipt, ProtocolError>>,
{
    if let Ok(guard) = RepositoryMutationGuard::acquire(root).await {
        return Ok(guard);
    }
    // Any refusal reaches here, but reconcile only reads receipts and settles what they
    // decide; a refusal it cannot change refuses again below.
    let detail = {
        let fence = RepositoryMutationGuard::recover(root).await?;
        reconcile(&fence, lookup).await.err()
    };
    RepositoryMutationGuard::acquire(root)
        .await
        .map_err(|error| match detail {
            Some(detail) => ProtocolError::internal(format!(
                "{error}\nAutomatic reconcile ran first and reported:\n{detail}"
            )),
            None => error,
        })
}

/// Query exact receipts for unresolved children and settle what they decide; never resend a
/// stored mutation. Returns every child or parent that stays blocked.
pub async fn reconcile<F, Fut>(
    fence: &RepositoryMutationGuard,
    lookup: F,
) -> Result<(), ProtocolError>
where
    F: Fn(Arc<RepositoryAttemptStore>, AttemptId) -> Fut,
    Fut: Future<Output = Result<DomainAttemptReceipt, ProtocolError>>,
{
    // Legacy Put, Copy and PutResolved children and childless parents need no server answer.
    fence.settle_receiptless().await?;
    // FORK-LOCAL (Tideshift): nor does a local commit journalled with its anchors.
    settle_local_commits(fence).await?;
    let mut blockers = Vec::new();
    for (source, store) in fence.recovery_stores() {
        for child in store.unresolved().await.map_err(|error| {
            ProtocolError::internal(format!("{source}: cannot read blockers: {error}"))
        })? {
            // Other storage mutations have no attributable receipt rail. Never infer their
            // result from content.
            if !lore_transport::caller_operation::has_receipt_reader(&child.operation) {
                blockers.push(format!(
                    "{source}: {} {} has no supported receipt reader; remains blocked",
                    child.attempt_id, child.operation
                ));
                continue;
            }
            if let Err(error) = store.recovery_context(&child.attempt_id).await {
                blockers.push(format!(
                    "{source}: {} cannot recover its recorded namespace: {error}; remains blocked",
                    child.attempt_id
                ));
                continue;
            }
            let receipt = match lookup(store.clone(), child.attempt_id).await {
                Ok(receipt) => receipt,
                Err(error) => {
                    blockers.push(format!(
                        "{source}: {} receipt unavailable: {error}; remains blocked",
                        child.attempt_id
                    ));
                    continue;
                }
            };
            // State before method: a lookup that found no receipt carries no method at all, and
            // checking the method first reported that absence as a method mismatch (Gate 0
            // campaign c13, 2026-10-13).
            let lore_transport::DomainReceiptState::Committed { outcome, .. } = &receipt.state
            else {
                blockers.push(format!(
                    "{source}: {} receipt is nondecisive ({}); remains blocked",
                    child.attempt_id,
                    receipt_state_label(&receipt.state)
                ));
                continue;
            };
            if !lore_transport::caller_operation::recovery_receipt_method_matches(
                &child.operation,
                &receipt.method,
            ) {
                blockers.push(format!(
                    "{source}: {} receipt method mismatch; remains blocked",
                    child.attempt_id
                ));
                continue;
            }
            let resolution = match outcome {
                lore_transport::DomainReceiptOutcome::Applied => {
                    lore_transport::AttemptResolution::Applied
                }
                lore_transport::DomainReceiptOutcome::NotApplied { .. } => {
                    lore_transport::AttemptResolution::NotApplied
                }
            };
            // Before the child settles: an applied acquire keeps its tokens and an applied release
            // clears them, exactly as the live verb would have. A failure keeps the child blocked.
            if let Err(error) = lore_revision::lock::recovered::settle_recovered_ownership(
                fence.root(),
                &store,
                &child.attempt_id,
                &child.operation,
                &receipt,
            )
            .await
            {
                blockers.push(format!(
                    "{source}: {} lock ownership not recovered: {error}; remains blocked",
                    child.attempt_id
                ));
                continue;
            }
            store.resolve(&child.attempt_id, resolution).await?;
        }
        for parent in store
            .managed_parents()
            .await?
            .iter()
            .filter(|parent| !parent.complete)
        {
            let id = Uuid::parse_str(&parent.id)
                .map_err(|_err| lore_transport::ProtocolError::internal("invalid parent UUID"))?;
            if let Err(error) = store.reconcile_parent(id).await {
                blockers.push(format!("{source}: {} remains blocked: {error}", parent.id));
            }
        }
    }
    if blockers.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::internal(blockers.join("\n")))
    }
}

/// FORK-LOCAL (Tideshift): settles, from the working copy's own anchors, every unresolved child
/// journalled with local commit evidence (see [`lore_revision::local_commit_evidence`]), then
/// closes each parent that evidence proved had no effect. Reads no receipt and resends nothing.
/// A child whose anchors prove nothing, or that cannot be read, stays unresolved. Returns
/// whether anything settled or closed.
///
/// Runs inside an execution context, under a recovery fence.
pub async fn settle_local_commits(fence: &RepositoryMutationGuard) -> Result<bool, ProtocolError> {
    // Inside a running workflow the child may be the body's own, mid-commit: its anchors have
    // not moved yet, and that must never read as NotApplied.
    if !fence.holds_admission_lock() {
        return Err(ProtocolError::internal(
            "cannot settle local commits inside a running managed workflow",
        ));
    }
    let mut pending = Vec::new();
    for (source, store) in fence.recovery_stores() {
        let found = store.unresolved_local_commits().await.map_err(|error| {
            ProtocolError::internal(format!("{source}: cannot read local commits: {error}"))
        })?;
        if !found.is_empty() {
            pending.push((store, found));
        }
    }
    if pending.is_empty() {
        return Ok(false);
    }
    if lore_revision::runtime::try_execution_context().is_none() {
        // Opening the working copy needs a command's context; without one nothing settles.
        return Ok(false);
    }
    let repository = lore_revision::repository::load_and_connect(
        fence.root(),
        lore_revision::repository::RepositoryAccess::ReadOnly,
    )
    .await
    .map_err(|error| ProtocolError::internal(format!("opening the working copy: {error}")))?;
    let mut changed = false;
    for (store, found) in pending {
        for (attempt, operation, evidence) in found {
            match lore_revision::local_commit_evidence::decide(&repository, &evidence).await {
                Ok(Some(resolution)) => {
                    lore_revision::lore_info!(
                        "Settled local commit {attempt} ({operation}) from local anchors: \
                         {resolution:?}"
                    );
                    store.resolve(&attempt, resolution).await?;
                    changed = true;
                }
                Ok(None) => {}
                Err(error) => {
                    lore_revision::lore_warn!(
                        "Local commit {attempt} ({operation}) stays unresolved: {error}"
                    );
                }
            }
        }
        changed |= store.close_parents_without_effect().await?;
    }
    Ok(changed)
}

/// FORK-LOCAL (Tideshift): reads, offline and in its own execution context, the anchors a local
/// commit of the working copy at `root` would move, for
/// `RepositoryAttemptStore::record_local_commit_child`. Fails where the working copy has no such
/// evidence (links, layers, a shared store) or a read fails; the caller then journals the child
/// without it, which leaves a lost outcome blocked as before.
pub async fn capture_local_commit_evidence(
    root: &Path,
) -> Result<lore_revision::local_commit_evidence::LocalCommitEvidence, ProtocolError> {
    let globals = lore_revision::interface::LoreGlobalArgs {
        repository_path: root.to_string_lossy().as_ref().into(),
        offline: 1,
        ..Default::default()
    };
    let execution = Arc::new(lore_revision::interface::ExecutionContext::new_client(
        globals,
        lore_revision::relay::EventDispatcher::default(),
    ));
    lore_base::runtime::LORE_CONTEXT
        .scope(execution, async {
            let repository = lore_revision::repository::load_and_connect(
                root,
                lore_revision::repository::RepositoryAccess::ReadOnly,
            )
            .await
            .map_err(|error| {
                ProtocolError::internal(format!("opening the working copy: {error}"))
            })?;
            lore_revision::local_commit_evidence::capture(&repository).await
        })
        .await
}

/// FORK-LOCAL (Tideshift): [`settle_local_commits`] for an embedder outside any command: takes a
/// recovery fence on the working copy at `root` (refused while a workflow runs there) and settles
/// in its own offline execution context. Returns whether anything settled or closed.
pub async fn settle_local_commits_at(root: &Path) -> Result<bool, ProtocolError> {
    let globals = lore_revision::interface::LoreGlobalArgs {
        repository_path: root.to_string_lossy().as_ref().into(),
        offline: 1,
        ..Default::default()
    };
    let execution = Arc::new(lore_revision::interface::ExecutionContext::new_client(
        globals,
        lore_revision::relay::EventDispatcher::default(),
    ));
    lore_base::runtime::LORE_CONTEXT
        .scope(execution, async {
            let fence = RepositoryMutationGuard::recover(root).await?;
            settle_local_commits(&fence).await
        })
        .await
}

/// FORK-LOCAL (Tideshift): write admission that first settles local commits from local anchors
/// ([`settle_local_commits`]) when the working copy is blocked, then admits again. Reads nothing
/// remote. Any other refusal, and a blocked copy local evidence cannot clear, refuses as
/// [`RepositoryMutationGuard::acquire`] does.
pub async fn acquire_settling_local_commits(
    root: &Path,
    execution: &Arc<lore_revision::interface::ExecutionContext>,
) -> Result<RepositoryMutationGuard, ProtocolError> {
    let refusal = match RepositoryMutationGuard::acquire(root).await {
        Ok(guard) => return Ok(guard),
        Err(refusal) => refusal,
    };
    // Offline: a settlement inside admission must not reach the network (a not-found branch
    // latest, for one, falls back to a metadata read that can go remote). Its own dispatcher, so
    // it emits nothing on the caller's event stream. The recovery fence holds the admission lock
    // and is dropped before admitting again.
    let mut globals = execution.globals().clone();
    globals.offline = 1;
    let offline = Arc::new(lore_revision::interface::ExecutionContext::new_client(
        globals,
        lore_revision::relay::EventDispatcher::default(),
    ));
    let settled = lore_base::runtime::LORE_CONTEXT
        .scope(offline, async {
            let fence = RepositoryMutationGuard::recover(root).await?;
            settle_local_commits(&fence).await
        })
        .await;
    match settled {
        Ok(true) => RepositoryMutationGuard::acquire(root).await,
        Ok(false) => Err(refusal),
        Err(error) => {
            lore_revision::lore_warn!("Local commit recovery did not run: {error}");
            Err(refusal)
        }
    }
}

/// The name an operator reads for a receipt state that cannot settle an attempt.
fn receipt_state_label(state: &lore_transport::DomainReceiptState) -> &'static str {
    match state {
        lore_transport::DomainReceiptState::Prepared { .. } => "prepared, not committed",
        lore_transport::DomainReceiptState::Committed { .. } => "committed",
        lore_transport::DomainReceiptState::Mismatch => "identity mismatch",
        lore_transport::DomainReceiptState::Expired => "expired",
        lore_transport::DomainReceiptState::ExpiredOrUnknown => "expired or unknown",
        lore_transport::DomainReceiptState::NotFound => "no receipt found",
    }
}

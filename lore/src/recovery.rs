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
            Some(detail) => ProtocolError::internal(format!("{error}\n{detail}")),
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
    let mut blockers = Vec::new();
    for (source, store) in fence.recovery_stores() {
        for child in store.unresolved().await.map_err(|error| {
            ProtocolError::internal(format!("{source}: cannot read blockers: {error}"))
        })? {
            // Other storage mutations have no attributable receipt rail. Never infer their
            // result from content.
            if !matches!(
                child.operation.as_str(),
                "RevisionService.BranchPush"
                    | "RevisionService.BranchCreate"
                    | "LockService.Lock"
                    | "LockService.Unlock"
                    | "LockService.ForceUnlock"
            ) {
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

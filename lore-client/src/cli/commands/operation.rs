// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use lore::interface::LoreGlobalArgs;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptStore;
use lore_transport::DomainAttemptReceipt;
use lore_transport::ProtocolError;
use uuid::Uuid;

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;

#[derive(clap::Args)]
pub struct OperationArgs {
    #[command(subcommand)]
    pub command: OperationCommands,
}

#[derive(clap::Subcommand)]
pub enum OperationCommands {
    /// List durable workflow identities and unresolved children.
    Status,
    /// Query exact receipts without sending stored mutation requests.
    Reconcile,
}

pub fn handle(globals: LoreGlobalArgs, args: &OperationArgs) -> u8 {
    lore::runtime().block_on(async {
        let result = match args.command {
            OperationCommands::Status => status(&globals).await,
            OperationCommands::Reconcile => reconcile(globals).await,
        };
        match result {
            Ok(()) => 0,
            Err(error) => {
                crate::eprintln!("{error}");
                255 // Internal (-1) as a process exit status.
            }
        }
    })
}

async fn status(globals: &LoreGlobalArgs) -> Result<(), lore_transport::ProtocolError> {
    let fence =
        RepositoryMutationGuard::recover(Path::new(globals.repository_path.as_str())).await?;
    for line in status_lines(&fence).await? {
        crate::println!("{line}");
    }
    Ok(())
}

async fn status_lines(fence: &RepositoryMutationGuard) -> Result<Vec<String>, ProtocolError> {
    let mut lines = Vec::new();
    for (source, store) in fence.recovery_stores() {
        let parents = store.managed_parents().await.map_err(|error| {
            ProtocolError::internal(format!("{source}: cannot read blockers: {error}"))
        })?;
        for parent in parents.iter().filter(|parent| !parent.complete) {
            lines.push(format!(
                "{source}: {} {} pending (body_completed={}, parent_uncertainty_code={:?})",
                parent.id, parent.operation, parent.body_completed, parent.parent_uncertainty_code,
            ));
        }
        for child in store.unresolved().await.map_err(|error| {
            ProtocolError::internal(format!("{source}: cannot read blockers: {error}"))
        })? {
            let recovery = match store.recovery_context(&child.attempt_id).await {
                Ok(_) => "recorded namespace".to_owned(),
                Err(error) => format!("recovery unavailable: {error}"),
            };
            lines.push(format!(
                "{source}: {} {} unknown ({recovery})",
                child.attempt_id, child.operation,
            ));
        }
    }
    Ok(lines)
}

async fn reconcile(globals: LoreGlobalArgs) -> Result<(), lore_transport::ProtocolError> {
    let fence =
        RepositoryMutationGuard::recover(Path::new(globals.repository_path.as_str())).await?;
    reconcile_stores(&fence, |store, attempt| async move {
        lore::recovery::receipt_get(&store, &attempt).await
    })
    .await
}

async fn reconcile_stores<F, Fut>(
    fence: &RepositoryMutationGuard,
    lookup: F,
) -> Result<(), ProtocolError>
where
    F: Fn(Arc<RepositoryAttemptStore>, AttemptId) -> Fut,
    Fut: Future<Output = Result<DomainAttemptReceipt, ProtocolError>>,
{
    let mut blockers = Vec::new();
    for (source, store) in fence.recovery_stores() {
        for child in store.unresolved().await.map_err(|error| {
            ProtocolError::internal(format!("{source}: cannot read blockers: {error}"))
        })? {
            // Storage has no attributable receipt rail. Never infer its result from content.
            if !matches!(
                child.operation.as_str(),
                "RevisionService.BranchPush"
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
            if let lore_transport::DomainReceiptState::Committed { outcome, .. } = receipt.state {
                let resolution = match outcome {
                    lore_transport::DomainReceiptOutcome::Applied => {
                        lore_transport::AttemptResolution::Applied
                    }
                    lore_transport::DomainReceiptOutcome::NotApplied { .. } => {
                        lore_transport::AttemptResolution::NotApplied
                    }
                };
                store.resolve(&child.attempt_id, resolution).await?;
            } else {
                blockers.push(format!(
                    "{source}: {} receipt is nondecisive; remains blocked",
                    child.attempt_id
                ));
            }
        }
        for parent in store
            .managed_parents()
            .await?
            .iter()
            .filter(|parent| !parent.complete)
        {
            let id = Uuid::parse_str(&parent.id)
                .map_err(|_| lore_transport::ProtocolError::internal("invalid parent UUID"))?;
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

/// Explicit CLI adoption for the supported push and lock families.
pub async fn managed<F, Fut>(
    globals: &LoreGlobalArgs,
    operation: &str,
    intent: String,
    command: F,
) -> i32
where
    F: FnOnce(Arc<dyn AttemptStore>) -> Fut,
    Fut: Future<Output = i32>,
{
    let result = async {
        let fence =
            RepositoryMutationGuard::acquire(Path::new(globals.repository_path.as_str())).await?;
        let parent = Uuid::now_v7();
        let store = fence.begin(parent, operation.to_owned(), intent).await?;
        let status = fence
            .run(lore_transport::with_managed_caller(
                parent,
                store.clone(),
                command(store.clone()),
            ))
            .await;
        // A crash before this proof, or an unnameable resource, cannot be cleared by
        // receipts for named children alone.
        if status == 194 {
            if let Err(error) = store.mark_parent_uncertain(parent, status).await {
                crate::eprintln!("{error}");
            }
        } else {
            store.complete_parent_body(parent).await?;
        }
        if status != 193 && status != 194 {
            fence.finish(parent).await?;
        }
        Ok::<_, lore_transport::ProtocolError>(status)
    }
    .await;
    match result {
        Ok(status) => status,
        Err(error) => {
            crate::eprintln!("{error}");
            -1 // Internal journal/admission error, not a receipt outcome.
        }
    }
}

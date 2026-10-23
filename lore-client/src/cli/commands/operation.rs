// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use lore::interface::LoreGlobalArgs;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::lore_base::error::OutcomeUnknown;
use lore_revision::lore_base::error::UnnameableResource;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptStore;
use lore_transport::DomainAttemptReceipt;
use lore_transport::ProtocolError;
use uuid::Uuid;

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

#[lore_macro::test_pub]
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

#[lore_macro::test_pub]
async fn reconcile_stores<F, Fut>(
    fence: &RepositoryMutationGuard,
    lookup: F,
) -> Result<(), ProtocolError>
where
    F: Fn(Arc<RepositoryAttemptStore>, AttemptId) -> Fut,
    Fut: Future<Output = Result<DomainAttemptReceipt, ProtocolError>>,
{
    lore::recovery::reconcile(fence, lookup).await
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
        let fence = lore::recovery::admit(Path::new(globals.repository_path.as_str())).await?;
        let parent = Uuid::now_v7();
        let store = fence.begin(parent, operation.to_owned(), intent).await?;
        let status = fence
            .run(lore_transport::with_managed_caller(
                parent,
                store.clone(),
                command(store.clone()),
            ))
            .await;
        // A crash before this proof leaves the parent open. The next admission closes it only
        // when no child needs a server answer (none, or settled fragment Puts); otherwise
        // receipts alone cannot clear it. An unnameable resource always stays open.
        if status == UnnameableResource::FFI_CODE {
            if let Err(error) = store.mark_parent_uncertain(parent, status).await {
                crate::eprintln!("{error}");
            }
        } else {
            store.complete_parent_body(parent).await?;
        }
        if status != OutcomeUnknown::FFI_CODE && status != UnnameableResource::FFI_CODE {
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

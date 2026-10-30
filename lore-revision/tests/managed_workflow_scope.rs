// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! [CLIENT] WP-124: the managed workflow scope (`lore_transport::with_managed_workflow`) and
//! `carry_managed_wait_scope`.
//!
//! A managed push (`lore::branch::push_managed`) has no caller operation until each
//! `ManagedPushRunner::run_stage`, yet it opens the repository (and its connect) first. The
//! workflow scope marks that whole span as managed for waiting, without making it a managed caller:
//! a stage must still be admitted inside it, and a stage inside a real caller operation is still
//! refused. `carry_managed_wait_scope` moves the scope across a spawn, as a marker only.
#![allow(clippy::disallowed_methods)] // This suite's owned temporary worktrees only.

use std::sync::Arc;

use lore_base::types::RepositoryId;
use lore_revision::managed_push::ManagedPushRunner;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptStore;
use lore_transport::CallerOperationContext;
use lore_transport::ProtocolError;
use lore_transport::VolatileAttemptStore;
use uuid::Uuid;

fn worktree() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temp directory");
    std::fs::create_dir(directory.path().join(".lore")).expect(".lore directory");
    directory
}

async fn runner(directory: &tempfile::TempDir) -> ManagedPushRunner {
    let guard = RepositoryMutationGuard::acquire(directory.path())
        .await
        .expect("the repository fence");
    ManagedPushRunner::new(Arc::new(guard), None)
}

fn operation() -> CallerOperationContext {
    CallerOperationContext::new(
        Uuid::new_v4(),
        RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    )
}

/// What each scope answers to the three questions a wait asks.
#[tokio::test]
async fn the_scopes_answer_the_three_predicates_as_documented() {
    let flags = || {
        (
            lore_transport::has_managed_caller(),
            lore_transport::in_managed_workflow(),
            lore_transport::in_managed_wait_scope(),
        )
    };

    assert_eq!(flags(), (false, false, false), "outside every scope");
    assert_eq!(
        lore_transport::with_managed_workflow(async { flags() }).await,
        (false, true, true),
        "a workflow is not a managed caller, but its waits are managed"
    );
    let attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    assert_eq!(
        lore_transport::caller_operation::with_managed_caller(Uuid::new_v4(), attempts, async {
            flags()
        })
        .await,
        (true, false, true),
        "a managed caller is not a workflow"
    );
    assert_eq!(
        lore_transport::with_caller_operation(operation(), async { flags() }).await,
        (true, false, true),
        "a caller operation is a managed caller"
    );
}

/// The stage a managed push opens must still be admitted inside the workflow, and it becomes a
/// managed caller for its own span.
#[tokio::test]
async fn a_stage_inside_a_managed_workflow_is_admitted() {
    let directory = worktree();
    let runner = runner(&directory).await;

    let result = lore_transport::with_managed_workflow(runner.run_stage(
        RepositoryId::from([0x24u8; 16]),
        "workflow stage",
        async { Ok::<_, ProtocolError>(lore_transport::has_managed_caller()) },
    ))
    .await;

    assert!(
        result.expect("a stage inside a workflow must be admitted"),
        "the stage body runs as a managed caller"
    );
}

/// A stage nested in a real caller operation stays refused: the workflow scope did not widen what
/// `run_stage` admits.
#[tokio::test]
async fn a_stage_inside_a_caller_operation_is_still_refused() {
    let directory = worktree();
    let runner = runner(&directory).await;

    let result = lore_transport::with_caller_operation(
        operation(),
        runner.run_stage(RepositoryId::from([0x24u8; 16]), "nested stage", async {
            Ok::<_, ProtocolError>(())
        }),
    )
    .await;

    let error = result.expect_err("a stage nested in a caller operation must be refused");
    assert!(
        error.to_string().contains("Cannot nest")
            || format!("{error:?}").contains("Cannot nest a managed push stage"),
        "refused for the nesting rule: {error:?}"
    );
}

/// What a task spawned through `carry_managed_wait_scope` sees: the wait scope crosses the spawn
/// from either managed scope, but the spawned task is never a managed caller, and an unmanaged
/// spawner passes nothing on.
#[tokio::test]
async fn a_carried_task_keeps_the_wait_scope_but_is_never_a_managed_caller() {
    let spawn_probe = || {
        lore_base::lore_spawn!(lore_transport::carry_managed_wait_scope(async {
            (
                lore_transport::has_managed_caller(),
                lore_transport::in_managed_workflow(),
                lore_transport::in_managed_wait_scope(),
            )
        }))
    };

    let from_workflow = lore_transport::with_managed_workflow(async { spawn_probe().await })
        .await
        .expect("probe task");
    assert_eq!(from_workflow, (false, true, true), "from a workflow");

    let from_caller =
        lore_transport::with_caller_operation(operation(), async { spawn_probe().await })
            .await
            .expect("probe task");
    assert_eq!(from_caller, (false, true, true), "from a caller operation");

    let attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    let from_managed_caller =
        lore_transport::caller_operation::with_managed_caller(Uuid::new_v4(), attempts, async {
            spawn_probe().await
        })
        .await
        .expect("probe task");
    assert_eq!(
        from_managed_caller,
        (false, true, true),
        "from a managed caller"
    );

    let from_unmanaged = spawn_probe().await.expect("probe task");
    assert_eq!(
        from_unmanaged,
        (false, false, false),
        "an unmanaged spawner passes no scope on"
    );

    // An uncarried spawn from a managed workflow loses the scope, which is why the carry exists.
    let uncarried = lore_transport::with_managed_workflow(async {
        lore_base::lore_spawn!(async { lore_transport::in_managed_wait_scope() }).await
    })
    .await
    .expect("probe task");
    assert!(!uncarried, "a plain spawn does not cross the scope");
}

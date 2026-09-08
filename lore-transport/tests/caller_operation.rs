// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] Explicit product contexts. Run with `--features test_seams`.
#![cfg(feature = "test_seams")]

use std::sync::Arc;

use lore_base::types::RepositoryId;
use lore_transport::VolatileAttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::current_caller_operation;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::caller_operation::with_optional_caller_operation;
use uuid::Uuid;

fn context() -> CallerOperationContext {
    CallerOperationContext::new(
        Uuid::now_v7(),
        RepositoryId::from([1; 16]),
        Arc::new(VolatileAttemptStore::new()),
    )
}

#[tokio::test]
async fn a_store_or_context_value_alone_does_not_declare_adoption() {
    let operation = context();
    assert!(current_caller_operation().is_none());
    assert_eq!(operation.capabilities(), "outcome_unknown_v1");
    assert!(current_caller_operation().is_none());
    let id = with_caller_operation(operation.clone(), async {
        current_caller_operation().unwrap().parent_id()
    })
    .await;
    assert_eq!(id, operation.parent_id());
    assert!(current_caller_operation().is_none());
}

#[tokio::test]
async fn concurrent_scopes_and_explicit_empty_nested_scope_are_isolated() {
    let a = context();
    let b = context();
    let a_id = a.parent_id();
    let b_id = b.parent_id();
    let barrier = tokio::sync::Barrier::new(2);
    let (actual_a, actual_b) = tokio::join!(
        with_caller_operation(a, async {
            barrier.wait().await;
            with_optional_caller_operation(None, async {
                assert!(current_caller_operation().is_none());
            })
            .await;
            current_caller_operation().unwrap().parent_id()
        }),
        with_caller_operation(b, async {
            barrier.wait().await;
            tokio::task::yield_now().await;
            current_caller_operation().unwrap().parent_id()
        })
    );
    assert_eq!((actual_a, actual_b), (a_id, b_id));
    assert!(current_caller_operation().is_none());
}

#[tokio::test]
async fn spawned_work_carries_only_the_explicitly_captured_operation() {
    let operation = context();
    let id = operation.parent_id();
    with_caller_operation(operation, async {
        let captured = current_caller_operation();
        let managed = lore_base::lore_spawn!(with_optional_caller_operation(captured, async {
            current_caller_operation().unwrap().parent_id()
        }));
        let undeclared = lore_base::lore_spawn!(async { current_caller_operation().is_none() });
        assert_eq!(managed.await.unwrap(), id);
        assert!(undeclared.await.unwrap());
    })
    .await;
    assert!(current_caller_operation().is_none());
}

#[tokio::test]
async fn dropping_a_pending_scoped_future_clears_its_declaration() {
    let mut pending = Box::pin(with_caller_operation(context(), async {
        assert!(current_caller_operation().is_some());
        std::future::pending::<()>().await;
    }));
    assert!(futures::poll!(&mut pending).is_pending());
    assert!(current_caller_operation().is_none());
    drop(pending);
    assert!(current_caller_operation().is_none());
}

#[test]
fn only_status_nine_with_one_exact_marker_is_unsupported_client() {
    for code in [
        tonic::Code::FailedPrecondition,
        tonic::Code::Unknown,
        tonic::Code::Unavailable,
        tonic::Code::Internal,
    ] {
        for marker in [
            None,
            Some("unsupported-client"),
            Some("Unsupported-client"),
            Some("unsupported-client-v2"),
        ] {
            for duplicates in [false, true] {
                let mut status = tonic::Status::new(code, "unsupported client capability");
                if let Some(marker) = marker {
                    status
                        .metadata_mut()
                        .insert("lore-client-admission-v1", marker.parse().unwrap());
                    if duplicates {
                        status
                            .metadata_mut()
                            .append("lore-client-admission-v1", marker.parse().unwrap());
                    }
                }
                let expected = code == tonic::Code::FailedPrecondition
                    && marker == Some("unsupported-client")
                    && !duplicates;
                let error = lore_transport::ProtocolError::from(status);
                assert_eq!(
                    lore_transport::error::is_unsupported_client(&error),
                    expected,
                    "code={code:?}, marker={marker:?}, duplicate={duplicates}, error={error:?}"
                );
            }
        }
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use lore_base::error::Disconnected;
use lore_base::error::OutcomeUnknown;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_error_set::FfiError;
use lore_revision::immutable::*;
use lore_revision::interface::ExecutionContext;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::relay::EventDispatcher;
use lore_revision::repository::RemoteState;
use lore_revision::repository::RepositoryContext;
use lore_storage::Fragment;
use lore_storage::options::ReadOptions;
use lore_storage::options::WriteOptions;
use lore_transport::ProtocolError;
use lore_transport::StorageSession;
use zerocopy::FromZeros;

/// A context carrying the given remote state, on in-memory stores so
/// everything but the remote is valid.
async fn context_with_state(state: RemoteState) -> Arc<RepositoryContext> {
    let (immutable, mutable) = lore_revision::repository::create_client_memory_stores()
        .await
        .expect("in-memory stores should be creatable");
    Arc::new(RepositoryContext::new_with_state(
        None,
        immutable,
        mutable,
        lore_revision::lore::RepositoryId::default(),
        lore_revision::instance::InstanceId::default(),
        state,
        Arc::default(),
        None,
    ))
}

/// Build and run the future `body` returns under an execution context, which is where the
/// correlation id a session is attributed to comes from. The future is built inside the
/// context, as a wrapper resolves its session when built.
async fn under_execution_context<F: Future>(body: impl FnOnce() -> F) -> F::Output {
    let execution = Arc::new(ExecutionContext::new_client(
        LoreGlobalArgs::default(),
        EventDispatcher::no_dispatch(),
    ));
    LORE_CONTEXT
        .scope(execution, async move { body().await })
        .await
}

/// An address nothing has stored, so a read of it reaches the point where a
/// session would have been used.
fn absent_address() -> Address {
    Address {
        hash: Hash::from([0xa5u8; 32]),
        context: Context::from([0xa5u8; 16]),
    }
}

/// A pool for the context to hold, with the strong reference left to the caller
/// and the one session in it to compare a pick against. That session is never
/// resolved: the test asks which pool answered, not what it yields.
fn held_pool() -> (Arc<lore_transport::SessionPool>, Arc<StorageSession>) {
    let session = Arc::new(StorageSession::pending(|| async {
        Err(ProtocolError::internal(
            "a pooled session this test never resolves",
        ))
    }));
    (
        Arc::new(lore_transport::SessionPool::new(vec![session.clone()])),
        session,
    )
}

#[tokio::test]
async fn remote_put_predispatch_refusal_returns_typed_error_without_panicking_or_retrying() {
    let resolutions = Arc::new(AtomicUsize::new(0));
    let calls = resolutions.clone();
    let session = Arc::new(StorageSession::pending(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        async {
            Err(ProtocolError::internal(
                "managed dispatch cannot bind credential namespace",
            ))
        }
    }));
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        store_raw_remote_retry(session, absent_address(), Fragment::new_zeroed(), None),
    )
    .await
    .expect("a decisive refusal must return without the SlowDown retry schedule")
    .expect_err("the refused session must never report a successful put");
    assert!(matches!(&error, ImmutableError::Internal(_)));
    assert!(format!("{error:?}").contains("managed dispatch cannot bind credential namespace"));
    assert_eq!(resolutions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn remote_put_preserves_the_exact_unknown_attempt_without_retrying() {
    let resolutions = Arc::new(AtomicUsize::new(0));
    let calls = resolutions.clone();
    let attempt = uuid::Uuid::now_v7().to_string();
    let returned_attempt = attempt.clone();
    let session = Arc::new(StorageSession::pending(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        let attempt_id = returned_attempt.clone();
        async move {
            Err(OutcomeUnknown {
                operation: "StorageService.Put".to_owned(),
                attempt_id,
            }
            .into())
        }
    }));
    let error = store_raw_remote_retry(session, absent_address(), Fragment::new_zeroed(), None)
        .await
        .expect_err("an unknown attempt is never a successful put");
    assert_eq!(error.ffi_code(), 248);
    let ImmutableError::OutcomeUnknown(unknown) = error else {
        panic!("the typed unknown result must survive the immutable layer");
    };
    assert_eq!(unknown.operation, "StorageService.Put");
    assert_eq!(unknown.attempt_id, attempt);
    assert_eq!(resolutions.load(Ordering::SeqCst), 1);
}
/// What a read or write ends up using comes from the pool the context holds.
/// This context's connect has failed, so reaching the pool at all is proof the
/// session was not looked up through the connection per call.
#[tokio::test]
async fn a_pooled_session_comes_from_the_pool_the_context_holds() {
    let context = context_with_state(RemoteState::Failed(ProtocolError::from(Disconnected))).await;
    let (pool, pooled) = held_pool();
    context.set_session_pool(&pool);

    let session = pooled_session(&context, "correlation")
        .await
        .expect("the pool the context holds answers, remote or no remote");
    assert!(Arc::ptr_eq(&session, &pooled));
}

/// A context with no remote has nothing a session could resolve to, so the
/// read and write paths take their local-only route rather than carrying one
/// per fragment and failing it.
#[tokio::test]
async fn an_offline_context_resolves_no_session() {
    let context = context_with_state(RemoteState::Offline).await;
    let session = under_execution_context(|| async { resolve_session(&context) }).await;
    assert!(session.is_none());
}

/// The context holds the session it is handed, so the session may not hold the
/// context back. A strong reference in the resolver is a cycle neither end can
/// free, and the command that built it completes with the context still alive.
#[tokio::test]
async fn a_resolved_session_does_not_keep_the_context_alive() {
    let context = context_with_state(RemoteState::Failed(ProtocolError::from(Disconnected))).await;
    let weak = Arc::downgrade(&context);

    under_execution_context(|| async { resolve_session(&context) })
        .await
        .expect("a context that is not offline resolves a session");

    drop(context);
    assert_eq!(weak.strong_count(), 0);
}

/// A failed connect is an answer a session carries, so one is still built: the
/// failure belongs in the error the read or write reports.
#[tokio::test]
async fn a_failed_connect_still_resolves_a_session() {
    let context = context_with_state(RemoteState::Failed(ProtocolError::from(Disconnected))).await;
    let session = under_execution_context(|| async { resolve_session(&context) })
        .await
        .expect("a context that is not offline resolves a session");
    assert!(
        session.is_lazy(),
        "the read path invalidates the session and retries that same one, \
             which only a lazy session resolves again"
    );
}

/// A write on a context with no remote stores locally and reports success,
/// which is what a write carrying a session reported: the upload's outcome only
/// sets the durable flag, it never fails the write.
#[tokio::test]
async fn a_write_on_an_offline_context_stores_locally() {
    let context = context_with_state(RemoteState::Offline).await;
    let payload = Bytes::from_static(b"content with no remote to go to");
    // Boxed: the write pipeline's future sits at the crate's `future-size-threshold`.
    let address = under_execution_context(|| {
        Box::pin(write(
            context.clone(),
            Context::from([0x5au8; 16]),
            payload.clone(),
            WriteOptions::default().with_remote_write(),
        ))
    })
    .await
    .expect("a write with no remote still stores locally");

    let stored = under_execution_context(|| read(context, address, None, ReadOptions::default()))
        .await
        .expect("what was stored reads back");
    assert_eq!(stored, payload);
}

/// Skipping the session on an offline context reports what carrying one
/// reported: a resolver finding no remote maps to the address not being found,
/// which is what no session at all reports.
#[tokio::test]
async fn a_miss_on_an_offline_context_reports_the_address_not_found() {
    let context = context_with_state(RemoteState::Offline).await;
    let err =
        under_execution_context(|| load_raw(context, absent_address(), ReadOptions::default()))
            .await
            .expect_err("nothing was ever stored under that address");
    assert!(err.is_address_not_found(), "reported {err:?}");
}

/// A read handed the last reference to its context holds the context until it completes, so
/// its session, which holds the context weakly, still reaches the pool the context holds rather
/// than finding no remote.
#[tokio::test]
async fn a_read_handed_the_last_context_reference_reaches_the_pool() {
    let context = context_with_state(RemoteState::Failed(ProtocolError::from(Disconnected))).await;
    let (pool, _pooled) = held_pool();
    context.set_session_pool(&pool);

    let err =
        under_execution_context(|| read(context, absent_address(), None, ReadOptions::default()))
            .await
            .expect_err("the pooled session never resolves");
    assert!(!err.is_address_not_found(), "reported {err:?}");
}

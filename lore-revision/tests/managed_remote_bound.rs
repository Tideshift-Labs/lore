// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! [CLIENT] WP-124: a managed caller waiting on a repository's background connect gives up at the
//! managed bound.
//!
//! `connect()` runs the remote connect, and the session-pool pre-warm behind it, in a `lore_spawn!`
//! task. That task does not carry the managed task-locals, so a QUIC reconnect inside it has no
//! deadline, and a managed push waiting on the shared future in `RepositoryContext::remote()` hung
//! for minutes with the UDP path blocked. `remote()` now races the wait against
//! `lore_transport::quic::client::managed_wait_bound()` for a managed caller, returns the typed
//! `managed_connect_expired()` marker, and leaves the state `Pending`.
//!
//! Why a separate binary: the bound comes from the process-wide `LORE_QUIC_MANAGED_IDLE_TIMEOUT`,
//! read each time `remote()` runs. Setting it in the shared `tests/unit` binary would change the
//! bound for every test there. Here every test wants the same short value, so it is set once
//! before any test body runs and nothing else in the process is affected.
//!
//! The realistic case drives a real QUIC reconnect (the scripted `lore-storage/0.4` peer that
//! `lore-transport`'s own bound tests use, included by path so the two cannot drift) inside a
//! `lore_spawn!`ed task, exactly the shape `connect()` builds. The managed-push case runs
//! `push_with_runner` against a real on-disk repository.
#![allow(clippy::disallowed_methods)] // Fixture temp directories only.

use std::sync::Arc;
use std::sync::Once;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use futures::FutureExt;
use futures::future::BoxFuture;
use lore_base::error::Disconnected;
use lore_base::error::NoRemote;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_error_set::FfiError;
use lore_revision::branch::push::PushOptions;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::lore::RepositoryId;
use lore_revision::repository::RemoteFuture;
use lore_revision::repository::RemoteState;
use lore_revision::repository::RepositoryAccess;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryWriteToken;
use lore_transport::AttemptStore;
use lore_transport::ProtocolError;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::VolatileAttemptStore;
use lore_transport::quic::storage_service::client::StorageClient;
use tokio::sync::oneshot;
use uuid::Uuid;

// The peer is `lore-transport`'s. Not every helper is used here.
#[allow(dead_code)]
#[path = "../../lore-transport/tests/unit/quic/scripted_storage_peer.rs"]
mod scripted_storage_peer;

use scripted_storage_peer::Peer;

/// The managed bound, in whole seconds (the variable's unit).
const BOUND_SECS: u64 = 1;
const BOUND: Duration = Duration::from_secs(BOUND_SECS);

/// Longer than any correct expiry. A missing bound must fail red here, not hang the suite.
const HANG_GUARD: Duration = Duration::from_secs(20);

/// Set once, before the first test body reads it.
fn short_bound() {
    static SET: Once = Once::new();
    SET.call_once(|| {
        // SAFETY: runs before any test in this binary reads the variable, and every test sets the
        // same value.
        unsafe {
            std::env::set_var("LORE_QUIC_MANAGED_IDLE_TIMEOUT", BOUND_SECS.to_string());
        }
    });
}

fn disconnected() -> ProtocolError {
    ProtocolError::from(Disconnected)
}

fn no_remote() -> ProtocolError {
    ProtocolError::from(NoRemote)
}

/// A context carrying `state`, with in-memory stores. Only `remote()` is exercised.
async fn context_with_state(state: RemoteState) -> Arc<RepositoryContext> {
    let (immutable, mutable) = lore_revision::repository::create_client_memory_stores()
        .await
        .expect("in-memory stores should be creatable");
    Arc::new(RepositoryContext::new_with_state(
        None,
        immutable,
        mutable,
        RepositoryId::default(),
        lore_revision::instance::InstanceId::default(),
        state,
        Arc::default(),
        None,
    ))
}

/// A shared connect that resolves to `result` once the returned sender fires.
fn gated_remote(
    result: Result<Arc<lore_transport::Connection>, ProtocolError>,
) -> (oneshot::Sender<()>, RemoteFuture) {
    let (open, gate) = oneshot::channel::<()>();
    let future: BoxFuture<'static, _> = async move {
        let _ = gate.await;
        result
    }
    .boxed();
    (open, future.shared())
}

/// Run `future` as a managed caller, as an embedder does before it opens the repository.
async fn managed<F: std::future::Future>(future: F) -> F::Output {
    let attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    lore_transport::caller_operation::with_managed_caller(Uuid::new_v4(), attempts, future).await
}

/// `remote()` as a managed caller, ended by the hang guard if the bound is missing.
async fn managed_remote(
    context: &RepositoryContext,
) -> (
    Result<Arc<lore_transport::Connection>, ProtocolError>,
    Duration,
) {
    let started = Instant::now();
    let result = tokio::time::timeout(HANG_GUARD, managed(context.remote()))
        .await
        .expect("a managed remote() never ended: the connect wait is unbounded");
    (result, started.elapsed())
}

fn assert_expired(
    result: &Result<Arc<lore_transport::Connection>, ProtocolError>,
    elapsed: Duration,
) {
    let error = match result {
        Ok(_) => panic!("a connect that has not finished cannot yield a connection"),
        Err(error) => error,
    };
    assert!(
        lore_transport::is_managed_reconnect_expired(error),
        "wrong error at the bound: {error:?}"
    );
    assert!(
        elapsed >= BOUND - Duration::from_millis(200),
        "gave up before the bound: {elapsed:?}"
    );
    assert!(
        elapsed < BOUND + Duration::from_secs(5),
        "outlasted the bound: {elapsed:?}"
    );
}

async fn assert_pending(context: &RepositoryContext, what: &str) {
    assert!(
        matches!(*context.remote.read().await, RemoteState::Pending(_)),
        "{what}: the state must stay Pending after the wait is dropped"
    );
}

/// The defect in miniature: a pending connect nobody resolves ends a managed `remote()` at the
/// bound, with the typed marker, and the state is not promoted.
#[tokio::test]
async fn a_managed_remote_on_a_pending_connect_ends_at_the_bound_and_stays_pending() {
    short_bound();
    let (_keep_pending, shared) = gated_remote(Err(disconnected()));
    let context = context_with_state(RemoteState::Pending(shared)).await;

    let (result, elapsed) = managed_remote(&context).await;

    assert_expired(&result, elapsed);
    assert_pending(&context, "after the first expiry").await;
}

/// A caller inside a `CallerOperationContext` scope is managed too (`has_managed_caller` is true for
/// either scope), so it gets the same bound.
#[tokio::test]
async fn a_remote_inside_a_caller_operation_scope_also_ends_at_the_bound() {
    short_bound();
    let (_keep_pending, shared) = gated_remote(Err(disconnected()));
    let context = context_with_state(RemoteState::Pending(shared)).await;

    let operation = lore_transport::CallerOperationContext::new(
        Uuid::new_v4(),
        lore_base::types::RepositoryId::from([0x24u8; 16]),
        Arc::new(VolatileAttemptStore::new()),
    );
    let started = Instant::now();
    let result = tokio::time::timeout(
        HANG_GUARD,
        lore_transport::with_caller_operation(operation, context.remote()),
    )
    .await
    .expect("a remote() in a caller-operation scope never ended");

    assert_expired(&result, started.elapsed());
    assert_pending(&context, "caller-operation scope").await;
}

/// The realistic shape. The connect is a `lore_spawn!`ed task driving a real QUIC reconnect against
/// a peer that went away. The task is outside the caller's managed scope, so its reconnect loop has
/// no deadline and is still running when the managed `remote()` gives up.
#[tokio::test]
async fn a_managed_remote_ends_at_the_bound_while_a_spawned_quic_reconnect_still_runs() {
    short_bound();
    let partition = Partition::from(Context::from([0x31u8; 16]));
    let peer = Peer::start();
    let client = StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "",
        "managed-remote-bound",
        partition,
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer");
    let (session, _) = client
        .session_start_declared(partition, "managed-remote-bound", "outcome_unknown_v1")
        .await
        .expect("declared session");

    // The server goes away: every connection and the endpoint close, so a reconnect handshake
    // fails or times out for real.
    peer.stop();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;

    let finished = Arc::new(AtomicBool::new(false));
    let task_finished = finished.clone();
    // The same spawn `connect()` uses, so the task-locals are lost the same way. An unmanaged read
    // on the dead connection runs the full reconnect loop.
    let handle: tokio::task::JoinHandle<Result<Arc<lore_transport::Connection>, ProtocolError>> =
        lore_base::lore_spawn!(async move {
            let address = Address::zero_context_hash(Hash::from([0x5Au8; 32]));
            let outcome = client.get(session, &address).await;
            task_finished.store(true, Ordering::SeqCst);
            match outcome {
                Ok(_) => Err(ProtocolError::internal("the read cannot succeed")),
                Err(error) => Err(error),
            }
        });
    let abort = handle.abort_handle();
    let shared: RemoteFuture = async move {
        handle
            .await
            .unwrap_or_else(|_| Err(ProtocolError::internal("connect task failed")))
    }
    .boxed()
    .shared();
    let context = context_with_state(RemoteState::Pending(shared)).await;

    let (result, elapsed) = managed_remote(&context).await;

    assert_expired(&result, elapsed);
    assert!(
        !finished.load(Ordering::SeqCst),
        "the reconnect loop must still be running when the managed caller gives up"
    );
    assert_pending(&context, "realistic reconnect").await;

    abort.abort();
    drop(peer);
}

/// Control: an unmanaged `remote()` is not bounded. It is still waiting well past the bound, and
/// when the connect resolves it returns the connect's own result and promotes the state.
#[tokio::test]
async fn an_unmanaged_remote_keeps_waiting_and_returns_the_connects_own_result() {
    short_bound();
    for (result, expect_offline) in [(disconnected(), false), (no_remote(), true)] {
        let (open, shared) = gated_remote(Err(result.clone()));
        let context = context_with_state(RemoteState::Pending(shared)).await;
        assert!(!lore_transport::has_managed_caller());

        let still_waiting = tokio::time::timeout(BOUND * 2 + BOUND / 2, context.remote()).await;
        assert!(
            still_waiting.is_err(),
            "an unmanaged remote() ended at the managed bound"
        );
        assert_pending(&context, "an unmanaged wait that was dropped").await;

        open.send(())
            .expect("the shared future still holds the gate");
        let resolved = context.remote().await;
        let error = resolved.err().expect("the connect resolved to an error");
        assert!(
            !lore_transport::is_managed_reconnect_expired(&error),
            "an unmanaged caller must see the connect's own error: {error:?}"
        );
        assert_eq!(error.to_string(), result.to_string());
        let promoted = context.remote.read().await;
        if expect_offline {
            assert!(matches!(*promoted, RemoteState::Offline));
        } else {
            assert!(matches!(*promoted, RemoteState::Failed(_)));
        }
    }
}

/// Control: a managed caller whose connect resolves inside the bound gets the connect's own result
/// and the usual promotion. The bound is a deadline, not an unconditional failure.
#[tokio::test]
async fn a_managed_remote_that_resolves_inside_the_bound_returns_its_result_and_promotes() {
    short_bound();
    let (open, shared) = gated_remote(Err(disconnected()));
    let context = context_with_state(RemoteState::Pending(shared)).await;
    open.send(())
        .expect("the gate is held by the shared future");

    let (result, elapsed) = managed_remote(&context).await;

    let error = result.err().expect("the connect resolved to an error");
    assert!(matches!(error, ProtocolError::Disconnected(_)), "{error:?}");
    assert!(!lore_transport::is_managed_reconnect_expired(&error));
    assert!(
        elapsed < BOUND,
        "a resolved connect waited for the bound: {elapsed:?}"
    );
    assert!(matches!(
        *context.remote.read().await,
        RemoteState::Failed(_)
    ));
}

/// After one expiry the context is not wedged: a second managed call also ends at the bound (no
/// hang, still Pending), and once the connect resolves a later call returns its result. The
/// connect's real `Arc<Connection>` comes from the live fixture, so the Connected promotion is
/// the production one.
#[tokio::test]
async fn a_managed_remote_expires_again_after_an_expiry_then_returns_the_resolved_connect() {
    short_bound();
    // The whole body, drops included, runs in an execution context: the fixture reads it.
    LORE_CONTEXT
        .scope(
            fixture_execution_context(),
            Box::pin(expires_again_then_resolves()),
        )
        .await;
}

async fn expires_again_then_resolves() {
    let server = LockServer::start().await;
    let fixture = LiveRepository::create(&server.remote_url()).await;
    let live = fixture.connect(RepositoryAccess::ReadOnly).await;
    let connection = live.remote().await.expect("the fixture remote connects");

    let (open, shared) = gated_remote(Ok(connection.clone()));
    let context = context_with_state(RemoteState::Pending(shared)).await;

    let (first, first_elapsed) = managed_remote(&context).await;
    assert_expired(&first, first_elapsed);
    assert_pending(&context, "after the first expiry").await;

    let (second, second_elapsed) = managed_remote(&context).await;
    assert_expired(&second, second_elapsed);
    assert_pending(&context, "after the second expiry").await;

    open.send(())
        .expect("the gate is held by the shared future");
    let (third, _) = managed_remote(&context).await;
    let resolved = third.expect("the resolved connect is returned to a later managed call");
    assert!(Arc::ptr_eq(&resolved, &connection));
    assert!(matches!(
        *context.remote.read().await,
        RemoteState::Connected(_)
    ));
}

/// A managed push whose remote never connects fails with the Disconnected code an embedder reads
/// (28), not Internal (-1). `remote()` is awaited inside `collect_fragments_and_push`, so the
/// marker passes through `not_sent_reads_disconnected` on its way out.
#[tokio::test]
async fn a_managed_push_whose_remote_never_connects_fails_with_ffi_code_disconnected() {
    short_bound();
    Box::pin(LORE_CONTEXT.scope(fixture_execution_context(), Box::pin(push_with_no_remote())))
        .await;
}

async fn push_with_no_remote() {
    let server = LockServer::start().await;
    let fixture = LiveRepository::create(&server.remote_url()).await;
    let path = fixture.path.clone();

    let token = RepositoryWriteToken::acquire(path.as_path()).await;
    let repository = lore_revision::repository::load_and_connect_with_token(
        path.as_path(),
        RepositoryAccess::ReadWrite,
        Some(token.share()),
    )
    .await
    .expect("opening the fixture repository");
    // The background connect never finishes.
    let (_keep_pending, never) = gated_remote(Err(disconnected()));
    *repository.remote.write().await = RemoteState::Pending(never);

    let started = Instant::now();
    let result = tokio::time::timeout(
        HANG_GUARD,
        managed(Box::pin(lore_revision::branch::push::push_with_runner(
            repository.clone(),
            &token,
            PushOptions::default(),
            None,
            None,
        ))),
    )
    .await
    .expect("a managed push never ended: the connect wait is unbounded");
    let elapsed = started.elapsed();

    let error = result.expect_err("a push with no remote cannot succeed");
    assert_eq!(
        error.ffi_code(),
        lore_base::error::Disconnected::FFI_CODE,
        "expected Disconnected (28), not Internal (-1): {error:?}"
    );
    assert_eq!(lore_base::error::Disconnected::FFI_CODE, 28);
    assert!(elapsed >= BOUND - Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < BOUND + Duration::from_secs(5), "{elapsed:?}");
    assert_pending(&repository, "after the push gave up").await;
    drop(fixture);
}

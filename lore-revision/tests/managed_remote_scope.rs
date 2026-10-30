// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! [CLIENT] WP-124: `RepositoryContext::remote()` for a managed command.
//!
//! `connect()` runs the remote connect, and the session-pool pre-warm behind it, in a `lore_spawn!`
//! task. A spawn drops every managed task-local, so a QUIC reconnect in that task had no deadline
//! and a managed push hung for minutes with the UDP path blocked. The fix is not a cap on how long
//! `remote()` may wait: `connect()` wraps the task in `carry_managed_wait_scope`, so the reconnect
//! inside it gets the per-command managed deadline, and a pre-warm that expires resolves the shared
//! connect to the not-sent marker. `remote()` itself is a plain await.
//!
//! What this binary pins at the `lore-revision` layer (the full QUIC order is
//! `lore-integration-tests/tests/quic_managed_push_hang_test.rs`):
//! - `remote()` has no total-time cap: a slow connect that outlasts the bound still resolves.
//! - A spawned QUIC reconnect that carried the managed scope ends at the bound and resolves the
//!   shared connect to the marker; one that did not carry it is unbounded (the defect).
//! - An unmanaged `remote()` is unchanged.
//! - A push whose remote resolved to the marker reports ffi 28 (`Disconnected`).
#![allow(clippy::disallowed_methods)] // Fixture temp directories only.

use std::sync::Arc;
use std::sync::Weak;
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

/// The managed reconnect deadline the QUIC client in these tests carries.
const BOUND: Duration = Duration::from_secs(2);

/// A wait that outlasts the bound by a clear margin.
const SLOW: Duration = Duration::from_millis(5_500);

/// Longer than any correct end. A missing deadline must fail red here, not hang the suite.
const HANG_GUARD: Duration = Duration::from_secs(40);

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

/// A real `Connection`, from the live fixture, for the cases that need an `Ok` connect.
async fn live_connection() -> (LockServer, Arc<lore_transport::Connection>) {
    let server = LockServer::start().await;
    let connection = LORE_CONTEXT
        .scope(fixture_execution_context(), async {
            let fixture = LiveRepository::create(&server.remote_url()).await;
            let live = fixture.connect(RepositoryAccess::ReadOnly).await;
            let connection = live.remote().await.expect("the fixture remote connects");
            drop(live);
            drop(fixture);
            connection
        })
        .await;
    (server, connection)
}

/// No total-time cap. A managed `remote()` on a connect that takes several bounds to finish waits
/// for it and returns its connection, from either managed scope.
#[tokio::test]
async fn a_slow_connect_in_a_managed_scope_is_not_cut_off() {
    let (_server, connection) = live_connection().await;

    for scope in ["managed caller", "managed workflow"] {
        let (open, shared) = gated_remote(Ok(connection.clone()));
        let context = context_with_state(RemoteState::Pending(shared)).await;
        let opener = tokio::spawn(async move {
            tokio::time::sleep(SLOW).await;
            let _ = open.send(());
        });

        let started = Instant::now();
        let wait = async {
            if scope == "managed caller" {
                managed(context.remote()).await
            } else {
                lore_transport::with_managed_workflow(context.remote()).await
            }
        };
        let resolved = tokio::time::timeout(HANG_GUARD, wait)
            .await
            .expect("remote() never returned");
        opener.await.expect("opener task");

        let resolved = resolved.unwrap_or_else(|error| {
            panic!("{scope}: a slow but healthy connect was cut off: {error:?}")
        });
        assert!(Arc::ptr_eq(&resolved, &connection), "{scope}");
        assert!(
            started.elapsed() >= SLOW - Duration::from_millis(200),
            "{scope}"
        );
        assert!(
            matches!(*context.remote.read().await, RemoteState::Connected(_)),
            "{scope}: promoted to Connected"
        );
    }
}

/// The realistic shape. The connect is a spawned task driving a real QUIC reconnect against a peer
/// that went away. Spawned from a managed workflow with the scope carried (what `connect()` does),
/// the reconnect ends at the bound, the shared connect resolves to the not-sent marker, and
/// `remote()` returns it.
// The scope has to be entered around the spawn itself, so the block yields the spawned handle.
#[allow(clippy::async_yields_async)]
#[tokio::test]
async fn a_carried_spawned_reconnect_resolves_the_connect_to_the_marker_at_the_bound() {
    let (peer, client, session) = dead_quic_client().await;

    let started = Instant::now();
    let shared = lore_transport::with_managed_workflow(async {
        shared_connect(spawn_get(client, session, true))
    })
    .await;
    let context = context_with_state(RemoteState::Pending(shared)).await;
    let result = tokio::time::timeout(HANG_GUARD, context.remote())
        .await
        .expect("remote() never returned: the spawned reconnect has no deadline");
    let elapsed = started.elapsed();

    let error = result
        .err()
        .expect("an unreachable server ends the connect");
    assert!(
        lore_transport::is_managed_reconnect_expired(&error),
        "{error:?}"
    );
    assert!(elapsed >= BOUND - Duration::from_millis(500), "{elapsed:?}");
    assert!(elapsed < BOUND + Duration::from_secs(8), "{elapsed:?}");
    assert!(matches!(
        *context.remote.read().await,
        RemoteState::Failed(_)
    ));
    drop(peer);
}

/// Control, the defect: the same spawn without the carry loses the managed scope and is still
/// reconnecting well past twice the bound.
// The scope has to be entered around the spawn itself, so the block yields the spawned handle.
#[allow(clippy::async_yields_async)]
#[tokio::test]
async fn an_uncarried_spawned_reconnect_has_no_deadline() {
    let (peer, client, session) = dead_quic_client().await;

    let spawned =
        lore_transport::with_managed_workflow(async { spawn_get(client, session, false) }).await;
    let abort = spawned.abort_handle();
    let context = context_with_state(RemoteState::Pending(shared_connect(spawned))).await;
    let still_waiting =
        tokio::time::timeout(BOUND * 2 + Duration::from_secs(1), context.remote()).await;
    assert!(
        still_waiting.is_err(),
        "a spawn that did not carry the managed scope must not end at the bound"
    );
    abort.abort();
    drop(peer);
}

/// Control: carrying from an unmanaged task adds no deadline.
#[tokio::test]
async fn a_carried_spawned_reconnect_from_an_unmanaged_task_is_unbounded() {
    let (peer, client, session) = dead_quic_client().await;

    let spawned = spawn_get(client, session, true);
    let abort = spawned.abort_handle();
    let context = context_with_state(RemoteState::Pending(shared_connect(spawned))).await;
    let still_waiting =
        tokio::time::timeout(BOUND * 2 + Duration::from_secs(1), context.remote()).await;
    assert!(
        still_waiting.is_err(),
        "an unmanaged connect must keep reconnecting past the managed bound"
    );
    abort.abort();
    drop(peer);
}

/// A QUIC client whose server is gone: the connection is closed and the port is dead, with the
/// managed reconnect deadline shortened to [`BOUND`].
async fn dead_quic_client() -> (Peer, StorageClient, u32) {
    let partition = Partition::from(Context::from([0x31u8; 16]));
    let peer = Peer::start();
    let client = StorageClient::connect(
        Weak::new(),
        &peer.url(),
        "127.0.0.1".to_string(),
        "",
        "managed-remote-scope",
        partition,
        &Arc::new(SuppliedCredentials::default()),
        None,
    )
    .await
    .expect("connect to the scripted peer");
    use lore_transport::quic::client::ServiceClient;
    client.quic().set_managed_idle_for_test(BOUND);
    let (session, _) = client
        .session_start_declared(partition, "managed-remote-scope", "outcome_unknown_v1")
        .await
        .expect("declared session");
    peer.stop();
    peer.wait_until("the connection to close", |peer| {
        peer.closed_connections() == peer.accepted_connections()
    })
    .await;
    (peer, client, session)
}

type ConnectTask = tokio::task::JoinHandle<Result<Arc<lore_transport::Connection>, ProtocolError>>;

/// An unmanaged read on the dead connection, spawned the way `connect()` spawns its task,
/// optionally carrying the spawner's managed scope.
fn spawn_get(client: StorageClient, session: u32, carry: bool) -> ConnectTask {
    let read = async move {
        let address = Address::zero_context_hash(Hash::from([0x5Au8; 32]));
        match client.get(session, &address).await {
            Ok(_) => Err(ProtocolError::internal("the read cannot succeed")),
            Err(error) => Err(error),
        }
    };
    if carry {
        lore_base::lore_spawn!(lore_transport::carry_managed_wait_scope(read))
    } else {
        lore_base::lore_spawn!(read)
    }
}

/// The shared connect future `connect()` builds around its task.
fn shared_connect(handle: ConnectTask) -> RemoteFuture {
    async move {
        handle
            .await
            .unwrap_or_else(|_| Err(ProtocolError::internal("connect task failed")))
    }
    .boxed()
    .shared()
}

/// Control: an unmanaged `remote()` is unchanged. It waits for as long as the connect takes and
/// returns the connect's own result, promoting the state.
#[tokio::test]
async fn an_unmanaged_remote_waits_and_returns_the_connects_own_result() {
    for (result, expect_offline) in [(disconnected(), false), (no_remote(), true)] {
        let (open, shared) = gated_remote(Err(result.clone()));
        let context = context_with_state(RemoteState::Pending(shared)).await;
        assert!(!lore_transport::in_managed_wait_scope());

        let still_waiting = tokio::time::timeout(BOUND, context.remote()).await;
        assert!(still_waiting.is_err(), "the connect has not resolved yet");
        assert!(matches!(
            *context.remote.read().await,
            RemoteState::Pending(_)
        ));

        open.send(())
            .expect("the shared future still holds the gate");
        let error = context
            .remote()
            .await
            .err()
            .expect("the connect resolved to an error");
        assert_eq!(error.to_string(), result.to_string());
        let promoted = context.remote.read().await;
        if expect_offline {
            assert!(matches!(*promoted, RemoteState::Offline));
        } else {
            assert!(matches!(*promoted, RemoteState::Failed(_)));
        }
    }
}

/// A push whose remote resolved to the not-sent marker (a pre-warm that expired) reports ffi code
/// 28 (`Disconnected`), not `Internal` (-1). `remote()` is awaited inside
/// `collect_fragments_and_push`, so the marker passes through `not_sent_reads_disconnected`.
#[tokio::test]
async fn a_push_whose_remote_resolved_to_the_marker_fails_with_ffi_code_disconnected() {
    LORE_CONTEXT
        .scope(
            fixture_execution_context(),
            Box::pin(push_with_marker_remote()),
        )
        .await;
}

async fn push_with_marker_remote() {
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
    let (open, expired) = gated_remote(Err(lore_transport::managed_reconnect_expired_for_test(
        "session",
    )));
    open.send(())
        .expect("the gate is held by the shared future");
    *repository.remote.write().await = RemoteState::Pending(expired);

    let error = Box::pin(lore_revision::branch::push::push_with_runner(
        repository.clone(),
        &token,
        PushOptions::default(),
        None,
        None,
    ))
    .await
    .expect_err("a push with an expired remote cannot succeed");

    assert_eq!(
        error.ffi_code(),
        lore_base::error::Disconnected::FFI_CODE,
        "expected Disconnected (28), not Internal (-1): {error:?}"
    );
    assert_eq!(lore_base::error::Disconnected::FFI_CODE, 28);
    drop(repository);
    drop(fixture);
}

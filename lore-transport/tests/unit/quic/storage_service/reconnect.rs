// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Sessions across a reconnect: a server numbers each connection's sessions from 1, so a session
//! the client started on one connection is started again on the next before a command runs under
//! it, and an id from the first never reaches the second.
//!
//! FORK-LOCAL (Tideshift, merge D-QS1): upstream 5c88e6e7 re-issues a session inside the QUIC
//! storage client, under a client-local id. The fork keeps CR-026: the client refuses a stale id at
//! the write boundary before any byte is sent, and [`StorageSession`] rebinds and resends once. So
//! these tests drive their commands through a `StorageSession`, the layer that rebinds, rather than
//! through raw `Storage` ids. Every command here is a read or a session start; none is a dispatched
//! mutation, so none of them exercises the no-resend rule (that is pinned by the managed send and
//! reconnect bound tests).

use std::sync::Arc;
use std::time::Duration;

use lore_base::lore_spawn_net;
use lore_base::types::Partition;
use lore_transport::Connection;
use lore_transport::StorageSession;
use lore_transport::traits::Storage;
use tokio::task::JoinSet;

use super::test_server::SessionStarts;
use super::test_server::TestStorageServer;
use super::test_server::test_address;
use super::test_server::test_partition;
use super::test_server::wait_until;

/// A partition other than [`test_partition`].
fn other_partition() -> Partition {
    Partition::from([0x5du8; 16])
}

/// A session for `partition` on `storage`, bound to the connection generation its start was framed
/// on, as the connector builds one.
async fn session_on(storage: &Arc<dyn Storage>, partition: Partition) -> Arc<StorageSession> {
    let (session_id, generation) = storage
        .session_start_bound(partition, "test")
        .await
        .expect("session start");
    Arc::new(StorageSession::resolved(
        storage.clone(),
        Connection::detached(Vec::new()),
        session_id,
        generation,
        partition,
        Arc::from("test"),
    ))
}

/// A command on a session after its connection is lost reconnects, starts the session again on the
/// new connection, and runs under it there, as a priority command after it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_after_a_reconnect_runs_under_its_session_issued_again() {
    let server = TestStorageServer::start();
    let storage = server.connect(1).await.remove(0);
    let session = session_on(&storage, test_partition()).await;
    session.get(&test_address(0)).await.expect("fetch");

    storage.close().await;
    session
        .get(&test_address(1))
        .await
        .expect("fetch after the reconnect");
    session
        .get_priority(&test_address(2))
        .await
        .expect("priority fetch after the reconnect");

    assert_eq!(server.started_sessions_per_connection(), vec![1, 1]);
    assert_eq!(server.gets_per_connection(), vec![1, 2]);
}

/// Sessions started again after a reconnect each run their commands under their own partition, in
/// whatever order they are started: the first started on the new connection takes the id another
/// held on the old one, which that other's command must not run under.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_issued_again_after_a_reconnect_keep_their_own_partitions() {
    let server = TestStorageServer::start();
    let storage = server.connect(1).await.remove(0);
    let first = session_on(&storage, test_partition()).await;
    let second = session_on(&storage, other_partition()).await;
    first.get(&test_address(0)).await.expect("fetch");

    storage.close().await;
    second
        .get(&test_address(1))
        .await
        .expect("fetch on the second session");
    first
        .get(&test_address(2))
        .await
        .expect("fetch on the first session");

    assert_eq!(
        server.served_partitions_per_connection(),
        vec![
            vec![test_partition()],
            vec![other_partition(), test_partition()]
        ]
    );
}

/// Commands that find their session stale at once after a reconnect all complete, each under the
/// session started on the new connection, and none reaches the server under the old id. Each
/// command may start at most one replacement (its one rebind), so the starts are bounded by the
/// commands; the fork does not promise a single shared start here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_after_a_reconnect_issue_their_session_once() {
    const COMMANDS: usize = 32;
    let server = TestStorageServer::start();
    let storage = server.connect(1).await.remove(0);
    let session = session_on(&storage, test_partition()).await;
    session.get(&test_address(0)).await.expect("fetch");

    storage.close().await;
    let mut fetches = JoinSet::new();
    for index in 1..=COMMANDS {
        let session = session.clone();
        lore_spawn_net!(
            fetches,
            async move { session.get(&test_address(index)).await }
        );
    }
    while let Some(fetched) = fetches.join_next().await {
        fetched
            .expect("fetch task")
            .expect("fetch after the reconnect");
    }

    let started = server.started_sessions_per_connection();
    assert_eq!(started.len(), 2, "one reconnect: {started:?}");
    assert_eq!(started[0], 1);
    assert!(
        (1..=COMMANDS as u32).contains(&started[1]),
        "at most one replacement start per command: {started:?}"
    );
    assert_eq!(server.gets_per_connection(), vec![1, COMMANDS as u64]);
    assert_eq!(
        server.received_gets_per_connection(),
        vec![1, COMMANDS as u64],
        "no command reached the new connection under its old id"
    );
}

/// Stopping a session the client started before a reconnect, and has not started since, stops
/// nothing on the new connection, where its old id names another session: the stop is refused at
/// the write boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_stopped_after_a_reconnect_stops_no_session_of_the_new_connection() {
    let server = TestStorageServer::start();
    let storage = server.connect(1).await.remove(0);
    let first = session_on(&storage, test_partition()).await;
    let second = session_on(&storage, other_partition()).await;

    storage.close().await;
    second
        .get(&test_address(0))
        .await
        .expect("fetch on the second session");
    // The first session's last reference: its stop is generation-checked and sends nothing.
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    second
        .get(&test_address(1))
        .await
        .expect("fetch on the second session after the first stopped");

    assert_eq!(server.live_sessions_per_connection()[1], 1);
}

/// A command on a session the client stopped is refused without reaching the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_command_on_a_stopped_session_is_not_sent() {
    let server = TestStorageServer::start();
    let storage = server.connect(1).await.remove(0);
    let session = storage
        .session_start(test_partition(), "test")
        .await
        .expect("session start");
    storage.session_stop(session).await.expect("session stop");

    // Refused at the write boundary: the stop forgot the id, so it is current on no connection.
    assert!(storage.get(session, &test_address(0)).await.is_err());
    assert_eq!(server.received_gets_per_connection(), vec![0]);
}

/// A session started again on the connection a reconnect opens, then stopped, leaves no session
/// open on that connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_issued_again_and_stopped_leaves_no_session_open() {
    let server = TestStorageServer::start();
    let storage = server.connect(1).await.remove(0);
    let session = session_on(&storage, test_partition()).await;

    storage.close().await;
    session
        .get(&test_address(0))
        .await
        .expect("fetch after the reconnect");
    drop(session);

    wait_until(
        || server.live_sessions_per_connection()[1] == 0,
        "the session started again was never stopped",
    )
    .await;
}

/// A stop requested while its session is started again (the last reference dropped while a command
/// still holds it) stops the session that start opened once the command ends, so none is left open
/// on the connection the reconnect opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_while_its_session_is_issued_again_leaves_no_session_open() {
    let (server, release) = TestStorageServer::start_holding_session_starts();
    release
        .send(true)
        .expect("the server answers the first start");
    let storage = server.connect(1).await.remove(0);
    let session = session_on(&storage, test_partition()).await;
    release
        .send(false)
        .expect("the server holds the next start");

    storage.close().await;
    let fetching = {
        let session = session.clone();
        lore_spawn_net!(async move { session.get(&test_address(0)).await })
    };
    wait_until(
        || server.started_sessions_per_connection() == [1, 1],
        "the session was not started again",
    )
    .await;
    drop(session);
    release
        .send(true)
        .expect("the server answers the held start");
    let _ = fetching.await.expect("fetch task");

    wait_until(
        || server.live_sessions_per_connection()[1] == 0,
        "the session started again was never stopped",
    )
    .await;
}

/// A start the server refuses after a reconnect reaches the command as the server's `SlowDown`,
/// for it to back off on, and a later command starts the session once the server accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_issue_reaches_the_command_and_a_later_one_issues_the_session() {
    let (server, starts) = TestStorageServer::start_controlling_session_starts();
    let storage = server.connect(1).await.remove(0);
    let session = session_on(&storage, test_partition()).await;
    starts
        .send(SessionStarts::Refuse)
        .expect("the server refuses starts");

    storage.close().await;
    let refused = session
        .get(&test_address(0))
        .await
        .expect_err("the start is refused");
    assert!(refused.is_slow_down(), "{refused}");
    starts
        .send(SessionStarts::Accept)
        .expect("the server accepts starts");
    session
        .get(&test_address(1))
        .await
        .expect("fetch once the server accepts");

    assert_eq!(server.started_sessions_per_connection(), vec![1, 1]);
    assert_eq!(server.gets_per_connection(), vec![0, 1]);
}

/// Commands that find their session stale while its start waits on the server each receive the
/// refusal it ends in, and none of them is sent. The fork shares a start only through the rebind
/// guard (a refused start is not handed to the callers queued behind it, unlike a managed-bound
/// expiry), so each command asks for at most one start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_waiting_for_a_refused_issue_each_receive_its_refusal() {
    const COMMANDS: usize = 32;
    let (server, starts) = TestStorageServer::start_controlling_session_starts();
    let storage = server.connect(1).await.remove(0);
    let session = session_on(&storage, test_partition()).await;
    starts
        .send(SessionStarts::Hold)
        .expect("the server holds starts");

    storage.close().await;
    let mut fetches = JoinSet::new();
    for index in 0..COMMANDS {
        let session = session.clone();
        lore_spawn_net!(
            fetches,
            async move { session.get(&test_address(index)).await }
        );
    }
    wait_until(
        || server.requested_session_starts_per_connection().get(1) == Some(&1),
        "no command asked for the session's start",
    )
    .await;
    starts
        .send(SessionStarts::Refuse)
        .expect("the server refuses the held start");
    while let Some(fetched) = fetches.join_next().await {
        let refused = fetched
            .expect("fetch task")
            .expect_err("the start is refused");
        assert!(refused.is_slow_down(), "{refused}");
    }

    let requested = server.requested_session_starts_per_connection();
    assert_eq!(requested[0], 1);
    assert!(
        (1..=COMMANDS as u32).contains(&requested[1]),
        "at most one start per command: {requested:?}"
    );
    assert_eq!(server.received_gets_per_connection(), vec![0, 0]);
}

/// A command dropped while the server holds its session's start does not wedge the session: a
/// later command starts it again if it has to and runs under a session of the new connection.
/// (Upstream runs the start to its end as a task of its own; the fork's start runs inside the
/// command, so a dropped command may leave the server one session that the connection reaps.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_issue_whose_command_is_dropped_issues_the_session() {
    let (server, starts) = TestStorageServer::start_controlling_session_starts();
    let storage = server.connect(1).await.remove(0);
    let session = session_on(&storage, test_partition()).await;
    starts
        .send(SessionStarts::Hold)
        .expect("the server holds starts");

    storage.close().await;
    let fetching = {
        let session = session.clone();
        lore_spawn_net!(async move { session.get(&test_address(0)).await })
    };
    wait_until(
        || server.requested_session_starts_per_connection() == [1, 1],
        "the session was not started again",
    )
    .await;
    fetching.abort();
    assert!(fetching.await.is_err_and(|join| join.is_cancelled()));
    starts
        .send(SessionStarts::Accept)
        .expect("the server answers the held start");
    session
        .get(&test_address(1))
        .await
        .expect("fetch after the dropped command");

    let started = server.started_sessions_per_connection();
    assert_eq!(started[0], 1);
    assert!((1..=2).contains(&started[1]), "{started:?}");
    assert_eq!(server.gets_per_connection(), vec![0, 1]);
}

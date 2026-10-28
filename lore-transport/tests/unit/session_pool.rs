// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! `StorageConnector::session_pool` when a parallel `session_start_bound` fails.
//!
//! The pool starts one server-side session per connection and waits for every start. If one fails,
//! the sessions the others opened belong to nobody, so the build stops them before it returns the
//! failure, on the same generation guard every other cleanup path uses.

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::error::SlowDown;
use lore_base::types::*;
use lore_transport::connection::Connection;
use lore_transport::connection::SuppliedCredentials;
use lore_transport::error::ProtocolError;
use lore_transport::session::StorageConnector;
use lore_transport::traits::*;
use lore_transport::types::*;
use parking_lot::Mutex;

/// A scripted storage connection. Starts hand out ids from `next_id` on `start_generation`, or fail
/// with `SlowDown`; every stop it receives is recorded.
struct ScriptedStorage {
    fail_start: AtomicBool,
    next_id: AtomicU32,
    /// The generation a start reports for the id it issues.
    start_generation: u32,
    /// What `connection_generation()` answers now; moving it past `start_generation` simulates a
    /// reconnect that replaced the connection after the start.
    current_generation: AtomicU32,
    starts: AtomicUsize,
    stops: Mutex<Vec<u32>>,
}

impl ScriptedStorage {
    fn new(first_id: u32, fail_start: bool) -> Arc<Self> {
        Arc::new(Self {
            fail_start: AtomicBool::new(fail_start),
            next_id: AtomicU32::new(first_id),
            start_generation: 1,
            current_generation: AtomicU32::new(1),
            starts: AtomicUsize::new(0),
            stops: Mutex::new(Vec::new()),
        })
    }

    fn stops(&self) -> Vec<u32> {
        self.stops.lock().clone()
    }

    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }
}

fn unsupported<T>() -> Result<T, ProtocolError> {
    Err(ProtocolError::internal("not scripted"))
}

#[async_trait]
impl Storage for ScriptedStorage {
    async fn session_start(&self, _: Partition, _: &str) -> Result<u32, ProtocolError> {
        self.session_start_bound(Partition::default(), "")
            .await
            .map(|(id, _)| id)
    }

    async fn session_start_bound(
        &self,
        _: Partition,
        _: &str,
    ) -> Result<(u32, u32), ProtocolError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        if self.fail_start.load(Ordering::SeqCst) {
            return Err(ProtocolError::from(SlowDown));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        Ok((id, self.start_generation))
    }

    async fn session_stop(&self, session_id: u32) -> Result<(), ProtocolError> {
        self.stops.lock().push(session_id);
        Ok(())
    }

    async fn get(&self, _: u32, _: &Address) -> Result<(Fragment, Bytes), ProtocolError> {
        unsupported()
    }

    async fn put(
        &self,
        _: u32,
        _: Address,
        _: Fragment,
        _: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        unsupported()
    }

    async fn query(&self, _: u32, _: &[Address]) -> Result<Bytes, ProtocolError> {
        unsupported()
    }

    async fn verify(&self, _: u32, _: &Address, _: bool) -> Result<VerifyResult, ProtocolError> {
        unsupported()
    }

    async fn copy(
        &self,
        _: u32,
        _: Partition,
        _: Address,
        _: Context,
    ) -> Result<(), ProtocolError> {
        unsupported()
    }

    fn connection_epoch(&self) -> u32 {
        self.current_generation.load(Ordering::SeqCst)
    }

    fn connection_generation(&self) -> u32 {
        self.current_generation.load(Ordering::SeqCst)
    }
}

/// Serves the environment and nothing else: `session_pool` only needs a live `Connection` to hand
/// to the sessions it builds, and `connect` builds one without touching a service.
struct EnvironmentOnlyProtocol;

struct EmptyEnvironment;

#[async_trait]
impl Environment for EmptyEnvironment {
    async fn get(&self) -> Result<EnvironmentConfig, ProtocolError> {
        Ok(EnvironmentConfig::default())
    }
}

#[async_trait]
impl Protocol for EnvironmentOnlyProtocol {
    async fn storage(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &str,
        _: &str,
        _: Partition,
        _: usize,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Storage>, ProtocolError> {
        unsupported()
    }

    async fn revision(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &str,
        _: &str,
        _: RepositoryId,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Revision>, ProtocolError> {
        unsupported()
    }

    async fn repository(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &str,
        _: &str,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Repository>, ProtocolError> {
        unsupported()
    }

    async fn admin(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &str,
        _: &str,
        _: RepositoryId,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Admin>, ProtocolError> {
        unsupported()
    }

    async fn lock(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &str,
        _: &str,
        _: RepositoryId,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Lock>, ProtocolError> {
        unsupported()
    }

    async fn environment(
        &self,
        _: Weak<Connection>,
        _: &str,
    ) -> Result<Arc<dyn Environment>, ProtocolError> {
        Ok(Arc::new(EmptyEnvironment))
    }
}

/// A connection on a scheme of its own, so tests sharing the process never share a cache entry.
async fn connection(scheme: &str) -> Arc<Connection> {
    lore_transport::connection::add(scheme, Arc::new(EnvironmentOnlyProtocol))
        .expect("register the scripted protocol");
    lore_transport::connect(
        &format!("{scheme}://pool.invalid"),
        "",
        RepositoryId::default(),
        1,
        "",
        "",
    )
    .await
    .expect("connect builds a connection without reaching any service")
}

fn partition() -> Partition {
    Partition::from([0x5au8; 16])
}

fn connector(storages: &[&Arc<ScriptedStorage>]) -> StorageConnector {
    StorageConnector::new(
        storages
            .iter()
            .map(|storage| (*storage).clone() as Arc<dyn Storage>)
            .collect(),
    )
}

/// One start fails: the pool build returns that failure, stops exactly the session each other
/// start opened, sends nothing to the failing connection, and caches nothing.
#[tokio::test]
async fn a_failed_start_stops_the_sessions_the_others_opened() {
    let first = ScriptedStorage::new(100, false);
    let second = ScriptedStorage::new(200, false);
    let failing = ScriptedStorage::new(300, true);
    let connector = connector(&[&first, &failing, &second]);
    let connection = connection("qlfpoolfail").await;

    let result = connector
        .session_pool(partition(), "corr", connection.clone())
        .await;

    assert!(
        result.is_err_and(|err| err.is_slow_down()),
        "the build returns the start's own failure"
    );
    assert_eq!(first.starts(), 1);
    assert_eq!(second.starts(), 1);
    assert_eq!(failing.starts(), 1);
    assert_eq!(
        first.stops(),
        vec![100],
        "the id this storage's start issued"
    );
    assert_eq!(
        second.stops(),
        vec![200],
        "the id this storage's start issued"
    );
    assert!(
        failing.stops().is_empty(),
        "a start that failed opened nothing to stop"
    );
    assert!(
        !connector.is_partition_authorized(partition()),
        "the partition is marked authorized only when every start succeeded"
    );

    // Nothing was cached: with the failure gone, the next build starts fresh sessions.
    failing.fail_start.store(false, Ordering::SeqCst);
    let pool = connector
        .session_pool(partition(), "corr", connection)
        .await
        .expect("every start succeeds now");
    assert_eq!(first.starts(), 2);
    assert_eq!(second.starts(), 2);
    assert_eq!(failing.starts(), 2);
    assert_eq!(
        first.stops(),
        vec![100],
        "the successful build stops nothing"
    );
    assert_eq!(
        second.stops(),
        vec![200],
        "the successful build stops nothing"
    );
    assert!(failing.stops().is_empty());
    assert!(connector.is_partition_authorized(partition()));
    drop(pool);
}

/// The generation guard holds on the failure path: a connection replaced since its start reported
/// is not sent a stop, because the id it issued may now name somebody else's session.
#[tokio::test]
async fn the_failure_path_does_not_stop_an_id_from_a_replaced_connection() {
    let current = ScriptedStorage::new(100, false);
    let replaced = ScriptedStorage::new(200, false);
    let failing = ScriptedStorage::new(300, true);
    // The connection moved on after the start reported generation 1.
    replaced.current_generation.store(2, Ordering::SeqCst);
    let connector = connector(&[&current, &replaced, &failing]);
    let connection = connection("qlfpoolgen").await;

    let result = connector
        .session_pool(partition(), "corr", connection)
        .await;

    assert!(result.is_err_and(|err| err.is_slow_down()));
    assert_eq!(current.stops(), vec![100]);
    assert!(
        replaced.stops().is_empty(),
        "an id issued on a connection that has since been replaced is never stopped"
    );
    assert!(failing.stops().is_empty());
}

/// The success path is unchanged: no stop is sent while the pool is built and held, and the
/// partition is marked authorized.
#[tokio::test]
async fn a_build_where_every_start_succeeds_stops_nothing() {
    let first = ScriptedStorage::new(100, false);
    let second = ScriptedStorage::new(200, false);
    let connector = connector(&[&first, &second]);
    let connection = connection("qlfpoolok").await;

    let pool = connector
        .session_pool(partition(), "corr", connection)
        .await
        .expect("every start succeeds");

    assert_eq!(first.starts(), 1);
    assert_eq!(second.starts(), 1);
    assert!(first.stops().is_empty());
    assert!(second.stops().is_empty());
    assert!(connector.is_partition_authorized(partition()));
    drop(pool);
}

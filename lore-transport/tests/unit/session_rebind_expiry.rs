// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 K10): callers queued on a binding's `rebind` guard behind a
//! replacement start that the managed bound expired share that expiry.
//!
//! Without the sharing, each caller queued behind such a start waited a whole bound on its own
//! start, in turn: N queued commands cost N bounds. The sessions here are real `StorageSession`s
//! over a scripted `Storage`; only the start's answer and its duration are scripted. The
//! connection is "replaced" by moving the generation the scripted storage reports, which makes
//! every caller's bound session stale so each one has to restart.

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::types::*;
use lore_transport::StorageSession;
use lore_transport::connection::Connection;
use lore_transport::connection::SuppliedCredentials;
use lore_transport::error::ProtocolError;
use lore_transport::session::StorageConnector;
use lore_transport::traits::*;
use lore_transport::types::*;
use parking_lot::Mutex;

/// How long a scripted replacement start takes: the stand-in for the managed bound.
const START: Duration = Duration::from_millis(300);

#[derive(Clone, Copy)]
enum Start {
    /// Succeeds at once. Used for the pool's own first start.
    Ok,
    /// Takes [`START`], then ends with the managed-bound expiry marker.
    Expire,
    /// Takes [`START`], moves the connection to the next generation (a reconnect replaced it
    /// meanwhile), then ends with the expiry marker.
    ExpireAfterGenerationMoves,
    /// Takes [`START`], then fails with an error that is not the expiry.
    Fail,
}

struct Peer {
    mode: Mutex<Start>,
    generation: AtomicU32,
    starts: AtomicUsize,
}

impl Peer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mode: Mutex::new(Start::Ok),
            generation: AtomicU32::new(1),
            starts: AtomicUsize::new(0),
        })
    }

    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    /// The connection was replaced: every session bound to the old generation is stale.
    fn replace_connection(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

fn not_scripted<T>() -> Result<T, ProtocolError> {
    Err(ProtocolError::internal("not scripted"))
}

#[async_trait]
impl Storage for Peer {
    async fn session_start(
        &self,
        partition: Partition,
        correlation_id: &str,
    ) -> Result<u32, ProtocolError> {
        self.session_start_bound(partition, correlation_id)
            .await
            .map(|(id, _)| id)
    }

    async fn session_start_bound(
        &self,
        _: Partition,
        _: &str,
    ) -> Result<(u32, u32), ProtocolError> {
        let n = self.starts.fetch_add(1, Ordering::SeqCst) as u32;
        let mode = *self.mode.lock();
        match mode {
            Start::Ok => Ok((10 + n, self.generation.load(Ordering::SeqCst))),
            Start::Expire => {
                tokio::time::sleep(START).await;
                Err(lore_transport::managed_reconnect_expired_for_test(
                    "Authorize",
                ))
            }
            Start::ExpireAfterGenerationMoves => {
                tokio::time::sleep(START).await;
                self.generation.fetch_add(1, Ordering::SeqCst);
                // The replacement start works the second time.
                *self.mode.lock() = Start::Ok;
                Err(lore_transport::managed_reconnect_expired_for_test(
                    "Authorize",
                ))
            }
            Start::Fail => {
                tokio::time::sleep(START).await;
                Err(ProtocolError::internal("start failed for another reason"))
            }
        }
    }

    async fn session_stop(&self, _: u32) -> Result<(), ProtocolError> {
        Ok(())
    }

    async fn get(&self, _: u32, _: &Address) -> Result<(Fragment, Bytes), ProtocolError> {
        not_scripted()
    }

    async fn put(
        &self,
        _: u32,
        _: Address,
        _: Fragment,
        _: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        not_scripted()
    }

    async fn query(&self, _: u32, _: &[Address]) -> Result<Bytes, ProtocolError> {
        not_scripted()
    }

    async fn verify(&self, _: u32, _: &Address, _: bool) -> Result<VerifyResult, ProtocolError> {
        not_scripted()
    }

    async fn copy(
        &self,
        _: u32,
        _: Partition,
        _: Address,
        _: Context,
    ) -> Result<(), ProtocolError> {
        not_scripted()
    }

    fn connection_epoch(&self) -> u32 {
        self.generation.load(Ordering::SeqCst)
    }

    fn connection_generation(&self) -> u32 {
        self.generation.load(Ordering::SeqCst)
    }
}

struct EmptyEnvironment;

#[async_trait]
impl Environment for EmptyEnvironment {
    async fn get(&self) -> Result<EnvironmentConfig, ProtocolError> {
        Ok(EnvironmentConfig::default())
    }
}

/// Serves the environment only: a connection is needed to build a session, nothing else.
struct EnvironmentOnlyProtocol;

#[async_trait]
impl Protocol for EnvironmentOnlyProtocol {
    async fn storage(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &lore_transport::auth::AuthEndpoint,
        _: &str,
        _: Partition,
        _: usize,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Storage>, ProtocolError> {
        not_scripted()
    }

    async fn revision(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &lore_transport::auth::AuthEndpoint,
        _: &str,
        _: RepositoryId,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Revision>, ProtocolError> {
        not_scripted()
    }

    async fn repository(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &lore_transport::auth::AuthEndpoint,
        _: &str,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Repository>, ProtocolError> {
        not_scripted()
    }

    async fn admin(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &lore_transport::auth::AuthEndpoint,
        _: &str,
        _: RepositoryId,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Admin>, ProtocolError> {
        not_scripted()
    }

    async fn lock(
        &self,
        _: Weak<Connection>,
        _: &str,
        _: &lore_transport::auth::AuthEndpoint,
        _: &str,
        _: RepositoryId,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Lock>, ProtocolError> {
        not_scripted()
    }

    async fn environment(
        &self,
        _: Weak<Connection>,
        _: &str,
    ) -> Result<Arc<dyn Environment>, ProtocolError> {
        Ok(Arc::new(EmptyEnvironment))
    }
}

/// A resolved session whose connection was then replaced, so each caller must start a new
/// session. `scheme` is unique per test (the connection cache is process-wide).
async fn stale_session(scheme: &str, peer: &Arc<Peer>) -> Arc<StorageSession> {
    lore_transport::connection::add(scheme, Arc::new(EnvironmentOnlyProtocol))
        .expect("register the scripted protocol");
    let connection = lore_transport::connect(
        &format!("{scheme}://rebind.invalid"),
        "",
        RepositoryId::default(),
        1,
        "",
        "",
        lore_transport::auth::AuthMode::Auto,
    )
    .await
    .expect("connect builds a connection without reaching any service");
    let connector = StorageConnector::new(vec![peer.clone() as Arc<dyn Storage>]);
    let pool = connector
        .session_pool(Partition::from([0x6b; 16]), "rebind", connection)
        .await
        .expect("the first start succeeds");
    assert_eq!(peer.starts(), 1);
    peer.replace_connection();
    pool.pick()
}

async fn call(session: &StorageSession) -> Result<Bytes, ProtocolError> {
    session.query(&[]).await
}

fn is_expired(result: &Result<Bytes, ProtocolError>) -> bool {
    result
        .as_ref()
        .is_err_and(|error| lore_transport::is_managed_reconnect_expired(error))
}

/// N callers queued behind one expiring start cost one start and one bound, and all of them get
/// the expiry (their command is not sent).
#[tokio::test]
async fn callers_queued_behind_an_expired_start_share_it() {
    const N: usize = 5;
    let peer = Peer::new();
    let session = stale_session("kmrebindshare", &peer).await;
    *peer.mode.lock() = Start::Expire;

    let started = Instant::now();
    let results = futures::future::join_all((0..N).map(|_| call(&session))).await;
    let elapsed = started.elapsed();

    assert_eq!(
        peer.starts(),
        2,
        "the pool's start plus ONE replacement start for all {N}"
    );
    assert!(
        results.iter().all(is_expired),
        "every queued caller gets the expiry: {results:?}"
    );
    assert!(
        elapsed < START * 2,
        "N queued callers cost one bound, not {N}: {elapsed:?}"
    );
    assert!(
        elapsed >= START - Duration::from_millis(50),
        "the start was waited for: {elapsed:?}"
    );
}

/// A caller that arrives after the expiry was not queued behind it, so it starts again (and waits
/// its own bound): a later command still gets to try a path that may have come back.
#[tokio::test]
async fn a_caller_arriving_after_the_expiry_starts_again() {
    let peer = Peer::new();
    let session = stale_session("kmrebindafter", &peer).await;
    *peer.mode.lock() = Start::Expire;

    let first = call(&session).await;
    assert!(is_expired(&first));
    assert_eq!(peer.starts(), 2);

    let started = Instant::now();
    let second = call(&session).await;
    assert!(is_expired(&second));
    assert_eq!(peer.starts(), 3, "the later caller made a start of its own");
    assert!(started.elapsed() >= START - Duration::from_millis(50));

    // And the path coming back is noticed: a start that succeeds binds the session.
    *peer.mode.lock() = Start::Ok;
    let third = call(&session).await;
    assert!(
        !is_expired(&third),
        "the next start is not served the old expiry"
    );
    assert_eq!(peer.starts(), 4);
}

/// The connection was replaced between the failed start and the queued caller: the expiry belongs
/// to the old generation, so the queued caller starts for itself.
#[tokio::test]
async fn a_generation_change_after_the_failed_start_makes_the_queued_caller_start() {
    let peer = Peer::new();
    let session = stale_session("kmrebindgeneration", &peer).await;
    *peer.mode.lock() = Start::ExpireAfterGenerationMoves;

    let (first, second) = tokio::join!(call(&session), call(&session));

    assert_eq!(
        peer.starts(),
        3,
        "pool start, the expiring start, the queued caller's own start"
    );
    let (expired, other) = if is_expired(&first) {
        (first, second)
    } else {
        (second, first)
    };
    assert!(
        is_expired(&expired),
        "the caller that ran the failing start got the expiry"
    );
    assert!(
        !is_expired(&other),
        "the queued caller was not served the old generation's expiry: {other:?}"
    );
}

/// Only a managed-bound expiry is shared: any other start failure is each caller's own to learn.
#[tokio::test]
async fn a_start_failure_that_is_not_an_expiry_is_not_shared() {
    const N: usize = 3;
    let peer = Peer::new();
    let session = stale_session("kmrebindother", &peer).await;
    *peer.mode.lock() = Start::Fail;

    let results = futures::future::join_all((0..N).map(|_| call(&session))).await;

    assert_eq!(peer.starts(), 1 + N, "each caller made its own start");
    assert!(
        results
            .iter()
            .all(|result| result.is_err() && !is_expired(result)),
        "{results:?}"
    );
}

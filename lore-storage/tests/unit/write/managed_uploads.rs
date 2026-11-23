// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 K10): a commit's fragment uploads in a `ManagedUploads` scope.
//!
//! The session under test is a real `StorageSession` over a scripted `Storage` that declares per
//! session (as QUIC does), so the scope, its caller operation, the declared binding and the leader
//! body are the production ones. Only the wire answer is scripted.
//!
//! Each test uses its own seed range: `STORE_IN_FLIGHT` is process-wide and keyed by
//! `(partition, address)`, so two tests storing one address would inherit each other's placement.
//! All tests here use a partition no other test file uses.
//!
//! Not reachable from here, because `ManagedUploads::run` and `note_failure` are `pub(crate)`: the
//! journal that refuses every record is exercised only through the legs `store_fragment` runs
//! (they write no journal child, and the counting below proves the scope never asked for one).

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::error::Disconnected;
use lore_base::error::NotAuthorized;
use lore_base::error::SlowDown;
use lore_base::types::RepositoryId;
use lore_base::types::VerifyResult;
use lore_storage::Address;
use lore_storage::Context;
use lore_storage::Fragment;
use lore_storage::Partition;
use lore_storage::fragment_flags::FragmentFlags;
use lore_storage::immutable_store::ImmutableStore;
use lore_storage::immutable_store::query_one;
use lore_storage::managed_uploads::ManagedUploads;
use lore_storage::write::StoreResult;
use lore_storage::write::store_fragment;
use lore_storage::write_stats::FragmentWriteCounts;
use lore_storage::write_stats::FragmentWriteStats;
use lore_storage::write_tracker::WriteContext;
use lore_storage::write_tracker::WriteTracker;
use lore_transport::MutableOutcome;
use lore_transport::StorageSession;
use lore_transport::VolatileAttemptStore;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::connection::Connection;
use lore_transport::connection::SuppliedCredentials;
use lore_transport::error::ProtocolError;
use lore_transport::error::QuicDeclarationRefused;
use lore_transport::error::UnsupportedClientCapability;
use lore_transport::session::StorageConnector;
use lore_transport::traits::*;
use lore_transport::types::*;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::make_test_store;

/// How the scripted peer answers one verb.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Answer {
    /// Applied.
    Apply,
    /// Refused as an unsupported client (a strict server's status 200).
    Unsupported,
    /// A disconnect before an answer.
    Disconnect,
    /// The managed not-sent expiry marker: the QUIC path could not be replaced within the bound.
    Expired,
    /// A generic server error.
    ServerError,
    /// An answered `NotAuthorized`.
    NotAuthorized,
    /// `SlowDown`, exhausting the retry schedule.
    SlowDown,
    /// Dispatched, answer lost, reported as an unknown-outcome error (the shape a lost answer
    /// takes when the transport reports it as an error).
    LostError,
    /// Dispatched, answer lost, reported as the typed unknown outcome.
    Lost,
}

struct Peer {
    put: Mutex<Answer>,
    copy: Mutex<Answer>,
    /// `true`: refuse the declared session start with `QuicDeclarationRefused`.
    refuse_declaration: Mutex<bool>,
    puts: AtomicUsize,
    copies: AtomicUsize,
    undeclared_starts: AtomicUsize,
    declared_starts: AtomicUsize,
    stopped: Mutex<Vec<u32>>,
}

const DECLARED_ID_BASE: u32 = 100;

impl Peer {
    fn new(put: Answer) -> Arc<Self> {
        Arc::new(Self {
            put: Mutex::new(put),
            copy: Mutex::new(Answer::Apply),
            refuse_declaration: Mutex::new(false),
            puts: AtomicUsize::new(0),
            copies: AtomicUsize::new(0),
            undeclared_starts: AtomicUsize::new(0),
            declared_starts: AtomicUsize::new(0),
            stopped: Mutex::new(Vec::new()),
        })
    }

    fn set_put(&self, answer: Answer) {
        *self.put.lock() = answer;
    }

    fn puts(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }

    fn copies(&self) -> usize {
        self.copies.load(Ordering::SeqCst)
    }

    fn declared_starts(&self) -> usize {
        self.declared_starts.load(Ordering::SeqCst)
    }

    fn undeclared_starts(&self) -> usize {
        self.undeclared_starts.load(Ordering::SeqCst)
    }

    fn answer(answer: Answer) -> Result<MutableOutcome<()>, ProtocolError> {
        match answer {
            Answer::Apply => Ok(MutableOutcome::Applied(())),
            Answer::LostError => Err(ProtocolError::from(lore_base::error::OutcomeUnknown {
                operation: "Put".into(),
                attempt_id: "scripted".into(),
            })),
            Answer::Lost => Ok(MutableOutcome::Unknown(lore_transport::OutcomeUnknown {
                command: "Put",
            })),
            Answer::Unsupported => Err(refusal()),
            Answer::Disconnect => Err(ProtocolError::from(Disconnected)),
            Answer::Expired => Err(lore_transport::managed_reconnect_expired_for_test("Put")),
            Answer::ServerError => Err(ProtocolError::internal("generic server error")),
            Answer::NotAuthorized => Err(ProtocolError::from(NotAuthorized)),
            Answer::SlowDown => Err(ProtocolError::from(SlowDown)),
        }
    }
}

fn refusal() -> ProtocolError {
    ProtocolError::internal_with_context(
        UnsupportedClientCapability,
        "client admission refused before dispatch",
    )
}

fn not_scripted<T>() -> Result<T, ProtocolError> {
    Err(ProtocolError::internal("not scripted"))
}

#[async_trait]
impl Storage for Peer {
    async fn session_start(&self, _: Partition, _: &str) -> Result<u32, ProtocolError> {
        self.undeclared_starts.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }

    async fn session_start_bound(
        &self,
        partition: Partition,
        correlation_id: &str,
    ) -> Result<(u32, u32), ProtocolError> {
        let id = self.session_start(partition, correlation_id).await?;
        Ok((id, 1))
    }

    async fn session_start_declared(
        &self,
        _: Partition,
        _: &str,
        _: &'static str,
    ) -> Result<(u32, u32), ProtocolError> {
        if *self.refuse_declaration.lock() {
            return Err(ProtocolError::internal_with_context(
                QuicDeclarationRefused { status: 200 },
                "declared start refused",
            ));
        }
        let n = self.declared_starts.fetch_add(1, Ordering::SeqCst) as u32;
        Ok((DECLARED_ID_BASE + n, 1))
    }

    fn declares_per_session(&self) -> bool {
        true
    }

    async fn session_stop(&self, session_id: u32) -> Result<(), ProtocolError> {
        self.stopped.lock().push(session_id);
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

    async fn put_outcome(
        &self,
        _: u32,
        _: Address,
        _: Fragment,
        _: Option<Bytes>,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        let answer = *self.put.lock();
        Self::answer(answer)
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

    async fn copy_outcome(
        &self,
        _: u32,
        _: Partition,
        _: Address,
        _: Context,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        self.copies.fetch_add(1, Ordering::SeqCst);
        let answer = *self.copy.lock();
        Self::answer(answer)
    }

    fn connection_epoch(&self) -> u32 {
        1
    }

    fn connection_generation(&self) -> u32 {
        1
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

const PARTITION: [u8; 16] = [0x5a; 16];

fn partition() -> Partition {
    Partition::from(PARTITION)
}

/// A real, resolved `StorageSession` over `peer`. Each test names its own scheme so tests sharing
/// the process never share a connection cache entry.
async fn session(scheme: &str, peer: &Arc<Peer>) -> Arc<StorageSession> {
    lore_transport::connection::add(scheme, Arc::new(EnvironmentOnlyProtocol))
        .expect("register the scripted protocol");
    let connection = lore_transport::connect(
        &format!("{scheme}://managed-uploads.invalid"),
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
        .session_pool(partition(), "managed-uploads", connection)
        .await
        .expect("the scripted start succeeds");
    pool.pick()
}

fn scope_ready() -> Arc<ManagedUploads> {
    ManagedUploads::new(async { true })
}

/// A fragment whose content depends on `seed` alone, under a context that depends on `context`.
fn input_in(seed: u8, context: u8) -> (Address, Fragment, Bytes) {
    let mut state = u64::from(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let payload: Vec<u8> = (0..256)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    let address = Address {
        hash: lore_storage::hash::hash_slice(&payload),
        context: Context::from([context; 16]),
    };
    let fragment = Fragment {
        flags: FragmentFlags::PayloadStoredLocal.bits(),
        size_payload: payload.len() as u32,
        size_content: payload.len() as u64,
    };
    (address, fragment, Bytes::from(payload))
}

async fn store_in(
    store: &Arc<dyn ImmutableStore>,
    session: &Arc<StorageSession>,
    writes: WriteContext,
    (address, fragment, payload): (Address, Fragment, Bytes),
) -> StoreResult {
    store_fragment(
        store.clone(),
        partition(),
        address,
        fragment,
        payload,
        true,
        Some(session.clone()),
        writes,
        None,
    )
    .await
    .expect("a commit upload never fails the write")
}

fn counted(stats: &Arc<FragmentWriteStats>, scope: &Arc<ManagedUploads>) -> WriteContext {
    WriteContext::counted(Some(stats.clone())).with_managed_uploads(Some(scope.clone()))
}

async fn store_one(
    store: &Arc<dyn ImmutableStore>,
    session: &Arc<StorageSession>,
    stats: &Arc<FragmentWriteStats>,
    scope: &Arc<ManagedUploads>,
    seed: u8,
) -> StoreResult {
    store_in(store, session, counted(stats, scope), input_in(seed, seed)).await
}

fn assert_local_not_durable(result: &StoreResult) {
    assert!(
        !result.stored_durable,
        "an upload that did not land is not durable"
    );
    assert!(
        result.stored_local,
        "the payload stays local for the next push"
    );
}

fn assert_sum_invariant(counts: &FragmentWriteCounts, expected: u64) {
    assert_eq!(counts.fragments_processed, expected);
    assert_eq!(
        counts.remote_writes
            + counts.remote_already_durable
            + counts.local_only_writes
            + counts.remote_upload_failed,
        counts.fragments_processed,
        "the stats sum invariant must hold: {counts:?}"
    );
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The scope runs the uploads on ONE declared session per partition, every Put goes out on it, the
/// fragments end durable, and the session's own unmanaged latch is never involved.
#[tokio::test]
async fn uploads_run_on_one_declared_session_and_end_durable() {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    let session = session("kmuaccept", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();

    for seed in 1..=3 {
        let result = store_one(&store, &session, &stats, &scope, seed).await;
        assert!(result.stored_durable && result.stored_local);
    }

    assert_eq!(peer.puts(), 3);
    assert_eq!(
        peer.declared_starts(),
        1,
        "one declared start serves every upload"
    );
    assert_eq!(
        peer.undeclared_starts(),
        1,
        "only the pool's own start is undeclared"
    );
    assert_eq!(scope.declared_session_count(), 1);
    assert!(!scope.is_latched());
    assert!(!session.unmanaged_writes().is_refused());
    let counts = stats.snapshot();
    assert_eq!(counts.remote_put_writes, 3);
    assert_sum_invariant(&counts, 3);
}

/// Dropping the scope stops the declared sessions it opened, and no other.
#[tokio::test]
async fn declared_sessions_stop_when_the_scope_drops() {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    let session = session("kmustop", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();

    store_one(&store, &session, &stats, &scope, 11).await;
    assert_eq!(scope.declared_session_count(), 1);
    assert!(
        peer.stopped.lock().is_empty(),
        "the declared session lives while the scope does"
    );

    drop(scope);
    eventually("the declared session to be stopped", || {
        peer.stopped.lock().contains(&DECLARED_ID_BASE)
    })
    .await;
    assert_eq!(
        *peer.stopped.lock(),
        vec![DECLARED_ID_BASE],
        "only the declared session is stopped by the scope"
    );
}

/// A failure that says every later upload of the command would fail the same way latches the
/// scope: the next write sends nothing, and stays local.
async fn assert_latches(scheme: &str, failure: Answer, seed: u8) {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(failure);
    let session = session(scheme, &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();

    let first = store_one(&store, &session, &stats, &scope, seed).await;
    assert_local_not_durable(&first);
    assert_eq!(
        peer.puts(),
        1,
        "{failure:?}: the first upload reached the peer"
    );
    assert!(scope.is_latched(), "{failure:?} must latch the scope");
    assert!(
        !session.unmanaged_writes().is_refused(),
        "{failure:?}: the scope's latch is not the session's unmanaged latch"
    );

    // The peer would now accept, so a skip is the latch's.
    peer.set_put(Answer::Apply);
    let later = store_one(&store, &session, &stats, &scope, seed + 1).await;
    assert_local_not_durable(&later);
    assert_eq!(
        peer.puts(),
        1,
        "{failure:?}: a latched scope sends nothing more"
    );
    assert_sum_invariant(&stats.snapshot(), 2);
}

/// A failure that is the peer's answer to this one fragment, or a lost answer, says nothing about
/// the next: no latch, and the next upload goes out.
async fn assert_does_not_latch(scheme: &str, failure: Answer, seed: u8) {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(failure);
    let session = session(scheme, &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();

    let first = store_one(&store, &session, &stats, &scope, seed).await;
    assert_local_not_durable(&first);
    let dispatched = peer.puts();
    if failure != Answer::SlowDown {
        assert_eq!(
            dispatched, 1,
            "{failure:?}: dispatched exactly once, never resent"
        );
    }
    assert!(dispatched >= 1);
    assert!(!scope.is_latched(), "{failure:?} must not latch the scope");

    peer.set_put(Answer::Apply);
    let later = store_one(&store, &session, &stats, &scope, seed + 1).await;
    assert!(
        later.stored_durable,
        "{failure:?}: a later upload still lands"
    );
    assert_eq!(peer.puts(), dispatched + 1);
    assert!(!scope.is_latched());
}

#[tokio::test]
async fn an_unsupported_client_refusal_latches() {
    assert_latches("kmulatchunsupported", Answer::Unsupported, 21).await;
}

#[tokio::test]
async fn a_managed_reconnect_expiry_latches() {
    assert_latches("kmulatchexpired", Answer::Expired, 23).await;
}

#[tokio::test]
async fn a_disconnect_latches() {
    assert_latches("kmulatchdisconnect", Answer::Disconnect, 25).await;
}

/// The declared session start itself refused (a stock or slice-0 server): final, and latches.
#[tokio::test]
async fn a_refused_declaration_latches_before_any_put() {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    *peer.refuse_declaration.lock() = true;
    let session = session("kmulatchdeclaration", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();

    let first = store_one(&store, &session, &stats, &scope, 27).await;
    assert_local_not_durable(&first);
    assert!(
        scope.is_latched(),
        "a refused declaration must latch the scope"
    );
    assert_eq!(
        peer.puts(),
        0,
        "no Put goes out on a session that was never declared"
    );
    assert_eq!(
        peer.undeclared_starts(),
        1,
        "and no undeclared session is opened in its place"
    );

    *peer.refuse_declaration.lock() = false;
    let later = store_one(&store, &session, &stats, &scope, 28).await;
    assert_local_not_durable(&later);
    assert_eq!(
        peer.declared_starts(),
        0,
        "a latched scope starts no session"
    );
    assert_eq!(peer.puts(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_generic_server_error_does_not_latch() {
    assert_does_not_latch("kmunolatchserver", Answer::ServerError, 31).await;
}

#[tokio::test(start_paused = true)]
async fn an_answered_not_authorized_does_not_latch() {
    assert_does_not_latch("kmunolatchauthz", Answer::NotAuthorized, 33).await;
}

#[tokio::test(start_paused = true)]
async fn an_exhausted_slow_down_does_not_latch() {
    assert_does_not_latch("kmunolatchslow", Answer::SlowDown, 35).await;
}

/// A lost answer is dispatched exactly once, is never resent, leaves the fragment local and LATCHES
/// the scope: on a connection gone silent each later wave of uploads would wait out its own answer
/// bound.
#[tokio::test(start_paused = true)]
async fn a_lost_put_answer_latches() {
    assert_latches("kmulatchlost", Answer::LostError, 37).await;
}

/// `ready` answering false (the command's connect pre-warm expired) skips every leg: no session
/// start, no Copy, no Put, and nothing latched.
#[tokio::test]
async fn a_ready_that_says_no_skips_every_leg() {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    let session = session("kmunotready", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = ManagedUploads::new(async { false });
    // A copy source for the third write, so the copy leg is a candidate too.
    let (address, mut fragment, payload) = input_in(43, 0xEE);
    fragment.flags =
        (FragmentFlags::PayloadStoredLocal | FragmentFlags::PayloadStoredDurable).bits();
    store
        .clone()
        .put(partition(), address, fragment, Some(payload), false)
        .await
        .expect("seed the copy source");

    let first = store_one(&store, &session, &stats, &scope, 41).await;
    let second = store_one(&store, &session, &stats, &scope, 42).await;
    let copy_candidate = store_in(
        &store,
        &session,
        counted(&stats, &scope),
        input_in(43, 0xDD),
    )
    .await;

    for result in [&first, &second, &copy_candidate] {
        assert_local_not_durable(result);
    }
    assert_eq!(peer.puts(), 0, "nothing is uploaded");
    assert_eq!(peer.copies(), 0, "no copy is sent");
    assert_eq!(peer.declared_starts(), 0, "no declared session is started");
    assert!(!scope.is_latched(), "a skip is not a failure");
    assert_sum_invariant(&stats.snapshot(), 3);
}

/// Uploads wait for `ready`, and `ready` is driven once and shared by every upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uploads_wait_for_ready_and_ready_runs_once() {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    let session = session("kmuwaitready", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let gate = Arc::new(Semaphore::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let scope = ManagedUploads::new({
        let (gate, polls) = (gate.clone(), polls.clone());
        async move {
            polls.fetch_add(1, Ordering::SeqCst);
            gate.acquire().await.expect("the gate stays open").forget();
            true
        }
    });

    let mut tasks = Vec::new();
    for seed in 51..=54 {
        let (store, session, stats, scope) =
            (store.clone(), session.clone(), stats.clone(), scope.clone());
        tasks.push(lore_base::lore_spawn!(async move {
            store_one(&store, &session, &stats, &scope, seed).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(peer.puts(), 0, "no upload starts before ready answers");
    assert_eq!(peer.declared_starts(), 0);

    gate.add_permits(1);
    for task in tasks {
        let result = task.await.expect("the store task joins");
        assert!(result.stored_durable);
    }
    assert_eq!(peer.puts(), 4);
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "ready is evaluated once for all uploads"
    );
}

/// A copy source for `seed` the peer already holds durably under another context.
async fn seed_copy_source(store: &Arc<dyn ImmutableStore>, seed: u8) {
    let (address, mut fragment, payload) = input_in(seed, 0xEE);
    fragment.flags =
        (FragmentFlags::PayloadStoredLocal | FragmentFlags::PayloadStoredDurable).bits();
    store
        .clone()
        .put(partition(), address, fragment, Some(payload), false)
        .await
        .expect("seed the copy source");
}

async fn copy_candidate(
    copy: Answer,
    scheme: &str,
    seed: u8,
) -> (Arc<Peer>, Arc<ManagedUploads>, StoreResult) {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    *peer.copy.lock() = copy;
    let session = session(scheme, &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();
    seed_copy_source(&store, seed).await;
    let result = store_in(
        &store,
        &session,
        counted(&stats, &scope),
        input_in(seed, 0xDD),
    )
    .await;
    (peer, scope, result)
}

/// A Copy that lands makes the fragment durable and uploads nothing.
#[tokio::test]
async fn a_copy_that_lands_uploads_nothing() {
    let (peer, scope, result) = copy_candidate(Answer::Apply, "kmucopyok", 61).await;
    assert_eq!(peer.copies(), 1);
    assert_eq!(peer.puts(), 0);
    assert!(result.stored_durable && result.stored_local);
    assert_eq!(
        peer.declared_starts(),
        1,
        "the copy ran on the declared session"
    );
    assert!(!scope.is_latched());
}

/// A Copy the server refuses as an unsupported client latches the scope: no fallback Put.
#[tokio::test]
async fn a_copy_refused_as_unsupported_latches_and_sends_no_fallback_put() {
    let (peer, scope, result) = copy_candidate(Answer::Unsupported, "kmucopyrefused", 63).await;
    assert_eq!(peer.copies(), 1);
    assert_eq!(peer.puts(), 0, "no fallback Put once the scope is latched");
    assert!(scope.is_latched());
    assert_local_not_durable(&result);
}

/// A Copy whose answer is lost latches the scope, so no fallback Put follows (the Copy may have
/// landed, and the connection may be silent).
#[tokio::test]
async fn a_lost_copy_answer_latches_and_sends_no_fallback_put() {
    let (peer, scope, result) = copy_candidate(Answer::Lost, "kmucopylost", 65).await;
    assert_eq!(peer.copies(), 1, "the Copy is dispatched once");
    assert_eq!(peer.puts(), 0, "no fallback Put after a lost Copy answer");
    assert!(scope.is_latched(), "a lost answer latches the scope");
    assert_local_not_durable(&result);
}

/// A Copy that disconnected latches the scope: no fallback Put.
#[tokio::test]
async fn a_copy_that_disconnected_latches_and_sends_no_fallback_put() {
    let (peer, scope, result) = copy_candidate(Answer::Disconnect, "kmucopydisc", 69).await;
    assert_eq!(peer.puts(), 0);
    assert!(scope.is_latched());
    assert_local_not_durable(&result);
}

/// A decisive refusal of the Copy (the source is gone, no claim to it) does not latch: the Put that
/// does everything the Copy would have is sent once, and the fragment ends durable.
async fn assert_decisive_copy_failure_falls_back(scheme: &str, failure: Answer, seed: u8) {
    let (peer, scope, result) = copy_candidate(failure, scheme, seed).await;
    assert_eq!(peer.copies(), 1);
    assert_eq!(peer.puts(), 1, "{failure:?}: exactly one fallback Put");
    assert!(
        !scope.is_latched(),
        "{failure:?} is no reason to skip later uploads"
    );
    assert!(result.stored_durable && result.stored_local);
}

#[tokio::test]
async fn a_copy_refused_as_not_authorized_falls_back_to_one_put() {
    assert_decisive_copy_failure_falls_back("kmucopyauthz", Answer::NotAuthorized, 67).await;
}

/// An answered server error is not proof the Copy did not apply (a handler may have done one
/// durable step first), so only an outright refusal falls back. This one sends no Put and does
/// not latch: the fragment stays local for the push.
#[tokio::test]
async fn a_copy_that_failed_on_the_server_sends_no_fallback_put() {
    let (peer, scope, result) = copy_candidate(Answer::ServerError, "kmucopyerror", 71).await;
    assert_eq!(peer.copies(), 1);
    assert_eq!(peer.puts(), 0, "a server error is not an outright refusal");
    assert!(!scope.is_latched());
    assert_local_not_durable(&result);
}

/// The session's unmanaged-write latch belongs to undeclared writes. A session an earlier
/// unmanaged refusal latched still uploads a scoped commit's fragments, declared.
#[tokio::test]
async fn a_scoped_upload_ignores_the_sessions_unmanaged_latch() {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    let session = session("kmusessionlatch", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    session.unmanaged_writes().refuse();
    let scope = scope_ready();

    let scoped = store_one(&store, &session, &stats, &scope, 73).await;
    assert!(scoped.stored_durable, "the scoped upload goes out");
    assert_eq!(peer.puts(), 1);
    assert_eq!(peer.declared_starts(), 1, "declared");

    // Control: with no scope the same latched session sends nothing.
    let (address, fragment, payload) = input_in(74, 74);
    let unscoped = store_in(
        &store,
        &session,
        WriteContext::counted(Some(stats.clone())),
        (address, fragment, payload),
    )
    .await;
    assert!(!unscoped.stored_durable);
    assert_eq!(
        peer.puts(),
        1,
        "the unmanaged write still honours the latch"
    );
}
/// A write already inside a managed caller operation is a managed write: it ignores the scope and
/// runs in its caller's operation.
#[tokio::test]
async fn a_write_inside_a_managed_caller_operation_ignores_the_scope() {
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    let session = session("kmuownercaller", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();
    let caller = CallerOperationContext::new(
        Uuid::from_u128(0x6b1),
        partition(),
        Arc::new(VolatileAttemptStore::new()),
    );

    let result = with_caller_operation(caller.clone(), {
        let (store, session, stats, scope) =
            (store.clone(), session.clone(), stats.clone(), scope.clone());
        async move { store_one(&store, &session, &stats, &scope, 71).await }
    })
    .await;

    assert!(result.stored_durable);
    assert_eq!(peer.puts(), 1);
    assert_eq!(
        scope.declared_session_count(),
        0,
        "the scope opened nothing"
    );
    assert_eq!(
        caller.declared_session_count(),
        1,
        "the caller's own operation carried it"
    );
}

/// The write-tracker path, which is what `lore commit` uses: background leaders upload through the
/// scope, all durable, on one declared session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tracked_writes_upload_through_the_scope() {
    const N: u8 = 8;
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Apply);
    let session = session("kmutracker", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();
    let tracker = Arc::new(WriteTracker::new());

    let mut addresses = Vec::new();
    for seed in 81..81 + N {
        let (address, fragment, payload) = input_in(seed, seed);
        store_fragment(
            store.clone(),
            partition(),
            address,
            fragment,
            payload,
            true,
            Some(session.clone()),
            WriteContext::tracked(Some(tracker.clone()), Some(stats.clone()))
                .with_managed_uploads(Some(scope.clone())),
            None,
        )
        .await
        .expect("dispatching a tracked write succeeds");
        addresses.push(address);
    }
    tracker
        .await_all()
        .await
        .expect("the tracked uploads finish");

    assert_eq!(peer.puts(), usize::from(N));
    assert_eq!(
        peer.declared_starts(),
        1,
        "concurrent leaders share one declared session"
    );
    assert_eq!(scope.declared_session_count(), 1);
    for address in addresses {
        let placed = query_one(&store, partition(), address)
            .await
            .expect("the fragment is in the local store");
        assert!(placed.stored_local && placed.stored_durable);
    }
    assert_sum_invariant(&stats.snapshot(), u64::from(N));
}

/// Tracked writes after a latch send nothing, and every fragment stays local and not durable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tracked_writes_after_a_latch_send_nothing() {
    const N: u8 = 8;
    let (_dir, store) = make_test_store().await;
    let peer = Peer::new(Answer::Expired);
    let session = session("kmutrackerlatch", &peer).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let scope = scope_ready();

    // Learn the expiry first, then dispatch a batch.
    store_one(&store, &session, &stats, &scope, 101).await;
    assert!(scope.is_latched());
    assert_eq!(peer.puts(), 1);

    let tracker = Arc::new(WriteTracker::new());
    let mut addresses = Vec::new();
    for seed in 102..102 + N {
        let (address, fragment, payload) = input_in(seed, seed);
        store_fragment(
            store.clone(),
            partition(),
            address,
            fragment,
            payload,
            true,
            Some(session.clone()),
            WriteContext::tracked(Some(tracker.clone()), Some(stats.clone()))
                .with_managed_uploads(Some(scope.clone())),
            None,
        )
        .await
        .expect("dispatching a tracked write succeeds");
        addresses.push(address);
    }
    tracker
        .await_all()
        .await
        .expect("a skipped upload is not a tracker failure");

    assert_eq!(
        peer.puts(),
        1,
        "a latched scope sends nothing for the batch"
    );
    for address in addresses {
        let placed = query_one(&store, partition(), address)
            .await
            .expect("the fragment is in the local store");
        assert!(placed.stored_local);
        assert!(!placed.stored_durable);
    }
    assert_sum_invariant(&stats.snapshot(), u64::from(N) + 1);
}

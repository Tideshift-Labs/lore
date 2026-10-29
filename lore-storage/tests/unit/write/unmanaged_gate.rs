// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 follow-up (b)): once a strict server has refused an unmanaged
//! write, later unmanaged writes on that session skip their copy and upload.
//!
//! The session under test is a real `StorageSession` over a scripted `Storage`, so the latch, the
//! retry loop and the leader body are the production ones. Only the wire answer is scripted.
//!
//! Each test uses its own seed range: `STORE_IN_FLIGHT` is process-wide and keyed by address, so
//! two tests storing one address would inherit each other's placement.

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::error::Disconnected;
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
use lore_transport::error::UnsupportedClientCapability;
use lore_transport::session::StorageConnector;
use lore_transport::traits::*;
use lore_transport::types::*;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::make_test_store;

/// What the scripted server answers with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    /// Accept every put; refuse every copy as an unsupported client.
    AcceptPutsRefuseCopies,
    /// Accept everything.
    Accept,
    /// Refuse every put and copy as an unsupported client.
    Refuse,
    /// Fail every put with a disconnect.
    Disconnect,
    /// Answer every put with `SlowDown`.
    SlowDown,
    /// Answer every put with a generic server error.
    ServerError,
    /// Lose every put's answer after dispatch.
    OutcomeUnknown,
}

struct ScriptedStorage {
    script: Mutex<Script>,
    puts: AtomicUsize,
    copies: AtomicUsize,
    /// When set, a put waits here until the `K`th put has arrived, then every waiter is let go.
    hold: Mutex<Option<(usize, Arc<Semaphore>)>>,
}

impl ScriptedStorage {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script),
            puts: AtomicUsize::new(0),
            copies: AtomicUsize::new(0),
            hold: Mutex::new(None),
        })
    }

    fn set(&self, script: Script) {
        *self.script.lock() = script;
    }

    /// Hold answers until `arrivals` puts have reached the server.
    fn hold_until(&self, arrivals: usize) {
        *self.hold.lock() = Some((arrivals, Arc::new(Semaphore::new(0))));
    }

    fn puts(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }

    fn copies(&self) -> usize {
        self.copies.load(Ordering::SeqCst)
    }

    async fn answer(&self) -> Result<(), ProtocolError> {
        let arrived = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
        let hold = self.hold.lock().clone();
        if let Some((arrivals, release)) = hold {
            if arrived == arrivals {
                release.add_permits(1 << 16);
            }
            release
                .acquire()
                .await
                .expect("the hold semaphore stays open")
                .forget();
        }
        let script = *self.script.lock();
        match script {
            Script::Refuse => Err(refusal()),
            Script::Disconnect => Err(ProtocolError::from(Disconnected)),
            Script::SlowDown => Err(ProtocolError::from(SlowDown)),
            Script::ServerError => Err(ProtocolError::internal("generic server error")),
            Script::Accept | Script::AcceptPutsRefuseCopies | Script::OutcomeUnknown => Ok(()),
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
impl Storage for ScriptedStorage {
    async fn session_start(&self, _: Partition, _: &str) -> Result<u32, ProtocolError> {
        Ok(1)
    }

    async fn session_start_bound(
        &self,
        _: Partition,
        _: &str,
    ) -> Result<(u32, u32), ProtocolError> {
        Ok((1, 1))
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
        self.answer().await
    }

    async fn put_outcome(
        &self,
        _: u32,
        _: Address,
        _: Fragment,
        _: Option<Bytes>,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        self.answer().await?;
        if *self.script.lock() == Script::OutcomeUnknown {
            return Ok(MutableOutcome::Unknown(lore_transport::OutcomeUnknown {
                command: "Put",
            }));
        }
        Ok(MutableOutcome::Applied(()))
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
        self.copies.fetch_add(1, Ordering::SeqCst);
        match *self.script.lock() {
            Script::Accept => Ok(()),
            _ => Err(refusal()),
        }
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
        _: &str,
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
        _: &str,
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
        _: &str,
        _: &str,
        _: &Arc<SuppliedCredentials>,
    ) -> Result<Arc<dyn Repository>, ProtocolError> {
        not_scripted()
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
        not_scripted()
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

/// A real, resolved `StorageSession` over `storage`. Each test names its own scheme so tests
/// sharing the process never share a connection cache entry.
async fn session(scheme: &str, storage: &Arc<ScriptedStorage>) -> Arc<StorageSession> {
    lore_transport::connection::add(scheme, Arc::new(EnvironmentOnlyProtocol))
        .expect("register the scripted protocol");
    let connection = lore_transport::connect(
        &format!("{scheme}://gate.invalid"),
        "",
        RepositoryId::default(),
        1,
        "",
        "",
    )
    .await
    .expect("connect builds a connection without reaching any service");
    let connector = StorageConnector::new(vec![storage.clone() as Arc<dyn Storage>]);
    let pool = connector
        .session_pool(Partition::from([0x77; 16]), "gate", connection)
        .await
        .expect("the scripted start succeeds");
    pool.pick()
}

const PARTITION: [u8; 16] = [0x77; 16];

fn partition() -> Partition {
    Partition::from(PARTITION)
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

fn input(seed: u8) -> (Address, Fragment, Bytes) {
    input_in(seed, seed)
}

async fn store_one(
    store: &Arc<dyn ImmutableStore>,
    session: &Arc<StorageSession>,
    stats: &Arc<FragmentWriteStats>,
    seed: u8,
) -> StoreResult {
    let (address, fragment, payload) = input(seed);
    store_fragment(
        store.clone(),
        partition(),
        address,
        fragment,
        payload,
        true,
        Some(session.clone()),
        WriteContext::counted(Some(stats.clone())),
        None,
    )
    .await
    .expect("an unmanaged store never fails on a refused upload")
}

/// Stores `seeds` concurrently, each as its own task.
async fn store_concurrently(
    store: &Arc<dyn ImmutableStore>,
    session: &Arc<StorageSession>,
    stats: &Arc<FragmentWriteStats>,
    seeds: std::ops::RangeInclusive<u8>,
) -> Vec<StoreResult> {
    let mut tasks = Vec::new();
    for seed in seeds {
        let (store, session, stats) = (store.clone(), session.clone(), stats.clone());
        tasks.push(lore_base::lore_spawn!(async move {
            store_one(&store, &session, &stats, seed).await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("the store task joins"));
    }
    results
}

/// Seeds `store` with a fragment the peer already holds durably under another context of this
/// partition, so a store of the same content under `context` names it as a copy source.
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

async fn store_copy_candidate(
    store: &Arc<dyn ImmutableStore>,
    session: &Arc<StorageSession>,
    stats: &Arc<FragmentWriteStats>,
    seed: u8,
) -> StoreResult {
    let (address, fragment, payload) = input_in(seed, 0xDD);
    store_fragment(
        store.clone(),
        partition(),
        address,
        fragment,
        payload,
        true,
        Some(session.clone()),
        WriteContext::counted(Some(stats.clone())),
        None,
    )
    .await
    .expect("an unmanaged store never fails on a refused copy or upload")
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

fn assert_local_not_durable(results: &[StoreResult]) {
    for result in results {
        assert!(
            !result.stored_durable,
            "a refused or skipped write is not durable"
        );
        assert!(result.stored_local, "the payload stays local for push");
    }
}

const N: u8 = 20;

/// (a) Sequential unmanaged writes against a strict server: the first is refused and latches, the
/// rest skip. One Put reaches the server.
#[tokio::test]
async fn a_refusing_server_sees_one_put_from_sequential_writes() {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::Refuse);
    let session = session("qlflatchseq", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());

    let mut results = Vec::new();
    for seed in 1..=N {
        results.push(store_one(&store, &session, &stats, seed).await);
    }

    assert_eq!(
        storage.puts(),
        1,
        "only the first write reaches a strict server"
    );
    assert!(session.unmanaged_writes().is_refused());
    assert_local_not_durable(&results);
    let counts = stats.snapshot();
    assert_eq!(counts.remote_upload_failed, u64::from(N));
    assert_sum_invariant(&counts, u64::from(N));
}

/// (b) Writes already in flight when the refusal arrives finish normally; later ones skip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_writes_finish_and_later_writes_skip() {
    const K: u8 = 5;
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::Refuse);
    storage.hold_until(usize::from(K));
    let session = session("qlflatchinflight", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());

    // K writes reach the server together and are all answered once the Kth has arrived.
    let mut results = store_concurrently(&store, &session, &stats, 41..=40 + K).await;
    assert_eq!(storage.puts(), usize::from(K));
    assert!(session.unmanaged_writes().is_refused());

    // Writes started after the refusal skip.
    results.extend(store_concurrently(&store, &session, &stats, 41 + K..=40 + N).await);
    assert_eq!(
        storage.puts(),
        usize::from(K),
        "no write started after the refusal reaches the server"
    );
    assert_eq!(results.len(), usize::from(N));
    assert_local_not_durable(&results);
    let counts = stats.snapshot();
    assert_eq!(counts.remote_upload_failed, u64::from(N));
    assert_sum_invariant(&counts, u64::from(N));
}

/// (c) A compatible server receives every Put and the latch stays unset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_compatible_server_receives_every_put() {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::Accept);
    let session = session("qlflatchaccept", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());

    let results = store_concurrently(&store, &session, &stats, 81..=80 + N).await;

    assert_eq!(storage.puts(), usize::from(N));
    assert!(!session.unmanaged_writes().is_refused());
    assert!(results.iter().all(|result| result.stored_durable));
    let counts = stats.snapshot();
    assert_eq!(counts.remote_put_writes, u64::from(N));
    assert_eq!(counts.remote_upload_failed, 0);
    assert_sum_invariant(&counts, u64::from(N));
}

/// (d) A transient or non-policy failure says nothing about the server's policy: it must not
/// latch, and later writes still upload once the server answers.
async fn a_failure_that_is_not_a_refusal_never_latches(scheme: &str, failure: Script, seed: u8) {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(failure);
    let session = session(scheme, &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());

    let failed = store_one(&store, &session, &stats, seed).await;
    assert!(!failed.stored_durable, "the failed write is not durable");
    assert!(failed.stored_local, "the failed write stays local");
    assert!(storage.puts() >= 1, "the failing write reached the server");
    assert!(
        !session.unmanaged_writes().is_refused(),
        "a failure that is not an unsupported-client refusal must not latch"
    );

    storage.set(Script::Accept);
    let before = storage.puts();
    let later = store_one(&store, &session, &stats, seed + 1).await;
    assert_eq!(storage.puts(), before + 1, "a later write still uploads");
    assert!(later.stored_durable);
    assert!(!session.unmanaged_writes().is_refused());
}

#[tokio::test(start_paused = true)]
async fn a_disconnect_does_not_latch() {
    a_failure_that_is_not_a_refusal_never_latches("qlflatchdisconnect", Script::Disconnect, 101)
        .await;
}

#[tokio::test(start_paused = true)]
async fn an_exhausted_slow_down_does_not_latch() {
    a_failure_that_is_not_a_refusal_never_latches("qlflatchslowdown", Script::SlowDown, 103).await;
}

#[tokio::test(start_paused = true)]
async fn a_generic_server_error_does_not_latch() {
    a_failure_that_is_not_a_refusal_never_latches("qlflatchservererror", Script::ServerError, 105)
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_lost_answer_does_not_latch() {
    a_failure_that_is_not_a_refusal_never_latches("qlflatchunknown", Script::OutcomeUnknown, 107)
        .await;
}

/// (e) A refused Copy latches, and the upload that would have followed it is skipped. The
/// compatible-for-puts server would have accepted that upload, so the skip is the latch's.
#[tokio::test]
async fn a_refused_copy_skips_the_upload_that_follows() {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::AcceptPutsRefuseCopies);
    let session = session("qlflatchcopy", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());
    seed_copy_source(&store, 121).await;

    let result = store_copy_candidate(&store, &session, &stats, 121).await;

    assert_eq!(storage.copies(), 1, "the copy was attempted and refused");
    assert!(session.unmanaged_writes().is_refused());
    assert_eq!(
        storage.puts(),
        0,
        "the upload after a refused copy is skipped"
    );
    assert!(!result.stored_durable);
    assert!(result.stored_local);
    assert_eq!(stats.snapshot().remote_upload_failed, 1);
}

/// Once latched, a write that names a copy source skips the copy too.
#[tokio::test]
async fn a_latched_session_skips_the_copy() {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::Refuse);
    let session = session("qlflatchskipcopy", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());

    store_one(&store, &session, &stats, 131).await;
    assert!(session.unmanaged_writes().is_refused());
    seed_copy_source(&store, 133).await;

    let result = store_copy_candidate(&store, &session, &stats, 133).await;

    assert_eq!(storage.copies(), 0, "a latched session sends no copy");
    assert_eq!(storage.puts(), 1);
    assert!(!result.stored_durable);
    assert!(result.stored_local);
}

/// (f) A managed write returns the refusal to its caller and never sets the latch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_managed_refusal_is_the_callers_error_and_leaves_the_latch_unset() {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::Refuse);
    let session = session("qlflatchmanaged", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());
    let context = CallerOperationContext::new(
        Uuid::from_u128(0x1234),
        RepositoryId::default(),
        Arc::new(VolatileAttemptStore::new()),
    );

    let (address, fragment, payload) = input(201);
    let result = with_caller_operation(context, {
        let store = store.clone();
        let session = session.clone();
        let stats = stats.clone();
        async move {
            store_fragment(
                store,
                partition(),
                address,
                fragment,
                payload,
                true,
                Some(session),
                WriteContext::counted(Some(stats)),
                None,
            )
            .await
        }
    })
    .await;

    assert!(
        result.is_err(),
        "a managed write returns the refusal to its caller, but it succeeded"
    );
    assert_eq!(storage.puts(), 1, "the managed write reached the server");
    assert!(
        !session.unmanaged_writes().is_refused(),
        "a managed refusal never sets the unmanaged latch"
    );
}

/// A latched session still sends a managed write: the latch is the unmanaged path's alone.
#[tokio::test]
async fn a_managed_write_ignores_a_latched_session() {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::Accept);
    let session = session("qlflatchmanagedsent", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());
    session.unmanaged_writes().refuse();
    let context = CallerOperationContext::new(
        Uuid::from_u128(0x5678),
        RepositoryId::default(),
        Arc::new(VolatileAttemptStore::new()),
    );

    let (address, fragment, payload) = input(211);
    let result = with_caller_operation(context, {
        let store = store.clone();
        let session = session.clone();
        async move {
            store_fragment(
                store,
                partition(),
                address,
                fragment,
                payload,
                true,
                Some(session),
                WriteContext::counted(Some(stats)),
                None,
            )
            .await
        }
    })
    .await
    .expect("a managed write is admitted whatever the unmanaged latch says");

    assert_eq!(storage.puts(), 1, "the managed Put reached the server");
    assert!(result.stored_durable, "the managed write is durable");
}
/// (g) The write-tracker path, which is what `lore commit` uses. A first batch learns the
/// refusal; a second batch of many fragments then sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tracker_path_sends_nothing_after_the_refusal() {
    let (_dir, store) = make_test_store().await;
    let storage = ScriptedStorage::new(Script::Refuse);
    let session = session("qlflatchtracker", &storage).await;
    let stats = Arc::new(FragmentWriteStats::default());

    let dispatch = |seeds: std::ops::RangeInclusive<u8>| {
        let tracker = Arc::new(WriteTracker::new());
        let store = store.clone();
        let session = session.clone();
        let stats = stats.clone();
        async move {
            let mut addresses = Vec::new();
            for seed in seeds {
                let (address, fragment, payload) = input(seed);
                store_fragment(
                    store.clone(),
                    partition(),
                    address,
                    fragment,
                    payload,
                    true,
                    Some(session.clone()),
                    WriteContext::tracked(Some(tracker.clone()), Some(stats.clone())),
                    None,
                )
                .await
                .expect("dispatching a tracked write succeeds");
                addresses.push(address);
            }
            tracker
                .await_all()
                .await
                .expect("a refused upload is not a tracker failure");
            (store, addresses)
        }
    };

    let (store, mut addresses) = dispatch(151..=151).await;
    assert_eq!(storage.puts(), 1);
    assert!(session.unmanaged_writes().is_refused());

    let (_, more) = dispatch(152..=150 + N).await;
    addresses.extend(more);

    assert_eq!(
        storage.puts(),
        1,
        "the second batch sends nothing to a strict server"
    );
    for address in addresses {
        let placed = query_one(&store, partition(), address)
            .await
            .expect("the fragment is in the local store");
        assert!(placed.stored_local, "the fragment stays local");
        assert!(!placed.stored_durable, "the fragment is not durable");
    }
    let counts = stats.snapshot();
    assert_eq!(counts.remote_upload_failed, u64::from(N));
    assert_sum_invariant(&counts, u64::from(N));
}

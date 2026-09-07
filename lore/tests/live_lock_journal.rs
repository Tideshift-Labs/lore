// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The lock verbs' attempt journal, driven against a remote that answers (WP-120).

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use lore::interface::LoreEventCallback;
use lore_base::error::NotAuthorized;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_revision::attempt_store::repository_attempt_store;
use lore_revision::event::LoreCompleteEventData;
use lore_revision::instance::load_current_anchor;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreError;
use lore_revision::interface::LoreEvent;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockPolicy;
use lore_revision::live_fixture::LockRpc;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::LockServerProbe;
use lore_revision::live_fixture::Refusal;
use lore_revision::live_fixture::RpcOutcome;
use lore_revision::live_fixture::UnlockEcho;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::lock::util::assemble_resource_for_path;
use lore_revision::repository::RepositoryAccess;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::OwnershipToken;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;

fn no_callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}

/// A real callback that captures the operation's `LoreEvent::Complete` data -- the only place the
/// error detail's `operation`/`attempt_id` fields (and the exact per-variant FFI code, distinct
/// from the coarse `translated()` code) are observable at all. `no_callback()` above throws every
/// event away, including this one, so a test that needs to read the detail rather than only the
/// plain status integer a call returns must use this instead.
fn capture_complete() -> (LoreEventCallback, Arc<Mutex<Option<LoreCompleteEventData>>>) {
    let captured: Arc<Mutex<Option<LoreCompleteEventData>>> = Arc::new(Mutex::new(None));
    let sink = captured.clone();
    let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
        if let LoreEvent::Complete(data) = event {
            *sink.lock().expect("the capture mutex must not be poisoned") = Some(data.clone());
        }
    }));
    (callback, captured)
}

// A smoke test lived here, asserting that an acquire reached the server carrying an attempt id.
// A reviewer proved it vacuous: replacing the caller's store with `None` at the entry point left
// it green, because the transport mints its own id per dispatch when no store is supplied, so the
// header it checked was there either way. Removed rather than reworded. Everything it covered --
// that the fixture connects, that a dispatch reaches the server, that the id is journalled -- is
// covered by `acquire_journals_one_attempt_per_dispatch_before_the_dispatch_and_resolves_it_after`
// below, which the same probe turned red.

/// Every path a lock verb needs, as absolute paths, in the shape `LoreLockFile*Args` wants.
fn all_paths(fixture: &LiveRepository) -> LoreArray<LoreString> {
    LoreArray::from_vec(
        fixture
            .committed_files_absolute
            .iter()
            .map(LoreString::from)
            .collect(),
    )
}

/// One entry in a [`JournalSpy`]'s log.
///
/// Carrying `server_calls_when_recorded` on the `Record` variant is the entire point of this
/// module: a snapshot of the store taken at the end of a test can only see that a record exists,
/// never when it was written relative to the request leaving. Pairing every `record()` with
/// [`LockServerProbe::call_count`] at that exact moment is what turns "the store holds a record"
/// into "the record was written before the request reached the server".
#[derive(Clone, Debug)]
enum JournalEntry {
    Record {
        attempt_id: String,
        operation: String,
        /// `None` only for a spy built with [`JournalSpy::without_server`], where there is no
        /// server to ask -- that shape's whole claim is that this variant is never logged at all.
        server_calls_when_recorded: Option<usize>,
    },
    Resolve {
        attempt_id: String,
        resolution: AttemptResolution,
    },
}

/// A test-local [`AttemptStore`] that journals every call it receives on top of a real
/// [`VolatileAttemptStore`] doing the actual bookkeeping.
///
/// A caller passes this in place of its own durable store, and the log it accumulates is a
/// timeline a plain end-of-test snapshot cannot produce: the store's own state after the call
/// only proves a record eventually existed, not that it existed *before* the dispatch that
/// produced it. This is implemented by hand against `AttemptStore`'s macro-expanded signature
/// (returning a boxed future directly) rather than with the `async_trait` attribute, because that
/// attribute's crate is not a dependency of `lore` and this file may only edit itself.
struct JournalSpy {
    inner: VolatileAttemptStore,
    probe: Option<LockServerProbe>,
    log: Mutex<Vec<JournalEntry>>,
}

impl JournalSpy {
    fn new(probe: LockServerProbe) -> Self {
        Self {
            inner: VolatileAttemptStore::new(),
            probe: Some(probe),
            log: Mutex::new(Vec::new()),
        }
    }

    /// A spy with no server to ask. Used only for the unreachable-remote case, whose entire claim
    /// is that `record()` is never called at all -- there is nothing to time against.
    fn without_server() -> Self {
        Self {
            inner: VolatileAttemptStore::new(),
            probe: None,
            log: Mutex::new(Vec::new()),
        }
    }

    fn entries(&self) -> Vec<JournalEntry> {
        self.log
            .lock()
            .expect("the spy's own log mutex must not be poisoned")
            .clone()
    }

    fn record_entries(&self) -> Vec<(String, String, Option<usize>)> {
        self.entries()
            .into_iter()
            .filter_map(|entry| match entry {
                JournalEntry::Record {
                    attempt_id,
                    operation,
                    server_calls_when_recorded,
                } => Some((attempt_id, operation, server_calls_when_recorded)),
                JournalEntry::Resolve { .. } => None,
            })
            .collect()
    }

    fn resolve_entries(&self) -> Vec<(String, AttemptResolution)> {
        self.entries()
            .into_iter()
            .filter_map(|entry| match entry {
                JournalEntry::Resolve {
                    attempt_id,
                    resolution,
                } => Some((attempt_id, resolution)),
                JournalEntry::Record { .. } => None,
            })
            .collect()
    }
}

impl AttemptStore for JournalSpy {
    fn record<'life0, 'life1, 'async_trait>(
        &'life0 self,
        record: &'life1 AttemptRecord,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        // Logged synchronously, before the returned future is ever polled: the caller's next
        // action after `record().await` is the dispatch itself, so the server's call count read
        // here is the count as of the moment the caller asked to record, which is what "before
        // the dispatch" means.
        self.log
            .lock()
            .expect("the spy's own log mutex must not be poisoned")
            .push(JournalEntry::Record {
                attempt_id: record.attempt_id.to_string(),
                operation: record.operation.clone(),
                server_calls_when_recorded: self.probe.as_ref().map(LockServerProbe::call_count),
            });
        self.inner.record(record)
    }

    fn lookup<'life0, 'life1, 'async_trait>(
        &'life0 self,
        attempt: &'life1 AttemptId,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<AttemptRecord>, ProtocolError>> + Send + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.lookup(attempt)
    }

    fn unresolved<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Vec<AttemptRecord>, ProtocolError>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.unresolved()
    }

    fn record_ownership<'life0, 'life1, 'async_trait>(
        &'life0 self,
        ownership: &'life1 LockOwnership,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.record_ownership(ownership)
    }

    fn ownership_for<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        branch: &'life1 Context,
        resource_hash: &'life2 Hash,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<LockOwnership>, ProtocolError>> + Send + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.ownership_for(branch, resource_hash)
    }

    fn clear_ownership<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        branch: &'life1 Context,
        resource_hash: &'life2 Hash,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.clear_ownership(branch, resource_hash)
    }

    fn resolve<'life0, 'life1, 'async_trait>(
        &'life0 self,
        attempt: &'life1 AttemptId,
        resolution: AttemptResolution,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.log
            .lock()
            .expect("the spy's own log mutex must not be poisoned")
            .push(JournalEntry::Resolve {
                attempt_id: attempt.to_string(),
                resolution,
            });
        self.inner.resolve(attempt, resolution)
    }
}

/// An [`AttemptStore`] that panics inside `resolve()`, before ever touching the real store
/// underneath -- everything else delegates to a genuine [`VolatileAttemptStore`].
///
/// The panic is placed in `resolve()` specifically so it can only be reached AFTER a real dispatch
/// has already succeeded: `under_named_attempt` calls `record()` (delegated, so the attempt's
/// Unresolved record is genuinely written) and dispatches the real RPC BEFORE ever calling
/// `resolve()` on success. So a batch task built on this double panics only once its own request
/// has already been granted by the server -- simulating a batch task that dies for a reason wholly
/// unrelated to whether the request reached the remote, which is exactly the ambiguity
/// `lost_batch_task` exists to name rather than paper over.
///
/// Panicking BEFORE delegating to `self.inner.resolve(...)` is deliberate, not incidental: it means
/// `self.inner`'s own `std::sync::Mutex` is never locked by the panicking call, so it cannot be
/// left poisoned, and the test can still read every other method on `self.inner` after the
/// panicking task has unwound.
struct PanicOnResolve {
    inner: VolatileAttemptStore,
}

impl PanicOnResolve {
    fn new() -> Self {
        Self {
            inner: VolatileAttemptStore::new(),
        }
    }
}

impl AttemptStore for PanicOnResolve {
    fn record<'life0, 'life1, 'async_trait>(
        &'life0 self,
        record: &'life1 AttemptRecord,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.record(record)
    }

    fn lookup<'life0, 'life1, 'async_trait>(
        &'life0 self,
        attempt: &'life1 AttemptId,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<AttemptRecord>, ProtocolError>> + Send + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.lookup(attempt)
    }

    fn unresolved<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Vec<AttemptRecord>, ProtocolError>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.unresolved()
    }

    fn record_ownership<'life0, 'life1, 'async_trait>(
        &'life0 self,
        ownership: &'life1 LockOwnership,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.record_ownership(ownership)
    }

    fn ownership_for<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        branch: &'life1 Context,
        resource_hash: &'life2 Hash,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<LockOwnership>, ProtocolError>> + Send + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.ownership_for(branch, resource_hash)
    }

    fn clear_ownership<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        branch: &'life1 Context,
        resource_hash: &'life2 Hash,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.clear_ownership(branch, resource_hash)
    }

    fn resolve<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _attempt: &'life1 AttemptId,
        _resolution: AttemptResolution,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        panic!(
            "PanicOnResolve: simulated batch task death after a real dispatch already succeeded"
        );
    }
}

/// An acquire mints one attempt id per dispatch, records it in the caller's store before the
/// dispatch leaves, and resolves it once the server answers.
///
/// The discriminating fact is the server call count captured *inside* `record()`: if the journal
/// entry were written after the request left (or not at all, and only backfilled from the
/// response), the server would already show one `Lock` call by the time `record()` ran. Catching
/// that ordering bug needs the count read from inside the store call itself, which is exactly what
/// `JournalSpy` and `LockServerProbe` exist to give a test outside the transport layer.
#[test]
fn acquire_journals_one_attempt_per_dispatch_before_the_dispatch_and_resolves_it_after() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));
    assert_eq!(status, 0, "the acquire must succeed against the fixture");

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        1,
        "one committed file is one batch is one dispatch, got {:?}",
        server.calls()
    );
    let server_attempt_id = locks[0]
        .attempt_id
        .clone()
        .expect("the dispatch must have carried an attempt id to the server");

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "one dispatch must journal exactly one record, got {records:?}"
    );
    let (record_attempt_id, operation, calls_when_recorded) = records[0].clone();
    assert_eq!(
        operation,
        GrpcRpc::LockLock.wire_name(),
        "the journalled operation must name the exact RPC that was dispatched"
    );
    assert_eq!(
        calls_when_recorded,
        Some(0),
        "the server must have received nothing yet at the moment the record was written -- a \
         nonzero count here would mean the request left before the journal entry did"
    );
    assert_eq!(
        record_attempt_id, server_attempt_id,
        "the id the caller journalled must be the exact id that reached the server"
    );

    let resolves = spy.resolve_entries();
    assert_eq!(
        resolves.len(),
        1,
        "the dispatch must be resolved exactly once, got {resolves:?}"
    );
    assert_eq!(resolves[0].0, server_attempt_id);
    assert_eq!(
        resolves[0].1,
        AttemptResolution::Applied,
        "a granted lock is a decisively applied attempt"
    );

    assert!(
        runtime
            .block_on(spy.inner.unresolved())
            .expect("unresolved() must succeed on a fresh store")
            .is_empty(),
        "a resolved attempt must not still count as unresolved"
    );
}

/// A release journals its own unlock dispatch the same way an acquire journals its lock dispatch,
/// and the two must not be confused with each other.
///
/// The release in this test runs against a repository that already has a lock outstanding from an
/// earlier acquire made with a *different* store. If release journalling were implemented by
/// reading back whatever the acquire wrote instead of recording its own attempt, or if the two
/// dispatches shared one store instance by accident, this test's fresh spy would show either zero
/// records (nothing of its own was ever written) or the acquire's `Lock` operation under this
/// spy's roof -- both are ruled out by asserting the exactly-one record here names `LockUnlock`.
#[test]
fn release_journals_its_unlock_dispatch_before_the_dispatch_and_resolves_it_after() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let acquire_attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    let acquire_status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        acquire_attempts,
    ));
    assert_eq!(
        acquire_status, 0,
        "acquiring the lock ahead of the release under test must succeed"
    );

    // A fresh spy: the acquire above must not leave a trace in the release's own journal.
    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let release_status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileReleaseArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));
    assert_eq!(
        release_status, 0,
        "the release must succeed against the fixture"
    );

    let unlocks = server.calls_for(LockRpc::Unlock);
    assert_eq!(
        unlocks.len(),
        1,
        "one committed file is one batch is one unlock dispatch, got {:?}",
        server.calls()
    );
    let server_attempt_id = unlocks[0]
        .attempt_id
        .clone()
        .expect("the dispatch must have carried an attempt id to the server");

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the release's own dispatch must be the only record in this spy's log, got {records:?}"
    );
    let (record_attempt_id, operation, calls_when_recorded) = records[0].clone();
    assert_eq!(
        operation,
        GrpcRpc::LockUnlock.wire_name(),
        "the journalled operation must name the release's own RPC, not the earlier acquire's"
    );
    assert_eq!(record_attempt_id, server_attempt_id);
    // Not zero here: the acquire above already put one call on this server. The discriminating
    // value is the position of the unlock itself, which is what "the record was written before
    // this request left" means once the server has a history.
    assert_eq!(
        calls_when_recorded,
        Some(call_index(&server.calls(), LockRpc::Unlock)),
        "the record must have been written before the unlock reached the server"
    );

    let resolves = spy.resolve_entries();
    assert_eq!(resolves.len(), 1, "got {resolves:?}");
    assert_eq!(resolves[0].0, server_attempt_id);
    assert_eq!(resolves[0].1, AttemptResolution::Applied);
}

/// A decisive refusal from the server still resolves the record it wrote, as `NotApplied` rather
/// than leaving it unresolved.
///
/// An unresolved decisive refusal would be the worst of both outcomes: the caller's boot-recovery
/// read (`unresolved()`) would keep surfacing an attempt that is already known, with certainty, not
/// to have happened, indefinitely blocking new writes to the repository over nothing.
#[test]
fn a_decisive_refusal_resolves_not_applied_and_the_record_still_exists() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Refuse(Refusal::PermissionDenied),
        ..LockPolicy::default()
    }));
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));
    assert_ne!(
        status, 0,
        "a permission-denied refusal must fail the acquire"
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the refused dispatch must still be journalled once, got {records:?}"
    );

    let resolves = spy.resolve_entries();
    assert_eq!(
        resolves.len(),
        1,
        "a decisive refusal must resolve the record rather than leaving it unresolved forever, \
         got {resolves:?}"
    );
    assert_eq!(
        resolves[0].0, records[0].0,
        "the same attempt id must both be recorded and resolved"
    );
    assert_eq!(resolves[0].1, AttemptResolution::NotApplied);
}

/// Nothing is journalled when the remote never resolves at all.
///
/// The remote here names a port nothing listens on, so the connect fails and the acquire never
/// reaches `under_own_attempt`. This pins that the journal entry is minted inside the batch task,
/// after a real lock connect, and not eagerly at the top of the verb -- a caller speculatively
/// recording an attempt for a connection that was never established would leave a permanently
/// unresolved record for a mutation that was never dispatched.
///
/// The second half is what makes the first half mean anything. An empty journal is also what a
/// repository that never opened at all would produce, and a reviewer proved that an earlier
/// version of this test stayed green when pointed at a path with no repository on it. So the same
/// call is made twice, once against a real repository whose remote is unreachable and once against
/// a path that holds no repository, and the two statuses must differ. A test that cannot tell
/// those apart is not testing the connect.
#[test]
fn nothing_is_journalled_when_the_remote_never_resolves() {
    let runtime = lore::runtime();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create("grpc://127.0.0.1:1").await
    }));

    let spy = Arc::new(JournalSpy::without_server());
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));
    assert_ne!(
        status, 0,
        "an acquire against a remote nothing answers on must fail"
    );

    assert!(
        spy.record_entries().is_empty(),
        "no record may be written when the connect that would precede it never succeeded, got {:?}",
        spy.record_entries()
    );

    let mut absent = fixture.globals();
    absent.repository_path =
        LoreString::from_str("Z:/lore-live-lock-journal-no-such-repository-4c81ad");
    let absent_spy = Arc::new(JournalSpy::without_server());
    let absent_attempts: Arc<dyn AttemptStore> = absent_spy.clone();
    let absent_status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        absent,
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        absent_attempts,
    ));

    assert_ne!(
        status, absent_status,
        "the unreachable-remote failure must be distinguishable from a repository that was never \
         opened; if these agree, this test cannot tell which one it just proved"
    );
}

/// The force-release escalation -- reached only through `--force` with no explicit paths, against
/// rows this client holds no ownership token for -- is journalled exactly like any other
/// irreversible dispatch.
///
/// This is the dispatch a caller most needs journalled: a takeover removes a lock row from
/// whoever currently holds it, so an unresolved outcome here is the one a reconciler cannot afford
/// to guess about. The policy forces every row down the tokenless path (`mint_ownership_tokens:
/// false`), refuses the ordinary `Unlock` so the escalation is reached, and grants the
/// `ForceUnlock` that follows it.
///
/// This is also the positive half of a pair with
/// `a_lost_answer_on_the_unlock_is_not_escalated_to_a_force_release`: a DECISIVE refusal still
/// escalates. That is what makes the sibling test's empty force-unlock log mean "the non-decisive
/// case was declined" rather than "escalation is broken here altogether" -- without this test, an
/// implementation that never escalates at all would make the sibling's empty log vacuous.
#[test]
fn the_force_release_escalation_is_journalled() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        mint_ownership_tokens: false,
        unlock: RpcOutcome::Refuse(Refusal::PermissionDenied),
        force_unlock: RpcOutcome::Grant,
        ..LockPolicy::default()
    }));
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    // The escalation needs a known owner, which only a `Query` response provides -- naming the
    // committed file exactly as the release path will rebuild it.
    server.set_policy(LockPolicy {
        mint_ownership_tokens: false,
        unlock: RpcOutcome::Refuse(Refusal::PermissionDenied),
        force_unlock: RpcOutcome::Grant,
        query_result: vec![(
            fixture.committed_files[0].clone(),
            "someone-else".to_owned(),
        )],
        ..LockPolicy::default()
    });

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let mut globals = fixture.globals();
    globals.force = 1;

    let status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        globals,
        lore::lock::LoreLockFileReleaseArgs {
            paths: LoreArray::default(),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));
    assert_eq!(
        status, 0,
        "the force-release must succeed once the takeover is granted"
    );

    let force_unlocks = server.calls_for(LockRpc::ForceUnlock);
    assert_eq!(
        force_unlocks.len(),
        1,
        "the escalation must reach the server exactly once, got {:?}",
        server.calls()
    );
    let server_attempt_id = force_unlocks[0]
        .attempt_id
        .clone()
        .expect("the escalation must have carried an attempt id to the server");

    let force_records: Vec<_> = spy
        .record_entries()
        .into_iter()
        .filter(|(_, operation, _)| operation == GrpcRpc::LockForceUnlock.wire_name())
        .collect();
    assert_eq!(
        force_records.len(),
        1,
        "the escalation must be journalled under the force-unlock operation name, got {:?}",
        spy.record_entries()
    );
    assert_eq!(force_records[0].0, server_attempt_id);
    // A release that escalates has already made a query and a refused unlock by this point, so the
    // discriminating value is the takeover's own position in the server's history rather than
    // zero. Recording after the takeover left would put this one higher.
    assert_eq!(
        force_records[0].2,
        Some(call_index(&server.calls(), LockRpc::ForceUnlock)),
        "the record must have been written before the takeover reached the server"
    );
}

/// A lost answer on the `Unlock` call must not be escalated to a `ForceUnlock` takeover.
///
/// This is a near-copy of `the_force_release_escalation_is_journalled`, differing in exactly ONE
/// input: the `unlock` policy answers `RpcOutcome::LoseTheAnswer` instead of
/// `RpcOutcome::Refuse(Refusal::PermissionDenied)`. That one-input difference is the whole point.
/// Paired with `the_force_release_escalation_is_journalled` (a decisive refusal still escalates),
/// this test shows the escalation is declined specifically because the outcome was non-decisive,
/// not because escalation is broken or because this policy shape can never reach it.
///
/// A version of this test that only checked `status != 0` would still pass on the buggy
/// implementation, which also fails the release (by way of the second, escalated mutation
/// failing or succeeding for the wrong reason) -- the status must be the exact `OutcomeUnknown`
/// code, and the force-unlock log must be provably empty, not merely "the release failed somehow".
#[test]
fn a_lost_answer_on_the_unlock_is_not_escalated_to_a_force_release() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        mint_ownership_tokens: false,
        unlock: RpcOutcome::LoseTheAnswer,
        force_unlock: RpcOutcome::Grant,
        ..LockPolicy::default()
    }));
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    // The escalation needs a known owner, which only a `Query` response provides -- naming the
    // committed file exactly as the release path will rebuild it. Set after the fixture exists,
    // matching `the_force_release_escalation_is_journalled`'s own two-step policy setup.
    server.set_policy(LockPolicy {
        mint_ownership_tokens: false,
        unlock: RpcOutcome::LoseTheAnswer,
        force_unlock: RpcOutcome::Grant,
        query_result: vec![(
            fixture.committed_files[0].clone(),
            "someone-else".to_owned(),
        )],
        ..LockPolicy::default()
    });

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let mut globals = fixture.globals();
    globals.force = 1;

    // `--force` with no explicit paths is the only shape that can escalate at all, because it is
    // the only one that learns an owner from a `Query`.
    let status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        globals,
        lore::lock::LoreLockFileReleaseArgs {
            paths: LoreArray::default(),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "a lost answer on the unlock must surface as the named OutcomeUnknown code, not merely a \
         nonzero status -- a nonzero-only assertion would pass on the buggy code path too"
    );

    let force_unlocks = server.calls_for(LockRpc::ForceUnlock);
    assert!(
        force_unlocks.is_empty(),
        "a non-decisive lost answer must never trigger a second irreversible mutation on a maybe \
         -- an administrative takeover is not a safe response to an unlock whose outcome is \
         unknown. Got {:?}",
        server.calls()
    );

    let unlocks = server.calls_for(LockRpc::Unlock);
    assert_eq!(
        unlocks.len(),
        1,
        "exactly one Unlock dispatch must have reached the server, got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the release must journal exactly one attempt, under the unlock operation name, got \
         {records:?}"
    );
    assert_eq!(
        records[0].1,
        GrpcRpc::LockUnlock.wire_name(),
        "the journalled attempt must be the unlock dispatch itself"
    );

    let resolves = spy.resolve_entries();
    assert!(
        resolves.is_empty(),
        "a lost answer must leave its attempt unresolved rather than resolving it, got \
         {resolves:?}"
    );
    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the one lost-answer attempt must remain standing for later reconciliation, got \
         {unresolved:?}"
    );
}

/// A lost answer on the `Unlock` for a lock this client actually holds a token for must leave
/// that lock's ownership row standing.
///
/// This is a regression pin, not a proof of the escalation fix: a reviewer confirmed this test
/// PASSES against `release.rs` reverted to HEAD (pre-fix), because the `held` path never
/// populates `unlocks` when the lone batch fails -- decisively refused or non-decisively lost, the
/// clear list is empty either way, so the row survives for a reason this change did not
/// introduce. `a_lost_answer_on_the_unlock_is_not_escalated_to_a_force_release` is the sibling
/// that genuinely fails on pre-fix code and is the real proof of the fix. This test is kept
/// because the `held` path is where a future change (e.g. clearing ownership unconditionally
/// rather than only for what the server confirmed) would most plausibly break the row's
/// survival, and a version of this test that only checked the returned status would not catch
/// that either -- discarding a token does not itself change the release's status.
#[test]
fn a_lost_answer_on_the_unlock_leaves_the_held_locks_ownership_row_standing() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    // Default policy: tokens minted. Acquire with a throwaway store; only the release under test
    // needs the spy.
    let acquire_attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    let acquire_status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        acquire_attempts,
    ));
    assert_eq!(acquire_status, 0, "acquiring the file must succeed");
    assert_eq!(
        ownership_row_count(&fixture.path),
        1,
        "the acquire must have minted and stored its own ownership row"
    );

    server.set_policy(LockPolicy {
        unlock: RpcOutcome::LoseTheAnswer,
        ..LockPolicy::default()
    });

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    // Explicit paths, no force: the shape that goes entirely through the `held` set.
    let release_status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileReleaseArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        release_status,
        LoreError::OutcomeUnknown as i32,
        "a lost answer on the unlock must surface as OutcomeUnknown to the caller"
    );

    assert_eq!(
        ownership_row_count(&fixture.path),
        1,
        "the held lock's ownership row must survive a release whose own attempt's outcome is \
         unknown -- zero would mean a token was discarded for a lock that may still be held, \
         leaving nothing able to release it"
    );

    let force_unlocks = server.calls_for(LockRpc::ForceUnlock);
    assert!(
        force_unlocks.is_empty(),
        "the held path has no escalation branch to reach in the first place; assert it stays \
         that way. Got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the release must journal exactly one LockUnlock attempt, got {records:?}"
    );
    assert_eq!(
        records[0].1,
        GrpcRpc::LockUnlock.wire_name(),
        "the journalled attempt must name the unlock dispatch"
    );

    assert!(
        spy.resolve_entries().is_empty(),
        "a lost answer must leave the attempt unresolved, got {:?}",
        spy.resolve_entries()
    );
    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the one lost-answer attempt must remain standing for reconciliation, got \
         {unresolved:?}"
    );
}

/// An `Unlock` answered `Status::cancelled` must not be escalated to a `ForceUnlock` takeover.
///
/// A near-copy of `a_lost_answer_on_the_unlock_is_not_escalated_to_a_force_release`, differing in
/// exactly ONE input: the `unlock` policy answers `RpcOutcome::LoseTheAnswerCancelled` instead of
/// `RpcOutcome::LoseTheAnswer`. This is the shape the defect actually reported -- a mid-flight
/// stream reset or an expired deadline reads as `Cancelled`/`DeadlineExceeded`, not `Unavailable`
/// -- so this test, not its `LoseTheAnswer` sibling, is the one that exercises
/// `lore-transport/src/error.rs`'s `AnswerLostInTransit` marker at all. A reviewer confirmed by
/// temporary mutation (substituting `Status::internal` for `Status::cancelled` in the fixture's
/// `lost_answer_cancelled()`) that 2 of this file's 8 tests before this addition fail without the
/// fix; this test and its ownership-row sibling below make that permanent rather than leaving it
/// as a one-off probe.
#[test]
fn an_unlock_answered_with_cancelled_is_not_escalated_to_a_force_release() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        mint_ownership_tokens: false,
        unlock: RpcOutcome::LoseTheAnswerCancelled,
        force_unlock: RpcOutcome::Grant,
        ..LockPolicy::default()
    }));
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    // The escalation needs a known owner, which only a `Query` response provides -- naming the
    // committed file exactly as the release path will rebuild it. Set after the fixture exists,
    // matching the sibling tests' own two-step policy setup.
    server.set_policy(LockPolicy {
        mint_ownership_tokens: false,
        unlock: RpcOutcome::LoseTheAnswerCancelled,
        force_unlock: RpcOutcome::Grant,
        query_result: vec![(
            fixture.committed_files[0].clone(),
            "someone-else".to_owned(),
        )],
        ..LockPolicy::default()
    });

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let mut globals = fixture.globals();
    globals.force = 1;

    // `--force` with no explicit paths is the only shape that can escalate at all, because it is
    // the only one that learns an owner from a `Query`.
    let status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        globals,
        lore::lock::LoreLockFileReleaseArgs {
            paths: LoreArray::default(),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "an unlock answered Cancelled must surface as the named OutcomeUnknown code, not merely a \
         nonzero status -- a nonzero-only assertion would pass on the pre-fix code path too, which \
         read a mid-flight reset as a decisive Internal refusal"
    );

    let force_unlocks = server.calls_for(LockRpc::ForceUnlock);
    assert!(
        force_unlocks.is_empty(),
        "a non-decisive Cancelled must never trigger a second irreversible mutation on a maybe -- \
         an administrative takeover is not a safe response to an unlock whose outcome is unknown. \
         Got {:?}",
        server.calls()
    );

    let unlocks = server.calls_for(LockRpc::Unlock);
    assert_eq!(
        unlocks.len(),
        1,
        "exactly one Unlock dispatch must have reached the server, got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the release must journal exactly one attempt, under the unlock operation name, got \
         {records:?}"
    );
    assert_eq!(
        records[0].1,
        GrpcRpc::LockUnlock.wire_name(),
        "the journalled attempt must be the unlock dispatch itself"
    );

    let resolves = spy.resolve_entries();
    assert!(
        resolves.is_empty(),
        "a lost answer must leave its attempt unresolved rather than resolving it, got \
         {resolves:?}"
    );
    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the one lost-answer attempt must remain standing for later reconciliation, got \
         {unresolved:?}"
    );
}

/// An `Unlock` answered `Status::cancelled`, for a lock this client actually holds a token for,
/// must leave that lock's ownership row standing.
///
/// A near-copy of `a_lost_answer_on_the_unlock_leaves_the_held_locks_ownership_row_standing`,
/// substituting `RpcOutcome::LoseTheAnswerCancelled` for `RpcOutcome::LoseTheAnswer` for the same
/// reason as its sibling above: this is the code path the defect actually took.
#[test]
fn an_unlock_answered_with_cancelled_leaves_the_held_locks_ownership_row_standing() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    // Default policy: tokens minted. Acquire with a throwaway store; only the release under test
    // needs the spy.
    let acquire_attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    let acquire_status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        acquire_attempts,
    ));
    assert_eq!(acquire_status, 0, "acquiring the file must succeed");
    assert_eq!(
        ownership_row_count(&fixture.path),
        1,
        "the acquire must have minted and stored its own ownership row"
    );

    server.set_policy(LockPolicy {
        unlock: RpcOutcome::LoseTheAnswerCancelled,
        ..LockPolicy::default()
    });

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    // Explicit paths, no force: the shape that goes entirely through the `held` set.
    let release_status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileReleaseArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        release_status,
        LoreError::OutcomeUnknown as i32,
        "an unlock answered Cancelled must surface as OutcomeUnknown to the caller"
    );

    assert_eq!(
        ownership_row_count(&fixture.path),
        1,
        "the held lock's ownership row must survive a release whose own attempt's outcome is \
         unknown -- zero would mean a token was discarded for a lock that may still be held, \
         leaving nothing able to release it"
    );

    let force_unlocks = server.calls_for(LockRpc::ForceUnlock);
    assert!(
        force_unlocks.is_empty(),
        "the held path has no escalation branch to reach in the first place; assert it stays \
         that way. Got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the release must journal exactly one LockUnlock attempt, got {records:?}"
    );
    assert_eq!(
        records[0].1,
        GrpcRpc::LockUnlock.wire_name(),
        "the journalled attempt must name the unlock dispatch"
    );

    assert!(
        spy.resolve_entries().is_empty(),
        "a lost answer must leave the attempt unresolved, got {:?}",
        spy.resolve_entries()
    );
    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the one lost-answer attempt must remain standing for reconciliation, got \
         {unresolved:?}"
    );
}

/// Where the first call of `rpc` sits in the server's arrival order.
///
/// The number a correct `record()` sees: every call before this one had already arrived, and this
/// one had not. Panics if the RPC never arrived, which is a test bug rather than a soft failure.
///
/// Taking the FIRST match is only right because every caller has already asserted that exactly one
/// call of that RPC reached the server. Add a second one without that assertion and this silently
/// starts answering about the wrong dispatch.
fn call_index(calls: &[lore_revision::live_fixture::LockCall], rpc: LockRpc) -> usize {
    calls
        .iter()
        .position(|call| call.rpc == rpc)
        .expect("the RPC under test must have reached the server")
}

/// Release clears ownership for exactly what the server confirmed, and `resolve` clears none of
/// it: two separate claims about the same ownership rows, proven against the live fixture's
/// on-disk `.lore/attempts` document.
///
/// The first half acquires two files (two ownership rows minted) and releases both, but the server
/// confirms only the first (`UnlockEcho::FirstOnly`). Counting rows before and after is what
/// discriminates all three plausible-looking implementations: clearing the whole request would
/// leave zero, clearing nothing would leave two, and only clearing what the server actually named
/// leaves exactly one.
///
/// The second half acquires one file, then releases it against a server that refuses the `Unlock`
/// outright. The release fails and its attempt record resolves `NotApplied`, but the ownership row
/// for the lock that attempt never released must still be present -- this is the live half of the
/// invariant that `resolve()` settles an attempt without dropping the lock it took: a lock outlives
/// the attempt that took it, and clearing the token on a merely-resolved (rather than
/// confirmed-released) attempt would strand a held lock behind an administrator.
#[test]
fn release_clears_ownership_for_exactly_what_the_server_confirmed_and_resolve_clears_none_of_it() {
    let runtime = lore::runtime();

    // Part one: partial confirmation clears exactly the confirmed row.
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &["a.file", "b.file"]).await
    }));

    let acquire_attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    let acquire_status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        acquire_attempts,
    ));
    assert_eq!(acquire_status, 0, "acquiring both files must succeed");
    assert_eq!(
        ownership_row_count(&fixture.path),
        2,
        "both acquires must have minted and stored their own ownership row"
    );

    server.set_policy(LockPolicy {
        unlock_echo: UnlockEcho::FirstOnly,
        ..LockPolicy::default()
    });

    let release_attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    let release_status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileReleaseArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        release_attempts,
    ));
    assert_eq!(
        release_status, 0,
        "the release itself succeeds even though only one resource was confirmed"
    );
    assert_eq!(
        ownership_row_count(&fixture.path),
        1,
        "exactly the one row the server confirmed released must be cleared, leaving one behind \
         -- zero would mean the whole request was cleared, two would mean nothing was"
    );

    // Part two: a resolved-but-refused release must not touch the held row.
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let acquire_attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
    let acquire_status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        acquire_attempts,
    ));
    assert_eq!(acquire_status, 0, "acquiring the file must succeed");
    assert_eq!(ownership_row_count(&fixture.path), 1);

    server.set_policy(LockPolicy {
        unlock: RpcOutcome::Refuse(Refusal::Internal),
        ..LockPolicy::default()
    });

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let release_status = runtime.block_on(lore::lock::file_release_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileReleaseArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));
    assert_ne!(
        release_status, 0,
        "the release must fail: the server refuses the unlock"
    );

    let resolves = spy.resolve_entries();
    assert_eq!(resolves.len(), 1, "got {resolves:?}");
    assert_eq!(
        resolves[0].1,
        AttemptResolution::NotApplied,
        "the release's own attempt is decisively not applied"
    );

    assert_eq!(
        ownership_row_count(&fixture.path),
        1,
        "the held lock's ownership row must survive a release whose own attempt merely resolved \
         -- only a confirmed release may clear it"
    );
}

/// A lost answer on the `Lock` call itself must not be rolled back, and must surface as the named
/// `OutcomeUnknown` code rather than a generic internal failure.
///
/// `LiveRepository::create` commits exactly one file, and `LOCK_BATCH_SIZE` is 100, so this
/// acquire is one batch, one dispatch. **What this test proves, and what it does not:** the exact
/// status code (`LoreError::OutcomeUnknown as i32`, asserted with `assert_eq!`, never a
/// `assert_ne!(status, 0)` that would also pass on the pre-fix `Internal` code path) plus the
/// surviving unresolved journal record together prove the answer was classified as ambiguous
/// rather than as a decisive failure. The empty `Unlock`/`ForceUnlock` assertions below are a
/// forward-guard against a future change to the join loop, **not** proof of the fix by
/// themselves: with a single batch, an all-failed acquire set never reaches any rollback arm
/// today, under either the pre-fix or the post-fix code, because the join loop's rollback branch
/// only runs when `0 < num_batch_success < num_batches` -- a wholly failed one-batch set is
/// `num_batch_success == 0`, which takes the earlier, non-rollback return in both versions. This
/// test does not claim a rollback used to happen here and was suppressed by the fix; there was
/// never a rollback to suppress at this batch count.
#[test]
fn a_lost_answer_on_the_acquire_is_not_rolled_back_and_surfaces_outcome_unknown() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::LoseTheAnswer,
        ..LockPolicy::default()
    }));
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "a lost answer on the acquire must surface as the named OutcomeUnknown code, not merely a \
         nonzero status -- a nonzero-only assertion would pass on the pre-fix code path too, \
         which fabricated a generic Internal failure"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        1,
        "exactly one Lock dispatch must have reached the server, got {:?}",
        server.calls()
    );

    assert!(
        server.calls_for(LockRpc::Unlock).is_empty(),
        "a non-decisive lost answer must never trigger a rollback release -- an administrative \
         mutation is not a safe response to an acquire whose outcome is unknown. Got {:?}",
        server.calls()
    );
    assert!(
        server.calls_for(LockRpc::ForceUnlock).is_empty(),
        "a non-decisive lost answer must never trigger a force-release either. Got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the acquire must journal exactly one attempt, got {records:?}"
    );
    let server_attempt_id = locks[0]
        .attempt_id
        .clone()
        .expect("the dispatch must have carried an attempt id to the server");
    assert_eq!(
        records[0].1,
        GrpcRpc::LockLock.wire_name(),
        "the journalled attempt must name the Lock dispatch"
    );
    assert_eq!(
        records[0].0, server_attempt_id,
        "the id the caller journalled must be the exact id that reached the server"
    );

    assert!(
        spy.resolve_entries().is_empty(),
        "a lost answer must leave its attempt unresolved rather than resolving it, got {:?}",
        spy.resolve_entries()
    );
    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the one lost-answer attempt must remain standing for later reconciliation, got \
         {unresolved:?}"
    );
}

/// An acquire answered `Status::cancelled` must not be rolled back either, and must surface as the
/// same named `OutcomeUnknown` code.
///
/// A near-copy of `a_lost_answer_on_the_acquire_is_not_rolled_back_and_surfaces_outcome_unknown`,
/// differing in exactly ONE input: `RpcOutcome::LoseTheAnswerCancelled` in place of
/// `RpcOutcome::LoseTheAnswer`. This is the shape the defect actually reported -- a mid-flight
/// reset or an expired handler deadline answers `Status::cancelled`, not a severed channel -- so
/// this test, not its `LoseTheAnswer` sibling above, is the one that exercises
/// `lore-transport/src/error.rs`'s `AnswerLostInTransit` marker at all. The same honesty note
/// applies here as on the sibling: the empty rollback-call assertions are a forward-guard, not the
/// proof; the proof is the exact status code plus the unresolved record, unreachable by any
/// rollback arm at this batch count regardless of which code path produced it.
#[test]
fn an_acquire_answered_with_cancelled_is_not_rolled_back_and_surfaces_outcome_unknown() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::LoseTheAnswerCancelled,
        ..LockPolicy::default()
    }));
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "an acquire answered Cancelled must surface as the named OutcomeUnknown code, not merely \
         a nonzero status -- a nonzero-only assertion would pass on the pre-fix code path too, \
         which read a mid-flight reset as a decisive Internal failure"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        1,
        "exactly one Lock dispatch must have reached the server, got {:?}",
        server.calls()
    );

    assert!(
        server.calls_for(LockRpc::Unlock).is_empty(),
        "a non-decisive Cancelled answer must never trigger a rollback release. Got {:?}",
        server.calls()
    );
    assert!(
        server.calls_for(LockRpc::ForceUnlock).is_empty(),
        "a non-decisive Cancelled answer must never trigger a force-release either. Got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the acquire must journal exactly one attempt, got {records:?}"
    );
    let server_attempt_id = locks[0]
        .attempt_id
        .clone()
        .expect("the dispatch must have carried an attempt id to the server");
    assert_eq!(
        records[0].1,
        GrpcRpc::LockLock.wire_name(),
        "the journalled attempt must name the Lock dispatch"
    );
    assert_eq!(
        records[0].0, server_attempt_id,
        "the id the caller journalled must be the exact id that reached the server"
    );

    assert!(
        spy.resolve_entries().is_empty(),
        "a lost answer must leave its attempt unresolved rather than resolving it, got {:?}",
        spy.resolve_entries()
    );
    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the one lost-answer attempt must remain standing for later reconciliation, got \
         {unresolved:?}"
    );
}

/// A decisive refusal on the acquire stays decisive, resolves `NotApplied`, and sends no
/// rollback -- the negative control for the two lost-answer tests above.
///
/// Without this test, an implementation that classified EVERY acquire failure as non-decisive
/// (for example, one that mapped every `AcquireError` variant to `OutcomeUnknown` rather than
/// only the genuinely ambiguous one) would still pass both lost-answer tests. This is what proves
/// the fix actually discriminates ambiguous outcomes from decisive ones, rather than just always
/// answering `OutcomeUnknown`.
#[test]
fn a_decisive_refusal_on_the_acquire_stays_decisive_and_sends_no_rollback() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Refuse(Refusal::PermissionDenied),
        ..LockPolicy::default()
    }));
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_ne!(
        status,
        LoreError::OutcomeUnknown as i32,
        "a decisive permission-denied refusal must not surface as OutcomeUnknown"
    );
    assert_ne!(
        status, 0,
        "a permission-denied refusal must fail the acquire"
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        1,
        "the refused dispatch must still be journalled once, got {records:?}"
    );

    let resolves = spy.resolve_entries();
    assert_eq!(
        resolves.len(),
        1,
        "a decisive refusal must resolve the record rather than leaving it unresolved, got \
         {resolves:?}"
    );
    assert_eq!(
        resolves[0].0, records[0].0,
        "the same attempt id must both be recorded and resolved"
    );
    assert_eq!(
        resolves[0].1,
        AttemptResolution::NotApplied,
        "a decisive refusal is a decisively not-applied attempt"
    );

    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert!(
        unresolved.is_empty(),
        "a decisively resolved attempt must not still count as unresolved, got {unresolved:?}"
    );

    assert!(
        server.calls_for(LockRpc::Unlock).is_empty(),
        "a decisive refusal must not send any rollback release. Got {:?}",
        server.calls()
    );
    assert!(
        server.calls_for(LockRpc::ForceUnlock).is_empty(),
        "a decisive refusal must not send any force-release either. Got {:?}",
        server.calls()
    );
}

/// 101 file names -- one more than `LOCK_BATCH_SIZE` (100), so a fixture built from these commits
/// exactly two batches, which is the only way this fixture can make one acquire's batches answer
/// differently: `LockPolicy::lock_after_first` numbers arrivals under the stub server's own calls
/// lock and switches the answer after the first, so the two multi-batch tests below assert how
/// many calls got which answer, never which resources were in which batch -- which arrives first
/// is not fixed.
fn multi_batch_file_names() -> Vec<String> {
    (0..101).map(|index| format!("f{index:03}.file")).collect()
}

/// A multi-batch acquire where one batch is granted and the other's answer is lost must not be
/// rolled back, and must surface the exact `OutcomeUnknown` code.
///
/// Unlike the single-batch acquire tests above, this is a genuinely PARTIAL set: one of the two
/// batches was granted. Pre-fix, `acquire`'s join loop counted this as
/// `0 < num_batch_success < num_batches` and took the rollback arm, dispatching a release for
/// every requested path -- `Unlock` calls reached the server. Post-fix, a set carrying a
/// non-decisive batch never returns `Ok` from the shared verdict at all, so the rollback arm is
/// structurally unreachable. That makes the empty `Unlock` log here actual proof of the fix, not
/// the forward-guard the single-batch tests' empty logs are.
#[test]
fn a_multi_batch_acquire_with_one_lost_answer_is_not_rolled_back() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Grant,
        lock_after_first: Some(RpcOutcome::LoseTheAnswer),
        ..LockPolicy::default()
    }));
    let names = multi_batch_file_names();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &name_refs).await
    }));

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "a partial set carrying a lost answer must surface as the named OutcomeUnknown code, not \
         merely a nonzero status -- a nonzero-only assertion would pass on the pre-fix rollback \
         path too"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        2,
        "101 committed files must split into exactly two batches, got {:?}",
        server.calls()
    );

    assert!(
        server.calls_for(LockRpc::Unlock).is_empty(),
        "a non-decisive partial set must never trigger a rollback release -- this is the real \
         discriminator for this test, not a forward-guard: the pre-fix join loop took exactly \
         this rollback arm on exactly this shape (one success, one failure). Got {:?}",
        server.calls()
    );
    assert!(
        server.calls_for(LockRpc::ForceUnlock).is_empty(),
        "a non-decisive partial set must never trigger a force-release either. Got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        2,
        "both batches must journal their own attempt, got {records:?}"
    );
    assert!(
        records
            .iter()
            .all(|(_, operation, _)| operation == GrpcRpc::LockLock.wire_name()),
        "both journalled attempts must name the Lock dispatch, got {records:?}"
    );

    let resolves = spy.resolve_entries();
    assert_eq!(
        resolves.len(),
        1,
        "only the granted batch's attempt may resolve, got {resolves:?}"
    );
    assert_eq!(
        resolves[0].1,
        AttemptResolution::Applied,
        "the granted batch is a decisively applied attempt"
    );

    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the lost-answer batch's attempt must remain standing for reconciliation, got \
         {unresolved:?}"
    );
}

/// A multi-batch acquire mixing a decisive refusal and a lost answer in the same set must surface
/// the lost answer's `OutcomeUnknown` code, not the refusal's.
///
/// This is the live proof of the unit-level claim in `acquire::tests::set_verdict`'s
/// `an_unknown_batch_outranks_a_refusal_in_the_same_set`: pre-fix, this returned
/// `LoreError::Internal as i32` (the refusal, or a fabricated internal failure), because the join
/// loop discarded each batch's classified error. A caller acting on a decisive-looking refusal
/// here would conclude the whole acquire was cleanly refused and might retry it, when in fact one
/// of the two locks it asked for may already be held.
#[test]
fn a_multi_batch_acquire_mixing_a_refusal_and_a_lost_answer_surfaces_the_lost_answer() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Refuse(Refusal::PermissionDenied),
        lock_after_first: Some(RpcOutcome::LoseTheAnswer),
        ..LockPolicy::default()
    }));
    let names = multi_batch_file_names();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &name_refs).await
    }));

    let spy = Arc::new(JournalSpy::new(server.probe()));
    let attempts: Arc<dyn AttemptStore> = spy.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "the lost answer must outrank the decisive refusal in the same set -- pre-fix this \
         returned the Internal code instead"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        2,
        "101 committed files must split into exactly two batches, got {:?}",
        server.calls()
    );
    assert!(
        server.calls_for(LockRpc::Unlock).is_empty(),
        "an all-failed set (refused plus lost) never reaches the rollback arm at any batch count \
         -- this assertion is a forward-guard, not the proof here. Got {:?}",
        server.calls()
    );
    assert!(
        server.calls_for(LockRpc::ForceUnlock).is_empty(),
        "Got {:?}",
        server.calls()
    );

    let records = spy.record_entries();
    assert_eq!(
        records.len(),
        2,
        "both batches must journal their own attempt, got {records:?}"
    );

    let resolves = spy.resolve_entries();
    assert_eq!(
        resolves.len(),
        1,
        "only the refused batch's attempt may resolve, got {resolves:?}"
    );
    assert_eq!(
        resolves[0].1,
        AttemptResolution::NotApplied,
        "the refused batch is a decisively not-applied attempt"
    );

    let unresolved = runtime
        .block_on(spy.inner.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "exactly the lost-answer batch's attempt must remain standing for reconciliation, got \
         {unresolved:?}"
    );
}

/// A multi-batch acquire whose every failure is decisive -- one batch granted, the other
/// refused -- must still roll back the granted batch.
///
/// This is the positive control the two non-decisive multi-batch tests above need to mean
/// anything: without it, an implementation that never rolled back at all would still pass
/// `a_multi_batch_acquire_with_one_lost_answer_is_not_rolled_back` and
/// `a_multi_batch_acquire_mixing_a_refusal_and_a_lost_answer_surfaces_the_lost_answer`, because
/// both of those assert an EMPTY `Unlock` log. This test asserts a non-empty one on the sibling
/// shape where every failure is decisive, which is End state 2's own reachable case: a partial
/// set whose failed batch answered with certainty, not a maybe.
///
/// Per the fixture trap noted in review: `lock_after_first` numbers arrivals over the server's
/// whole lifetime, not per acquire, so this test gets its own fresh `LockServer`.
#[test]
fn a_multi_batch_acquire_with_a_decisive_refusal_still_rolls_back() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Grant,
        lock_after_first: Some(RpcOutcome::Refuse(Refusal::PermissionDenied)),
        ..LockPolicy::default()
    }));
    let names = multi_batch_file_names();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &name_refs).await
    }));

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        Arc::new(VolatileAttemptStore::new()),
    ));

    assert_ne!(
        status,
        LoreError::OutcomeUnknown as i32,
        "a set whose every failure is decisive must not surface as OutcomeUnknown"
    );
    assert_ne!(status, 0, "the refused batch must fail the acquire overall");

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        2,
        "101 committed files must split into exactly two batches, got {:?}",
        server.calls()
    );

    let unlocks = server.calls_for(LockRpc::Unlock);
    assert!(
        !unlocks.is_empty(),
        "a decisive partial failure must still trigger the rollback release -- this is the \
         positive control for the non-decisive multi-batch tests' empty Unlock log: without this \
         test, an implementation that never rolls back at all would still pass them. Got {:?}",
        server.calls()
    );
}

/// The rollback release's own answer can be lost in turn, and the caller must be told
/// `OutcomeUnknown` for it rather than a decisive acquire failure.
///
/// `acquire` forwards the rollback's `ReleaseError` with `.forward::<AcquireError>(...)`, and
/// this pins that the `OutcomeUnknown` variant survives that forward intact -- proving what a
/// probe confirmed by inspection, rather than leaving it unpinned.
#[test]
fn a_lost_answer_on_the_rollback_release_surfaces_outcome_unknown() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Grant,
        lock_after_first: Some(RpcOutcome::Refuse(Refusal::PermissionDenied)),
        unlock: RpcOutcome::LoseTheAnswer,
        ..LockPolicy::default()
    }));
    let names = multi_batch_file_names();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &name_refs).await
    }));

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        Arc::new(VolatileAttemptStore::new()),
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "a rollback release whose own answer is lost must surface as OutcomeUnknown, not a \
         decisive acquire failure -- some of the requested locks may still be held and the \
         caller has to reconcile rather than assume the acquire cleanly failed"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        2,
        "101 committed files must split into exactly two batches, got {:?}",
        server.calls()
    );

    assert!(
        !server.calls_for(LockRpc::Unlock).is_empty(),
        "the rollback must actually have been attempted -- a rollback that never ran would also \
         produce a non-OutcomeUnknown status for a different reason, and the empty log would make \
         that ambiguity invisible. Got {:?}",
        server.calls()
    );
}

/// A batch task that panics AFTER its own dispatch was already granted must surface as
/// `OutcomeUnknown`, naming the exact attempt id its own record was recorded under -- not a
/// generic internal failure that reads as "provably did not happen".
///
/// `PanicOnResolve` panics inside `resolve()`, reached only once `under_named_attempt` sees the
/// real `Lock` RPC succeed, so the panic here happens on the far side of a real grant: the fixture
/// server actually locked the file, and only the CLIENT's own bookkeeping died afterward. Pre-fix,
/// `acquire`'s join loop had no id to report for a dead batch task and fell back to a flat
/// `Internal` -- indistinguishable, to a caller, from a request that never left. This test proves
/// the fix by three independent facts none of which is provable from the status code alone: the
/// exact `OutcomeUnknown` status (via a real `LoreEventCallback`, since the plain returned integer
/// carries the status but not the `operation`/`attempt_id` detail fields this test also checks);
/// the store still holding exactly the one record `record()` wrote before the dispatch (proving
/// `resolve()` really never ran, not merely that this test forgot to check); and that record's own
/// id being the exact one the error names, which is what makes the id actionable rather than a
/// number that merely happens to be present.
///
/// `LiveRepository::create` commits exactly one file, and `LOCK_BATCH_SIZE` is 100, so this
/// acquire is one batch -- the whole request fails when its only batch panics.
#[test]
fn a_panicking_batch_task_surfaces_outcome_unknown_naming_its_own_recorded_attempt() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let attempts: Arc<dyn AttemptStore> = Arc::new(PanicOnResolve::new());
    let (callback, captured) = capture_complete();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        callback,
        attempts.clone(),
    ));

    assert_eq!(
        status,
        LoreError::OutcomeUnknown as i32,
        "a batch task that panicked after its own dispatch was granted must surface as \
         OutcomeUnknown, not the pre-fix flat Internal fallback with no attempt id to name"
    );

    let complete = captured
        .lock()
        .expect("the capture mutex must not be poisoned")
        .take()
        .expect("a Complete event must have been emitted");
    assert_eq!(
        complete.status,
        LoreError::OutcomeUnknown as i32,
        "the Complete event's own status must agree with the returned status"
    );
    assert_eq!(
        complete.error.operation.as_str(),
        GrpcRpc::LockLock.wire_name(),
        "the error detail must name the Lock RPC that actually panicked"
    );

    let unresolved = runtime
        .block_on(attempts.unresolved())
        .expect("unresolved() must succeed on a fresh store");
    assert_eq!(
        unresolved.len(),
        1,
        "the panicking batch's own record must be the only one left standing -- resolve() never \
         ran, so nothing settled it. Got {unresolved:?}"
    );
    assert_eq!(
        complete.error.attempt_id.as_str(),
        unresolved[0].attempt_id.to_string(),
        "the id named in the error must be the exact id whose record survived unresolved -- \
         anything else would send a reconciler looking for the wrong receipt"
    );
}

/// The exact status a caller receives for a partial acquire whose failing batch was a decisive
/// server refusal, pinned to the refusal's own `#[ffi_code]` rather than merely `!= 0` and
/// `!= OutcomeUnknown`.
///
/// This is the case commit 9106c1c's `first_decisive_failure` carry-back exists for: pre-fix,
/// `acquire`'s rollback arm re-raised a flat `AcquireError::internal("Failed to acquire the
/// lock")`, which translates to `Internal`'s code (-1, CLI exit 255) regardless of what the
/// server actually said. Every existing acquire test in this file asserts `assert_ne!` against 0
/// and 193 (`LoreError::OutcomeUnknown as i32`) for exactly this reason: that assertion shape
/// stays green whether the carry-back exists or not, because both `Internal` and `NotAuthorized`
/// satisfy it. Asserting the exact code is what a revert of the carry-back turns red.
///
/// The 101-file two-batch fixture is the same shape `a_multi_batch_acquire_with_a_decisive_refusal_
/// still_rolls_back` uses: one batch granted, the other refused with `PermissionDenied`, so the
/// refusal survives as `AcquireError::NotAuthorized`, whose own `#[ffi_code(17)]` is what must
/// reach the caller -- not the fallback message's `Internal`.
#[test]
fn a_decisive_refusal_in_a_partial_acquire_surfaces_the_refusals_own_ffi_code() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Grant,
        lock_after_first: Some(RpcOutcome::Refuse(Refusal::PermissionDenied)),
        ..LockPolicy::default()
    }));
    let names = multi_batch_file_names();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &name_refs).await
    }));

    let (callback, captured) = capture_complete();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        callback,
        Arc::new(VolatileAttemptStore::new()),
    ));

    assert_eq!(
        status,
        NotAuthorized::FFI_CODE,
        "a PermissionDenied refusal in a partial acquire must surface NotAuthorized's own ffi \
         code, not the pre-9106c1c Internal fallback -- got {status}, Internal is {}",
        LoreError::Internal as i32
    );
    assert_ne!(
        status,
        LoreError::Internal as i32,
        "the discriminating fact: the pre-fix fallback and the fixed code must differ"
    );

    let complete = captured
        .lock()
        .expect("the capture mutex must not be poisoned")
        .take()
        .expect("a Complete event must have been emitted");
    assert_eq!(
        complete.status,
        NotAuthorized::FFI_CODE,
        "the Complete event's own status must agree with the returned status"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        2,
        "101 committed files must split into exactly two batches, got {:?}",
        server.calls()
    );
}

/// One arbitrary but well-formed ownership token for a seeded pre-held row.
///
/// The value is never asserted on anywhere -- only that a row holding one is present or absent --
/// so every seeded row reuses this same one rather than minting something distinguishable.
fn seed_token() -> OwnershipToken {
    OwnershipToken::from_wire(&[0xEEu8; OwnershipToken::LEN])
        .expect("32 bytes must decode")
        .expect("32 bytes must produce a token, not None")
}

/// Seed pre-held ownership rows for a set of committed files, directly through
/// `RepositoryAttemptStore` and the same `assemble_resource_for_path` keying `acquire` itself
/// calls -- rather than dispatched through a real prior `acquire`.
///
/// **Why not a real prior acquire:** `LockPolicy::lock_after_first`'s ordinal counts `Lock`
/// arrivals over the server's WHOLE lifetime, not per acquire (see its own doc comment). A prior
/// acquire of enough files to matter would consume ordinals before the acquire under test ever
/// dispatches, landing ITS batches past the "first" boundary and refusing every one of them --
/// `num_batch_success` would be 0, and the rollback path these tests exist to pin would never run
/// at all (a wholly failed set takes the non-rollback return). A second `LockServer` would reset
/// the ordinal, but the fixture repository's remote address is fixed at creation with no public
/// way to repoint it. Seeding directly sidesteps the ordinal question entirely: the acquire under
/// test dispatches the first `Lock` calls this server ever sees.
///
/// Dropped before returning: holding the connection open would contend with `load_and_connect`'s
/// own acquisition inside the real acquire call that follows, matching
/// `LiveRepository::create_with_files`'s own convention.
fn seed_pre_held_ownership(
    runtime: &tokio::runtime::Handle,
    fixture: &LiveRepository,
    names: &[String],
) {
    runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        let repository = fixture.connect(RepositoryAccess::ReadOnly).await;
        let (_, branch) = load_current_anchor(&repository)
            .await
            .expect("reading the fixture's current anchor");
        let ownership = repository_attempt_store(&repository);
        for name in names {
            let resource = assemble_resource_for_path(name, branch);
            ownership
                .record_ownership(&LockOwnership {
                    attempt_id: AttemptId::new(),
                    branch: resource.branch,
                    resource_hash: resource.hash,
                    token: seed_token(),
                })
                .await
                .expect("seeding a pre-held ownership row");
        }
        drop(repository);
    }));
}

/// A PURE renewal -- every requested row already held before the call -- releases NOTHING.
///
/// This is the discriminating case for `rollback_set`'s `pre_held` exclusion, distinct from
/// (and superseding) an earlier version of this test that expected the rollback to release the
/// granted batch's own rows: a reviewer pass found that a granted lock does not distinguish a
/// first acquire from a renewal (the fenced coordinator reports both in one `committed` set), so
/// the correct rollback excludes anything the client already held, not merely "whatever this
/// call's own batches happened to grant". With all 101 rows pre-held, the granted batch's rows are
/// ALL excluded, so the rollback releases zero locks -- proving three implementations apart at
/// once: the original pre-fix code released all 101 (blanket `options.paths`), an intermediate
/// version released the granted batch's own rows regardless of prior ownership, and this one
/// releases none.
#[test]
fn a_pure_renewals_rollback_releases_nothing() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Grant,
        lock_after_first: Some(RpcOutcome::Refuse(Refusal::PermissionDenied)),
        ..LockPolicy::default()
    }));
    let names = multi_batch_file_names();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &name_refs).await
    }));

    seed_pre_held_ownership(&runtime, &fixture, &fixture.committed_files);
    assert_eq!(
        ownership_row_count(&fixture.path),
        101,
        "every one of the 101 rows must hold a pre-existing token before the renewal -- that is \
         what makes this call a pure renewal"
    );

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        Arc::new(VolatileAttemptStore::new()),
    ));
    assert_ne!(
        status, 0,
        "the renewal must fail: one of its two batches is a decisive refusal"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        2,
        "the renewal's own 101 paths must split into exactly two batches, and nothing else may \
         have dispatched a Lock before it -- seeding wrote the store directly. Got {:?}",
        server.calls()
    );

    assert!(
        server.calls_for(LockRpc::Unlock).is_empty(),
        "every row was already held, so the correct rollback releases nothing -- against the \
         pre-fix code (blanket options.paths) or the intermediate one (the whole granted batch \
         regardless of prior ownership), this would be non-empty. Got {:?}",
        server.calls()
    );
    assert_eq!(
        ownership_row_count(&fixture.path),
        101,
        "no row's token may be cleared by a rollback that released nothing"
    );
}

/// A MIXED renewal -- some rows already held, some genuinely new -- releases exactly the granted
/// batch's own new rows, and never a pre-held one.
///
/// 50 of the 101 files are seeded pre-held; the other 51 are new to this call. Whichever of the
/// renewal's two batches (100 resources, 1 resource -- `chunks(LOCK_BATCH_SIZE)` on 101 items is
/// always that split) wins the race to be granted, the correct release set is that batch's own
/// members MINUS whichever of them were already held -- never the whole batch (that would leak a
/// pre-held release, the intermediate version's bug) and never a description outside that batch.
/// Because which specific file lands in the size-1 batch is a hash-order accident this test does
/// not control, every assertion below computes its expectation from the granted batch's own
/// observed membership rather than assuming a fixed composition -- the discriminating fact is
/// still real in every draw: a batch containing a held row must not release it, and one containing
/// a new row must.
///
/// The final row count is the one invariant that holds regardless of the draw: whatever this call
/// newly acquired and then rolled back nets to zero (recorded, then cleared), so exactly the 50
/// originally seeded rows -- untouched or merely renewed -- remain.
#[test]
fn a_mixed_renewal_releases_only_the_granted_batchs_new_rows() {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start_with_policy(LockPolicy {
        lock: RpcOutcome::Grant,
        lock_after_first: Some(RpcOutcome::Refuse(Refusal::PermissionDenied)),
        ..LockPolicy::default()
    }));
    let names = multi_batch_file_names();
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files(&server.remote_url(), &name_refs).await
    }));

    let held_names: BTreeSet<String> = fixture.committed_files[..50].iter().cloned().collect();
    seed_pre_held_ownership(
        &runtime,
        &fixture,
        &held_names.iter().cloned().collect::<Vec<_>>(),
    );
    assert_eq!(
        ownership_row_count(&fixture.path),
        50,
        "exactly the first 50 rows must be pre-held before this renewal"
    );

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: all_paths(&fixture),
            branch: LoreString::default(),
        },
        no_callback(),
        Arc::new(VolatileAttemptStore::new()),
    ));
    assert_ne!(
        status, 0,
        "the renewal must fail: one of its two batches is a decisive refusal"
    );

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        2,
        "the renewal's own 101 paths must split into exactly two batches. Got {:?}",
        server.calls()
    );

    let unlocked_descriptions: BTreeSet<String> = server
        .calls_for(LockRpc::Unlock)
        .into_iter()
        .flat_map(|call| call.descriptions)
        .collect();
    assert!(
        unlocked_descriptions.is_disjoint(&held_names),
        "a pre-held row must never be released by this renewal's rollback -- got these held \
         names among the unlocked descriptions: {:?}",
        unlocked_descriptions
            .intersection(&held_names)
            .collect::<Vec<_>>()
    );

    // Whichever batch was granted, the released set is exactly that batch's own new (non-held)
    // members -- computed from the batch's real, observed membership, not assumed.
    if !unlocked_descriptions.is_empty() {
        let matching_lock = locks
            .iter()
            .find(|call| {
                let call_set: BTreeSet<String> = call.descriptions.iter().cloned().collect();
                unlocked_descriptions.is_subset(&call_set)
            })
            .expect(
                "a non-empty released set must be a subset of exactly one Lock call's \
                 descriptions -- the renewal's two batches partition the 101 files disjointly",
            );
        let expected: BTreeSet<String> = matching_lock
            .descriptions
            .iter()
            .filter(|description| !held_names.contains(*description))
            .cloned()
            .collect();
        assert_eq!(
            unlocked_descriptions, expected,
            "the released set must be exactly the granted batch's new rows, neither more (that \
             would be the intermediate version's whole-batch bug) nor fewer"
        );
    }

    assert_eq!(
        ownership_row_count(&fixture.path),
        50,
        "whatever this call newly acquired and then rolled back nets to zero, so exactly the 50 \
         originally pre-held rows remain -- the pre-fix code (blanket options.paths) would have \
         cleared some or all of those 50 too, landing below 50"
    );
}

/// Count the `ownership` rows in the live fixture's on-disk attempt-store document.
///
/// Reads `<repository path>/.lore/attempts` directly rather than through any `AttemptStore`
/// method, because the ownership store this file exercises is the repository-derived one lore
/// builds internally (`lore_revision::attempt_store::repository_attempt_store`), never the
/// `attempts: Arc<dyn AttemptStore>` a caller supplies -- there is no handle on it from outside
/// the operation to ask any other way.
fn ownership_row_count(repository_path: &std::path::Path) -> usize {
    let document = std::fs::read(repository_path.join(".lore").join("attempts"))
        .expect("the attempt store file must exist after a call that wrote to it");
    // Byte 0 is the format version, not part of the JSON body.
    let json: serde_json::Value =
        serde_json::from_slice(&document[1..]).expect("the attempt store body must be valid JSON");
    json.get("ownership")
        .and_then(serde_json::Value::as_array)
        .expect("the document must have an `ownership` array")
        .len()
}

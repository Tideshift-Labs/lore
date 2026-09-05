// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The lock verbs' attempt journal, driven against a remote that answers (WP-120).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use lore::interface::LoreEventCallback;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_revision::interface::LoreArray;
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
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;

fn no_callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}

/// The fixture reaches a real lock dispatch, and the caller's store is what journals it.
///
/// This is the smoke test for the fixture itself as much as for the entry point: if the remote
/// were not resolving to `Connected`, the acquire would fail offline before it reached a single
/// dispatch and the server would have seen nothing.
#[test]
fn file_acquire_with_attempt_store_journals_the_lock_dispatch() {
    let runtime = lore::runtime();

    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let store = Arc::new(VolatileAttemptStore::new());
    let attempts: Arc<dyn AttemptStore> = store.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: LoreArray::from_vec(
                fixture
                    .committed_files_absolute
                    .iter()
                    .map(LoreString::from)
                    .collect(),
            ),
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
        "one batch of one path is one lock dispatch, got {:?}",
        server.calls()
    );
    assert!(
        locks[0].attempt_id.is_some(),
        "the dispatch must have carried an attempt id to the server"
    );
}

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
    let (record_attempt_id, operation, _) = records[0].clone();
    assert_eq!(
        operation,
        GrpcRpc::LockUnlock.wire_name(),
        "the journalled operation must name the release's own RPC, not the earlier acquire's"
    );
    assert_eq!(record_attempt_id, server_attempt_id);

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
/// The remote here names a port nothing listens on, so the connect inside the batch task fails
/// before `under_own_attempt` ever mints an id. This pins that the journal entry is minted inside
/// the batch task, after a real lock connect, and not eagerly at the top of the verb -- a caller
/// speculatively recording an attempt for a connection that was never established would leave a
/// permanently unresolved record for a mutation that was never dispatched.
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

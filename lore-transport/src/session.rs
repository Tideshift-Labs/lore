// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use futures::FutureExt;
use futures::future::BoxFuture;
use lore_base::error::Disconnected;
use lore_base::lore_drain_tasks;
use lore_base::lore_spawn_net;
use lore_base::types::*;
use parking_lot::Mutex;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinSet;

use crate::connection::Connection;
use crate::error::ProtocolError;
use crate::replay::ATTEMPT_BUDGET;
use crate::replay::MutableOutcome;
use crate::traits::Storage;

/// A live session on a `Storage` connection. Provides all storage operations
/// scoped to a specific partition and correlation ID. Sends `session_stop`
/// to the server when the last reference is dropped.
///
/// A session may be constructed in one of two states:
/// - `Resolved`: the caller has already established the server-side session.
/// - `Pending`: the caller has everything needed to establish a session but
///   hasn't done so yet. The session is started lazily on the first operation
///   and cached for subsequent ones. This is how local-only command paths avoid
///   forcing the background connect to resolve.
pub struct StorageSession {
    inner: SessionInner,
}

struct ResolvedFields {
    /// Everything needed to hold, and to replace, the server-side session.
    binding: Arc<SessionBinding>,
    /// Keeps the connection alive while this session exists, and is what a source partition is
    /// authorized on — authorization is per connection, not per session.
    connection: Arc<Connection>,
}

/// A resolved server-side session, bound to the connection generation it belongs to.
struct SessionBinding {
    storage: Arc<dyn Storage>,
    /// The server-assigned session id and the connection generation it was assigned on.
    ///
    /// A storage session belongs to one connection. Holding the id without the epoch it came
    /// from is what lets an id from a replaced connection reach a server that never issued it,
    /// so the two are stored together and read together.
    session: Mutex<BoundSession>,
    /// Serialises replacement `session_start` calls, so concurrent commands that all notice the
    /// same epoch change cost one authorization round trip rather than one each.
    rebind: TokioMutex<()>,
    /// The partition this session was started for, so a copy naming it as its source needs no
    /// authorization beyond the session itself.
    partition: Partition,
    /// The correlation id the session was started under, so authorizing a further partition on this
    /// connection is attributed to the same command.
    correlation_id: Arc<str>,
}

/// A session id and the connection generation it is valid on.
///
/// `epoch` is `None` for a session that is known to be gone, which is not the same as one
/// bound to some particular generation: there is no epoch value that could stand for it, since
/// every value the transport reports is a generation a session could legitimately hold.
#[derive(Clone, Copy)]
struct BoundSession {
    id: u32,
    epoch: Option<u32>,
}

impl SessionBinding {
    /// The session id to send on the connection as it is now, starting a replacement session
    /// first if the connection has been replaced since this one was issued.
    ///
    /// The epoch is sampled before `session_start` rather than after, so a connection replaced
    /// again mid-call records the older generation and the next caller rebinds. That costs an
    /// extra round trip in a rare race, which is the way round this has to fail.
    ///
    /// What this guarantees is that no id is *handed out* for a generation it did not come
    /// from. It does not guarantee the id is still current when the bytes reach the socket.
    /// `send_with_reconnect` re-reads the epoch after its permit wait, which is the longest
    /// block in the path, and refuses rather than sending. Three awaits still follow that
    /// check inside `send_command_tracked` — growing a stream, taking the connection read
    /// lock, and taking the writer — and the read lock is the one a reconnect holds in write
    /// mode while it swaps the connection, so a whole reconnect can land between the check and
    /// the write. A stale id sent in that window is rejected by the server, and
    /// [`StorageSession::attempt`] rebinds and retries: the window is closed after the fact,
    /// not before. Closing it beforehand needs this binding's epoch threaded down to the
    /// write, which the send path's future-size bound does not currently have room for.
    async fn session_id(&self) -> Result<u32, ProtocolError> {
        let current = self.storage.connection_epoch();
        if let Some(id) = self.bound_to(current) {
            return Ok(id);
        }

        let _flight = self.rebind.lock().await;
        // Re-read under the guard: whoever held it before us may already have rebound, and the
        // epoch may have moved again while we waited.
        let current = self.storage.connection_epoch();
        if let Some(id) = self.bound_to(current) {
            return Ok(id);
        }

        // A fresh `session_start` re-runs the token exchange and the server's authorization
        // check for this partition. Nothing from the old session's permission snapshot carries
        // over, which is the point: the replacement connection decides for itself.
        let id = self
            .storage
            .session_start(self.partition, &self.correlation_id)
            .await?;
        *self.session.lock() = BoundSession {
            id,
            epoch: Some(current),
        };
        Ok(id)
    }

    /// The session id if it belongs to `epoch`, otherwise nothing.
    fn bound_to(&self, epoch: u32) -> Option<u32> {
        let bound = *self.session.lock();
        (bound.epoch == Some(epoch)).then_some(bound.id)
    }

    /// Force the next use to start a replacement session, whatever the epoch reads as.
    ///
    /// Used when the connection was replaced under a command: the id we hold belongs to the
    /// generation that is gone, and the epoch comparison alone is not enough to say so at
    /// every moment we might look.
    fn unbind(&self) {
        self.session.lock().epoch = None;
    }
}

/// The epoch the QUIC client stores when it stops trying to reconnect.
///
/// Not a generation, so a session is never bound to it and a move *to* it is not a replacement
/// worth rebinding onto.
const GAVE_UP_EPOCH: u32 = 0;

/// Closure signature for a pending session's resolver. The resolver runs at most
/// once and returns an eager `Arc<StorageSession>` (typically obtained by calling
/// `Connection::session` after awaiting the caller's pending connection).
type PendingResolver =
    Arc<dyn Fn() -> BoxFuture<'static, Result<Arc<StorageSession>, ProtocolError>> + Send + Sync>;

type ResolvedSlot = Arc<TokioMutex<Option<Result<Arc<StorageSession>, ProtocolError>>>>;

enum SessionInner {
    Resolved(ResolvedFields),
    Pending {
        resolver: PendingResolver,
        /// Resolved session, lazily populated by the resolver. A `Mutex<Option<_>>`
        /// rather than a `OnceCell` so that `StorageSession::invalidate` can drop
        /// the cached resolution and force a fresh `session_start` on the next
        /// operation — needed when a QUIC reconnect has invalidated the
        /// server-side session map (the same connection-id is gone, so our
        /// `session_id` is unknown on the new connection).
        resolved: ResolvedSlot,
    },
}

impl StorageSession {
    /// Construct an already-resolved session. Used by the connection internals
    /// after a successful `session_start` RPC.
    /// `epoch` is the connection generation `session_id` was issued on, sampled before the
    /// `session_start` that produced it.
    pub(crate) fn resolved(
        storage: Arc<dyn Storage>,
        connection: Arc<Connection>,
        session_id: u32,
        epoch: u32,
        partition: Partition,
        correlation_id: Arc<str>,
    ) -> Self {
        Self {
            inner: SessionInner::Resolved(ResolvedFields {
                binding: Arc::new(SessionBinding {
                    storage,
                    session: Mutex::new(BoundSession {
                        id: session_id,
                        epoch: Some(epoch),
                    }),
                    rebind: TokioMutex::new(()),
                    partition,
                    correlation_id,
                }),
                connection,
            }),
        }
    }

    /// Construct a session whose server-side session will be started on the
    /// first operation. The resolver is called at most once; subsequent
    /// operations use the cached resolved session. Typical use: defer the
    /// underlying remote connect and session creation until actually needed.
    ///
    /// The resolver returns an eager `Arc<StorageSession>` — callers obtain
    /// this by awaiting their pending connection and invoking
    /// `Connection::session`. That makes the lazy session transparently share
    /// the connection's session dedup cache.
    pub fn pending<F, Fut>(resolver: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Arc<StorageSession>, ProtocolError>>
            + Send
            + 'static,
    {
        Self {
            inner: SessionInner::Pending {
                resolver: Arc::new(move || resolver().boxed()),
                resolved: Arc::new(TokioMutex::new(None)),
            },
        }
    }

    /// Whether the server-side session is established on first use rather than
    /// held already.
    ///
    /// Only a lazy session survives an [`invalidate`](Self::invalidate): the next
    /// operation on it re-runs the resolver and obtains a `session_id` the server
    /// knows about. An eager one keeps the id it was built with, so a caller that
    /// invalidates and retries the same session has to hold a lazy one.
    pub fn is_lazy(&self) -> bool {
        matches!(self.inner, SessionInner::Pending { .. })
    }

    /// Drop any cached server-side session. The next operation re-runs the
    /// resolver, triggering a fresh `session_start` against the current
    /// connection. Also clears the parent `Connection`'s session pool cache
    /// so the rebuild observes a clean slate (no stale `Arc<SessionPool>`
    /// keeping dead session-ids alive). Call this after the transport
    /// surfaces a `NotConnected`/`Failed` server response indicating the
    /// session-id is no longer known server-side.
    pub async fn invalidate(&self) {
        match &self.inner {
            SessionInner::Resolved(r) => {
                r.binding.unbind();
                r.connection.invalidate_all_sessions();
            }
            SessionInner::Pending { resolved, .. } => {
                let mut guard = resolved.lock().await;
                // Bubble the connection invalidation through the cached
                // eager session if one resolved, so the next resolver call
                // is the only thing the parent `Connection` has on file.
                if let Some(Ok(inner)) = guard.as_ref()
                    && let SessionInner::Resolved(r) = &inner.inner
                {
                    r.binding.unbind();
                    r.connection.invalidate_all_sessions();
                }
                *guard = None;
            }
        }
    }

    /// Mark the resolved session gone so the next operation starts a replacement.
    ///
    /// Narrower than [`invalidate`](Self::invalidate): the connection's pool cache is left
    /// alone, because a replaced connection invalidates one session's id, not the caller's
    /// pinned pools.
    async fn unbind(&self) {
        if let Ok(binding) = self.binding().await {
            binding.unbind();
        }
    }

    /// Run one storage operation, allowing a single rebound retry when the connection was
    /// replaced while the command was in flight.
    ///
    /// Retrying here is safe only because of what the transport does *not* return on this
    /// path. A mutable command that was dispatched and then lost its response never comes back
    /// as an error — it comes back as [`MutableOutcome::Unknown`], which is an `Ok` and leaves
    /// this loop untouched. So an error from a mutable operation means either the request never
    /// reached the wire or the server answered it, and neither can be applied twice by asking
    /// again on a replacement session.
    ///
    /// That is why every mutable operation below runs its `_outcome` form through here and
    /// collapses the unknown to an error *afterwards*, rather than calling the plain form and
    /// letting the transport collapse it first. Collapsing underneath this loop turns an
    /// ambiguous write into an ordinary error and this retry into a second `Put`.
    ///
    /// At most [`ATTEMPT_BUDGET`] dispatches of the operation itself, one rebind between them.
    async fn attempt<T, Fut>(
        &self,
        operation: impl Fn(Arc<dyn Storage>, u32) -> Fut,
    ) -> Result<T, ProtocolError>
    where
        Fut: std::future::Future<Output = Result<T, ProtocolError>>,
    {
        let mut attempts_left = ATTEMPT_BUDGET;
        loop {
            attempts_left -= 1;
            // Resolves the session, and starts a replacement first if the connection has moved
            // on since this one was issued.
            let (storage, session_id) = self.ensure().await?;
            let epoch = storage.connection_epoch();

            let error = match operation(storage.clone(), session_id).await {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };

            // Retry only when the connection was actually replaced under the command. Zero is
            // the transport's "reconnection gave up" sentinel rather than a new generation, so
            // it is not a replacement to rebind onto — reading it as one spends the last
            // attempt on a connection that is never coming back.
            let epoch_now = storage.connection_epoch();
            if attempts_left == 0 || epoch_now == epoch || epoch_now == GAVE_UP_EPOCH {
                return Err(error);
            }

            self.unbind().await;
        }
    }

    /// Collapse an unknown outcome into the error an unadopted caller has always seen.
    ///
    /// Above [`attempt`](Self::attempt), never below it: the loop needs to see the unknown to
    /// know not to retry.
    fn collapse<T>(outcome: MutableOutcome<T>) -> Result<T, ProtocolError> {
        match outcome {
            MutableOutcome::Applied(value) => Ok(value),
            // The same error the transport produces for this case, arrived at without going
            // back through `map_send_error`: it says the connection carrying the command is
            // gone, which is what a caller here already saw, and claims nothing about whether
            // the write committed. The unknown's command name is dropped because that mapping
            // discards it too; a caller that wants it calls the `_outcome` method.
            MutableOutcome::Unknown(_) => Err(ProtocolError::from(Disconnected)),
        }
    }

    /// Read from the resolved session, driving the pending resolver on first call. Every method
    /// needing the server-side session goes through here, so a pending one resolves exactly once
    /// whatever is asked of it.
    async fn with_resolved<T>(
        &self,
        project: impl FnOnce(&ResolvedFields) -> T,
    ) -> Result<T, ProtocolError> {
        match &self.inner {
            SessionInner::Resolved(r) => Ok(project(r)),
            SessionInner::Pending { resolver, resolved } => {
                // Single-writer initialization: the lock both serialises
                // resolver calls and gates the slot against concurrent
                // `invalidate()` resetting it back to `None`.
                let inner = {
                    let mut guard = resolved.lock().await;
                    if guard.is_none() {
                        *guard = Some(resolver().await);
                    }
                    match guard.as_ref().expect("just populated") {
                        Ok(session) => session.clone(),
                        Err(err) => return Err(err.clone()),
                    }
                };
                // The resolver always produces an eager session, so reach
                // directly into its fields without recursing.
                match &inner.inner {
                    SessionInner::Resolved(r) => Ok(project(r)),
                    SessionInner::Pending { .. } => {
                        Err(ProtocolError::internal("nested pending session"))
                    }
                }
            }
        }
    }

    /// Get the resolved `(storage, session_id)` pair, driving the pending resolver on first
    /// call. All operation methods go through here.
    ///
    /// The id is bound to the connection generation it was issued on, so this is also where a
    /// replaced connection gets its replacement session. Two steps because the projection out
    /// of the resolver cannot await and starting a session can.
    async fn ensure(&self) -> Result<(Arc<dyn Storage>, u32), ProtocolError> {
        let binding = self.binding().await?;
        let session_id = binding.session_id().await?;
        Ok((binding.storage.clone(), session_id))
    }

    /// The resolved session binding, driving the pending resolver on first call.
    async fn binding(&self) -> Result<Arc<SessionBinding>, ProtocolError> {
        self.with_resolved(|r| r.binding.clone()).await
    }

    /// The partition this session is scoped to, driving the pending resolver on first call.
    pub async fn partition(&self) -> Result<Partition, ProtocolError> {
        self.with_resolved(|r| r.binding.partition).await
    }

    /// Whether a [`StorageSession::copy`] on this session may name `partition` as its source.
    ///
    /// The session's own partition always may. Any other has to be authorized on the connection,
    /// which is the scope the server checks a copy's source against; that costs one `session_start`
    /// the first time and nothing afterwards. Answers `false` rather than erroring because a caller
    /// asking this is choosing whether to name a source at all, and trades a copy the server would
    /// refuse for a cached lookup.
    pub async fn can_copy_from(&self, partition: Partition) -> bool {
        let Ok((connection, own, correlation_id)) = self
            .with_resolved(|r| {
                (
                    r.connection.clone(),
                    r.binding.partition,
                    r.binding.correlation_id.clone(),
                )
            })
            .await
        else {
            return false;
        };
        if own == partition {
            return true;
        }
        connection
            .ensure_partition_authorized(partition, &correlation_id)
            .await
            .is_ok()
    }

    pub async fn get(&self, address: &Address) -> Result<(Fragment, Bytes), ProtocolError> {
        self.attempt(|storage, session_id| async move { storage.get(session_id, address).await })
            .await
    }

    pub async fn get_priority(
        &self,
        address: &Address,
    ) -> Result<(Fragment, Bytes), ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage.get_priority(session_id, address).await
        })
        .await
    }

    pub async fn put(
        &self,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        Self::collapse(self.put_outcome(address, fragment, payload).await?)
    }

    /// [`put`](Self::put), reporting a dispatched request whose response was lost as
    /// [`MutableOutcome::Unknown`] rather than as an error.
    ///
    /// `Put` publishes or revives the repository/context lifecycle association for its payload,
    /// so an ambiguous one is never repeated. Refresh and reconcile authoritative state on an
    /// unknown outcome; do not read it as proof the attempt did not commit.
    pub async fn put_outcome(
        &self,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        self.attempt(|storage, session_id| {
            let payload = payload.clone();
            async move {
                storage
                    .put_outcome(session_id, address, fragment, payload)
                    .await
            }
        })
        .await
    }

    pub async fn query(&self, address: &[Address]) -> Result<Bytes, ProtocolError> {
        self.attempt(|storage, session_id| async move { storage.query(session_id, address).await })
            .await
    }

    pub async fn verify(
        &self,
        address: &Address,
        heal: bool,
    ) -> Result<VerifyResult, ProtocolError> {
        Self::collapse(self.verify_outcome(address, heal).await?)
    }

    /// [`verify`](Self::verify) on the typed outcome path. See [`put_outcome`](Self::put_outcome).
    pub async fn verify_outcome(
        &self,
        address: &Address,
        heal: bool,
    ) -> Result<MutableOutcome<VerifyResult>, ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage.verify_outcome(session_id, address, heal).await
        })
        .await
    }

    pub async fn copy(
        &self,
        source_partition: Partition,
        source_address: Address,
        target_context: Context,
    ) -> Result<(), ProtocolError> {
        Self::collapse(
            self.copy_outcome(source_partition, source_address, target_context)
                .await?,
        )
    }

    /// [`copy`](Self::copy) on the typed outcome path. See [`put_outcome`](Self::put_outcome).
    pub async fn copy_outcome(
        &self,
        source_partition: Partition,
        source_address: Address,
        target_context: Context,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage
                .copy_outcome(session_id, source_partition, source_address, target_context)
                .await
        })
        .await
    }

    /// Fetch only fragment metadata (`flags`, `size_payload`, `size_content`) for `address`.
    /// The wire request is identical to `get`; the server's response carries no payload bytes.
    /// Use this when the caller needs metadata without paying the payload transfer cost — e.g.
    /// the storage API's `query` op for remote-hit metadata lookups.
    pub async fn get_metadata(&self, address: &Address) -> Result<Fragment, ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage.get_metadata(session_id, address).await
        })
        .await
    }

    pub async fn mutable_load(&self, key: &Hash, key_type: KeyType) -> Result<Hash, ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage.mutable_load(session_id, key, key_type).await
        })
        .await
    }

    /// `mutable_load` + `get` in one round trip, always reading the key as
    /// [`KeyType::Resolve`]. Returns `(resolved_hash, fragment, payload)`.
    /// `flags` is a `get_resolved_flags` bitmask; 0 for default behaviour.
    pub async fn get_resolved(
        &self,
        key: &Hash,
        context: &Context,
        flags: u32,
    ) -> Result<(Hash, Fragment, Bytes), ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage.get_resolved(session_id, key, context, flags).await
        })
        .await
    }

    /// `put` + `mutable_store` in one round trip: store the fragment, then map `key` to
    /// `address.hash` under [`KeyType::Resolve`]. The write side of [`Self::get_resolved`].
    pub async fn put_resolved(
        &self,
        key: &Hash,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        Self::collapse(
            self.put_resolved_outcome(key, address, fragment, payload)
                .await?,
        )
    }

    /// [`put_resolved`](Self::put_resolved) on the typed outcome path. See
    /// [`put_outcome`](Self::put_outcome).
    ///
    /// This publishes a mutable key, so an ambiguous one is not an immutable put that happens
    /// to carry a key: repeating it can overwrite a successor mapping.
    pub async fn put_resolved_outcome(
        &self,
        key: &Hash,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        self.attempt(|storage, session_id| {
            let payload = payload.clone();
            async move {
                storage
                    .put_resolved_outcome(session_id, key, address, fragment, payload)
                    .await
            }
        })
        .await
    }

    pub async fn mutable_store(
        &self,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), ProtocolError> {
        Self::collapse(self.mutable_store_outcome(key, value, key_type).await?)
    }

    /// [`mutable_store`](Self::mutable_store) on the typed outcome path. See
    /// [`put_outcome`](Self::put_outcome).
    pub async fn mutable_store_outcome(
        &self,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<MutableOutcome<()>, ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage
                .mutable_store_outcome(session_id, key, value, key_type)
                .await
        })
        .await
    }

    pub async fn mutable_compare_and_swap(
        &self,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, ProtocolError> {
        Self::collapse(
            self.mutable_compare_and_swap_outcome(key, expected, value, key_type)
                .await?,
        )
    }

    /// [`mutable_compare_and_swap`](Self::mutable_compare_and_swap) on the typed outcome path.
    /// See [`put_outcome`](Self::put_outcome).
    ///
    /// An unknown outcome here is not a failed swap. Read the key back before deciding what
    /// happened, and remember that another writer may have moved it since.
    pub async fn mutable_compare_and_swap_outcome(
        &self,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<MutableOutcome<Hash>, ProtocolError> {
        self.attempt(|storage, session_id| async move {
            storage
                .mutable_compare_and_swap_outcome(session_id, key, expected, value, key_type)
                .await
        })
        .await
    }
}

impl Drop for StorageSession {
    fn drop(&mut self) {
        // Only the Resolved variant owns a server-side session directly. A
        // Pending variant that never resolved has nothing to stop. A Pending
        // variant that did resolve delegates: the inner Arc<StorageSession>
        // in the OnceCell has its own Drop that fires session_stop when its
        // refcount reaches zero.
        if let SessionInner::Resolved(r) = &self.inner {
            let storage = r.binding.storage.clone();
            let bound = *r.binding.session.lock();
            // Stopping a session is still putting its id on the wire, so it obeys the same rule
            // as every other command: only on the connection that issued it. A session from a
            // replaced connection needs no stop — the server drops the whole session map with
            // the connection — and sending one would be the exact defect this fix removes.
            //
            // The check has to be inside the task, not here. `Drop` only decides to try; the
            // connection can be replaced before the task runs, `session_stop` carries no epoch
            // guard of its own, and its result is discarded, so a stale id sent from here would
            // go out unnoticed by anything.
            if let Some(epoch) = bound.epoch {
                lore_base::lore_spawn_net!(async move {
                    if storage.connection_epoch() == epoch {
                        let _ = storage.session_stop(bound.id).await;
                    }
                });
            }
        }
    }
}

/// A pool of `StorageSession`s for a single `(partition, correlation_id)`
/// tuple. Holds one session per underlying `Storage` connection, plus a
/// round-robin counter so successive `pick()` calls spread load across all
/// connections in the pool.
pub struct SessionPool {
    sessions: Vec<Arc<StorageSession>>,
    next: AtomicUsize,
}

impl SessionPool {
    /// A pool over `sessions`, which [`pick`](Self::pick) round-robins across.
    ///
    /// The connector builds one session per underlying `Storage` connection, so a
    /// pick spreads a command's operations over every connection the connect phase
    /// established.
    pub fn new(sessions: Vec<Arc<StorageSession>>) -> Self {
        Self {
            sessions,
            next: AtomicUsize::new(0),
        }
    }

    /// Returns the next session in the pool via round-robin.
    ///
    /// Every call advances the cursor, so only a caller that is going to use the
    /// session picks. One that discards what it picked makes every other caller
    /// stride over the connections rather than visit each in turn.
    pub fn pick(&self) -> Arc<StorageSession> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.sessions.len();
        self.sessions[index].clone()
    }
}

/// Tracks a pool entry in the connector's `DashMap`. Mirrors the previous
/// per-session bookkeeping but at pool granularity: when the pool's strong
/// refcount reaches zero (caller releases the pin in `Connection::session_cache`),
/// the `Weak` becomes unupgradeable and the next access rebuilds the pool.
struct PoolEntry {
    /// Weak ref to the live pool. If upgradeable, every session it owns is in use.
    pool: Weak<SessionPool>,
    /// Server-assigned session IDs aligned with `storages`, for sending
    /// `session_stop` if this entry is replaced.
    session_ids: Vec<u32>,
    /// Weak refs to the storages each session was started on, aligned with
    /// `session_ids`. If a `Weak` no longer upgrades, the connection is gone
    /// and the server already cleaned up -- no stop needed.
    storages: Vec<Weak<dyn Storage>>,
}

/// Result of the synchronous `DashMap` entry check in
/// [`StorageConnector::session_pool`].
enum PoolOutcome {
    /// We inserted into a vacant slot -- we own this pool.
    Inserted { pool: Arc<SessionPool> },
    /// We replaced an expired entry -- we own the new pool, must stop the old sessions.
    Replaced {
        pool: Arc<SessionPool>,
        old_session_ids: Vec<u32>,
        old_storages: Vec<Weak<dyn Storage>>,
    },
    /// Another task won the race -- use the winner, stop our server-side sessions.
    RaceLost { winner: Arc<SessionPool> },
}

/// Owns a pool of Storage connections and manages session lifecycle with
/// deduplication, round-robin connection assignment, and automatic cleanup.
///
/// Each `(partition, correlation_id)` maps to a `SessionPool` containing one
/// `StorageSession` per underlying `Storage` connection. Operations on a
/// returned session round-robin across the pool so a single command spreads
/// load over every connection set up in the connect phase.
pub struct StorageConnector {
    connections: Vec<Arc<dyn Storage>>,
    counter: AtomicUsize,
    pools: dashmap::DashMap<(Partition, String), PoolEntry>,
    /// Partitions for which `session_start` has already succeeded on every underlying
    /// `Storage`. Tracks the server-side `authorized_repos` state — once a partition is
    /// registered here, the server keeps it in `authorized_repos` for the connection's
    /// lifetime regardless of `session_stop`, so subsequent ops for the same partition can
    /// skip the `session_start` round-trip purely for authorization.
    ///
    /// The set is per-`StorageConnector`, which matches the server scoping: one
    /// `StorageServiceV4` instance (and its `SessionMap`) per accepted connection. When the
    /// owning `Connection` drops, the connector goes with it and the set resets.
    authorized_partitions: dashmap::DashSet<Partition>,
    /// Partitions this connector's identity has been refused. Only a refusal is recorded — a
    /// transport failure says nothing about the claim and stays retryable — so the entry means the
    /// answer will not change until the identity does, and asking again is a round trip that can
    /// only fail. Cleared by a `session_start` that later succeeds, which is proof it has.
    refused_partitions: dashmap::DashSet<Partition>,
}

impl StorageConnector {
    pub fn new(connections: Vec<Arc<dyn Storage>>) -> Self {
        Self {
            connections,
            counter: AtomicUsize::new(0),
            pools: dashmap::DashMap::new(),
            authorized_partitions: dashmap::DashSet::new(),
            refused_partitions: dashmap::DashSet::new(),
        }
    }

    /// Whether the given partition has previously had `session_start` succeed on every
    /// underlying `Storage` for this connector. A `true` answer means the server's
    /// `authorized_repos` set already contains the partition and a fresh `session_start`
    /// purely for authorization is unnecessary.
    pub fn is_partition_authorized(&self, partition: Partition) -> bool {
        self.authorized_partitions.contains(&partition)
    }

    /// Whether `session_start` for this partition has already been refused on this connector.
    pub fn is_partition_refused(&self, partition: Partition) -> bool {
        self.refused_partitions.contains(&partition)
    }

    /// Record that this connector's identity holds no claim to `partition`.
    pub fn mark_partition_refused(&self, partition: Partition) {
        self.refused_partitions.insert(partition);
    }

    /// Record that `session_start` has succeeded, which retires any earlier refusal: the claim was
    /// just exercised, so whatever the refusal was about no longer holds.
    pub(crate) fn mark_partition_authorized(&self, partition: Partition) {
        self.authorized_partitions.insert(partition);
        self.refused_partitions.remove(&partition);
    }

    /// Get or create the `SessionPool` for the given partition and correlation ID.
    /// The caller pins the pool to keep every session it owns alive across the
    /// operations of one command, and [`picks`](SessionPool::pick) from it per
    /// operation.
    ///
    /// Nothing is picked here. A pick advances the pool's round-robin cursor, so a
    /// caller that only wanted the pool would leave every picking caller striding
    /// over the connections instead of visiting each in turn.
    ///
    /// On a miss, one server-side session is started per underlying connection, in
    /// parallel. The first writer wins the key, vacant or expired entry alike; a
    /// losing racer stops every server-side session it just started.
    pub async fn session_pool(
        &self,
        partition: Partition,
        correlation_id: &str,
        connection: Arc<Connection>,
    ) -> Result<Arc<SessionPool>, ProtocolError> {
        let key = (partition, correlation_id.to_string());

        // Fast path: live pool exists.
        if let Some(entry) = self.pools.get(&key)
            && let Some(pool) = entry.pool.upgrade()
        {
            return Ok(pool);
        }

        // Slow path: start one session per connection in parallel. No lock held.
        let started = Arc::new(Mutex::new(Vec::with_capacity(self.connections.len())));
        let mut tasks = JoinSet::new();
        for storage in self.connections.iter().cloned() {
            let correlation_id = correlation_id.to_string();
            let started = started.clone();
            lore_spawn_net!(tasks, async move {
                // Sampled before the call, so a connection replaced while `session_start` is in
                // flight leaves the session bound to the older generation and the first use
                // rebinds. The other order would record a generation the id was never valid on.
                let epoch = storage.connection_epoch();
                let session_id = storage.session_start(partition, &correlation_id).await?;
                started.lock().push((storage, session_id, epoch));
                Ok::<_, ProtocolError>(())
            });
        }
        lore_drain_tasks!(
            tasks,
            ProtocolError::internal("session_start task join failure")
        )?;
        let Ok(started) = Arc::try_unwrap(started) else {
            unreachable!("session_start tasks dropped their Arc<Mutex<_>> clones");
        };
        let started: Vec<(Arc<dyn Storage>, u32, u32)> = started.into_inner();

        // session_start succeeded on every connection in parallel above; the partition is now
        // in `authorized_repos` of every server-side `SessionMap` for the pool. Even on the
        // race-loser path below (which stops these sessions to defer to the winner), the
        // server keeps the partition in `authorized_repos` permanently — `session_stop` only
        // touches the per-session map, not the authorization set. So this is the right point
        // to mark the partition as authorized for any future fast-path query.
        self.mark_partition_authorized(partition);

        // Build the pool with strong refs to every session.
        let correlation: Arc<str> = Arc::from(correlation_id);
        let sessions: Vec<Arc<StorageSession>> = started
            .iter()
            .map(|(storage, session_id, epoch)| {
                Arc::new(StorageSession::resolved(
                    storage.clone(),
                    connection.clone(),
                    *session_id,
                    *epoch,
                    partition,
                    correlation.clone(),
                ))
            })
            .collect();
        let pool = Arc::new(SessionPool::new(sessions));
        let session_ids: Vec<u32> = started.iter().map(|(_, id, _)| *id).collect();
        let storages: Vec<Weak<dyn Storage>> =
            started.iter().map(|(s, _, _)| Arc::downgrade(s)).collect();

        // Try to insert under the entry lock (synchronous only -- no .await).
        let outcome = {
            #[allow(clippy::disallowed_methods)]
            // Synchronous entry check; no await while lock is held.
            let entry = self.pools.entry(key);
            match entry {
                dashmap::mapref::entry::Entry::Occupied(mut e) => {
                    if let Some(alive) = e.get().pool.upgrade() {
                        // Race loser -- another task won while we were starting sessions.
                        PoolOutcome::RaceLost { winner: alive }
                    } else {
                        // Expired entry -- take old info for cleanup, replace with ours.
                        let old_session_ids = std::mem::take(&mut e.get_mut().session_ids);
                        let old_storages = std::mem::take(&mut e.get_mut().storages);
                        e.insert(PoolEntry {
                            pool: Arc::downgrade(&pool),
                            session_ids: session_ids.clone(),
                            storages: storages.clone(),
                        });
                        PoolOutcome::Replaced {
                            pool: pool.clone(),
                            old_session_ids,
                            old_storages,
                        }
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(v) => {
                    v.insert(PoolEntry {
                        pool: Arc::downgrade(&pool),
                        session_ids: session_ids.clone(),
                        storages: storages.clone(),
                    });
                    PoolOutcome::Inserted { pool: pool.clone() }
                }
            }
        }; // entry lock released here

        match outcome {
            PoolOutcome::Inserted { pool } => Ok(pool),
            PoolOutcome::Replaced {
                pool,
                old_session_ids,
                old_storages,
            } => {
                // Stop expired sessions outside the lock.
                for (id, storage) in old_session_ids.into_iter().zip(old_storages) {
                    if let Some(storage) = storage.upgrade() {
                        let _ = storage.session_stop(id).await;
                    }
                }
                Ok(pool)
            }
            PoolOutcome::RaceLost { winner } => {
                // Stop every server-side session we just started -- the winner owns this key.
                for (id, storage) in session_ids.into_iter().zip(storages) {
                    if let Some(storage) = storage.upgrade() {
                        let _ = storage.session_stop(id).await;
                    }
                }
                Ok(winner)
            }
        }
    }

    /// Direct access to the underlying connections.
    pub fn connections(&self) -> &[Arc<dyn Storage>] {
        &self.connections
    }

    /// Returns the next connection index via round-robin.
    pub fn next_connection_index(&self) -> usize {
        self.counter.fetch_add(1, Ordering::Relaxed) % self.connections.len()
    }

    /// Gracefully close every underlying storage connection, draining in-flight
    /// streams before sending the transport close frame.
    pub async fn close_all(&self) {
        for storage in &self.connections {
            storage.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lazy session whose resolver counts its calls and always fails, so how
    /// often it is asked is what the test reads and what it resolves to is out of
    /// the way.
    fn counting_session(calls: Arc<AtomicUsize>) -> StorageSession {
        StorageSession::pending(move || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                Err(ProtocolError::internal("nothing to resolve"))
            }
        })
    }

    /// One resolution serves every operation, the outcome being held whether it
    /// succeeded or not.
    #[tokio::test]
    async fn a_lazy_session_resolves_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let session = counting_session(calls.clone());

        assert!(session.is_lazy());
        assert!(session.partition().await.is_err());
        assert!(session.partition().await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    /// The read path recovers a rotated server session map by invalidating the
    /// session and retrying that same session, which only gets a `session_id` the
    /// server knows about where the session resolves again.
    #[tokio::test]
    async fn an_invalidated_lazy_session_resolves_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let session = counting_session(calls.clone());

        assert!(session.partition().await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        session.invalidate().await;

        assert!(session.partition().await.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
}

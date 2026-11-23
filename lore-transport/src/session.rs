// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use crossbeam::epoch;
use crossbeam::epoch::Atomic;
use crossbeam::epoch::Owned;
use crossbeam::epoch::Shared;
use futures::FutureExt;
use futures::future::BoxFuture;
use lore_base::error::Disconnected;
use lore_base::lore_spawn_net;
use lore_base::runtime::DetachingJoinSet;
use lore_base::types::*;
use lore_error_set::prelude::*;
use parking_lot::Mutex;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

use crate::connection::Connection;
use crate::error::ProtocolError;
use crate::replay::ATTEMPT_BUDGET;
use crate::replay::MutableOutcome;
use crate::traits::Storage;
use crate::unmanaged_write::UnmanagedWriteLatch;

/// A live session on a `Storage` connection. Provides all storage operations
/// scoped to a specific partition and correlation ID. Sends `session_stop`
/// to the server when the last reference is dropped.
///
/// A session may be constructed in one of three states:
/// - `Resolved`: the caller has already established the server-side session.
/// - `Pooled`: each operation runs on the next session of a [`SessionPool`].
/// - `Pending`: the caller has everything needed to establish a session but
///   hasn't done so yet. The session is started lazily on the first operation
///   and cached for subsequent ones. This is how local-only command paths avoid
///   forcing the background connect to resolve.
pub struct StorageSession {
    inner: SessionInner,
    /// FORK-LOCAL (Tideshift, WP-124 follow-up (b)): whether this session's server has refused
    /// a write made outside a managed caller operation.
    unmanaged_writes: UnmanagedWriteLatch,
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
    /// A storage session belongs to one connection. Holding the id without the generation it came
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
    /// FORK-LOCAL (Tideshift, WP-124): the managed parent and capability list this session
    /// declares, or `None` for an undeclared session. Fixed at construction, so a rebind of a
    /// declared session declares again and a rebind of an undeclared one never does.
    declared: Option<(Uuid, &'static str)>,
    /// FORK-LOCAL (Tideshift, WP-124 K10): how the replacement starts under `rebind` ended.
    starts: Mutex<StartHistory>,
}

/// FORK-LOCAL (Tideshift, WP-124 K10): the replacement starts a [`SessionBinding`] has finished,
/// and the error of the last one when the managed bound ended it.
///
/// A caller that queued on the rebind guard behind a start shares that start's result: a success
/// through the binding, and a managed-bound expiry through this record. Without it, each caller
/// queued behind a start that a dead QUIC path expired spent a whole bound on its own start, in
/// turn, so N queued commands cost N bounds. A caller that arrives after the expiry is not queued
/// behind it and starts again.
#[derive(Default)]
struct StartHistory {
    finished: u64,
    /// The connection generation the expired start ran on, and its error.
    expired: Option<(u32, ProtocolError)>,
}

/// A session id and the connection generation it is valid on.
///
/// `generation` is `None` for a session that is known to be gone, which is not the same as one
/// bound to some particular generation: there is no generation value that could stand for it,
/// since every value the transport reports is one a session could legitimately hold.
#[derive(Clone, Copy)]
struct BoundSession {
    id: u32,
    generation: Option<u32>,
    /// FORK-LOCAL (Tideshift, WP-124): the token `exp` a proactive rebind replaced this session
    /// to get away from, if one did. A session whose own `exp` is the same one is not rebound
    /// again: the start got the same token back (a supplied token, or one the authz cache still
    /// serves), so another start would cost a round trip and a server session per command and
    /// change nothing. The server's expired-session answer then decides.
    refreshed_from: Option<u64>,
}

impl SessionBinding {
    /// The session id to send on the connection as it is now, starting a replacement session
    /// first if the connection has been replaced since this one was issued.
    ///
    /// A replacement is bound to the generation the start itself reports
    /// ([`Storage::session_start_bound`]), never to one sampled here. The start's own send may
    /// reconnect, which it does whenever the connection died before this call; a sample taken
    /// before it then names the dead connection, the write boundary refuses the new id, and a
    /// second start strands the first session on the server (WP-124). A connection replaced
    /// again after the start answers still leaves the id on the older generation, and the
    /// next caller rebinds.
    ///
    /// What this guarantees is that no id is *handed out* for a generation it did not come from.
    /// It does not guarantee the id is still current when the bytes reach the socket, because
    /// awaits follow: growing a stream, taking the connection read lock, taking the writer. That
    /// remainder is not left to the server to catch. The QUIC send path repeats the check at the
    /// write boundary, inside the read lock a reconnect must take in write mode to replace the
    /// connection, and refuses to frame an id whose generation has moved
    /// (`QuicConnection::session_is_current`). So the window is closed before the write, not
    /// after it, and [`StorageSession::attempt`] turns the refusal into a rebind and one retry.
    ///
    /// Returns the generation alongside the id, rather than leaving the caller to read it back
    /// off the binding afterwards. The two have to be one observation: a sibling task calling
    /// [`StorageSession::invalidate`] can clear the binding at any moment, and a caller that
    /// re-read it would see "not bound to anything" and conclude the connection had been
    /// replaced under its command when it had not.
    ///
    /// FORK-LOCAL (Tideshift, WP-124): a session whose token has reached its `exp`
    /// ([`Storage::session_refresh_due`]) is replaced the same way, before its next command. The
    /// superseded id is not stopped: a sibling may have resolved it and still be sending on it,
    /// and the server accepts it until `exp` plus leeway, then sweeps it.
    async fn resolve(&self) -> Result<(u32, u32), ProtocolError> {
        let current = self.storage.connection_generation();
        if let Some(id) = self.current_on(current) {
            return Ok((id, current));
        }

        // FORK-LOCAL (Tideshift, WP-124 K10): the starts finished before we queue, so the
        // record below can tell whether one we waited behind expired.
        let queued_after = self.starts.lock().finished;
        let _flight = self.rebind.lock().await;
        // Re-read under the guard: whoever held it before us may already have rebound, and the
        // generation may have moved again while we waited.
        let current = self.storage.connection_generation();
        if let Some(id) = self.current_on(current) {
            return Ok((id, current));
        }
        // FORK-LOCAL (Tideshift, WP-124 K10): a start we waited behind ended at the managed
        // bound, and the connection has not been replaced since, so ours would only wait the
        // bound again. Our command was not sent; it gets the error its own start would have
        // ended with.
        {
            let starts = self.starts.lock();
            if starts.finished > queued_after
                && let Some((generation, expired)) = &starts.expired
                && *generation == current
            {
                return Err(expired.clone());
            }
        }

        // FORK-LOCAL (Tideshift, WP-124): a session still bound to the current generation is
        // being replaced only because its token is due, so remember which `exp` it was.
        let previous = self.bound();
        let refreshed_from = if previous.generation == Some(current) {
            self.storage.session_token_expiry(previous.id)
        } else {
            None
        };

        // A fresh `session_start` re-runs the token exchange and the server's authorization
        // check for this partition. Nothing from the old session's permission snapshot carries
        // over, which is the point: the replacement connection decides for itself.
        let started = match self.declared {
            Some((_, capabilities)) => {
                self.storage
                    .session_start_declared(self.partition, &self.correlation_id, capabilities)
                    .await
            }
            None => {
                self.storage
                    .session_start_bound(self.partition, &self.correlation_id)
                    .await
            }
        };
        {
            let mut starts = self.starts.lock();
            starts.finished += 1;
            starts.expired = match &started {
                Err(error) if crate::error::is_managed_reconnect_expired(error) => {
                    Some((current, error.clone()))
                }
                _ => None,
            };
        }
        let (id, generation) = started?;
        *self.session.lock() = BoundSession {
            id,
            generation: Some(generation),
            refreshed_from,
        };
        Ok((id, generation))
    }

    /// The session id if it belongs to `generation`, otherwise nothing.
    ///
    /// FORK-LOCAL (Tideshift, WP-124): also nothing when its token is due for refresh. A token is not due again when a proactive
    /// rebind already left that same `exp` behind (see [`BoundSession::refreshed_from`]).
    fn current_on(&self, generation: u32) -> Option<u32> {
        let bound = *self.session.lock();
        if bound.generation != Some(generation) {
            return None;
        }
        let due = self.storage.session_refresh_due(bound.id)
            && self.storage.session_token_expiry(bound.id) != bound.refreshed_from;
        (!due).then_some(bound.id)
    }

    /// FORK-LOCAL (Tideshift, WP-124): unbind only if the binding still holds `session_id`.
    ///
    /// For the expired-session answer. Every command in flight on the expired id gets that answer,
    /// so the slower ones arrive after the first has already rebound. Unbinding unconditionally
    /// there would throw the fresh session away and start another, once per sibling.
    fn unbind_if(&self, session_id: u32) {
        let mut bound = self.session.lock();
        if bound.id == session_id {
            bound.generation = None;
        }
    }

    /// The id and the generation it is bound to, whatever either reads as. For the cleanup paths,
    /// which have to decide whether a stop is still worth sending.
    fn bound(&self) -> BoundSession {
        *self.session.lock()
    }

    /// Force the next use to start a replacement session, whatever the generation reads as.
    ///
    /// Used when the connection was replaced under a command: the id we hold belongs to the
    /// generation that is gone, and the generation comparison alone is not enough to say so at
    /// every moment we might look.
    ///
    /// This gives up the *binding*, not the server-side session, and deliberately does not tell
    /// the transport to forget the id. It was made to, briefly, to stop an abandoned id sitting
    /// in the transport's registry until the connection was replaced. That cure was worse than
    /// the leak: `invalidate` is called on healthy connections, the pool still holds the same id
    /// for cleanup, and a forgotten id fails the write-boundary check — so the eventual
    /// `session_stop` was refused and the *server's* session leaked instead, one per invalidate
    /// against a 10,000 limit. A stale client-side entry costs bytes; a stranded server session
    /// costs a session slot.
    fn unbind(&self) {
        self.session.lock().generation = None;
    }
}

/// FORK-LOCAL (Tideshift, WP-124): the declared sessions one managed parent has opened, keyed by
/// the storage connection and partition they were opened for.
///
/// Owned by the [`crate::CallerOperationContext`], never by a connection or a pool. The context
/// lives exactly as long as the managed scope, on every path (CLI, push stage, desktop call), so
/// when its last clone drops the declared sessions are stopped. A connection or a pool can
/// outlive many scopes; declared sessions held there would leak across workflows and pile up
/// toward the server's session limit.
#[derive(Default)]
pub(crate) struct DeclaredBindings {
    bindings: Mutex<HashMap<(usize, Partition), Arc<SessionBinding>>>,
}

/// The key of the declared binding twinned with `undeclared`.
///
/// The storage is keyed by address. That is sound because the entry holds a strong reference to
/// the same storage, so the address cannot be reused while the entry exists.
fn declared_key(undeclared: &SessionBinding) -> (usize, Partition) {
    (
        Arc::as_ptr(&undeclared.storage).cast::<()>() as usize,
        undeclared.partition,
    )
}

impl DeclaredBindings {
    /// The declared binding for `undeclared`'s connection and partition, created unbound on
    /// first use. Synchronous, so concurrent first calls share one entry; the first
    /// [`SessionBinding::resolve`] on it opens the session, under its rebind guard.
    fn get_or_insert(
        &self,
        undeclared: &SessionBinding,
        parent_id: Uuid,
        capabilities: &'static str,
    ) -> Arc<SessionBinding> {
        let mut bindings = self.bindings.lock();
        bindings
            .entry(declared_key(undeclared))
            .or_insert_with(|| {
                Arc::new(SessionBinding {
                    storage: undeclared.storage.clone(),
                    session: Mutex::new(BoundSession {
                        id: 0,
                        generation: None,
                        refreshed_from: None,
                    }),
                    rebind: TokioMutex::new(()),
                    partition: undeclared.partition,
                    correlation_id: undeclared.correlation_id.clone(),
                    declared: Some((parent_id, capabilities)),
                    starts: Mutex::default(),
                })
            })
            .clone()
    }

    /// Forget the declared binding for `undeclared`'s connection and partition. Its session is
    /// stopped once the last attempt holding it returns.
    fn remove(&self, undeclared: &SessionBinding) {
        let removed = self.bindings.lock().remove(&declared_key(undeclared));
        drop(removed);
    }

    /// How many declared bindings this parent holds.
    pub(crate) fn len(&self) -> usize {
        self.bindings.lock().len()
    }
}

/// FORK-LOCAL (Tideshift, WP-124): a declared session is stopped when its binding's last
/// reference drops.
///
/// The last reference, not the map entry. An attempt that selected the binding holds it until it
/// returns, and may still resolve it after the entry was removed (an `invalidate` in scope); a
/// stop tied to the entry would race that attempt, or miss a session it opened afterwards. Once
/// the last reference is gone nothing can resolve the binding, so the id read here is final.
///
/// Declared bindings only: [`StorageSession`]'s own `Drop` already stops each undeclared session,
/// and stopping here too would send a second stop for every one of them.
impl Drop for SessionBinding {
    fn drop(&mut self) {
        if self.declared.is_none() {
            return;
        }
        let storage = self.storage.clone();
        let bound = self.bound();
        // Same rule as `StorageSession::drop`: `drop` only decides to try, and the generation is
        // compared inside the task, immediately before the stop goes out.
        if let Some(generation) = bound.generation {
            lore_base::lore_spawn_net!(async move {
                if storage.connection_generation() == generation {
                    let _ = storage.session_stop(bound.id).await;
                }
            });
        }
    }
}

/// The epoch the QUIC client stores when it stops trying to reconnect.
///
/// Not a generation, so a session is never bound to it and a move *to* it is not a replacement
/// worth rebinding onto.
///
/// This is why [`StorageSession::attempt`] reads both counters. The generation answers "was the
/// connection replaced under this command", which is what decides whether a rebind could help;
/// the epoch answers "is a replacement ever coming", and a zero says no, so the last attempt is
/// not spent on a connection that will not return.
const GAVE_UP_EPOCH: u32 = 0;

/// Closure signature for a pending session's resolver. Returns an eager or a pooled
/// `Arc<StorageSession>`, typically a pooled one from the caller's connection once it
/// resolves. Runs once per resolution, not once per session: a throttled or invalidated
/// resolution is asked again.
type PendingResolver =
    Arc<dyn Fn() -> BoxFuture<'static, Result<Arc<StorageSession>, ProtocolError>> + Send + Sync>;

enum SessionInner {
    Resolved(ResolvedFields),
    Pooled(Arc<SessionPool>),
    Pending {
        resolver: PendingResolver,
        /// The session the resolver produced, read by every operation without a lock. Null
        /// before the first resolution and after an [`invalidate`](StorageSession::invalidate),
        /// which forces a fresh `session_start` on the next operation, as a read's retry of a
        /// failed session asks for. Written only under `resolution`.
        current: Atomic<Arc<StorageSession>>,
        /// Serialises resolutions and invalidations, and holds a failed resolution's error.
        ///
        /// A throttled `session_start` is not held. `SlowDown` is the one failure the retrying
        /// callers answer with back-off instead of `invalidate`, so a held one would be served
        /// to every later attempt and the retry would spend its whole schedule without ever
        /// reaching the server. Every other failure is held, so the rest of a batch sharing the
        /// session fails without repeating a `session_start` that cannot succeed.
        resolution: TokioMutex<Option<ProtocolError>>,
    },
}

impl StorageSession {
    /// Construct an already-resolved session. Used by the connection internals
    /// after a successful `session_start` RPC.
    /// `generation` is the connection generation `session_id` was issued on, as
    /// [`Storage::session_start_bound`] reported it.
    #[lore_macro::test_pub]
    pub(crate) fn resolved(
        storage: Arc<dyn Storage>,
        connection: Arc<Connection>,
        session_id: u32,
        generation: u32,
        partition: Partition,
        correlation_id: Arc<str>,
    ) -> Self {
        Self {
            inner: SessionInner::Resolved(ResolvedFields {
                binding: Arc::new(SessionBinding {
                    storage,
                    session: Mutex::new(BoundSession {
                        id: session_id,
                        generation: Some(generation),
                        refreshed_from: None,
                    }),
                    rebind: TokioMutex::new(()),
                    partition,
                    correlation_id,
                    declared: None,
                    starts: Mutex::default(),
                }),
                connection,
            }),
            unmanaged_writes: UnmanagedWriteLatch::default(),
        }
    }

    /// Construct a session whose server-side session will be started on the
    /// first operation. Subsequent operations use the resolved session; the
    /// resolver runs again only after an [`invalidate`](Self::invalidate) or a
    /// throttled `session_start`. Typical use: defer the underlying remote
    /// connect and session creation until actually needed.
    ///
    /// The resolver returns an eager or a pooled `Arc<StorageSession>`, over a pool the
    /// connection pins ([`Connection::session_pool`]) or one its caller holds
    /// ([`Connection::unpinned_session_pool`]).
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
                current: Atomic::null(),
                resolution: TokioMutex::new(None),
            },
            unmanaged_writes: UnmanagedWriteLatch::default(),
        }
    }

    /// FORK-LOCAL (Tideshift, WP-124 follow-up (b)): the latch an unmanaged write reads
    /// before it uploads on this session. See [`crate::unmanaged_write`].
    pub fn unmanaged_writes(&self) -> &UnmanagedWriteLatch {
        &self.unmanaged_writes
    }

    /// A session over every session in `pool`: each operation runs on the next one in turn, so
    /// the operations of one holder spread over every connection the pool spans.
    pub fn pooled(pool: Arc<SessionPool>) -> Self {
        Self {
            inner: SessionInner::Pooled(pool),
            unmanaged_writes: UnmanagedWriteLatch::default(),
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
    /// connection. Also marks the pool the session runs over stale and clears
    /// the parent `Connection`'s session pool cache, so no resolution hands out
    /// a pool holding session ids the server may not know. Call this after the
    /// transport surfaces a `NotConnected`/`Failed` server response indicating
    /// the session-id is no longer known server-side.
    pub async fn invalidate(&self) {
        match &self.inner {
            SessionInner::Pending {
                current,
                resolution,
                ..
            } => {
                let mut failure = resolution.lock().await;
                let guard = epoch::pin();
                let resolved = current.swap(Shared::null(), Ordering::AcqRel, &guard);
                // SAFETY: published by `resolve_pending` and freed only here, deferred past every
                // reader pinned when it was unlinked.
                if let Some(inner) = unsafe { resolved.as_ref() } {
                    inner.invalidate_connection_sessions();
                    unsafe { guard.defer_destroy(resolved) };
                    guard.flush();
                }
                *failure = None;
            }
            _ => self.invalidate_connection_sessions(),
        }
    }

    /// Holds a pending session's resolution lock until the guard drops; `None` for any other.
    #[cfg(feature = "test-util")]
    pub async fn hold_resolution(
        &self,
    ) -> Option<tokio::sync::MutexGuard<'_, Option<ProtocolError>>> {
        match &self.inner {
            SessionInner::Pending { resolution, .. } => Some(resolution.lock().await),
            _ => None,
        }
    }

    /// Clears the session pool cache of the `Connection` each session this one runs on belongs
    /// to, and marks a pool this session runs over stale, so no resolution serves it again.
    fn invalidate_connection_sessions(&self) {
        match &self.inner {
            // FORK-LOCAL (Tideshift, CR-026/WP-124): the binding gives up its id (the next use
            // starts a replacement), and the declared binding the caller's scope owns for this
            // connection and partition is released, as before the pooled form existed.
            SessionInner::Resolved(r) => {
                r.binding.unbind();
                Self::release_declared(&r.binding);
                r.connection.invalidate_all_sessions();
            }
            SessionInner::Pooled(pool) => {
                pool.mark_stale();
                for session in &pool.sessions {
                    session.invalidate_connection_sessions();
                }
            }
            SessionInner::Pending { .. } => {}
        }
    }

    /// Run one storage operation, allowing a single rebound retry when the connection was
    /// replaced while the command was in flight.
    ///
    /// Retrying here is safe only when the transport returns its distinct
    /// [`crate::error::SessionRebindRequired`] proof. That error is produced from
    /// [`crate::replay::DispatchState::NotDispatched`] at the write boundary. Every answered error is returned,
    /// even if a sibling reconnect moved the generation before this task resumed: an answer
    /// proves only that the server received the command, not that the handler had no effect.
    /// A dispatched mutable command whose response was lost returns
    /// [`MutableOutcome::Unknown`] and also leaves this loop untouched.
    ///
    /// That is why every mutable operation below runs its `_outcome` form through here and
    /// collapses the unknown to an error *afterwards*, rather than calling the plain form and
    /// letting the transport collapse it first. Collapsing underneath this loop turns an
    /// ambiguous write into an ordinary error and this retry into a second `Put`.
    ///
    /// At most [`ATTEMPT_BUDGET`] dispatches of the operation itself, one rebind between them.
    ///
    /// FORK-LOCAL (Tideshift, WP-124): the server's expired-session answer
    /// ([`crate::error::is_session_expired`]) is the second proof that allows that rebind. It is
    /// sent before any handler runs, so it proves non-dispatch without any generation change.
    ///
    /// `write` says whether the operation mutates; it only decides what a managed caller on a
    /// foreign partition gets (see [`binding`](Self::binding)).
    async fn attempt<T, Fut>(
        &self,
        write: bool,
        operation: impl Fn(Arc<dyn Storage>, u32) -> Fut,
    ) -> Result<T, ProtocolError>
    where
        Fut: std::future::Future<Output = Result<T, ProtocolError>>,
    {
        let mut attempts_left = ATTEMPT_BUDGET;
        loop {
            attempts_left -= 1;
            // Resolves the session, and starts a replacement first if the connection has moved
            // on since this one was issued. Chosen per call: the caller's managed scope can
            // differ from one operation on this session to the next.
            let binding = self.binding(write).await?;
            let (session_id, sent_on) = binding.resolve().await?;
            let storage = binding.storage.clone();

            let error = match operation(storage.clone(), session_id).await {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };

            // Retry only when the connection the id was sent on has since been replaced, which
            // is the one condition a replacement session could have avoided.
            //
            // `sent_on` comes back from `resolve` rather than being read off the binding here,
            // and that is load-bearing rather than tidy. Reading the binding afterwards asks
            // "is it bound to the current generation", which a sibling task's `invalidate` can
            // answer no to without any connection having been replaced — turning an ordinary
            // server refusal into a second dispatch of a command that must not be repeated.
            // Comparing the generation the id actually went out on cannot be perturbed by
            // anything but a real replacement.
            //
            // Not "the connection generation moved since some earlier moment", either: a command
            // whose session was already rebound before it ran would read a moved generation and
            // be dispatched again after an error the server itself returned.
            //
            // A zero epoch is consulted for its own separate meaning: reconnection has given up,
            // so there is nothing to rebind onto and spending the last attempt is waste.
            //
            // FORK-LOCAL (Tideshift, WP-124): an expired-session answer is the other proof that
            // allows one more pass. The server sends it before any handler runs, so nothing
            // was dispatched, and the connection is fine: only this session is stale. It needs no
            // generation change, and the next pass starts a new session with a fresh token. Only
            // the id it named is unbound, so a sibling that arrives after the rebind keeps it.
            if attempts_left > 0 && crate::error::is_session_expired(&error) {
                binding.unbind_if(session_id);
                continue;
            }

            let not_dispatched = crate::error::is_session_rebind_required(&error);
            let replaced = sent_on != storage.connection_generation();
            if attempts_left == 0
                || !not_dispatched
                || !replaced
                || storage.connection_epoch() == GAVE_UP_EPOCH
            {
                return Err(error);
            }

            // Unbind the binding this attempt used, not whatever `binding` would pick now: with
            // per-call selection a second lookup could name a different session. The next pass
            // selects again, so a declared binding retries on a declared session.
            binding.unbind();
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
    /// needing the server-side session goes through here, so one resolution serves whatever is
    /// asked of a pending session. A pooled session reads from the next session of its pool when
    /// `turn`, and from its first otherwise; a query that only reads a session's fields takes no
    /// turn, so it leaves the operations visiting every session in turn.
    ///
    /// A pending session once resolved is read without a lock ([`project_current`]).
    async fn with_resolved<T>(
        &self,
        turn: bool,
        project: impl FnOnce(&ResolvedFields) -> T,
    ) -> Result<T, ProtocolError> {
        let SessionInner::Pending {
            resolver,
            current,
            resolution,
        } = &self.inner
        else {
            return self.project_member(turn, project).await;
        };
        let project = match project_current(current, turn, project) {
            Ok(answer) => return Ok(answer),
            Err(project) => project,
        };
        resolve_pending(resolver, current, resolution)
            .await?
            .project_member(turn, project)
            .await
    }

    /// `project` applied to the fields of this session or of its pool's
    /// [`member`](SessionPool::member) for `turn`. Only a pool built outside the connector holds
    /// pending sessions, so resolving one is boxed and stays out of every operation's future.
    async fn project_member<T>(
        &self,
        turn: bool,
        project: impl FnOnce(&ResolvedFields) -> T,
    ) -> Result<T, ProtocolError> {
        let member = match &self.inner {
            SessionInner::Resolved(r) => return Ok(project(r)),
            SessionInner::Pooled(pool) => pool.member(turn),
            SessionInner::Pending { .. } => {
                return Err(ProtocolError::internal("nested pending session"));
            }
        };
        match &member.inner {
            SessionInner::Resolved(r) => Ok(project(r)),
            SessionInner::Pending {
                resolver,
                current,
                resolution,
            } => {
                let inner = Box::pin(resolve_pending(resolver, current, resolution)).await?;
                match &inner.inner {
                    SessionInner::Resolved(r) => Ok(project(r)),
                    _ => Err(ProtocolError::internal("nested session")),
                }
            }
            SessionInner::Pooled(_) => Err(ProtocolError::internal("nested pooled session")),
        }
    }

    /// The binding this call runs on, driving the pending resolver on first call.
    ///
    /// FORK-LOCAL (Tideshift, WP-124): chosen per call from the caller's managed scope, read here
    /// in the caller's own task. No scope gets the undeclared binding, always. A scope on a
    /// transport that declares per session gets the declared binding its
    /// [`crate::CallerOperationContext`] owns for this connection and partition, so a binding
    /// declared for one parent is never used by another, and never outside a scope. A scope on
    /// another partition than its repository reads on the undeclared binding and is refused a
    /// write locally, as the gRPC managed path refuses one.
    async fn binding(&self, write: bool) -> Result<Arc<SessionBinding>, ProtocolError> {
        let undeclared = self.with_resolved(true, |r| r.binding.clone()).await?;
        let Some(context) = crate::caller_operation::current_caller_operation() else {
            return Ok(undeclared);
        };
        if !undeclared.storage.declares_per_session() {
            return Ok(undeclared);
        }
        if undeclared.partition != context.repository() {
            if write {
                return Err(ProtocolError::internal(
                    "managed operation repository mismatch",
                ));
            }
            return Ok(undeclared);
        }
        Ok(context.declared_bindings().get_or_insert(
            &undeclared,
            context.parent_id(),
            context.capabilities(),
        ))
    }

    /// FORK-LOCAL (Tideshift, WP-124): refuse a managed `MutableStore` or `MutableCas` on a
    /// transport that declares per session (QUIC), before [`attempt`](Self::attempt) selects a
    /// binding. Here, a declared session is never started for a write that cannot be sent, so
    /// the refusal puts no byte on the wire. A pending session still resolves its undeclared
    /// session first, as any first use does; that is what tells the transport apart. gRPC journals
    /// both verbs through `caller_operation::dispatch` and is not refused. The storage client
    /// keeps the same refusal for a caller that bypasses this session.
    ///
    /// A foreign partition is left to [`binding`](Self::binding), which refuses that write
    /// locally as a repository mismatch, also before any byte.
    async fn refuse_managed_mutable_key(&self) -> Result<(), ProtocolError> {
        let Some(context) = crate::caller_operation::current_caller_operation() else {
            return Ok(());
        };
        let undeclared = self.with_resolved(false, |r| r.binding.clone()).await?;
        if undeclared.storage.declares_per_session() && undeclared.partition == context.repository()
        {
            return Err(ProtocolError::internal(
                "managed mutable-key writes require gRPC",
            ));
        }
        Ok(())
    }

    /// FORK-LOCAL (Tideshift, WP-124): release the declared binding the current scope owns for
    /// `undeclared`'s connection and partition, if it has one.
    ///
    /// Removed rather than unbound. Unbinding would forget the id while the server still holds
    /// the session, and nothing would stop it before the connection closed. Without the entry,
    /// the binding's last reference drop sends the generation-checked stop, and the next call in
    /// scope declares a fresh session.
    ///
    /// Reads the scope of the task that calls `invalidate`. A task that never re-entered the
    /// scope releases nothing; the scope's declared binding then keeps its id until a rebind
    /// replaces it or the scope ends.
    fn release_declared(undeclared: &SessionBinding) {
        if let Some(context) = crate::caller_operation::current_caller_operation() {
            context.declared_bindings().remove(undeclared);
        }
    }

    /// The partition this session is scoped to, driving the pending resolver on first call.
    pub async fn partition(&self) -> Result<Partition, ProtocolError> {
        self.with_resolved(false, |r| r.binding.partition).await
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
            .with_resolved(false, |r| {
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
        self.attempt(false, |storage, session_id| async move {
            storage.get(session_id, address).await
        })
        .await
    }

    pub async fn get_priority(
        &self,
        address: &Address,
    ) -> Result<(Fragment, Bytes), ProtocolError> {
        self.attempt(false, |storage, session_id| async move {
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
        self.attempt(true, |storage, session_id| {
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
        self.attempt(false, |storage, session_id| async move {
            storage.query(session_id, address).await
        })
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
        self.attempt(heal, |storage, session_id| async move {
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
        self.attempt(true, |storage, session_id| async move {
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
        self.attempt(false, |storage, session_id| async move {
            storage.get_metadata(session_id, address).await
        })
        .await
    }

    pub async fn mutable_load(&self, key: &Hash, key_type: KeyType) -> Result<Hash, ProtocolError> {
        self.attempt(false, |storage, session_id| async move {
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
        self.attempt(false, |storage, session_id| async move {
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
        self.attempt(true, |storage, session_id| {
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
        self.refuse_managed_mutable_key().await?;
        self.attempt(true, |storage, session_id| async move {
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
        self.refuse_managed_mutable_key().await?;
        self.attempt(true, |storage, session_id| async move {
            storage
                .mutable_compare_and_swap_outcome(session_id, key, expected, value, key_type)
                .await
        })
        .await
    }
}

/// `project` applied without a lock to the fields of the session `current` holds resolved, or of
/// its pool's [`member`](SessionPool::member) for `turn` where every session of the pool is
/// resolved. Hands `project` back otherwise.
fn project_current<T, F: FnOnce(&ResolvedFields) -> T>(
    current: &Atomic<Arc<StorageSession>>,
    turn: bool,
    project: F,
) -> Result<T, F> {
    let guard = epoch::pin();
    // SAFETY: published by `resolve_pending` and freed only by `invalidate`, deferred past every
    // reader pinned when it was unlinked.
    let Some(session) = (unsafe { current.load(Ordering::Acquire, &guard).as_ref() }) else {
        return Err(project);
    };
    let member = match &session.inner {
        SessionInner::Pooled(pool) if pool.resolved => pool.member(turn),
        _ => session,
    };
    match &member.inner {
        SessionInner::Resolved(r) => Ok(project(r)),
        _ => Err(project),
    }
}

/// The session a pending session resolves to: the one another call published while this one
/// waited for `resolution`, the failure it holds, or what the resolver answers now, published to
/// `current` on success.
async fn resolve_pending(
    resolver: &PendingResolver,
    current: &Atomic<Arc<StorageSession>>,
    resolution: &TokioMutex<Option<ProtocolError>>,
) -> Result<Arc<StorageSession>, ProtocolError> {
    let mut failure = resolution.lock().await;
    {
        let guard = epoch::pin();
        // SAFETY: as in `project_current`.
        if let Some(session) = unsafe { current.load(Ordering::Acquire, &guard).as_ref() } {
            return Ok(session.clone());
        }
    }
    if let Some(err) = failure.as_ref() {
        return Err(err.clone());
    }
    match resolver().await {
        Ok(session) => {
            current.store(Owned::new(session.clone()), Ordering::Release);
            Ok(session)
        }
        Err(err) => {
            if !err.is_slow_down() {
                *failure = Some(err.clone());
            }
            Err(err)
        }
    }
}

impl Drop for StorageSession {
    fn drop(&mut self) {
        // Only the Resolved variant owns a server-side session directly. A
        // Pooled variant's sessions and a resolved Pending variant's session
        // each stop their own when their last reference drops.
        match &mut self.inner {
            SessionInner::Resolved(r) => {
                let storage = r.binding.storage.clone();
                let bound = r.binding.bound();
                // Stopping a session is still putting its id on the wire, so it obeys the same
                // rule as every other command: only on the connection that issued it. A session
                // from a replaced connection needs no stop (the server drops the whole session
                // map with the connection), and sending one would be the exact defect CR-026
                // removes.
                //
                // The check has to be inside the task, not here. `Drop` only decides to try; the
                // connection can be replaced before the task runs, `session_stop` carries no
                // generation guard of its own, and its result is discarded, so a stale id sent
                // from here would go out unnoticed by anything.
                if let Some(generation) = bound.generation {
                    lore_base::lore_spawn_net!(async move {
                        if storage.connection_generation() == generation {
                            let _ = storage.session_stop(bound.id).await;
                        }
                    });
                }
            }
            SessionInner::Pending { current, .. } => {
                // SAFETY: `drop` holds the only reference, so no reader is pinned on it.
                drop(unsafe { std::mem::take(current).try_into_owned() });
            }
            SessionInner::Pooled(_) => {}
        }
    }
}

/// A pool of `StorageSession`s for a single `(partition, correlation_id)`
/// tuple. Holds one session per underlying `Storage` connection, plus a
/// round-robin counter: a [`StorageSession::pooled`] session runs each operation
/// on the next session, and [`pick`](Self::pick) hands out the next one for a
/// single unit of work.
pub struct SessionPool {
    correlation_id: Arc<str>,
    sessions: Vec<Arc<StorageSession>>,
    /// Whether every session is resolved, so an operation reads its turn's fields without
    /// awaiting a resolution.
    resolved: bool,
    next: AtomicUsize,
    /// Set when a session over this pool is invalidated: its session ids may be unknown to the
    /// server, so no resolution hands the pool out again, though its holders keep it.
    stale: AtomicBool,
}

impl SessionPool {
    /// A pool over `sessions`, started for `correlation_id` and taken in turn.
    ///
    /// The connector builds one session per underlying `Storage` connection, so taking them in
    /// turn spreads a command's operations over every connection the connect phase established.
    pub fn new(correlation_id: Arc<str>, sessions: Vec<Arc<StorageSession>>) -> Self {
        Self {
            correlation_id,
            resolved: sessions
                .iter()
                .all(|session| matches!(session.inner, SessionInner::Resolved(_))),
            sessions,
            next: AtomicUsize::new(0),
            stale: AtomicBool::new(false),
        }
    }

    /// Whether a session over this pool was invalidated since it was built.
    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }

    pub(crate) fn mark_stale(&self) {
        self.stale.store(true, Ordering::Relaxed);
    }

    /// Whether a call under `correlation_id` may take sessions from this pool: it was started
    /// for that correlation id and is not stale.
    pub fn serves(&self, correlation_id: &str) -> bool {
        *self.correlation_id == *correlation_id && !self.is_stale()
    }

    /// Whether the connection this pool's first session runs on is marked stale, as the transport
    /// marks one it has given up on. A connector starts every session of a pool on one connection.
    pub fn connection_is_stale(&self) -> bool {
        matches!(
            self.sessions.first().map(|session| &session.inner),
            Some(SessionInner::Resolved(resolved))
                if resolved.connection.stale.load(Ordering::Relaxed)
        )
    }

    /// Returns the next session in the pool via round-robin.
    ///
    /// Every call advances the cursor, so only a caller that is going to use the
    /// session picks. One that discards what it picked makes every other caller
    /// stride over the connections rather than visit each in turn.
    pub fn pick(&self) -> Arc<StorageSession> {
        self.sessions[self.next_index()].clone()
    }

    /// The session an operation runs on: the next via round-robin when `turn`, and the first
    /// otherwise.
    fn member(&self, turn: bool) -> &StorageSession {
        if turn {
            &self.sessions[self.next_index()]
        } else {
            &self.sessions[0]
        }
    }

    fn next_index(&self) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed) % self.sessions.len()
    }
}

/// The session pool an owner holds for each partition it uses: the one started for the latest
/// correlation id to reach that partition. A pool replaced or dropped here stops its sessions once
/// no call still holds it.
#[derive(Default)]
pub struct PartitionSessions {
    pools: dashmap::DashMap<Partition, Arc<SessionPool>>,
}

impl PartitionSessions {
    /// The pool held for `partition`, if it [`serves`](SessionPool::serves) `correlation_id`.
    pub fn get(&self, partition: Partition, correlation_id: &str) -> Option<Arc<SessionPool>> {
        self.pools
            .get(&partition)
            .filter(|pool| pool.serves(correlation_id))
            .map(|pool| pool.clone())
    }

    /// Holds `pool` for `partition` in place of the one held before.
    pub fn hold(&self, partition: Partition, pool: Arc<SessionPool>) {
        self.pools.insert(partition, pool);
    }

    /// FORK-LOCAL (Tideshift, WP-124): drops the pool held for `partition` only if it serves
    /// `correlation_id`, so a caller that finished its unit of work frees its server sessions (and
    /// their admission slots) at once rather than when the next correlation id replaces the pool. A
    /// pool another correlation id already replaced is left alone. Its sessions stop once no call
    /// still holds it.
    pub fn release(&self, partition: Partition, correlation_id: &str) {
        self.pools
            .remove_if(&partition, |_, pool| pool.serves(correlation_id));
    }

    /// Drops every pool held.
    pub fn clear(&self) {
        self.pools.clear();
    }

    /// Marks every pool held stale, so no resolution hands it out again while another holder
    /// keeps it, and drops it.
    pub(crate) fn invalidate(&self) {
        for pool in self.pools.iter() {
            pool.mark_stale();
        }
        self.pools.clear();
    }
}

/// Owns a pool of Storage connections and manages session lifecycle with
/// deduplication, round-robin connection assignment, and automatic cleanup.
///
/// Each partition maps to the latest `SessionPool` started for it, containing one
/// `StorageSession` per underlying `Storage` connection. Operations on a
/// returned session round-robin across the pool so a single command spreads
/// load over every connection set up in the connect phase.
pub struct StorageConnector {
    connections: Vec<Arc<dyn Storage>>,
    counter: AtomicUsize,
    pools: dashmap::DashMap<Partition, Weak<SessionPool>>,
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
    #[lore_macro::test_pub]
    pub(crate) fn mark_partition_authorized(&self, partition: Partition) {
        self.authorized_partitions.insert(partition);
        self.refused_partitions.remove(&partition);
    }

    /// Get or create the `SessionPool` for the given partition and correlation ID. The
    /// connector holds each pool weakly, the latest per partition, so the pool lives as long as
    /// a caller holds it. A stale pool is not handed out again.
    ///
    /// Nothing is taken from the pool here. Taking a session advances the pool's
    /// round-robin cursor, so a caller that only wanted the pool would leave every
    /// other caller striding over the connections instead of visiting each in turn.
    ///
    /// On a miss, one server-side session is started per underlying connection, in
    /// parallel. The first writer wins the partition's entry, vacant, expired, stale or for
    /// another correlation id alike. Each started session is held as a [`StorageSession`], which
    /// stops it when its last reference drops, on the connection generation that issued it: a
    /// losing racer's as its pool drops, and a failed or dropped start's as each start task ends,
    /// which it runs to even when this future is dropped.
    pub async fn session_pool(
        &self,
        partition: Partition,
        correlation_id: &str,
        connection: Arc<Connection>,
    ) -> Result<Arc<SessionPool>, ProtocolError> {
        // Fast path: live pool exists.
        if let Some(pool) = self
            .pools
            .get(&partition)
            .and_then(|entry| entry.upgrade())
            .filter(|pool| pool.serves(correlation_id))
        {
            return Ok(pool);
        }

        // Slow path: start one session per connection in parallel. No lock held.
        let correlation: Arc<str> = Arc::from(correlation_id);
        let mut tasks = DetachingJoinSet::default();
        for storage in self.connections.iter().cloned() {
            let correlation = correlation.clone();
            let connection = connection.clone();
            // FORK-LOCAL (Tideshift, WP-124): a start that reconnects keeps the managed deadline of
            // the caller that spawned it.
            lore_spawn_net!(
                tasks,
                crate::caller_operation::carry_managed_wait_scope(async move {
                    // FORK-LOCAL (Tideshift, WP-124): the generation the start reports, never a
                    // sample taken before it. A start that reconnects would otherwise bind the id
                    // to the dead connection, so the first use rebinds and the first session is
                    // never stopped.
                    let (session_id, generation) =
                        storage.session_start_bound(partition, &correlation).await?;
                    Ok::<_, ProtocolError>(StorageSession::resolved(
                        storage,
                        connection,
                        session_id,
                        generation,
                        partition,
                        correlation,
                    ))
                })
            );
        }
        let mut sessions = Vec::with_capacity(tasks.len());
        while let Some(started) = tasks.join_next().await {
            sessions.push(Arc::new(started.internal("session_start task join")??));
        }

        // session_start succeeded on every connection in parallel above; the partition is now
        // in `authorized_repos` of every server-side `SessionMap` for the pool. Even on the
        // race-loser path below (which stops these sessions to defer to the winner), the
        // server keeps the partition in `authorized_repos` permanently — `session_stop` only
        // touches the per-session map, not the authorization set. So this is the right point
        // to mark the partition as authorized for any future fast-path query.
        self.mark_partition_authorized(partition);

        let pool = Arc::new(SessionPool::new(correlation, sessions));

        #[allow(clippy::disallowed_methods)]
        // Synchronous entry check; no await while lock is held.
        let winner = match self.pools.entry(partition) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if let Some(alive) = entry
                    .get()
                    .upgrade()
                    .filter(|alive| alive.serves(correlation_id))
                {
                    alive
                } else {
                    entry.insert(Arc::downgrade(&pool));
                    pool
                }
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::downgrade(&pool));
                pool
            }
        };
        Ok(winner)
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

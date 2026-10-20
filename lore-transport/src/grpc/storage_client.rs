// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use dashmap::DashMap;
use lore_base::error::Disconnected;
use lore_base::error::NotFound;
use lore_base::error::SlowDown;
use lore_base::lore_debug;
use lore_base::lore_error;
use lore_base::lore_spawn_net;
use lore_base::lore_warn;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::HealResult;
use lore_base::types::KeyType;
use lore_base::types::Partition;
use lore_base::types::VerifyResult;
use lore_error_set::prelude::*;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_client::StorageServiceClient;
use prost::Message;
use tokio::sync::Notify;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tonic::metadata::MetadataValue;

use super::CORRELATION_ID_HEADER;
use super::PARTITION_ID_KEY;
use super::REPOSITORY_ID_KEY;
use crate::error::ProtocolError;
use crate::outcome::AttemptId;
use crate::outcome::GrpcRpc;
use crate::outcome::grpc_replay_class;
use crate::outcome::outcome_unknown;
use crate::replay::ReplayClass;

/// Translate a response's in-band `status` into a [`ProtocolError`], or `None` when the item
/// succeeded. Absence means `OK`, so a peer that predates the field reads as success.
///
/// **This is a server verdict wearing a transport type, and the difference matters here.**
/// [`ProtocolError::from`] reads a `Cancelled`, `DeadlineExceeded`, or sourced `Internal` as
/// proof that the *call* failed and the answer may be lost, because that is what those codes
/// mean when `tonic` raises them. An in-band item status means the opposite: the server
/// answered, per item, and named this code itself.
///
/// The mislabel is inert today and only by accident of wiring — every verb reaching here goes
/// through [`super::GRPCStorage::with_reconnect_dispatch_aware`], which branches on
/// `Disconnected` alone, and [`StreamCache::request`] filters on `is_disconnected` alone, so a
/// marked item status is returned to the caller exactly as it was before the marker existed.
/// Moving any stream verb onto `with_reconnect_classified` would arm it into a false unknown
/// outcome. There is a standing test pinning the inertness; the real fix, if a verb ever moves,
/// is to map the item's code here without going through the transport classifier.
#[lore_macro::test_pub]
fn item_status_error(
    status: Option<&lore_proto::lore::model::v1::ItemStatus>,
) -> Option<ProtocolError> {
    let status = status?;
    let code = tonic::Code::from_i32(status.code as i32);
    if code == tonic::Code::Ok && !status.has_outcome_unknown() {
        return None;
    }
    Some(ProtocolError::from(tonic::Status::from(status)))
}

const STREAM_WRITE_BUFFER_SIZE: usize = 32 * 1024;
const INFLIGHT_COMMAND_LIMIT: usize = 10000;

/// Bound on stream-level reissues before handing off to connection-level reconnect.
///
/// Reissuing here only covers a stream dying on an otherwise healthy channel, which needs no
/// backoff. Anything the channel itself is responsible for belongs to
/// `GRPCConnection::reconnect`, which owns the epoch, single-flight guard and backoff — so
/// this only has to be large enough to absorb a server resetting individual streams.
const MAX_STREAM_REISSUES: usize = 8;

/// Session context for gRPC metadata injection. Cached at `session_start` time.
#[derive(Clone)]
pub struct GrpcSessionContext {
    pub partition: Partition,
    pub correlation_id: String,
    pub auth_token: String,
}

/// Which streaming RPC a cached stream belongs to.
///
/// Part of the stream-cache key so rotating a dead Get stream leaves the session's
/// `GetMetadata`, Put and Copy streams untouched — they're independent RPCs and one dying
/// says nothing about the others.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Verb {
    Get,
    GetMetadata,
    Put,
    Copy,
    GetResolved,
    PutResolved,
}

impl Verb {
    fn label(self) -> &'static str {
        match self {
            Verb::Get => "get",
            Verb::GetMetadata => "get_metadata",
            Verb::Put => "put",
            Verb::Copy => "copy",
            Verb::GetResolved => "get_resolved",
            Verb::PutResolved => "put_resolved",
        }
    }
}

type StreamItem<K, S> = (K, oneshot::Sender<Result<S, ProtocolError>>);

/// How long a stream may hold an unanswered request without making any progress before the
/// request gives up on it, unless `LORE_GRPC_STREAM_IDLE_TIMEOUT` (seconds) says otherwise.
///
/// Progress, not age: a request taken off the stream by the transport and any response at all
/// both count, so a long upload that keeps moving is never cut. Fragments are at most
/// `FRAGMENT_SIZE_THRESHOLD`, so one request never needs anything like this long on its own.
const STREAM_IDLE_TIMEOUT_SECS: u64 = 60;

/// How long a request whose stream has closed waits for that stream's own drain to answer it.
/// The drain runs right after the close, so this only bounds a drain that never comes.
const CLOSED_STREAM_GRACE: Duration = Duration::from_secs(1);

fn stream_idle_timeout() -> Duration {
    let secs = std::env::var("LORE_GRPC_STREAM_IDLE_TIMEOUT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(STREAM_IDLE_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// What a stream's request generator, its reader task and its waiters share.
///
/// Kept apart from [`StreamState`] so the task and the generator never hold the request
/// sender: the cache dropping its handle has to end the generator, and through it the RPC.
struct StreamLife {
    /// Lets `StreamCache::request` tell a stream that died mid-flight from one that never
    /// established, since the sender is handed out before the RPC is attempted. By the time
    /// a request observes a failure the flag has settled.
    opened: AtomicBool,
    /// The open was refused by the server's caller-admission layer. The admission contract
    /// (`grpc-caller-capability-admission-v1`, "Admission and refusal") places that refusal
    /// before the body is polled, with no request-stream item effect. So nothing sent on this
    /// stream was applied, and every request on it fails with this refusal rather than an
    /// unknown outcome. Kept apart from `terminal`, which an idle expiry may have set first.
    refusal: OnceLock<ProtocolError>,
    /// Set when a waiter closed the stream for want of progress.
    idle_expired: AtomicBool,
    /// Cancelled when the reader task exits, or when a waiter gives up on a stream that has
    /// stopped making progress. The task, the generator and every waiter stop on it, so no
    /// request can be taken onto a stream nobody will answer.
    closed: CancellationToken,
    /// What the stream ended with, for whoever fails a request after `closed`.
    terminal: OnceLock<ProtocolError>,
    started: Instant,
    /// Milliseconds after `started` of the stream's last progress.
    progress: AtomicU64,
    idle: Duration,
}

impl StreamLife {
    fn new(idle: Duration) -> Arc<Self> {
        Arc::new(Self {
            opened: AtomicBool::new(false),
            refusal: OnceLock::new(),
            idle_expired: AtomicBool::new(false),
            closed: CancellationToken::new(),
            terminal: OnceLock::new(),
            started: Instant::now(),
            progress: AtomicU64::new(0),
            idle,
        })
    }

    fn elapsed_millis(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn mark_progress(&self) {
        self.progress
            .fetch_max(self.elapsed_millis(), Ordering::Relaxed);
    }

    /// The terminal is set before the token is cancelled, so anything woken by the token
    /// reads the reason the stream ended rather than a default.
    fn close(&self, terminal: ProtocolError) {
        let _ = self.terminal.set(terminal);
        self.closed.cancel();
    }

    fn terminal(&self) -> ProtocolError {
        self.terminal
            .get()
            .cloned()
            .unwrap_or_else(|| ProtocolError::from(Disconnected))
    }

    fn refusal(&self) -> Option<ProtocolError> {
        self.refusal.get().cloned()
    }

    /// Classify a failed open. Only the exact admission marker proves the server read nothing.
    fn open_failure(&self, verb: Verb, status: tonic::Status) -> ProtocolError {
        lore_debug!("{} request failed: {status}", verb.label());
        let refused = crate::error::is_unsupported_client_status(&status);
        let error = ProtocolError::from(status);
        if refused {
            let _ = self.refusal.set(error.clone());
        }
        error
    }

    /// Wait for `answer` while the stream keeps making progress.
    ///
    /// A stream with nothing moving for `idle` is closed here, which ends its task and fails
    /// everything on it as a stream death. `StreamCache::request` then hands a read back for a
    /// reconnect and reports a dispatched mutation as an unknown outcome. `None` means no
    /// answer arrived.
    async fn await_answer<S>(
        &self,
        verb: Verb,
        mut answer: oneshot::Receiver<Result<S, ProtocolError>>,
    ) -> Option<Result<S, ProtocolError>> {
        let since = self.elapsed_millis();
        loop {
            let last = self.progress.load(Ordering::Relaxed).max(since);
            let deadline = self.started + Duration::from_millis(last) + self.idle;
            tokio::select! {
                biased;
                result = &mut answer => {
                    if result.is_err() {
                        self.settle().await;
                    }
                    return result.ok();
                }
                () = self.closed.cancelled() => break,
                () = tokio::time::sleep_until(deadline) => {
                    if self.progress.load(Ordering::Relaxed) > last {
                        continue;
                    }
                    let message = format!(
                        "{} stream made no progress for {} s; closing it",
                        verb.label(),
                        self.idle.as_secs()
                    );
                    lore_warn!("{message}");
                    let mut err = ProtocolError::from(Disconnected);
                    err.push_trace(lore_error_set::Location::with_context(
                        file!(),
                        line!(),
                        column!(),
                        Arc::from(message),
                    ));
                    self.idle_expired.store(true, Ordering::SeqCst);
                    self.close(err);
                    break;
                }
            }
        }
        tokio::time::timeout(CLOSED_STREAM_GRACE, answer)
            .await
            .ok()
            .and_then(Result::ok)
    }

    /// Wait briefly for the task to close the stream.
    ///
    /// A request that lost its channel before the task finished, because the transport dropped
    /// the request body first, cannot yet tell a refused open from a dead stream. The task
    /// records which it was before it closes.
    async fn settle(&self) {
        let _ = tokio::time::timeout(CLOSED_STREAM_GRACE, self.closed.cancelled()).await;
    }
}

/// A live stream's request channel plus the state it shares with its task.
struct StreamState<K, S> {
    sender: mpsc::Sender<StreamItem<K, S>>,
    life: Arc<StreamLife>,
}

impl<K, S> StreamState<K, S> {
    fn new(sender: mpsc::Sender<StreamItem<K, S>>, idle: Duration) -> Arc<Self> {
        Arc::new(Self {
            sender,
            life: StreamLife::new(idle),
        })
    }
}

type StreamHandle<K, S> = Arc<StreamState<K, S>>;

/// Keyed by the address the server echoes back. A `Vec` per key so concurrent requests for
/// the same address coalesce onto one round trip and all get woken by its response.
type Inflight<S> = DashMap<Address, Vec<oneshot::Sender<Result<S, ProtocolError>>>>;

/// Returns true for the first waiter on `key`, meaning the caller should put the request on
/// the wire; later waiters ride along on that one round trip.
fn register<S>(
    inflight: &Inflight<S>,
    key: Address,
    sender: oneshot::Sender<Result<S, ProtocolError>>,
) -> bool {
    let mut first = false;
    #[allow(clippy::disallowed_methods)] // Brief write lock; no await while held.
    inflight
        .entry(key)
        .or_insert_with(|| {
            first = true;
            Vec::new()
        })
        .push(sender);
    first
}

/// Answering explicitly rather than letting the senders drop: a dropped sender reaches the
/// caller as an opaque `RecvError` that the storage layer can only classify as an internal
/// fault, whereas a real error tells it whether a retry is worth attempting.
fn fail_inflight<S>(inflight: &Inflight<S>, verb: Verb, err: &ProtocolError) {
    let mut failed = 0usize;
    inflight.retain(|_, senders| {
        for sender in senders.drain(..) {
            failed += 1;
            let _ = sender.send(Err(err.clone()));
        }
        false
    });
    if failed > 0 {
        lore_debug!(
            "{} stream ended with {failed} request(s) outstanding: {err}",
            verb.label()
        );
    }
}

/// Lets one generic pump serve every streaming verb: the only per-verb differences are which
/// field carries the routing address and where an in-band per-item failure lives.
trait StreamResponse: Sized {
    type Success: Clone + Send + 'static;

    /// The key this response's request was registered under.
    fn key(&self) -> Option<Address>;

    /// Preserves the server's status code, which callers pattern-match on — a remote
    /// `NotFound` is a routine answer on the metadata path rather than a fault.
    ///
    /// An absent status is success: the field postdates the original response, so a peer
    /// without it signals a per-item failure by ending the stream instead.
    fn into_result(self) -> Result<Self::Success, ProtocolError>;
}

impl StreamResponse for storage_v1::GetResponse {
    type Success = (model_v1::Fragment, Bytes);

    fn key(&self) -> Option<Address> {
        self.address.as_ref().map(Address::from)
    }

    fn into_result(self) -> Result<Self::Success, ProtocolError> {
        if let Some(status) = self.status.as_ref().filter(|status| !status.is_ok()) {
            return Err(ProtocolError::from(tonic::Status::from(status)));
        }
        let fragment = self
            .fragment
            .ok_or_else(|| ProtocolError::internal("get: successful response has no fragment"))?;
        Ok((fragment, self.payload))
    }
}

impl StreamResponse for storage_v1::PutResponse {
    type Success = ();

    fn key(&self) -> Option<Address> {
        self.address.as_ref().map(Address::from)
    }

    fn into_result(self) -> Result<Self::Success, ProtocolError> {
        match self.status.as_ref().filter(|status| !status.is_ok()) {
            Some(status) => Err(ProtocolError::from(tonic::Status::from(status))),
            None => Ok(()),
        }
    }
}

impl StreamResponse for storage_v1::CopyResponse {
    type Success = ();

    fn key(&self) -> Option<Address> {
        self.source_address.as_ref().map(Address::from)
    }

    fn into_result(self) -> Result<Self::Success, ProtocolError> {
        match self.status.as_ref().filter(|status| !status.is_ok()) {
            Some(status) => Err(ProtocolError::from(tonic::Status::from(status))),
            None => Ok(()),
        }
    }
}

/// A per-item failure arrives in-band on an `Ok` message and costs only that request. An
/// `Err` is terminal by construction — tonic surfaces a stream status once and then reports
/// the stream exhausted — so it ends the loop and everything still outstanding fails.
///
/// Those outstanding requests are failed as `Disconnected` whatever the terminal code says,
/// because a stream status describes the stream rather than any one request on it. That is
/// also what lets `StreamCache::request` replay them: the ordinary ways a connection dies
/// arrive as `Internal` or `Cancelled` (`Status::from_h2_error`), neither of which a caller
/// would otherwise retry. The real status is kept on the error's trace.
///
/// Returns the error everything still outstanding fails with; [`run_stream`] does the failing.
async fn pump_responses<R>(
    mut stream: tonic::Streaming<R>,
    inflight: &Inflight<R::Success>,
    life: &StreamLife,
    verb: Verb,
) -> ProtocolError
where
    R: StreamResponse,
{
    while let Some(message) = stream.next().await {
        life.mark_progress();
        let response = match message {
            Ok(response) => response,
            Err(status) => {
                let mut err = ProtocolError::from(Disconnected);
                err.push_trace(lore_error_set::Location::with_context(
                    file!(),
                    line!(),
                    column!(),
                    Arc::from(format!("{} stream terminated: {status}", verb.label())),
                ));
                return err;
            }
        };

        let Some(address) = response.key() else {
            lore_error!("{} response missing address", verb.label());
            continue;
        };
        let Some((_, senders)) = inflight.remove(&address) else {
            lore_error!(
                "{} received unexpected result for address {address}",
                verb.label()
            );
            continue;
        };

        let result = response.into_result();
        let mut senders = senders;
        if let Some(last) = senders.pop() {
            for sender in senders {
                let _ = sender.send(result.clone());
            }
            let _ = last.send(result);
        }
    }

    ProtocolError::from(Disconnected)
}

/// Run an address-keyed stream's RPC to its end, then close the stream and fail whatever it
/// left unanswered.
///
/// The close comes before the drain. A request the generator registers after the drain then
/// finds the stream closed and settles itself, so none is left waiting on a task that is gone.
/// A waiter closing the stream for want of progress ends the RPC here as well.
async fn run_stream<R>(
    life: Arc<StreamLife>,
    inflight: Arc<Inflight<R::Success>>,
    verb: Verb,
    open: impl Future<Output = Result<tonic::Response<tonic::Streaming<R>>, tonic::Status>>,
) where
    R: StreamResponse,
{
    let terminal = tokio::select! {
        biased;
        () = life.closed.cancelled() => life.terminal(),
        terminal = async {
            match open.await {
                Ok(response) => {
                    life.opened.store(true, Ordering::SeqCst);
                    life.mark_progress();
                    pump_responses(response.into_inner(), &inflight, &life, verb).await
                }
                // A failure to open keeps its real status rather than becoming a disconnect:
                // it applies equally to everything queued behind it, and an `Unauthenticated`
                // or an admission refusal should reach the caller instead of being replayed.
                Err(status) => life.open_failure(verb, status),
            }
        } => terminal,
    };
    life.close(terminal.clone());
    fail_inflight(&inflight, verb, &life.terminal());
}

/// The request side of an address-keyed stream.
///
/// Ends as soon as the stream closes. A front can keep the request body open after the
/// response has ended, and a generator that kept reading would register requests no task will
/// ever answer. Requests still queued when it ends fail with the stream's terminal error.
fn request_stream<K, S, T>(
    mut rx: mpsc::Receiver<StreamItem<K, S>>,
    inflight: Arc<Inflight<S>>,
    life: Arc<StreamLife>,
    verb: Verb,
    route: fn(K) -> Option<(Address, T)>,
) -> impl tokio_stream::Stream<Item = T> + Send + 'static
where
    K: Send + 'static,
    S: Send + 'static,
    T: Send + 'static,
{
    async_stream::stream! {
        loop {
            let item = tokio::select! {
                biased;
                () = life.closed.cancelled() => None,
                item = rx.recv() => item,
            };
            let Some((request, sender)) = item else {
                break;
            };
            let Some((address, message)) = route(request) else {
                lore_debug!("Missing address in {} request", verb.label());
                let _ = sender.send(Err(ProtocolError::internal(format!(
                    "{}: missing address",
                    verb.label()
                ))));
                continue;
            };
            if register(&inflight, address, sender) {
                life.mark_progress();
                yield message;
                life.mark_progress();
            }
            // The task closes before it drains, and the drain takes the shard lock this register
            // took, so either the drain saw this request or this check sees the close. The check
            // runs after the yield: if the transport drops the body at the yield instead, the
            // request stays in the map the task drains, and its waiter is bounded by that drain
            // or by the idle wait.
            if life.closed.is_cancelled() {
                fail_inflight(&inflight, verb, &life.terminal());
                break;
            }
        }
        rx.close();
        let mut queued = Vec::new();
        while let Ok((_, sender)) = rx.try_recv() {
            queued.push(sender);
        }
        if !queued.is_empty() {
            let terminal = life.terminal();
            for sender in queued {
                let _ = sender.send(Err(terminal.clone()));
            }
        }
    }
}

/// Requests on a resolved stream, keyed by the `request_id` its response echoes.
type Pending<S> = DashMap<u64, oneshot::Sender<Result<S, ProtocolError>>>;

fn drain_pending<S>(pending: &Pending<S>, err: &ProtocolError) {
    let ids: Vec<u64> = pending.iter().map(|entry| *entry.key()).collect();
    for id in ids {
        if let Some((_, sender)) = pending.remove(&id) {
            let _ = sender.send(Err(err.clone()));
        }
    }
}

/// [`request_stream`] for the resolved verbs, which correlate by `request_id`.
fn resolved_request_stream<Q, S>(
    mut rx: mpsc::Receiver<StreamItem<Q, S>>,
    pending: Arc<Pending<S>>,
    life: Arc<StreamLife>,
    request_id: fn(&Q) -> u64,
) -> impl tokio_stream::Stream<Item = Q> + Send + 'static
where
    Q: Send + 'static,
    S: Send + 'static,
{
    async_stream::stream! {
        loop {
            let item = tokio::select! {
                biased;
                () = life.closed.cancelled() => None,
                item = rx.recv() => item,
            };
            let Some((request, sender)) = item else {
                break;
            };
            pending.insert(request_id(&request), sender);
            life.mark_progress();
            yield request;
            life.mark_progress();
            if life.closed.is_cancelled() {
                drain_pending(&pending, &life.terminal());
                break;
            }
        }
        rx.close();
        let mut queued = Vec::new();
        while let Ok((_, sender)) = rx.try_recv() {
            queued.push(sender);
        }
        if !queued.is_empty() {
            let terminal = life.terminal();
            for sender in queued {
                let _ = sender.send(Err(terminal.clone()));
            }
        }
    }
}

/// Reader for a resolved stream, correlating by `request_id`.
///
/// `pump_responses` keys on the address the server echoes back, which the resolved verbs
/// cannot use: the address is what the request is asking for, not what identifies it. The
/// close and the drain on exit follow the same contract as [`run_stream`]. A stream status
/// fails what is outstanding with that status, and a clean end with an internal error, as
/// these verbs always have.
async fn run_resolved_stream<R>(
    life: Arc<StreamLife>,
    pending: Arc<Pending<Arc<R>>>,
    verb: Verb,
    open: impl Future<Output = Result<tonic::Response<tonic::Streaming<R>>, tonic::Status>>,
    request_id: fn(&R) -> u64,
    status: fn(&R) -> Option<&lore_proto::lore::model::v1::ItemStatus>,
) where
    R: Send + Sync + 'static,
{
    let terminal = tokio::select! {
        biased;
        () = life.closed.cancelled() => life.terminal(),
        terminal = async {
            let mut responses = match open.await {
                Ok(response) => {
                    life.opened.store(true, Ordering::SeqCst);
                    life.mark_progress();
                    response.into_inner()
                }
                Err(status) => return life.open_failure(verb, status),
            };
            loop {
                match responses.next().await {
                    Some(Ok(response)) => {
                        life.mark_progress();
                        let id = request_id(&response);
                        let Some((_, sender)) = pending.remove(&id) else {
                            lore_error!("{} unexpected result for request_id {id}", verb.label());
                            continue;
                        };
                        let result = match item_status_error(status(&response)) {
                            Some(err) => Err(err),
                            None => Ok(Arc::new(response)),
                        };
                        let _ = sender.send(result);
                    }
                    Some(Err(status)) => return ProtocolError::from(status),
                    None => {
                        return ProtocolError::internal(format!(
                            "{}: stream closed before responding",
                            verb.label()
                        ));
                    }
                }
            }
        } => terminal,
    };
    life.close(terminal);
    drain_pending(&pending, &life.terminal());
}

/// The hot path is a single `DashMap` read plus an `Arc` clone — no write lock and no second
/// level of indirection. A dead stream announces itself through its closed token or by failing
/// the send, and a waiter's idle timer is the only liveness check. The reader tasks never touch
/// this map: the request path is its only mutator, which is what makes rotation race-free.
struct StreamCache<K, S> {
    streams: DashMap<(u32, Verb), StreamHandle<K, S>>,
}

impl<K: Clone, S> StreamCache<K, S> {
    fn new() -> Self {
        Self {
            streams: DashMap::new(),
        }
    }

    /// Dropping the last sender ends the request generator, which ends the RPC and its
    /// reader task.
    fn remove(&self, session_id: u32, verb: Verb) {
        self.streams.remove(&(session_id, verb));
    }

    /// Drop a handle whose stream never opened, so the next request establishes a fresh one
    /// instead of inheriting a known-dead entry and giving up on it again. Pointer identity keeps
    /// a replacement installed by a concurrent caller safe.
    fn discard(&self, key: (u32, Verb), failed: &StreamHandle<K, S>) {
        #[allow(clippy::disallowed_methods)] // Brief write lock; no await while held.
        self.streams
            .remove_if(&key, |_, current| Arc::ptr_eq(current, failed));
    }

    /// `failed` is the handle whose send just failed. Pointer identity against the current
    /// entry is the single-flight check, and doing it under the shard lock makes it exact: of N
    /// callers that all failed on the same dead handle, the first to take the lock spawns and
    /// the rest adopt its replacement, so `spawn` runs once per stream death, not per caller.
    fn rotate(
        &self,
        key: (u32, Verb),
        failed: Option<&StreamHandle<K, S>>,
        spawn: impl FnOnce() -> StreamHandle<K, S>,
    ) -> StreamHandle<K, S> {
        use dashmap::mapref::entry::Entry;

        #[allow(clippy::disallowed_methods)] // Cold path; `spawn` does not await.
        match self.streams.entry(key) {
            Entry::Occupied(mut occupied) => {
                let superseded = match failed {
                    Some(failed) => !Arc::ptr_eq(occupied.get(), failed),
                    // Nothing of ours to compare against, so any cached handle wins.
                    None => true,
                };
                if superseded {
                    return occupied.get().clone();
                }
                let fresh = spawn();
                occupied.insert(fresh.clone());
                fresh
            }
            Entry::Vacant(vacant) => {
                let fresh = spawn();
                vacant.insert(fresh.clone());
                fresh
            }
        }
    }

    /// Reconnect and reissue on a stream death, the way the QUIC client's
    /// `send_with_reconnect` does, so a caller never sees one.
    ///
    /// A death shows up these ways, all handled here: the stream is already closed when the
    /// request finds it, reserving a place in the queue fails because the receiver is already
    /// gone (nothing has been sent in either case, so nothing is lost), the reader answers with
    /// a disconnect, it exits without answering at all, or nothing on the stream moves for the
    /// idle bound and the wait closes it. Anything else the reader answers is the server's
    /// verdict on this request and goes straight back — matching QUIC, where `NotFound`,
    /// `SlowDown` and `NotAuthorized` bubble rather than provoking a reconnect. A refused open
    /// is final for every request on that stream; see [`StreamLife::refusal`].
    ///
    /// Reissuing continues while the remote is still reachable. A replacement stream that will
    /// not open means the channel is suspect rather than the stream, so it hands straight back
    /// as `Disconnected` for `GRPCStorage` to drive `GRPCConnection::reconnect` — the same
    /// division QUIC draws between reissuing a command and reconnecting the socket. The dead
    /// handle is discarded on the way out, so the request that follows a successful reconnect
    /// establishes a stream on the new channel rather than inheriting this one.
    /// `rpc` is what makes the mutable half of this loop safe (WP-120 Phase 3). A read reissues
    /// exactly as it always did. A mutation reissues only on the one failure that carries
    /// positive proof it was never dispatched — the send whose payload came straight back
    /// because the stream task was already gone. A mutation that reached the task and got no
    /// answer is [`ProtocolError::OutcomeUnknown`] and is not sent again.
    async fn request(
        &self,
        rpc: GrpcRpc,
        key: (u32, Verb),
        payload: K,
        spawn: impl Fn() -> StreamHandle<K, S>,
    ) -> Result<S, ProtocolError> {
        let mut failed: Option<StreamHandle<K, S>> = None;
        let replay = grpc_replay_class(rpc);
        let attempt = AttemptId::new();

        for _ in 0..MAX_STREAM_REISSUES {
            let handle = match (&failed, self.streams.get(&key)) {
                (None, Some(entry)) => entry.value().clone(),
                (_, entry) => {
                    // `rotate` write-locks the shard this read guard holds, so keeping the
                    // guard here self-deadlocks.
                    drop(entry);
                    self.rotate(key, failed.as_ref(), &spawn)
                }
            };

            // `Err` here is the sole non-dispatch proof this transport has: the channel refused a
            // slot because the receiving task is gone, so nothing was written.
            //
            // `Ok` is weaker than it looks, and the name below is chosen to be the honest
            // reading of it: the payload is in the task's buffer, not necessarily on the wire.
            // That is the right side to be imprecise on. Treating a buffered request as
            // possibly-dispatched costs an unknown outcome for a mutation that may never have
            // left; treating it as certainly-undispatched would license sending a mutation
            // twice. Only the first of those is recoverable by reading authoritative state.
            //
            // The slot is reserved before the payload is cloned (upstream cd2613e9), so a
            // waiting send holds no copy of it.
            //
            // A closed stream takes nothing. Its generator has stopped reading, so a send would
            // only park the request until a drain answered it, and would count as a dispatch
            // that never happened.
            let mut dispatched = false;
            let answer = if handle.life.closed.is_cancelled() {
                None
            } else if let Ok(permit) = handle.sender.reserve().await {
                let (tx, rx) = oneshot::channel();
                permit.send((payload.clone(), tx));
                dispatched = true;
                handle.life.await_answer(key.1, rx).await
            } else {
                handle.life.settle().await;
                None
            };
            let server_verdict =
                answer.filter(|answer| !matches!(answer, Err(err) if err.is_disconnected()));
            if let Some(result) = server_verdict {
                return result;
            }

            // Checked before the replay class: the admission layer refused the stream before
            // the handler read any request on it, so this request is known not applied, whether
            // or not it was queued. The refusal is final; reconnecting would only be refused again.
            if let Some(refusal) = handle.life.refusal() {
                self.discard(key, &handle);
                return Err(refusal);
            }

            let idle_expired = handle.life.idle_expired.load(Ordering::SeqCst);
            if dispatched && replay == ReplayClass::MutableNoReplay {
                // Do not discard the handle: whether this stream is reusable is a separate
                // question from whether this mutation may be repeated, and the next caller's
                // rotation decides it.
                let mut err = outcome_unknown(rpc.wire_name(), &attempt);
                if idle_expired {
                    err.push_trace(lore_error_set::Location::with_context(
                        file!(),
                        line!(),
                        column!(),
                        Arc::from(format!(
                            "no answer from the {} stream for {} s",
                            key.1.label(),
                            handle.life.idle.as_secs()
                        )),
                    ));
                }
                return Err(err);
            }

            // A stream that went silent says the channel is suspect, as a refused open does.
            // Handing back to `GRPCStorage`'s reconnect rather than reissuing here bounds a read
            // to one idle wait per reconnect, instead of one per stream reissue as well.
            if idle_expired || !handle.life.opened.load(Ordering::SeqCst) {
                self.discard(key, &handle);
                return Err(ProtocolError::from(Disconnected));
            }
            failed = Some(handle);
        }

        Err(ProtocolError::from(Disconnected))
    }
}

pub struct StorageService {
    /// Resolved to a client per stream open rather than cached, so a channel rebuilt by
    /// `GRPCConnection::reconnect` is picked up by the next rotation without costing the
    /// request path a lock.
    connection: Arc<super::GRPCConnection>,
    /// Get and `GetMetadata` share a cache: same request and response shape, told apart by
    /// `Verb`.
    get_streams: StreamCache<Address, (model_v1::Fragment, Bytes)>,
    put_streams: StreamCache<storage_v1::PutRequest, ()>,
    copy_streams: StreamCache<storage_v1::CopyRequest, ()>,
    /// Correlates resolved requests with their responses; never handed out as zero, which the
    /// server treats as uncorrelatable and stream-fatal.
    resolved_counter: AtomicU64,
    /// The resolved verbs correlate by `request_id`, not by address: one key can resolve to any
    /// content, so the address is an answer rather than a question. They carry their own reader
    /// instead of `pump_responses`.
    get_resolved_streams:
        StreamCache<storage_v1::GetResolvedRequest, Arc<storage_v1::GetResolvedResponse>>,
    put_resolved_streams:
        StreamCache<storage_v1::PutResolvedRequest, Arc<storage_v1::PutResolvedResponse>>,
    get_put_limiter: Semaphore,
    /// See [`STREAM_IDLE_TIMEOUT_SECS`]. Also bounds a managed single-message mutation.
    stream_idle: Duration,
    managed_progress: ManagedProgress,
}

fn inject_metadata<T>(request: &mut tonic::Request<T>, ctx: &GrpcSessionContext) {
    let md = request.metadata_mut();
    md.insert_bin(
        PARTITION_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(ctx.partition.data()),
    );
    md.insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(ctx.partition.data()),
    );
    if !ctx.correlation_id.is_empty()
        && let Ok(val) = MetadataValue::from_str(&ctx.correlation_id)
    {
        md.insert(CORRELATION_ID_HEADER, val);
    }
    if !ctx.auth_token.is_empty()
        && let Ok(mut val) = MetadataValue::from_str(&format!("Bearer {}", ctx.auth_token))
    {
        val.set_sensitive(true);
        md.insert("authorization", val);
    }
}

fn inject_managed_metadata<T>(request: &mut tonic::Request<T>, ctx: &GrpcSessionContext) {
    inject_metadata(request, ctx);
    if let Some(context) = crate::caller_operation::current_caller_operation() {
        request.metadata_mut().insert(
            crate::caller_operation::CALLER_CAPABILITIES_METADATA_KEY,
            MetadataValue::from_static(context.capabilities()),
        );
        if let Some(attempt) = crate::outcome::current_dispatch_attempt()
            && let Ok(value) = MetadataValue::from_str(&attempt.to_string())
        {
            request
                .metadata_mut()
                .insert(crate::outcome::ATTEMPT_ID_METADATA_KEY, value);
        }
    }
}

fn stream_lost(rpc: GrpcRpc) -> ProtocolError {
    outcome_unknown(
        rpc.wire_name(),
        &crate::outcome::current_dispatch_attempt().unwrap_or_else(AttemptId::new),
    )
}

const CLAIM_PENDING: u8 = 0;
const CLAIM_TAKEN: u8 = 1;
const CLAIM_ABANDONED: u8 = 2;

/// Who owns a managed call's one message: still pending, taken by the transport for sending, or
/// abandoned by the caller as never sent. One compare-and-swap decides between the last two, so
/// a call reported not sent can never have its message sent afterwards, even when the transport
/// opens the stream late and polls the body after the caller gave up.
struct ManagedClaim {
    state: AtomicU8,
    taken: Notify,
}

impl ManagedClaim {
    /// The caller gives up on a message the transport has not taken. False when it was taken.
    fn abandon(&self) -> bool {
        self.state
            .compare_exchange(
                CLAIM_PENDING,
                CLAIM_ABANDONED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }
}

/// The one-message request body of a managed mutation, and the claim on its message. The body
/// yields the message only if it wins the claim; an abandoned body ends empty.
fn managed_body<T: Send + 'static>(
    request: T,
) -> (
    impl tokio_stream::Stream<Item = T> + Send + 'static,
    Arc<ManagedClaim>,
) {
    let claim = Arc::new(ManagedClaim {
        state: AtomicU8::new(CLAIM_PENDING),
        taken: Notify::new(),
    });
    let body_claim = claim.clone();
    let body = async_stream::stream! {
        if body_claim
            .state
            .compare_exchange(CLAIM_PENDING, CLAIM_TAKEN, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            body_claim.taken.notify_one();
            yield request;
        }
    };
    (body, claim)
}

/// When any managed single-message call on one service last made progress: its message was
/// taken by the transport, or it got an answer.
///
/// Shared across the calls because they share the connection and the server's capacity. A call
/// queued behind others, on the client or on the server, is waiting, not stalled, while any of
/// them is still moving; the same reading the stream path takes per stream.
struct ManagedProgress {
    started: Instant,
    last: AtomicU64,
}

impl ManagedProgress {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn mark(&self) {
        self.last.fetch_max(self.now(), Ordering::Relaxed);
    }

    fn last(&self) -> u64 {
        self.last.load(Ordering::Relaxed)
    }
}

/// A managed single-message mutation, bounded by silence rather than by age.
///
/// Before the transport takes the one message, `idle` with no managed progress at all ends the
/// call as [`crate::error::RequestNotSent`]: the message provably never left, so the journal
/// settles it not applied and the reconnect layer may send it again. After it is taken, the same
/// silence is an unknown outcome, because the request may have reached the server.
async fn bounded_managed<T>(
    rpc: GrpcRpc,
    idle: Duration,
    progress: &ManagedProgress,
    claim: Arc<ManagedClaim>,
    future: impl Future<Output = Result<T, ProtocolError>>,
) -> Result<T, ProtocolError> {
    tokio::pin!(future);
    let mut base = progress.now();
    let mut sent = false;
    loop {
        let last = progress.last().max(base);
        let deadline = progress.started + Duration::from_millis(last) + idle;
        tokio::select! {
            biased;
            result = &mut future => {
                progress.mark();
                return result;
            }
            () = claim.taken.notified(), if !sent => {
                sent = true;
                progress.mark();
                base = progress.now();
            }
            () = tokio::time::sleep_until(deadline) => {
                if progress.last() > last {
                    continue;
                }
                if sent {
                    lore_warn!(
                        "{} got no answer for {:?}; its outcome is unknown",
                        rpc.wire_name(),
                        idle
                    );
                    return Err(stream_lost(rpc));
                }
                if !claim.abandon() {
                    // The transport took the message as the bound ran out: it may be on its way.
                    sent = true;
                    progress.mark();
                    base = progress.now();
                    continue;
                }
                lore_warn!(
                    "{} was not taken for sending within {:?}; it was not sent",
                    rpc.wire_name(),
                    idle
                );
                return Err(ProtocolError::internal_with_context(
                    crate::error::RequestNotSent,
                    "no stream took the request",
                ));
            }
        }
    }
}

fn managed_stream_status(status: tonic::Status, rpc: GrpcRpc) -> ProtocolError {
    if crate::error::is_unsupported_client_status(&status) {
        ProtocolError::from(status)
    } else {
        stream_lost(rpc)
    }
}

fn decisive_item_error(error: ProtocolError) -> ProtocolError {
    if crate::error::answer_lost_code(&error).is_some() || error.is_disconnected() {
        ProtocolError::internal(error.to_string())
    } else {
        error
    }
}

impl StorageService {
    /// The connection this service sends on, for the crate's own tests. An accessor rather
    /// than `test_pub` on the struct, which would also publish its private stream caches.
    #[cfg(feature = "test-util")]
    pub fn connection_for_test(&self) -> &Arc<super::GRPCConnection> {
        &self.connection
    }

    pub fn new(connection: Arc<super::GRPCConnection>) -> Self {
        Self {
            connection,
            get_streams: StreamCache::new(),
            put_streams: StreamCache::new(),
            copy_streams: StreamCache::new(),
            resolved_counter: AtomicU64::new(0),
            get_resolved_streams: StreamCache::new(),
            put_resolved_streams: StreamCache::new(),
            get_put_limiter: Semaphore::new(INFLIGHT_COMMAND_LIMIT),
            stream_idle: stream_idle_timeout(),
            managed_progress: ManagedProgress::new(),
        }
    }

    /// The same service with a different idle bound, for tests that cannot wait the default.
    #[cfg(feature = "test-util")]
    pub fn with_stream_idle_timeout(mut self, idle: Duration) -> Self {
        self.stream_idle = idle;
        self
    }

    /// Remove streams for a session. Dropping the senders terminates the stream tasks.
    pub fn remove_session_streams(&self, session_id: u32) {
        self.get_streams.remove(session_id, Verb::Get);
        self.get_streams.remove(session_id, Verb::GetMetadata);
        self.put_streams.remove(session_id, Verb::Put);
        self.copy_streams.remove(session_id, Verb::Copy);
        self.get_resolved_streams
            .remove(session_id, Verb::GetResolved);
        self.put_resolved_streams
            .remove(session_id, Verb::PutResolved);
    }

    pub async fn get(
        &self,
        session_id: u32,
        ctx: &GrpcSessionContext,
        address: &Address,
    ) -> Result<(Fragment, Bytes), ProtocolError> {
        lore_debug!("gRPC get fragment: {}", address);

        let _permit = self
            .get_put_limiter
            .acquire()
            .await
            .internal("permit acquire")?;

        let (fragment, payload) = self
            .get_streams
            .request(
                GrpcRpc::StorageGet,
                (session_id, Verb::Get),
                *address,
                || self.spawn_get_stream(ctx),
            )
            .await?;

        let fragment = Fragment {
            flags: fragment.flags,
            size_payload: fragment.size_payload,
            size_content: fragment.size_content,
        };

        if let Err(reason) = lore_base::types::validate_fragment_response(&fragment) {
            lore_error!("Invalid fragment in get response {fragment:?}: {reason}");
            return Err(ProtocolError::internal(format!(
                "get: invalid fragment: {reason}"
            )));
        }
        if payload.len() != fragment.size_payload as usize {
            lore_error!(
                "Fragment payload is invalid in get response : {} bytes, expected {}",
                payload.len(),
                fragment.size_payload
            );
            return Err(ProtocolError::internal("get: Invalid payload"));
        }

        Ok((fragment, payload))
    }

    /// Fetch only the fragment metadata for an address. Same wire request as `get` (just an
    /// `Address`), but the server's response carries `Fragment` only — no payload bytes — so
    /// callers that don't need the payload skip the transfer cost. Used by the storage API's
    /// query op for remote-hit metadata lookups.
    ///
    /// A `NotFound` here is an ordinary answer rather than a fault — see
    /// `RemoteImmutableStore::get_metadata`, which maps it to `MatchNone` — so it arrives
    /// in-band and costs only this lookup.
    pub async fn get_metadata(
        &self,
        session_id: u32,
        ctx: &GrpcSessionContext,
        address: &Address,
    ) -> Result<Fragment, ProtocolError> {
        lore_debug!("gRPC get_metadata fragment: {}", address);

        let _permit = self
            .get_put_limiter
            .acquire()
            .await
            .internal("permit acquire")?;

        let (fragment, _payload) = self
            .get_streams
            .request(
                GrpcRpc::StorageGetMetadata,
                (session_id, Verb::GetMetadata),
                *address,
                || self.spawn_get_metadata_stream(ctx),
            )
            .await?;

        let fragment = Fragment {
            flags: fragment.flags,
            size_payload: fragment.size_payload,
            size_content: fragment.size_content,
        };

        if let Err(reason) = lore_base::types::validate_fragment_response(&fragment) {
            lore_error!("Invalid fragment in get_metadata response {fragment:?}: {reason}");
            return Err(ProtocolError::internal(format!(
                "get_metadata: invalid fragment: {reason}"
            )));
        }

        Ok(fragment)
    }

    pub async fn put(
        &self,
        session_id: u32,
        ctx: &GrpcSessionContext,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        lore_debug!("Put fragment: {address}");

        let _permit = self
            .get_put_limiter
            .acquire()
            .await
            .internal("permit acquire")?;

        let request = storage_v1::PutRequest {
            address: Some(address.into()),
            fragment: Some(fragment.into()),
            payload,
        };

        if crate::caller_operation::current_caller_operation().is_some() {
            let mut canonical = request.clone();
            canonical.payload = canonical.payload.map(|_| Bytes::new());
            let (body, claim) = managed_body(request);
            return crate::caller_operation::dispatch(
                ctx.partition,
                GrpcRpc::StoragePut,
                canonical.encode_to_vec(),
                self.connection.remote_url.to_string(),
                ctx.auth_token.clone(),
                bounded_managed(
                    GrpcRpc::StoragePut,
                    self.stream_idle,
                    &self.managed_progress,
                    claim,
                    Box::pin(async {
                        let mut req = tonic::Request::new(body);
                        inject_managed_metadata(&mut req, ctx);
                        let mut client = StorageServiceClient::new(self.connection.channel());
                        let mut responses = client
                            .put(req)
                            .await
                            .map_err(ProtocolError::from)?
                            .into_inner();
                        let response = responses
                            .message()
                            .await
                            .map_err(|status| managed_stream_status(status, GrpcRpc::StoragePut))?
                            .ok_or_else(|| stream_lost(GrpcRpc::StoragePut))?;
                        if response.key() != Some(address) {
                            return Err(stream_lost(GrpcRpc::StoragePut));
                        }
                        response.into_result().map_err(decisive_item_error)
                    }),
                ),
            )
            .await;
        }

        self.put_streams
            .request(
                GrpcRpc::StoragePut,
                (session_id, Verb::Put),
                request,
                || self.spawn_put_stream(ctx),
            )
            .await
    }

    pub async fn query(
        &self,
        ctx: &GrpcSessionContext,
        address: &[Address],
    ) -> Result<Bytes, ProtocolError> {
        lore_debug!("Query {} fragments", address.len());

        let request = storage_v1::QueryRequest {
            addresses: address.iter().map(model_v1::Address::from).collect(),
        };
        let mut client = StorageServiceClient::new(self.connection.channel());
        let mut req = tonic::Request::new(request);
        inject_metadata(&mut req, ctx);

        let res = client
            .query(req)
            .await
            .map(|res| res.into_inner())
            .map_err(|err| match err.code() {
                tonic::Code::Unavailable => ProtocolError::from(SlowDown),
                _ => ProtocolError::internal_with_context(err, "query"),
            })?;

        let mut buffer = BytesMut::with_capacity(res.results.len());
        for value in res.results.iter() {
            buffer.put_u8(*value as u8);
        }
        Ok(buffer.freeze())
    }

    pub async fn verify(
        &self,
        ctx: &GrpcSessionContext,
        address: &Address,
        heal: bool,
    ) -> Result<VerifyResult, ProtocolError> {
        lore_debug!("Verify fragment: {address}");

        let request = storage_v1::VerifyRequest {
            address: Some((*address).into()),
            heal,
        };
        if heal && crate::caller_operation::current_caller_operation().is_some() {
            return crate::caller_operation::dispatch(
                ctx.partition,
                GrpcRpc::StorageVerify,
                request.encode_to_vec(),
                self.connection.remote_url.to_string(),
                ctx.auth_token.clone(),
                async {
                    let mut req = tonic::Request::new(request);
                    inject_managed_metadata(&mut req, ctx);
                    let mut client = StorageServiceClient::new(self.connection.channel());
                    let res = client
                        .verify(req)
                        .await
                        .map_err(ProtocolError::from)?
                        .into_inner();
                    Ok(VerifyResult {
                        corrupted: res.corrupted,
                        healed: HealResult::from(res.healed),
                    })
                },
            )
            .await;
        }
        let mut client = StorageServiceClient::new(self.connection.channel());
        let mut req = tonic::Request::new(request);
        inject_metadata(&mut req, ctx);

        client
            .verify(req)
            .await
            .map(|res| res.into_inner())
            .map_err(|err| match err.code() {
                tonic::Code::Unavailable => ProtocolError::from(SlowDown),
                tonic::Code::NotFound => ProtocolError::from(NotFound),
                tonic::Code::Unimplemented => ProtocolError::internal("unsupported: verify"),
                _ => ProtocolError::internal_with_context(err, "verify"),
            })
            .map(|res| VerifyResult {
                corrupted: res.corrupted,
                healed: HealResult::from(res.healed),
            })
    }

    pub async fn copy(
        &self,
        session_id: u32,
        ctx: &GrpcSessionContext,
        source_partition: Partition,
        source_address: Address,
        target_context: Context,
    ) -> Result<(), ProtocolError> {
        lore_debug!(
            "gRPC copy fragment: {} from partition {} (target context {})",
            source_address,
            source_partition,
            target_context
        );

        let _permit = self
            .get_put_limiter
            .acquire()
            .await
            .internal("permit acquire")?;

        let request = storage_v1::CopyRequest {
            source_repository_id: Bytes::copy_from_slice(source_partition.data()),
            source_address: Some(source_address.into()),
            target_context: Bytes::copy_from_slice(zerocopy::IntoBytes::as_bytes(&target_context)),
        };

        if crate::caller_operation::current_caller_operation().is_some() {
            let canonical = request.encode_to_vec();
            let (body, claim) = managed_body(request);
            return crate::caller_operation::dispatch(
                ctx.partition,
                GrpcRpc::StorageCopy,
                canonical,
                self.connection.remote_url.to_string(),
                ctx.auth_token.clone(),
                bounded_managed(
                    GrpcRpc::StorageCopy,
                    self.stream_idle,
                    &self.managed_progress,
                    claim,
                    Box::pin(async {
                        let mut req = tonic::Request::new(body);
                        inject_managed_metadata(&mut req, ctx);
                        let mut client = StorageServiceClient::new(self.connection.channel());
                        let mut responses = client
                            .copy(req)
                            .await
                            .map_err(ProtocolError::from)?
                            .into_inner();
                        let response = responses
                            .message()
                            .await
                            .map_err(|status| managed_stream_status(status, GrpcRpc::StorageCopy))?
                            .ok_or_else(|| stream_lost(GrpcRpc::StorageCopy))?;
                        if response.key() != Some(source_address) {
                            return Err(stream_lost(GrpcRpc::StorageCopy));
                        }
                        response.into_result().map_err(decisive_item_error)
                    }),
                ),
            )
            .await;
        }

        self.copy_streams
            .request(
                GrpcRpc::StorageCopy,
                (session_id, Verb::Copy),
                request,
                || self.spawn_copy_stream(ctx),
            )
            .await
    }

    pub async fn mutable_load(
        &self,
        ctx: &GrpcSessionContext,
        key: &Hash,
        key_type: KeyType,
    ) -> Result<Hash, ProtocolError> {
        lore_debug!("gRPC mutable_load: {}", key);

        let request = storage_v1::MutableLoadRequest {
            key: Bytes::copy_from_slice(key.data()),
            key_type: key_type as u32,
        };
        let mut client = StorageServiceClient::new(self.connection.channel());
        let mut req = tonic::Request::new(request);
        inject_metadata(&mut req, ctx);

        let res = client
            .mutable_load(req)
            .await
            .map(|res| res.into_inner())
            .map_err(|err| match err.code() {
                tonic::Code::Unavailable => ProtocolError::from(SlowDown),
                tonic::Code::NotFound => ProtocolError::from(NotFound),
                tonic::Code::Unimplemented => ProtocolError::internal("unsupported: mutable_load"),
                _ => ProtocolError::internal_with_context(err, "mutable_load"),
            })?;

        Ok(Hash::from(&res.value[..]))
    }

    pub async fn mutable_store(
        &self,
        ctx: &GrpcSessionContext,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), ProtocolError> {
        lore_debug!("gRPC mutable_store: {}", key);

        let request = storage_v1::MutableStoreRequest {
            key: Bytes::copy_from_slice(key.data()),
            value: Bytes::copy_from_slice(value.data()),
            key_type: key_type as u32,
        };
        if crate::caller_operation::current_caller_operation().is_some() {
            return crate::caller_operation::dispatch(
                ctx.partition,
                GrpcRpc::StorageMutableStore,
                request.encode_to_vec(),
                self.connection.remote_url.to_string(),
                ctx.auth_token.clone(),
                async {
                    let mut req = tonic::Request::new(request);
                    inject_managed_metadata(&mut req, ctx);
                    let mut client = StorageServiceClient::new(self.connection.channel());
                    client
                        .mutable_store(req)
                        .await
                        .map_err(ProtocolError::from)
                        .map(|_| ())
                },
            )
            .await;
        }
        let mut client = StorageServiceClient::new(self.connection.channel());
        let mut req = tonic::Request::new(request);
        inject_metadata(&mut req, ctx);

        client
            .mutable_store(req)
            .await
            .map(|_| ())
            .map_err(|err| match err.code() {
                tonic::Code::Unavailable => ProtocolError::from(SlowDown),
                tonic::Code::Unimplemented => ProtocolError::internal("unsupported: mutable_store"),
                _ => ProtocolError::internal_with_context(err, "mutable_store"),
            })
    }

    pub async fn mutable_compare_and_swap(
        &self,
        ctx: &GrpcSessionContext,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, ProtocolError> {
        lore_debug!("gRPC mutable_cas: {}", key);

        let request = storage_v1::MutableCompareAndSwapRequest {
            key: Bytes::copy_from_slice(key.data()),
            expected: Bytes::copy_from_slice(expected.data()),
            value: Bytes::copy_from_slice(value.data()),
            key_type: key_type as u32,
        };
        if crate::caller_operation::current_caller_operation().is_some() {
            return crate::caller_operation::dispatch(
                ctx.partition,
                GrpcRpc::StorageMutableCompareAndSwap,
                request.encode_to_vec(),
                self.connection.remote_url.to_string(),
                ctx.auth_token.clone(),
                async {
                    let mut req = tonic::Request::new(request);
                    inject_managed_metadata(&mut req, ctx);
                    let mut client = StorageServiceClient::new(self.connection.channel());
                    let response = client
                        .mutable_compare_and_swap(req)
                        .await
                        .map_err(ProtocolError::from)?
                        .into_inner();
                    if response.current_value.len() != size_of::<Hash>() {
                        return Err(stream_lost(GrpcRpc::StorageMutableCompareAndSwap));
                    }
                    Ok(Hash::from(&response.current_value[..]))
                },
            )
            .await;
        }
        let mut client = StorageServiceClient::new(self.connection.channel());
        let mut req = tonic::Request::new(request);
        inject_metadata(&mut req, ctx);

        let res = client
            .mutable_compare_and_swap(req)
            .await
            .map(|res| res.into_inner())
            .map_err(|err| match err.code() {
                tonic::Code::Unavailable => ProtocolError::from(SlowDown),
                tonic::Code::Unimplemented => ProtocolError::internal("unsupported: mutable_cas"),
                _ => ProtocolError::internal_with_context(err, "mutable_cas"),
            })?;

        Ok(Hash::from(&res.current_value[..]))
    }

    /// Resolve `key` in `context` and fetch the fragment it names. The stream correlates by
    /// `request_id`; see [`run_resolved_stream`].
    pub async fn get_resolved(
        &self,
        session_id: u32,
        ctx: &GrpcSessionContext,
        key: &Hash,
        context: &Context,
        flags: u32,
    ) -> Result<(Hash, Fragment, Bytes), ProtocolError> {
        let key_address = Address {
            hash: *key,
            context: *context,
        };
        lore_debug!("gRPC get_resolved key: {}", key_address);

        let request_id = self
            .resolved_counter
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let request = storage_v1::GetResolvedRequest {
            request_id,
            key: Some(key_address.into()),
            flags,
        };

        let _permit = self
            .get_put_limiter
            .acquire()
            .await
            .internal("permit acquire")?;

        let res = self
            .get_resolved_streams
            .request(
                GrpcRpc::StorageGetResolved,
                (session_id, Verb::GetResolved),
                request,
                || self.spawn_get_resolved_stream(ctx),
            )
            .await?;

        if res.resolved.len() != size_of::<Hash>() {
            lore_error!(
                "Invalid get_resolved response, resolved hash is {} bytes, expected {}",
                res.resolved.len(),
                size_of::<Hash>()
            );
            return Err(ProtocolError::internal(
                "get_resolved: Invalid resolved hash length",
            ));
        }

        let Some(fragment) = res.fragment else {
            lore_error!("Invalid get_resolved response, missing fragment");
            return Err(ProtocolError::internal("get_resolved: Missing fragment"));
        };

        let fragment = Fragment {
            flags: fragment.flags,
            size_payload: fragment.size_payload,
            size_content: fragment.size_content,
        };

        if let Err(reason) = lore_base::types::validate_fragment_response(&fragment) {
            lore_error!("Invalid fragment in get_resolved response {fragment:?}: {reason}");
            return Err(ProtocolError::internal(format!(
                "get_resolved: invalid fragment: {reason}"
            )));
        }
        if res.payload.len() != fragment.size_payload as usize {
            lore_error!(
                "Fragment payload is invalid in get_resolved response: {} bytes, expected {}",
                res.payload.len(),
                fragment.size_payload
            );
            return Err(ProtocolError::internal("get_resolved: Invalid payload"));
        }

        Ok((Hash::from(&res.resolved[..]), fragment, res.payload.clone()))
    }

    pub async fn put_resolved(
        &self,
        session_id: u32,
        ctx: &GrpcSessionContext,
        key: &Hash,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        lore_debug!("gRPC put_resolved key: {} -> {}", key, address);

        let request_id = self
            .resolved_counter
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let request = storage_v1::PutResolvedRequest {
            request_id,
            key: Bytes::from_owner(*key),
            address: Some(address.into()),
            fragment: Some(fragment.into()),
            payload: payload.unwrap_or_default(),
        };

        if crate::caller_operation::current_caller_operation().is_some() {
            let _permit = self
                .get_put_limiter
                .acquire()
                .await
                .internal("permit acquire")?;
            let mut canonical = request.clone();
            canonical.payload = Bytes::new();
            canonical.request_id = 0;
            let (body, claim) = managed_body(request);
            return crate::caller_operation::dispatch(
                ctx.partition,
                GrpcRpc::StoragePutResolved,
                canonical.encode_to_vec(),
                self.connection.remote_url.to_string(),
                ctx.auth_token.clone(),
                bounded_managed(
                    GrpcRpc::StoragePutResolved,
                    self.stream_idle,
                    &self.managed_progress,
                    claim,
                    Box::pin(async {
                        let mut req = tonic::Request::new(body);
                        inject_managed_metadata(&mut req, ctx);
                        let mut client = StorageServiceClient::new(self.connection.channel());
                        let mut responses = client
                            .put_resolved(req)
                            .await
                            .map_err(ProtocolError::from)?
                            .into_inner();
                        let response = responses
                            .message()
                            .await
                            .map_err(|status| {
                                managed_stream_status(status, GrpcRpc::StoragePutResolved)
                            })?
                            .ok_or_else(|| stream_lost(GrpcRpc::StoragePutResolved))?;
                        if response.request_id != request_id {
                            return Err(stream_lost(GrpcRpc::StoragePutResolved));
                        }
                        match item_status_error(response.status.as_ref()) {
                            Some(error) => Err(decisive_item_error(error)),
                            None => Ok(()),
                        }
                    }),
                ),
            )
            .await;
        }

        let _permit = self
            .get_put_limiter
            .acquire()
            .await
            .internal("permit acquire")?;

        self.put_resolved_streams
            .request(
                GrpcRpc::StoragePutResolved,
                (session_id, Verb::PutResolved),
                request,
                || self.spawn_put_resolved_stream(ctx),
            )
            .await
            .map(|_| ())
    }

    fn spawn_get_resolved_stream(
        &self,
        ctx: &GrpcSessionContext,
    ) -> StreamHandle<storage_v1::GetResolvedRequest, Arc<storage_v1::GetResolvedResponse>> {
        let mut client = StorageServiceClient::new(self.connection.channel());
        let (tx, rx) = mpsc::channel(STREAM_WRITE_BUFFER_SIZE);
        let handle = StreamState::new(tx, self.stream_idle);
        let pending: Arc<Pending<Arc<storage_v1::GetResolvedResponse>>> = Arc::new(DashMap::new());
        let requests = resolved_request_stream(
            rx,
            pending.clone(),
            handle.life.clone(),
            |request: &storage_v1::GetResolvedRequest| request.request_id,
        );

        let life = handle.life.clone();
        let ctx = ctx.clone();
        lore_spawn_net!(async move {
            let mut req = tonic::Request::new(requests);
            inject_metadata(&mut req, &ctx);
            run_resolved_stream(
                life,
                pending,
                Verb::GetResolved,
                client.get_resolved(req),
                |response: &storage_v1::GetResolvedResponse| response.request_id,
                |response: &storage_v1::GetResolvedResponse| response.status.as_ref(),
            )
            .await;
        });

        handle
    }

    /// See [`StorageService::spawn_get_resolved_stream`]; the write side, same correlation.
    fn spawn_put_resolved_stream(
        &self,
        ctx: &GrpcSessionContext,
    ) -> StreamHandle<storage_v1::PutResolvedRequest, Arc<storage_v1::PutResolvedResponse>> {
        let mut client = StorageServiceClient::new(self.connection.channel());
        let (tx, rx) = mpsc::channel(STREAM_WRITE_BUFFER_SIZE);
        let handle = StreamState::new(tx, self.stream_idle);
        let pending: Arc<Pending<Arc<storage_v1::PutResolvedResponse>>> = Arc::new(DashMap::new());
        let requests = resolved_request_stream(
            rx,
            pending.clone(),
            handle.life.clone(),
            |request: &storage_v1::PutResolvedRequest| request.request_id,
        );

        let life = handle.life.clone();
        let ctx = ctx.clone();
        lore_spawn_net!(async move {
            let mut req = tonic::Request::new(requests);
            inject_metadata(&mut req, &ctx);
            run_resolved_stream(
                life,
                pending,
                Verb::PutResolved,
                client.put_resolved(req),
                |response: &storage_v1::PutResolvedResponse| response.request_id,
                |response: &storage_v1::PutResolvedResponse| response.status.as_ref(),
            )
            .await;
        });

        handle
    }

    fn spawn_get_stream(
        &self,
        ctx: &GrpcSessionContext,
    ) -> StreamHandle<Address, (model_v1::Fragment, Bytes)> {
        let mut client = StorageServiceClient::new(self.connection.channel());
        let (tx, rx) = mpsc::channel(STREAM_WRITE_BUFFER_SIZE);
        let handle = StreamState::new(tx, self.stream_idle);
        let inflight: Arc<Inflight<(model_v1::Fragment, Bytes)>> = Arc::new(DashMap::new());
        let requests = request_stream(
            rx,
            inflight.clone(),
            handle.life.clone(),
            Verb::Get,
            |address: Address| Some((address, model_v1::Address::from(address))),
        );

        let life = handle.life.clone();
        let ctx = ctx.clone();
        lore_spawn_net!(async move {
            let mut req = tonic::Request::new(requests);
            inject_metadata(&mut req, &ctx);
            run_stream(life, inflight, Verb::Get, client.get(req)).await;
        });

        handle
    }

    fn spawn_get_metadata_stream(
        &self,
        ctx: &GrpcSessionContext,
    ) -> StreamHandle<Address, (model_v1::Fragment, Bytes)> {
        let mut client = StorageServiceClient::new(self.connection.channel());
        let (tx, rx) = mpsc::channel(STREAM_WRITE_BUFFER_SIZE);
        let handle = StreamState::new(tx, self.stream_idle);
        let inflight: Arc<Inflight<(model_v1::Fragment, Bytes)>> = Arc::new(DashMap::new());
        let requests = request_stream(
            rx,
            inflight.clone(),
            handle.life.clone(),
            Verb::GetMetadata,
            |address: Address| Some((address, model_v1::Address::from(address))),
        );

        let life = handle.life.clone();
        let ctx = ctx.clone();
        lore_spawn_net!(async move {
            let mut req = tonic::Request::new(requests);
            inject_metadata(&mut req, &ctx);
            run_stream(life, inflight, Verb::GetMetadata, client.get_metadata(req)).await;
        });

        handle
    }

    fn spawn_put_stream(
        &self,
        ctx: &GrpcSessionContext,
    ) -> StreamHandle<storage_v1::PutRequest, ()> {
        let mut client = StorageServiceClient::new(self.connection.channel());
        let (tx, rx) =
            mpsc::channel::<StreamItem<storage_v1::PutRequest, ()>>(STREAM_WRITE_BUFFER_SIZE);
        let handle = StreamState::new(tx, self.stream_idle);
        let inflight: Arc<Inflight<()>> = Arc::new(DashMap::new());
        let requests = request_stream(
            rx,
            inflight.clone(),
            handle.life.clone(),
            Verb::Put,
            |request: storage_v1::PutRequest| {
                let address = request.address.as_ref().map(Address::from)?;
                Some((address, request))
            },
        );

        let life = handle.life.clone();
        let ctx = ctx.clone();
        lore_spawn_net!(async move {
            let mut req = tonic::Request::new(requests);
            inject_metadata(&mut req, &ctx);
            run_stream(life, inflight, Verb::Put, client.put(req)).await;
        });

        handle
    }

    fn spawn_copy_stream(
        &self,
        ctx: &GrpcSessionContext,
    ) -> StreamHandle<storage_v1::CopyRequest, ()> {
        let mut client = StorageServiceClient::new(self.connection.channel());
        let (tx, rx) =
            mpsc::channel::<StreamItem<storage_v1::CopyRequest, ()>>(STREAM_WRITE_BUFFER_SIZE);
        let handle = StreamState::new(tx, self.stream_idle);
        let inflight: Arc<Inflight<()>> = Arc::new(DashMap::new());
        let requests = request_stream(
            rx,
            inflight.clone(),
            handle.life.clone(),
            Verb::Copy,
            |request: storage_v1::CopyRequest| {
                let address = request.source_address.as_ref().map(Address::from)?;
                Some((address, request))
            },
        );

        let life = handle.life.clone();
        let ctx = ctx.clone();
        lore_spawn_net!(async move {
            let mut req = tonic::Request::new(requests);
            inject_metadata(&mut req, &ctx);
            run_stream(life, inflight, Verb::Copy, client.copy(req)).await;
        });

        handle
    }
}

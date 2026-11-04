// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::cell::Cell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use futures::FutureExt;
use futures::future::BoxFuture;
use futures::future::Shared;
use lore_base::lore_spawn_net_nocontext;
use lore_proto::auth::CheckUserPermissionRequest;
use lore_proto::auth::CheckUserPermissionResponse;
use lore_proto::auth::LookupUserPermissionsRequest;
use lore_proto::auth::LookupUserPermissionsResponse;
use lore_proto::auth::urc_auth_api_client::UrcAuthApiClient;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::LabelArray;
use lore_telemetry::METRICS_OPERATION_LATENCY_METRIC_NAME;
use lore_telemetry::timed;
use lore_telemetry::timer::TimedResult;
use lore_transport::auth::ucs_auth::grpc_endpoint;
use lore_transport::grpc::CorrelationInterceptor;
use opentelemetry::KeyValue;
use smallvec::SmallVec;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::codegen::InterceptedService;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;
use tracing::debug;
use tracing::warn;

use crate::grpc::ServerResultExt;

type LoreAuthApiResult<T> = Result<Response<T>, Status>;

/// FORK-LOCAL (Tideshift): ceiling on one whole dial to the auth service:
/// DNS, TCP connect, TLS handshake and HTTP/2 handshake together. Every
/// caller sharing a dial waits at most about this long for it. Also set as
/// the endpoint's TCP connect timeout, which bounds the TCP step of tonic's
/// own re-dials. Matches the internal gRPC client's default.
pub const AUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// FORK-LOCAL (Tideshift): ceiling on one whole auth request, from
/// [`AuthChannel::client`] to the RPC's answer: any wait on a dial, then the
/// RPC with any re-dial tonic makes under it. Nothing else bounds a call:
/// HTTP/2 PINGs need a finished handshake, and neither the authorizer nor the
/// gRPC server sets a deadline. Well under a client's own operation budget
/// (the desktop gives an online op 15 s), so a slow auth service fails the
/// request as an auth error before the client gives up on the operation. A
/// call that hits it fails as a connection failure, so the channel is
/// discarded and the next call takes the dial path. Longer than
/// [`AUTH_CONNECT_TIMEOUT`], so a call that has to re-dial can still finish.
pub const AUTH_DEADLINE: Duration = Duration::from_secs(8);
/// FORK-LOCAL (Tideshift): how long an [`AuthChannel`] fails every new call at
/// once after a call or a dial ran out of time. One client operation can send
/// several requests in series (`metadata set` reads, then writes), and each
/// would otherwise wait out its own [`AUTH_DEADLINE`] on a hung auth service.
/// Only a timeout starts it: a denial, any other answer and a fast transport
/// error do not. The first call after it sends a real request; a successful
/// call ends it early.
pub const AUTH_OUTAGE_HOLD: Duration = Duration::from_secs(5);
/// FORK-LOCAL (Tideshift): TCP keep-alive on the shared auth connection, so a
/// peer that vanished without closing is found while the connection idles.
/// Matches the internal gRPC client's default.
const AUTH_TCP_KEEPALIVE: Duration = Duration::from_secs(30);
/// FORK-LOCAL (Tideshift): HTTP/2 PING cadence while a call is in flight on
/// the shared connection, so a stalled connection fails its calls (and is
/// replaced) instead of holding every later call. Not sent while idle: the
/// auth service's gRPC stack may treat idle pings as abuse.
const AUTH_HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const AUTH_HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// FORK-LOCAL (Tideshift): the source that marks a [`Status`] as "the auth
/// service did not answer in time", as opposed to an answer. Set only by this
/// module, and a source never crosses the wire, so neither the auth service
/// nor a client can forge it.
#[derive(Debug, thiserror::Error)]
#[error("lore auth service unavailable")]
pub struct AuthUnavailable;

/// An `Internal` status carrying `message` and the [`AuthUnavailable`]
/// marker. `Internal`, not `Unavailable`: a Lore client reads `Unavailable` as
/// a lost connection and reconnects, and `Cancelled` or `DeadlineExceeded` as
/// a lost answer, while this is the server's decisive refusal.
#[lore_macro::test_pub]
fn auth_unavailable_status(message: String) -> Status {
    let mut status = Status::internal(message);
    status.set_source(Arc::new(AuthUnavailable));
    status
}

/// Whether `status` says the auth service did not answer in time. An
/// authorization check passes such a status on rather than reporting it as a
/// denial; it fails the request either way.
pub fn is_auth_unavailable(status: &Status) -> bool {
    std::error::Error::source(status).is_some_and(|source| source.is::<AuthUnavailable>())
}

tokio::task_local! {
    /// Auth time one request has spent so far, across all its auth calls.
    static AUTH_SPENT: Cell<Duration>;
}

/// FORK-LOCAL (Tideshift): runs `request` under one [`AUTH_DEADLINE`] shared
/// by every auth call it makes on this task, so a request that asks twice
/// still fails within one deadline. Only time inside auth calls counts. A
/// nested call joins the budget already running. Outside it (a spawned task,
/// say) each call gets a whole deadline of its own.
pub async fn with_auth_budget<F: Future>(request: F) -> F::Output {
    if AUTH_SPENT.try_with(|_| ()).is_ok() {
        request.await
    } else {
        AUTH_SPENT.scope(Cell::new(Duration::ZERO), request).await
    }
}

fn budget_left() -> Duration {
    AUTH_SPENT
        .try_with(|spent| AUTH_DEADLINE.saturating_sub(spent.get()))
        .unwrap_or(AUTH_DEADLINE)
}

fn charge(started: tokio::time::Instant) {
    // Outside a budget there is nothing to charge.
    let _ = AUTH_SPENT.try_with(|spent| spent.set(spent.get() + started.elapsed()));
}

pub struct LoreAuthClientHelper {
    client: UrcAuthApiClient<InterceptedService<Channel, CorrelationInterceptor>>,
}

/// Builds the endpoint to dial for `auth_url`, whose scheme is the configured
/// one (`ucs-auth://`, `oidc://`) rather than one tonic can dial.
#[lore_macro::test_pub]
fn auth_endpoint(auth_url: &str) -> Result<tonic::transport::Endpoint, Status> {
    let auth_url = grpc_endpoint(auth_url);
    let mut endpoint = tonic::transport::Endpoint::from_shared(auth_url.clone())
        .warn_map_err(|_| Status::internal("Failed to create lore auth endpoint"))?
        .connect_timeout(AUTH_CONNECT_TIMEOUT)
        .tcp_keepalive(Some(AUTH_TCP_KEEPALIVE))
        .http2_keep_alive_interval(AUTH_HTTP2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(AUTH_HTTP2_KEEPALIVE_TIMEOUT);
    if auth_url.starts_with("https://") {
        endpoint = endpoint
            .tls_config(
                ClientTlsConfig::new()
                    .assume_http2(true)
                    .with_native_roots(),
            )
            .warn_map_err(|_| Status::internal("Failed to configure TLS for lore auth"))?;
    }
    Ok(endpoint)
}

/// Dials `auth_url` and waits for the connection, with the errors the
/// per-call path always returned. Runs on the net runtime (see
/// [`AuthChannel::start_dial`]). The endpoint build (which loads the native
/// root store for `https`) and the connect are timed separately at debug
/// level.
async fn connect_auth_channel(auth_url: String) -> Result<Channel, Status> {
    let started = Instant::now();
    let endpoint = auth_endpoint(&auth_url)?;
    let endpoint_built = started.elapsed();
    // A dial that ran out of time is a timeout whether this bound or the
    // endpoint's own TCP connect timeout (the same length) fired first.
    let timed_out = || {
        auth_unavailable_status(format!(
            "lore auth service did not connect within {AUTH_CONNECT_TIMEOUT:?}"
        ))
    };
    let channel = match tokio::time::timeout(AUTH_CONNECT_TIMEOUT, endpoint.connect()).await {
        Ok(Ok(channel)) => channel,
        Ok(Err(error)) if started.elapsed() < AUTH_CONNECT_TIMEOUT => {
            return Err(error)
                .warn_map_err(|_| Status::internal("Failed to connect to lore auth service"));
        }
        Ok(Err(_)) | Err(_) => return Err(timed_out()),
    };
    debug!(
        endpoint_build_ms = endpoint_built.as_secs_f64() * 1000.0,
        connect_ms = (started.elapsed() - endpoint_built).as_secs_f64() * 1000.0,
        "Connected to lore auth service"
    );
    Ok(channel)
}
/// Whether a failed call says the connection under it is unusable, rather
/// than carrying the auth service's own answer. A status the service sent
/// arrives with no source; one tonic built from a transport or buffer error
/// carries it.
///
/// Deliberately broad: ANY status with a source counts, whatever its code,
/// as does any `Unavailable`. A false positive costs one extra dial; a false
/// negative could leave every later call on a channel that cannot serve.
/// Either way the call itself fails closed.
fn is_connection_failure(status: &Status) -> bool {
    status.code() == Code::Unavailable || std::error::Error::source(status).is_some()
}

/// A dial every caller arriving while it runs awaits, sharing its result.
type SharedDial = Shared<BoxFuture<'static, Result<Channel, Status>>>;

#[derive(Default)]
enum ChannelState {
    #[default]
    Empty,
    /// A dial is running. `attempt` tells its result apart from a later one.
    Dialing {
        attempt: u64,
        dial: SharedDial,
    },
    Ready(Channel),
}

#[derive(Default)]
struct ChannelSlot {
    state: ChannelState,
    /// Dials started; also names each dial.
    attempts: u64,
    /// Bumped each time a channel is installed, so a call that failed on an
    /// old channel cannot discard its replacement.
    generation: u64,
    /// The [`AUTH_OUTAGE_HOLD`] the last timeout started, if any.
    hold: Option<Hold>,
}

struct Hold {
    until: tokio::time::Instant,
    /// The timeout's own message, which every call the hold fails repeats.
    message: String,
}

impl ChannelSlot {
    fn names(&self, attempt: u64) -> bool {
        matches!(&self.state, ChannelState::Dialing { attempt: current, .. } if *current == attempt)
    }

    /// The refusal for a call arriving now, while a hold is running.
    fn held(&self, now: tokio::time::Instant) -> Option<Status> {
        self.hold
            .as_ref()
            .filter(|hold| hold.until > now)
            .map(|hold| auth_unavailable_status(hold.message.clone()))
    }

    /// Starts (or restarts) the hold after a timeout carrying `message`.
    /// Logs only when no hold was running, so a burst of timeouts logs once.
    fn start_hold(&mut self, message: &str) {
        let now = tokio::time::Instant::now();
        if self.hold.as_ref().is_none_or(|hold| hold.until <= now) {
            warn!(
                "lore auth service timed out; failing auth calls at once for \
                 {AUTH_OUTAGE_HOLD:?}: {message}"
            );
        }
        self.hold = Some(Hold {
            until: now + AUTH_OUTAGE_HOLD,
            message: message.to_string(),
        });
    }
}

fn lock(slot: &Mutex<ChannelSlot>) -> MutexGuard<'_, ChannelSlot> {
    // The slot holds no invariant a panicking holder could break halfway.
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

/// FORK-LOCAL (Tideshift): one long-lived channel to one auth URL, shared by
/// every call. A tonic channel multiplexes calls over one HTTP/2 connection
/// and re-dials it after the connection drops, so a call no longer pays for a
/// DNS lookup, TCP connect and TLS handshake of its own.
///
/// Callers arriving while a dial runs share that one dial and its result,
/// failure included. The dial runs as its own task and records its own
/// outcome, so it finishes, bounded by [`AUTH_CONNECT_TIMEOUT`], even when
/// every caller waiting on it is cancelled. A failed dial leaves nothing
/// behind, so the first call after it dials again. A call that fails on a
/// broken connection discards the channel, so the next call dials a fresh
/// one rather than reusing a channel that can no longer serve. The lock is
/// never held across an await.
pub struct AuthChannel {
    auth_url: String,
    slot: Arc<Mutex<ChannelSlot>>,
}

impl AuthChannel {
    pub fn new(auth_url: String) -> Self {
        Self {
            auth_url,
            slot: Arc::default(),
        }
    }

    /// Dials started so far: a diagnostic, and what tests count.
    pub fn dial_attempts(&self) -> u64 {
        lock(&self.slot).attempts
    }

    /// Starts dial `attempt` as a net-runtime task that installs its channel,
    /// or clears the slot on failure, if the slot still names it. On the net
    /// runtime so the hyper/h2 driver tasks it spawns bind there rather than
    /// to the core runtime; without `LORE_CONTEXT`, as the connection
    /// outlives the request that happens to open it.
    fn start_dial(&self, slot: &mut ChannelSlot) -> (u64, SharedDial) {
        slot.attempts += 1;
        let attempt = slot.attempts;
        let auth_url = self.auth_url.clone();
        let shared = self.slot.clone();
        let task = lore_spawn_net_nocontext!(async move {
            let result = connect_auth_channel(auth_url).await;
            let mut slot = lock(&shared);
            if let Err(status) = &result
                && is_auth_unavailable(status)
            {
                slot.start_hold(status.message());
            }
            if slot.names(attempt) {
                match &result {
                    Ok(channel) => {
                        slot.generation = slot.generation.wrapping_add(1);
                        slot.state = ChannelState::Ready(channel.clone());
                    }
                    Err(_) => slot.state = ChannelState::Empty,
                }
            }
            result
        });
        let dial = async move {
            task.await
                .warn_map_err(|_| Status::internal("lore auth connection task failed"))?
        }
        .boxed()
        .shared();
        slot.state = ChannelState::Dialing {
            attempt,
            dial: dial.clone(),
        };
        (attempt, dial)
    }

    /// A client on the shared channel, dialling first when there is none.
    /// A failed dial is returned as the per-call path always returned it.
    /// Fails at once, sending nothing, while an [`AUTH_OUTAGE_HOLD`] runs.
    /// Starts the call's deadline: what is left of the request's
    /// [`AUTH_DEADLINE`] (see [`with_auth_budget`]), shared by the wait on a
    /// dial and the returned client's one call.
    pub async fn client(&self) -> Result<AuthClient<'_>, Status> {
        let started = tokio::time::Instant::now();
        let allowance = budget_left();
        let deadline = started + allowance;
        let (attempt, dial) = {
            let mut slot = lock(&self.slot);
            if let Some(refusal) = slot.held(started) {
                return Err(refusal);
            }
            match &slot.state {
                ChannelState::Ready(channel) => {
                    let channel = channel.clone();
                    return Ok(self.client_on(channel, Some(slot.generation), started, allowance));
                }
                ChannelState::Dialing { attempt, dial } => (*attempt, dial.clone()),
                ChannelState::Empty => self.start_dial(&mut slot),
            }
        };
        // Giving up on the wait leaves the dial running and named: its own
        // task records its outcome, and later callers still share it.
        let Ok(result) = tokio::time::timeout_at(deadline, dial).await else {
            debug!("lore auth connect did not finish within {allowance:?}");
            charge(started);
            let message = format!("lore auth service did not connect within {allowance:?}");
            // A request that spent most of its budget elsewhere says nothing
            // about the service: only a whole deadline starts a hold.
            if allowance == AUTH_DEADLINE {
                lock(&self.slot).start_hold(&message);
            }
            return Err(auth_unavailable_status(message));
        };
        let mut slot = lock(&self.slot);
        match result {
            Ok(channel) => {
                // A caller resuming late may find its channel discarded and
                // replaced: it takes the current one, under that one's
                // generation, rather than tagging an old channel with it.
                if let ChannelState::Ready(current) = &slot.state {
                    let current = current.clone();
                    return Ok(self.client_on(current, Some(slot.generation), started, allowance));
                }
                // Already discarded, no replacement yet: a channel that may
                // discard nothing.
                Ok(self.client_on(channel, None, started, allowance))
            }
            Err(status) => {
                charge(started);
                // Only a task that never finished leaves its attempt named.
                if slot.names(attempt) {
                    slot.state = ChannelState::Empty;
                }
                Err(status)
            }
        }
    }

    fn client_on(
        &self,
        channel: Channel,
        generation: Option<u64>,
        started: tokio::time::Instant,
        allowance: Duration,
    ) -> AuthClient<'_> {
        AuthClient {
            owner: self,
            generation,
            started,
            allowance,
            helper: LoreAuthClientHelper::new(channel),
        }
    }

    fn discard(&self, generation: u64) {
        let mut slot = lock(&self.slot);
        if matches!(slot.state, ChannelState::Ready(_)) && slot.generation == generation {
            slot.state = ChannelState::Empty;
        }
    }
}

/// Runs `call` for `allowance` from `started`: what was left of the request's
/// [`AUTH_DEADLINE`]. A timeout becomes an [`auth_unavailable_status`], which
/// [`is_connection_failure`] matches (it has a source), and which every
/// caller's error mapping passes on as a failure, never an allow.
async fn within_deadline<T>(
    rpc: &str,
    started: tokio::time::Instant,
    allowance: Duration,
    call: impl Future<Output = LoreAuthApiResult<T>>,
) -> LoreAuthApiResult<T> {
    tokio::time::timeout_at(started + allowance, call)
        .await
        .unwrap_or_else(|_elapsed| {
            debug!("lore auth {rpc} did not answer within {allowance:?}");
            Err(auth_unavailable_status(format!(
                "lore auth service did not answer {rpc} within {allowance:?}"
            )))
        })
}

/// One caller's handle on an [`AuthChannel`]'s connection, for one call: the
/// call gets only what remains of the deadline [`AuthChannel::client`] started.
pub struct AuthClient<'a> {
    owner: &'a AuthChannel,
    /// The installed channel this client uses; `None` when it is not the
    /// installed one, so its failures discard nothing.
    generation: Option<u64>,
    /// When [`AuthChannel::client`] was called: the call's charge to the
    /// request's budget runs from here.
    started: tokio::time::Instant,
    /// What was left of the request's [`AUTH_DEADLINE`] when
    /// [`AuthChannel::client`] was called; the call's deadline runs from
    /// `started`.
    allowance: Duration,
    helper: LoreAuthClientHelper,
}

impl AuthClient<'_> {
    fn settle<T>(&self, result: LoreAuthApiResult<T>) -> LoreAuthApiResult<T> {
        charge(self.started);
        // A call that had only the rest of a spent budget and ran out of it
        // says nothing about the service or the connection: it neither starts
        // a hold nor discards the channel.
        let budget_short = self.allowance < AUTH_DEADLINE
            && matches!(&result, Err(status) if is_auth_unavailable(status));
        match &result {
            // Only this module's own timeout starts a hold; any status the
            // service sent, a denial included, does not.
            Err(status) if is_auth_unavailable(status) && !budget_short => {
                lock(&self.owner.slot).start_hold(status.message());
            }
            Err(_) => {}
            // The service answered: any hold is over.
            Ok(_) => lock(&self.owner.slot).hold = None,
        }
        if let Err(status) = &result
            && !budget_short
            && is_connection_failure(status)
            && let Some(generation) = self.generation
        {
            debug!("Discarding the lore auth channel after a connection failure: {status}");
            self.owner.discard(generation);
        }
        result
    }

    pub async fn check_user_permission(
        &mut self,
        request: Request<CheckUserPermissionRequest>,
    ) -> LoreAuthApiResult<CheckUserPermissionResponse> {
        let result = within_deadline(
            "check_user_permission",
            self.started,
            self.allowance,
            self.helper.check_user_permission(request),
        )
        .await;
        self.settle(result)
    }

    pub async fn lookup_user_permissions(
        &mut self,
        request: Request<LookupUserPermissionsRequest>,
    ) -> LoreAuthApiResult<LookupUserPermissionsResponse> {
        let result = within_deadline(
            "lookup_user_permissions",
            self.started,
            self.allowance,
            self.helper.lookup_user_permissions(request),
        )
        .await;
        self.settle(result)
    }
}
impl LoreAuthClientHelper {
    fn new(channel: Channel) -> LoreAuthClientHelper {
        let client = UrcAuthApiClient::with_interceptor(channel, CorrelationInterceptor);
        LoreAuthClientHelper { client }
    }

    pub async fn lookup_user_permissions(
        &mut self,
        request: Request<LookupUserPermissionsRequest>,
    ) -> LoreAuthApiResult<LookupUserPermissionsResponse> {
        timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("lookup_user_permissions"),
            self.client.lookup_user_permissions(request).await
        )
        .result
    }

    pub async fn check_user_permission(
        &mut self,
        request: Request<CheckUserPermissionRequest>,
    ) -> LoreAuthApiResult<CheckUserPermissionResponse> {
        timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("check_user_permission"),
            self.client.check_user_permission(request).await
        )
        .result
    }
}

impl InstrumentProvider for LoreAuthClientHelper {
    fn namespace(&self) -> &'static str {
        "urc.authnz.urc_auth"
    }
}

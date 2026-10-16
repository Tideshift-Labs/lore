// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
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

use crate::grpc::ServerResultExt;

type LoreAuthApiResult<T> = Result<Response<T>, Status>;

/// FORK-LOCAL (Tideshift): ceiling on the TCP connect of a dial to the auth
/// service (not DNS, not the TLS handshake). Every caller waiting on a dial
/// waits at most this long for the connect. Matches the internal gRPC
/// client's default; no per-call deadline exists on this path to stay under.
pub const AUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
/// per-call path always returned. The endpoint build (which loads the native
/// root store for `https`) and the connect (DNS, TCP, TLS, HTTP/2 handshake)
/// are timed separately at debug level.
async fn connect_auth_channel(auth_url: String) -> Result<Channel, Status> {
    let started = Instant::now();
    let endpoint = auth_endpoint(&auth_url)?;
    let endpoint_built = started.elapsed();
    // Connect from net so the hyper/h2 driver tasks this spawns bind there
    // rather than to the core runtime the caller runs on. No `LORE_CONTEXT`:
    // the connection outlives the request that happens to open it.
    let channel = lore_spawn_net_nocontext!(async move { endpoint.connect().await })
        .await
        .warn_map_err(|_| Status::internal("lore auth connection task failed"))?
        .warn_map_err(|_| Status::internal("Failed to connect to lore auth service"))?;
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
}

/// FORK-LOCAL (Tideshift): one long-lived channel to one auth URL, shared by
/// every call. A tonic channel multiplexes calls over one HTTP/2 connection
/// and re-dials it after the connection drops, so a call no longer pays for a
/// DNS lookup, TCP connect and TLS handshake of its own.
///
/// Callers arriving while a dial runs share that one dial and its result,
/// failure included. A failed dial installs nothing, so the first call after
/// it dials again. A call that fails on a broken connection discards the
/// channel, so the next call dials a fresh one rather than reusing a channel
/// that can no longer serve. The lock is never held across an await.
pub struct AuthChannel {
    auth_url: String,
    slot: Mutex<ChannelSlot>,
}

impl AuthChannel {
    pub fn new(auth_url: String) -> Self {
        Self {
            auth_url,
            slot: Mutex::new(ChannelSlot::default()),
        }
    }

    fn slot(&self) -> MutexGuard<'_, ChannelSlot> {
        // The slot holds no invariant a panicking holder could break halfway.
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Dials started so far: a diagnostic, and what tests count.
    pub fn dial_attempts(&self) -> u64 {
        self.slot().attempts
    }

    /// A client on the shared channel, dialling first when there is none.
    /// A failed dial is returned as the per-call path always returned it.
    pub async fn client(&self) -> Result<AuthClient<'_>, Status> {
        let (attempt, dial) = {
            let mut slot = self.slot();
            match &slot.state {
                ChannelState::Ready(channel) => {
                    let channel = channel.clone();
                    return Ok(self.client_on(channel, slot.generation));
                }
                ChannelState::Dialing { attempt, dial } => (*attempt, dial.clone()),
                ChannelState::Empty => {
                    slot.attempts += 1;
                    let attempt = slot.attempts;
                    let dial = connect_auth_channel(self.auth_url.clone()).boxed().shared();
                    slot.state = ChannelState::Dialing {
                        attempt,
                        dial: dial.clone(),
                    };
                    (attempt, dial)
                }
            }
        };
        let result = dial.await;
        let mut slot = self.slot();
        let ours = matches!(
            &slot.state,
            ChannelState::Dialing { attempt: current, .. } if *current == attempt
        );
        match result {
            Ok(channel) => {
                if ours {
                    slot.generation = slot.generation.wrapping_add(1);
                    slot.state = ChannelState::Ready(channel.clone());
                }
                // A caller resuming late may find the channel already
                // discarded; a generation no `Ready` holds never discards.
                let generation = match &slot.state {
                    ChannelState::Ready(_) => slot.generation,
                    _ => slot.generation.wrapping_sub(1),
                };
                Ok(self.client_on(channel, generation))
            }
            Err(status) => {
                if ours {
                    slot.state = ChannelState::Empty;
                }
                Err(status)
            }
        }
    }

    fn client_on(&self, channel: Channel, generation: u64) -> AuthClient<'_> {
        AuthClient {
            owner: self,
            generation,
            helper: LoreAuthClientHelper::new(channel),
        }
    }

    fn discard(&self, generation: u64) {
        let mut slot = self.slot();
        if matches!(slot.state, ChannelState::Ready(_)) && slot.generation == generation {
            slot.state = ChannelState::Empty;
        }
    }
}

/// One caller's handle on an [`AuthChannel`]'s connection.
pub struct AuthClient<'a> {
    owner: &'a AuthChannel,
    generation: u64,
    helper: LoreAuthClientHelper,
}

impl AuthClient<'_> {
    fn settle<T>(&self, result: LoreAuthApiResult<T>) -> LoreAuthApiResult<T> {
        if let Err(status) = &result
            && is_connection_failure(status)
        {
            debug!("Discarding the lore auth channel after a connection failure: {status}");
            self.owner.discard(self.generation);
        }
        result
    }

    pub async fn check_user_permission(
        &mut self,
        request: Request<CheckUserPermissionRequest>,
    ) -> LoreAuthApiResult<CheckUserPermissionResponse> {
        let result = self.helper.check_user_permission(request).await;
        self.settle(result)
    }

    pub async fn lookup_user_permissions(
        &mut self,
        request: Request<LookupUserPermissionsRequest>,
    ) -> LoreAuthApiResult<LookupUserPermissionsResponse> {
        let result = self.helper.lookup_user_permissions(request).await;
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

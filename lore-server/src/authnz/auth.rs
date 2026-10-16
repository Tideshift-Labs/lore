// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;
use std::time::Instant;

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
use tokio::sync::Mutex;
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
async fn connect_auth_channel(auth_url: &str) -> Result<Channel, Status> {
    let started = Instant::now();
    let endpoint = auth_endpoint(auth_url)?;
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
fn is_connection_failure(status: &Status) -> bool {
    status.code() == Code::Unavailable || std::error::Error::source(status).is_some()
}

#[derive(Default)]
struct ChannelSlot {
    /// Bumped each time a channel is installed, so a call that failed on an
    /// old channel cannot discard its replacement.
    generation: u64,
    channel: Option<Channel>,
}

/// FORK-LOCAL (Tideshift): one long-lived channel to one auth URL, shared by
/// every call. A tonic channel multiplexes calls over one HTTP/2 connection
/// and re-dials it after the connection drops, so a call no longer pays for a
/// DNS lookup, TCP connect and TLS handshake of its own.
///
/// The first call dials; concurrent first calls wait for that one dial. A
/// failed dial installs nothing, so the next call dials again. A call that
/// fails on a broken connection discards the channel, so the next call dials
/// a fresh one rather than reusing a channel that can no longer serve.
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

    /// A client on the shared channel, dialling first when there is none.
    /// A failed dial is returned as the per-call path always returned it.
    pub async fn client(&self) -> Result<AuthClient<'_>, Status> {
        let mut slot = self.slot.lock().await;
        let channel = if let Some(channel) = &slot.channel {
            channel.clone()
        } else {
            let channel = connect_auth_channel(&self.auth_url).await?;
            slot.generation = slot.generation.wrapping_add(1);
            slot.channel = Some(channel.clone());
            channel
        };
        Ok(AuthClient {
            owner: self,
            generation: slot.generation,
            helper: LoreAuthClientHelper::new(channel),
        })
    }

    async fn discard(&self, generation: u64) {
        let mut slot = self.slot.lock().await;
        if slot.generation == generation {
            slot.channel = None;
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
    async fn settle<T>(&self, result: LoreAuthApiResult<T>) -> LoreAuthApiResult<T> {
        if let Err(status) = &result
            && is_connection_failure(status)
        {
            debug!("Discarding the lore auth channel after a connection failure: {status}");
            self.owner.discard(self.generation).await;
        }
        result
    }

    pub async fn check_user_permission(
        &mut self,
        request: Request<CheckUserPermissionRequest>,
    ) -> LoreAuthApiResult<CheckUserPermissionResponse> {
        let result = self.helper.check_user_permission(request).await;
        self.settle(result).await
    }

    pub async fn lookup_user_permissions(
        &mut self,
        request: Request<LookupUserPermissionsRequest>,
    ) -> LoreAuthApiResult<LookupUserPermissionsResponse> {
        let result = self.helper.lookup_user_permissions(request).await;
        self.settle(result).await
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

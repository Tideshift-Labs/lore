// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;

const MIN_HMAC_KEY_BYTES: usize = 32;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing;
use blake3;
use hex;
use lore_base::lore_spawn_net;
use lore_telemetry::http_tower_layer::HttpMetricsLayer;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use ring::hmac;
use tokio::net::TcpListener;
use tracing::info;

use super::drain_status;
use super::event_readiness;
use super::health_check;
use super::presigned;
use super::security_headers::ContentTypeAllowlist;
use super::security_headers::ContentTypePolicy;
use super::security_headers::PolicyField;
use super::tracing::lore_http_tracing;
use crate::auth::jwt::JwtVerifier;
use crate::auth::jwt_axum_middleware::jwt_axum_verify_authorization;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::correlation::layer::CorrelationIdLayerBuilder;
use crate::drain::DrainState;
use crate::http::repositories;
use crate::util::core_hop::CoreHopLayer;

#[derive(Clone, Debug)]
pub struct LoreHttpServer {}

/// Configuration for the pre-signed URL vending and redemption feature.
/// Absent in test contexts; required for production (startup fails without it).
#[derive(Clone)]
pub struct PresignConfig {
    /// HMAC-SHA256 signing key.
    pub hmac_key: hmac::Key,
    /// First 16 hex chars of the BLAKE3 hash of the raw key bytes.
    pub key_id: String,
    pub min_ttl_seconds: u64,
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    /// Allowlist of `Content-Type` values that redeemed content may be served
    /// with. Disallowed types are rejected at mint and coerced to
    /// `application/octet-stream` at redeem.
    pub content_type_allowlist: ContentTypeAllowlist,
}

#[derive(Clone)]
pub struct ServerState {
    pub immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    pub mutable_store: Arc<dyn lore_storage::MutableStore>,
    pub jwt_verifier: Option<JwtVerifier>,
    pub repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    pub max_file_size: u64,
    pub presign_config: Option<PresignConfig>,
    /// FORK-LOCAL (Tideshift, ADR-00011): the `enforce_write_permission`
    /// setting. Every route that mutates repository state checks the fork
    /// claim reader for `write` (see `put_repository_content`); upstream's
    /// authorizer only decides whether the repository is reachable.
    pub enforce_write_permission: bool,
}

/// The readiness facets `/event_readiness` reports, grouped so [`serve`]'s
/// signature stays readable as facets are added.
///
/// [`serve`]: LoreHttpServer::serve
#[derive(Default)]
pub struct HealthFacets {
    pub write_behind: Option<Arc<crate::fragment_write_behind::FragmentWriteBehindReadiness>>,
    /// CR-032's event-plane facets, when this cell runs a relay.
    pub event_relay: Option<Arc<crate::event_relay::readiness::EventRelayReadiness>>,
    /// WP-114 CD-6's terminal write-claim prune facet, when this cell runs the
    /// scheduler.
    pub fragment_prune: Option<Arc<crate::fragment_prune::FragmentPruneReadiness>>,
    /// WP-114 CD-8's cell-scale retention facet, when this cell runs the
    /// scheduler.
    pub cell_retention: Option<Arc<lore_object_dispatch::cell_retention::CellRetentionReadiness>>,
}

pub struct ServerHealth {
    pub write_behind: Option<Arc<crate::fragment_write_behind::FragmentWriteBehindReadiness>>,
    pub immutable_store: Weak<dyn lore_storage::ImmutableStore>,
    pub available: AtomicBool,
    pub interval_timeout: Option<(Duration, Duration)>,
    pub store_health_check: bool,
    /// Aggregate drain view; when present and draining, `/health_check`
    /// reports 503 so load balancers pull the node, and `/drain_status`
    /// reports the remaining active connections.
    pub drain: Option<Arc<DrainState>>,
    /// CR-032's event-plane facets, when this cell runs a relay.
    ///
    /// Read only by `/event_readiness`. It is deliberately **not** consulted by
    /// `/health_check`: CR-032 requires storage readiness to be separate, so
    /// broker loss cannot pull a node that is serving reads perfectly well out
    /// of the load balancer.
    pub event_relay: Option<Arc<crate::event_relay::readiness::EventRelayReadiness>>,
    /// WP-114 CD-6's terminal write-claim prune facet, when this cell runs the
    /// scheduler.
    ///
    /// On `/event_readiness` beside the relay facets, and — same rule as
    /// `event_relay` — deliberately **not** consulted by `/health_check`. An
    /// evidence table that has stopped draining is an activation-blocking
    /// condition an operator must see; it is not a reason to stop serving
    /// reads, and putting it behind the load balancer's probe would make it
    /// one.
    pub fragment_prune: Option<Arc<crate::fragment_prune::FragmentPruneReadiness>>,
    /// WP-114 CD-8's cell-scale retention facet, when this cell runs the
    /// scheduler.
    ///
    /// Same placement rule as `fragment_prune`: reported on `/event_readiness`,
    /// never consulted by `/health_check`. A dispatch evidence table that has
    /// stopped draining blocks activation and must be visible; it is not a
    /// reason to pull a node that is serving reads.
    pub cell_retention: Option<Arc<lore_object_dispatch::cell_retention::CellRetentionReadiness>>,
}

impl ServerHealth {
    pub fn new_without_availability(
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    ) -> Self {
        ServerHealth {
            write_behind: None,
            immutable_store: Arc::downgrade(&immutable_store),
            available: AtomicBool::new(true),
            interval_timeout: None,
            store_health_check: false,
            drain: None,
            event_relay: None,
            fragment_prune: None,
            cell_retention: None,
        }
    }
}

#[derive(Default)]
pub struct PresignSettings {
    pub hmac_key: Option<String>,
    pub min_ttl_seconds: u64,
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub content_type_policy: ContentTypePolicy,
}

#[derive(Default)]
pub struct LoreHttpServerSettings {
    pub caller_capability_policy: crate::grpc::caller_capabilities::CallerCapabilityPolicy,
    pub host: String,
    pub port: i32,
    pub max_file_size: u64,
    pub request_timeout_seconds: u64,
    pub request_body_timeout_seconds: u64,
    pub available_interval_seconds: u64,
    pub available_timeout_seconds: u64,
    pub store_health_check: bool,
    pub presign: PresignSettings,
    /// User-agent filter applied to HTTP metrics labels.
    pub user_agent_filter: Arc<UserAgentFilter>,
    /// FORK-LOCAL (Tideshift, ADR-00011): copied into
    /// [`ServerState::enforce_write_permission`]. The launcher sets it from
    /// `[server.auth]`, as it does for the gRPC and QUIC surfaces.
    pub enforce_write_permission: bool,
}

impl LoreHttpServerSettings {
    /// Settings suitable for unit tests: generous timeouts so a zero-duration
    /// `TimeoutLayer` (the result of `u64::default() == 0`) does not race
    /// against async handlers
    #[cfg(feature = "test-util")]
    pub fn test_default() -> Self {
        Self {
            request_timeout_seconds: 30,
            request_body_timeout_seconds: 30,
            ..Self::default()
        }
    }
}

#[lore_macro::test_pub]
fn apply_presigned_transport_limits(
    router: Router,
    max_file_size: u64,
    settings: &LoreHttpServerSettings,
) -> Router {
    // This route bypasses `authenticated_router`, so it needs its own transport limits.
    router
        .layer(DefaultBodyLimit::max(max_file_size as usize))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(settings.request_timeout_seconds),
        ))
        .layer(tower_http::timeout::RequestBodyTimeoutLayer::new(
            Duration::from_secs(settings.request_body_timeout_seconds),
        ))
}

// Expose a testable router factory
pub fn create_router(
    shared_state: ServerState,
    health: ServerHealth,
    settings: &LoreHttpServerSettings,
) -> Router {
    let repository_router: Router<ServerState> = repositories::create_router(shared_state.clone());
    let authenticated_router = Router::new()
        .nest("/repository", repository_router)
        .route_layer(middleware::from_fn_with_state(
            shared_state.clone(),
            jwt_axum_verify_authorization,
        ))
        // Do not process request that have more than 10 MiB in the body
        .layer(DefaultBodyLimit::max(shared_state.max_file_size as usize))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(settings.request_timeout_seconds),
        ))
        .layer(tower_http::timeout::RequestBodyTimeoutLayer::new(
            Duration::from_secs(settings.request_body_timeout_seconds),
        ))
        .with_state(shared_state.clone());

    let upload_drain = health.drain.clone();
    let server_health = Arc::new(health);
    let unauthenticated_router = Router::new()
        .route(
            "/health_check",
            routing::get(health_check::handler).with_state(server_health.clone()),
        )
        .route(
            "/drain_status",
            routing::get(drain_status::handler).with_state(server_health.clone()),
        )
        .route(
            "/event_readiness",
            routing::get(event_readiness::handler).with_state(server_health.clone()),
        )
        .route(
            "/caller_capability_readiness",
            routing::get(caller_capability_readiness).with_state(settings.caller_capability_policy),
        );

    crate::store::spawn_immutable_store_availability_monitor(server_health);

    let mut router = Router::new()
        .merge(unauthenticated_router)
        .nest("/v1", authenticated_router);

    if shared_state.presign_config.is_some() {
        let presigned_router = apply_presigned_transport_limits(
            presigned::create_router(Arc::new(shared_state.clone())),
            shared_state.max_file_size,
            settings,
        );

        router = router.nest("/v1/presigned", presigned_router);
    }

    router
        .layer(middleware::from_fn_with_state(
            settings.caller_capability_policy,
            caller_capability_admission,
        ))
        // Outside admission, as `GrpcDrainLayer` sits outside the gRPC
        // `CallerCapabilityLayer`.
        .layer(middleware::from_fn_with_state(
            upload_drain,
            content_upload_drain,
        ))
        .layer(middleware::from_fn(lore_http_tracing))
        .layer(CorrelationIdLayerBuilder::new().with_http_tracer().build())
        .layer(HttpMetricsLayer::new(settings.user_agent_filter.clone()))
        // Outermost, so everything inward runs on core: this router is served
        // from net.
        .layer(CoreHopLayer)
}

/// Maps a policy list to the config key that populates it.
fn presign_content_type_field(field: PolicyField) -> &'static str {
    match field {
        PolicyField::Extra => "presigned_url_extra_content_types",
        PolicyField::Denied => "presigned_url_denied_content_types",
    }
}

/// Renders the resolved allowlist for the startup log.
#[lore_macro::test_pub]
fn describe_allowed_types(types: &[String]) -> String {
    if types.is_empty() {
        "<none>".to_string()
    } else {
        types.join(", ")
    }
}

#[lore_macro::test_pub]
fn build_presign_config(settings: &PresignSettings) -> Result<Option<PresignConfig>> {
    let Some(key_hex) = settings.hmac_key.as_deref() else {
        return Ok(None);
    };

    let key_bytes = hex::decode(key_hex)
        .map_err(|e| anyhow::anyhow!("presigned_url_hmac_key is not valid hex: {e}"))?;

    if key_bytes.len() < MIN_HMAC_KEY_BYTES {
        anyhow::bail!(
            "presigned_url_hmac_key must be at least {MIN_HMAC_KEY_BYTES} bytes, got {}",
            key_bytes.len()
        );
    }

    let key_id = blake3::hash(&key_bytes).to_hex()[..16].to_string();
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);

    Ok(Some(PresignConfig {
        hmac_key,
        key_id,
        min_ttl_seconds: settings.min_ttl_seconds,
        default_ttl_seconds: settings.default_ttl_seconds,
        max_ttl_seconds: settings.max_ttl_seconds,
        content_type_allowlist: ContentTypeAllowlist::try_from_policy(
            &settings.content_type_policy,
        )
        .map_err(|err| anyhow!("{} {err}", presign_content_type_field(err.field())))?,
    }))
}

/// Report the immutable policy held by this running HTTP surface.
pub async fn caller_capability_readiness(
    axum::extract::State(policy): axum::extract::State<
        crate::grpc::caller_capabilities::CallerCapabilityPolicy,
    >,
) -> axum::Json<serde_json::Value> {
    use crate::grpc::caller_capabilities::CallerCapabilityPolicy;
    let required = policy == CallerCapabilityPolicy::RequireOutcomeUnknownV1;
    // FORK-LOCAL (Tideshift, WP-124): same order as ServerInfo.
    let features = if required {
        vec![
            "outcome_unknown_v1",
            "quic_caller_declaration_v1",
            "requires_outcome_unknown_v1",
        ]
    } else {
        vec!["outcome_unknown_v1", "quic_caller_declaration_v1"]
    };
    axum::Json(serde_json::json!({
        "policy": if required { "require_outcome_unknown_v1" } else { "compatible_single_replica" },
        "features": features,
        "contract": "grpc-caller-capability-admission-v1",
    }))
}

/// HTTP content uploads share the pre-body declaration grammar with gRPC.
/// Content reads and presign vending retain their existing access checks.
pub async fn caller_capability_admission(
    axum::extract::State(policy): axum::extract::State<
        crate::grpc::caller_capabilities::CallerCapabilityPolicy,
    >,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    use crate::grpc::caller_capabilities::ADMISSION_HEADER;
    use crate::grpc::caller_capabilities::CallerCapabilityPolicy;
    use crate::grpc::caller_capabilities::declares_outcome_unknown;
    if policy == CallerCapabilityPolicy::RequireOutcomeUnknownV1
        && request.method() == http::Method::PUT
        && !matches!(declares_outcome_unknown(request.headers()), Ok(true))
    {
        return (
            http::StatusCode::PRECONDITION_FAILED,
            [(ADMISSION_HEADER, "unsupported-client")],
            "unsupported client capability",
        )
            .into_response();
    }
    next.run(request).await
}

/// FORK-LOCAL (Tideshift): the drain gate for HTTP content uploads, matching
/// public gRPC.
///
/// A PUT is counted as public RPC work for as long as it runs, so a graceful
/// drain waits for it as it waits for a gRPC `Put` (`GrpcDrainLayer`). Once
/// admission closes (draining, lame duck over), a new PUT is refused with 503
/// before its body is read, as tonic refuses a new call after shutdown; the
/// client retries on another node. During the lame-duck period PUTs are still
/// served, as gRPC is. Reads, health and drain status are not affected, so a
/// deploy controller can poll `/drain_status` through the drain.
pub async fn content_upload_drain(
    axum::extract::State(drain): axum::extract::State<Option<Arc<DrainState>>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let Some(drain) = drain.filter(|_| request.method() == http::Method::PUT) else {
        return next.run(request).await;
    };
    // Count first, then check. Checking first left a window in which the lame
    // duck could end and `wait_idle` read zero between an admitted PUT's check
    // and its count, so the drain finished with the PUT still to run.
    let guard = drain.begin_rpc();
    if drain.is_draining() && !drain.is_lame_duck() {
        drop(guard);
        return (
            http::StatusCode::SERVICE_UNAVAILABLE,
            [(http::header::RETRY_AFTER, "1")],
            "server draining",
        )
            .into_response();
    }
    let response = next.run(request).await;
    drop(guard);
    response
}

impl LoreHttpServer {
    /// Starts a minimal HTTP server that only serves the `/health_check` endpoint.
    ///
    /// Used during maintenance mode so that load balancers and monitoring systems
    /// can still reach the server. Always returns 200 OK (store health checks are
    /// disabled since the server is intentionally in a reduced state).
    pub async fn serve_maintenance(
        host: String,
        port: i32,
        user_agent_filter: Arc<UserAgentFilter>,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        let addr = SocketAddr::from_str(format!("{host}:{port}").as_str())
            .map_err(|err| anyhow!("Failed to start maintenance HTTP server: {err}"))?;
        info!("Starting Lore maintenance HTTP Server: {}", &addr);

        let health = Arc::new(ServerHealth {
            write_behind: None,
            immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
            available: AtomicBool::new(true),
            interval_timeout: None,
            store_health_check: false,
            drain: None,
            event_relay: None,
            fragment_prune: None,
            cell_retention: None,
        });

        let app = Router::new()
            .route(
                "/health_check",
                routing::get(health_check::handler).with_state(health),
            )
            .layer(HttpMetricsLayer::new(user_agent_filter))
            .layer(CoreHopLayer);

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|err| anyhow!("Failed to start maintenance HTTP server: {err}"))?;
        lore_spawn_net!(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(signal)
                .await
        })
        .await??;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn serve(
        settings: LoreHttpServerSettings,
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
        jwt_verifier: Option<JwtVerifier>,
        repository_authorizer: Arc<dyn RepositoryAuthorizer>,
        drain: Option<Arc<DrainState>>,
        facets: HealthFacets,
        signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        let addr = SocketAddr::from_str(format!("{}:{}", settings.host, settings.port).as_str())
            .map_err(|err| anyhow!("Failed to start HTTP server: {err}"))?;
        info!(
            "Starting Lore HTTP Server: {}, Auth: {}",
            &addr,
            jwt_verifier.as_ref().map_or("no", |_| "yes")
        );

        let health = ServerHealth {
            write_behind: facets.write_behind,
            immutable_store: Arc::downgrade(&immutable_store),
            available: AtomicBool::new(true),
            interval_timeout: if settings.available_interval_seconds > 0
                && settings.available_timeout_seconds > 0
            {
                Some((
                    Duration::from_secs(settings.available_interval_seconds),
                    Duration::from_secs(settings.available_timeout_seconds),
                ))
            } else {
                None
            },
            store_health_check: settings.store_health_check,
            drain,
            event_relay: facets.event_relay,
            fragment_prune: facets.fragment_prune,
            cell_retention: facets.cell_retention,
        };

        let presign_config = build_presign_config(&settings.presign)?;
        if let Some(cfg) = presign_config.as_ref() {
            // Log the resolved set so operators can confirm what their config produced.
            info!(
                "Presigned URL feature enabled (key_id: {}, allowed content types: {})",
                cfg.key_id,
                describe_allowed_types(&cfg.content_type_allowlist.allowed_types())
            );
        } else {
            info!("Presigned URL feature disabled (presigned_url_hmac_key not configured)");
        }

        let shared_state = ServerState {
            immutable_store,
            mutable_store,
            jwt_verifier,
            repository_authorizer,
            max_file_size: settings.max_file_size,
            presign_config,
            enforce_write_permission: settings.enforce_write_permission,
        };

        let app = create_router(shared_state, health, &settings);

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|err| anyhow!("Failed to start HTTP server: {err}"))?;
        lore_spawn_net!(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(signal)
                .await
        })
        .await??;

        Ok(())
    }
}

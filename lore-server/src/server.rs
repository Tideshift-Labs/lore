// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Server entry point for Lore Server.
//!
//! This module provides [`server_main()`], the public entry point that both the
//! base `loreserver` binary and derived server binaries (e.g., `lore-server-epic`)
//! call after configuring their [`ServerConfig`](crate::server_config::ServerConfig).

#[cfg(feature = "seeding")]
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use clap::Subcommand;
use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::runtime::LoreTaskLifecycleEvent;
use lore_base::runtime::LoreTaskSpawn;
use lore_base::runtime::TaskLifecycleObserver;
use lore_base::runtime::runtime;
use lore_base::runtime::runtime_with_settings;
use lore_base::runtime::set_task_lifecycle_observer;
use lore_base::version::LORE_LIBRARY_VERSION;
use lore_postgres::domain::fragments::FragmentCellRetentionHandle;
use lore_postgres::store::fragment_write_behind::FragmentWriteBehindHandle;
use lore_postgres::store::write_behind::WriteBehindStage;
use lore_revision::cluster::topology::Topology;
use lore_revision::environment::EnvironmentConfig;
use lore_revision::lock::LockStore;
use lore_revision::notification::NotificationSender;
use lore_revision::runtime::execution_context;
use lore_revision::store::composite::CompositeStoreBuilder;
use lore_revision::store::remote::RemoteImmutableStore;
use lore_revision::store::remote::RemoteMutableStore;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use lore_storage::assume_server_policies;
use lore_storage::compress::COMPRESSION_MODE;
use lore_storage::hash::StringHash;
use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
use lore_telemetry::execution_state::ServerExecutionState;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use lore_transport::make_user_agent_with_component;
use lore_transport::quic::client;
use lore_transport::quic::client::ClientCerts;
use lore_transport::quic::client::STREAM_COUNT;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::client::StorageClient;
use lore_transport::set_fallback_user_agent_product;
use lore_transport::user_agent_product;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry::metrics::UpDownCounter;
use opentelemetry_sdk::resource::ResourceDetector;
use rustls::server::NoClientAuth;
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tracing::Instrument;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::info_span;
use tracing::trace;
use tracing::warn;

use crate::auth::jwk::JwkServiceImpl;
use crate::auth::jwt::JwtVerifier;
use crate::auth::oidc::advertised_oidc;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::authnz::repository_catalog::RepositoryCatalog;
use crate::drain::ConnectionRegistry;
use crate::drain::DrainState;
use crate::drain::DrainTimeouts;
use crate::drain::QuinnConnectionRegistry;
use crate::drain::run_drain;
use crate::drain::spawn_drain_metrics;
use crate::grpc::GrpcInternalServerBuilder;
use crate::grpc::GrpcServerBuilder;
use crate::grpc::GrpcTimeouts;
use crate::grpc::forwarded_requests::ForwardedRequests;
use crate::grpc::forwarded_requests::GrpcForwardedRequests;
use crate::grpc::notification_service::NotificationService;
use crate::hooks::HookDispatcher;
use crate::hooks::HookRegistrationContext;
use crate::hooks::HookRegistry;
use crate::http::LoreHttpServer;
use crate::http::security_headers::ContentTypePolicy;
use crate::http::server::LoreHttpServerSettings;
use crate::http::server::PresignSettings;
use crate::plugins;
use crate::plugins::MutableStorePluginContext;
use crate::plugins::PluginRegistry;
use crate::plugins::traits::NotificationPluginContext;
use crate::protocol::attribute_map::AttributeMap;
use crate::quic::StreamDataHandler;
use crate::quic::StreamHandlerFactory;
use crate::quic::quinn::QuinnConfigBuilder;
use crate::quic::quinn::QuinnServer;
use crate::quic::quinn::build_cert_verifier;
use crate::quic::quinn::service_store::ServiceStore;
use crate::quic::quinn::service_store::StreamDataHandlerBuilder;
use crate::quic::replication_store_service;
use crate::quic::replication_store_service::client::ReplicationStoreClient;
use crate::quic::replication_store_service::client_container;
use crate::quic::replication_store_service::client_container::ClientContainerConfig;
use crate::quic::replication_store_service::server::ReplicationStoreService;
use crate::quic::storage_service::StorageService;
use crate::quic::stream_handler::AdmissionLimits;
use crate::quic::stream_handler::StreamHandler;
use crate::server_config::ServerConfig;
use crate::settings::CompositeStoreSettings;
use crate::settings::CompositeSubStoreSettings;
use crate::settings::GrpcSettings;
use crate::settings::HttpSettings;
use crate::settings::ImmutableStoreSettings;
use crate::settings::LocalImmutableStoreSettings;
use crate::settings::LocalMutableStoreSettings;
use crate::settings::MutableStoreSettings;
use crate::settings::NotificationSettings;
use crate::settings::QuicSettings;
use crate::settings::RemoteStoreSettings;
use crate::settings::ReplicatedStoreSettings;
use crate::settings::ReplicationMode;
use crate::settings::Settings;
use crate::settings::default_authorization_timeout_seconds;
use crate::store::replica_factory::ReplicationStoreTargetFactory;
use crate::store::replicated_store::ReplicatedStore;
use crate::store::resolve_plugin_config_with_fallback;
use crate::telemetry::OtelTokioRuntimeMetrics;
use crate::telemetry::ResourceDetectorProvider;
use crate::telemetry::TelemetryInitializer;
use crate::tls::load_client_tls;
use crate::topology::configure_topology_with_registry;
use crate::util::setup_execution;

/// Store mode constants for string-based configuration of built-in store types
mod store_mode {
    pub const LOCAL: &str = "local";
    pub const REMOTE: &str = "remote";
    pub const COMPOSITE: &str = "composite";
    pub const REPLICATED: &str = "replicated";
    /// Build no store. `[lock_store]` only.
    pub const NONE: &str = "none";
}

/// Command-line options for the Lore server binary.
///
/// All configuration is optional: with no arguments the server starts from the
/// defaults baked into the binary. Both flags also fall back to their
/// corresponding environment variables.
#[derive(Debug, Parser)]
#[command(name = "loreserver", version, about = "Lore revision control server")]
pub struct Cli {
    /// Directory of TOML config files layered over the built-in defaults.
    ///
    /// When set, the server loads (if present) `default.toml`,
    /// `<environment>.toml`, `<environment>_<region>.toml`, and `local.toml`
    /// from this directory as overrides. When unset, only the built-in defaults
    /// and environment variables are used.
    #[arg(long, value_name = "DIR", env = "LORE_CONFIG_PATH")]
    pub config: Option<String>,

    /// Environment name selecting the `<environment>.toml` override to load.
    ///
    /// Defaults to `local` when neither the flag nor `LORE_ENV` is set.
    #[arg(long, value_name = "ENV", env = "LORE_ENV")]
    pub env: Option<String>,

    /// Rebuild the Postgres immutable store's exact metering projection, then
    /// exit without binding any server endpoint.
    ///
    /// This maintenance operation refuses to run unless the effective
    /// immutable-store mode is `postgres`.
    #[arg(long)]
    pub rebuild_postgres_metering: bool,

    /// A maintenance operation to run instead of serving.
    ///
    /// Optional, so `loreserver` with no arguments still starts a server
    /// exactly as before. See `event_relay::operator` for why CR-032's operator
    /// recovery surface is a subcommand rather than another flag beside
    /// `--rebuild-postgres-metering`.
    #[command(subcommand)]
    pub command: Option<MaintenanceOperation>,
}

/// Every maintenance operation this binary can run instead of serving.
///
/// One enum per owning subsystem, gathered here rather than in either of them:
/// `event_relay::operator` owns CR-032's outbox surface and `domain::operator`
/// owns CR-029's domain surface, and neither should have to name the other to
/// be reachable from the command line.
///
/// The outbox arm is `#[command(flatten)]`ed so its own `outbox` subcommand
/// keeps the exact spelling and help text it already had. Its enum and its
/// `run` signature are untouched, so nothing that already drives that surface
/// changes.
#[derive(Debug, Subcommand)]
pub enum MaintenanceOperation {
    /// CR-032's transactional event outbox (`loreserver outbox ...`).
    #[command(flatten)]
    Outbox(crate::event_relay::operator::MaintenanceCommand),
    /// CR-029's domain state: report it, or arm this cell.
    Domain {
        /// The operation to run.
        #[command(subcommand)]
        command: crate::domain::operator::DomainCommand,
    },
    /// The cell database's schema: validate the boot path's NOT VALID
    /// constraints.
    Schema {
        /// The operation to run.
        #[command(subcommand)]
        command: crate::domain::schema_operator::SchemaCommand,
    },
}

#[lore_macro::test_pub]
fn ensure_postgres_rebuild_mode(mode: &str) -> Result<()> {
    if mode != "postgres" {
        return Err(anyhow!(
            "--rebuild-postgres-metering requires immutable_store.mode = postgres; effective mode is '{mode}'"
        ));
    }
    Ok(())
}

async fn rebuild_postgres_metering(settings: &Settings) -> Result<u64> {
    let mode = settings.immutable_store.mode.as_str();
    ensure_postgres_rebuild_mode(mode)?;

    let plugin_config =
        resolve_plugin_config_with_fallback(&settings.plugins, mode, "immutable_store")
            .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));
    let fragment_provider_enabled = plugins::postgres::fragment_provider_enabled(&plugin_config)
        .map_err(|error| anyhow!("Invalid Postgres immutable store configuration: {error}"))?;
    if fragment_provider_enabled {
        // Validate the exact six-pool inventory before opening even the
        // provider-free domain pool. This is the same activation invariant as
        // normal server boot, but the validated value is deliberately not used
        // to construct S3, a provider gateway, or an object-dispatch client.
        //
        // The inventory it builds counts CR-032's relay pool whenever
        // `[outbox_relay]` is enabled, even though this maintenance path never
        // spawns the relay. That over-declares by five connections rather than
        // under-declaring, so it can only refuse a configuration that a serving
        // process would also refuse — never admit one it would reject.
        let process_pool_inventory = postgres_fragment_process_pool_inventory(settings)?
            .ok_or_else(|| anyhow!("enabled fragment_provider has no process pool inventory"))?;
        let _validated_process_pool_inventory = process_pool_inventory
            .validate()
            .map_err(|error| anyhow!("Invalid Postgres process pool inventory: {error}"))?;
        let configured_domain = crate::domain::configure_domain_context(settings).await?;
        let coordinator = configured_domain.fragment_coordinator.ok_or_else(|| {
            anyhow!(
                "enabled fragment_provider requires the Postgres fragment lifecycle coordinator"
            )
        })?;
        return coordinator
            .rebuild_metering_projection()
            .await
            .map_err(|error| {
                anyhow!("Failed to rebuild Postgres lifecycle metering projection: {error}")
            });
    }

    // The absent/disabled route keeps the legacy construction and provider
    // metadata rebuild unchanged.
    // No staging tier on the maintenance path, for the same reason it passes no
    // fragment activation: rebuilding the metering projection serves no PUT, so
    // a proven root and a running sampler would be cost without a consumer.
    let store = plugins::postgres::connect_immutable_store(&plugin_config, None, None)
        .await
        .map_err(|e| anyhow!("Failed to create Postgres immutable store: {e}"))?;

    store
        .rebuild_metering_projection()
        .await
        .map_err(|e| anyhow!("Failed to rebuild Postgres metering projection: {e}"))
}

/// Entry point for the Lore server.
///
/// Both the base `loreserver` binary and derived server binaries call this
/// function after configuring their [`ServerConfig`] with plugins, hooks,
/// and resource detectors.
///
/// This function:
/// 1. Loads settings from the configuration files
/// 2. Creates and configures the tokio runtime
/// 3. Initializes telemetry with the provided resource detectors
/// 4. Registers plugins and hooks
/// 5. Configures stores, starts endpoints, and runs until shutdown
///
/// # Example
///
/// ```no_run
/// use lore_server::server_config::ServerConfig;
///
/// // Base server with no plugins
/// lore_server::server::server_main(ServerConfig::default()).unwrap();
/// ```
pub fn server_main(config: ServerConfig) -> Result<()> {
    set_fallback_user_agent_product("lore-server".to_string());
    assume_server_policies();

    let cli = Cli::parse();
    let (settings, settings_hash) = Settings::load(cli.config.as_deref(), cli.env.as_deref())?;
    let runtime_shutdown_timeout = settings.server.runtime_shutdown_timeout_seconds;
    let rebuild_metering = cli.rebuild_postgres_metering;
    let maintenance = cli.command;
    // Both maintenance routes exit without binding an endpoint, so neither
    // waits on the endpoint-drain timeout below.
    let serving = !rebuild_metering && maintenance.is_none();

    lore_base::log::set_log_callback(Some(server_log_dispatch));

    // Server default: one net-runtime thread per processor — serving
    // thousands of concurrent client connections is its normal case. An
    // explicit `tokio.net_threads` config (seeded first inside
    // runtime_with_settings) wins over this default.
    let runtime_handle = match settings.tokio.as_ref() {
        Some(tokio) => runtime_with_settings(Some(tokio.clone())),
        None => runtime(),
    };
    let _ = lore_base::runtime::set_net_threads_default(
        std::thread::available_parallelism().map_or(2, |count| count.get()),
    );
    let result = runtime_handle.block_on({
        let execution = setup_execution(module_path!(), String::default(), String::default());
        #[allow(clippy::large_futures)]
        LORE_CONTEXT.scope(execution, async move {
            if rebuild_metering {
                let associated_hash_count = rebuild_postgres_metering(&settings).await?;
                // Maintenance CLI contract: stdout contains only the raw rebuilt-hash count so
                // deployment scripts can parse it without depending on the tracing format.
                println!("{associated_hash_count}");
                Ok(())
            } else if let Some(operation) = maintenance {
                // One bounded operation against the configured cell, then exit;
                // no endpoint is bound and no relay worker starts.
                match operation {
                    // CR-032's operator recovery surface (WP-119 Phase 8).
                    MaintenanceOperation::Outbox(command) => {
                        crate::event_relay::operator::run(&command, &settings).await
                    }
                    // CR-029/CR-030's cell arming surface (WP-120).
                    //
                    // Spawned rather than awaited inline, because `block_on`
                    // polls on the process's MAIN thread and `cutover` opens the
                    // Postgres immutable store, whose S3 client construction is
                    // a very deep async call in a debug build. Inline it
                    // overflowed the main thread's stack on Windows (1 MiB by
                    // default) before it could report anything; a runtime worker
                    // gets tokio's own, larger stack. Neither `Box::pin` nor the
                    // enclosing `#[allow(clippy::large_futures)]` helps — the
                    // cost is in the poll frames, not in the future's size.
                    MaintenanceOperation::Domain { command } => lore_spawn!(async move {
                        crate::domain::operator::run(&command, &settings).await
                    })
                    .await
                    .map_err(|error| {
                        anyhow!("The domain maintenance task did not complete: {error}")
                    })?,
                    MaintenanceOperation::Schema { command } => {
                        crate::domain::schema_operator::run(&command, &settings).await
                    }
                }
            } else {
                async_main((settings, settings_hash), config).await
            }
        })
    });

    if serving {
        info!("Wait up to {runtime_shutdown_timeout} seconds for runtime shutdown");
    }
    lore_base::runtime::runtime_shutdown_timeout(Duration::from_secs(
        runtime_shutdown_timeout as u64,
    ));

    result
}

/// Waits for a shutdown signal, then drains all endpoints within the given timeout.
///
/// 1. Waits for the shutdown signal (watch channel becomes `true`) or for an
///    endpoint to exit unexpectedly (which triggers the signal).
/// 2. Records the time the signal was received.
/// 3. Joins all remaining endpoint tasks.
/// 4. If the elapsed time since the signal exceeds `connection_close_timeout`,
///    force-closes any remaining endpoints. `None` disables the deadline and
///    waits indefinitely (graceful drain with `drain_timeout_seconds = 0`).
#[lore_macro::test_pub]
async fn wait_for_shutdown(
    mut endpoints: JoinSet<Result<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    connection_close_timeout: Option<Duration>,
) -> Result<()> {
    let mut shutdown_rx = shutdown_tx.subscribe();

    // Phase 1: wait for signal or unexpected endpoint exit
    info!("Server is up, waiting for shutdown signal");
    tokio::select! {
        _ = shutdown_rx.wait_for(|&v| v) => {}
        res = endpoints.join_next() => {
            match res {
                Some(Ok(Err(e))) => {
                    error!("Endpoint returned error: {e:?}, triggering shutdown");
                    let _ = shutdown_tx.send(true);
                }
                Some(Err(e)) => {
                    error!("Endpoint task failed: {e}, triggering shutdown");
                    let _ = shutdown_tx.send(true);
                }
                Some(Ok(Ok(()))) => {
                    info!("Endpoint exited, triggering shutdown");
                    let _ = shutdown_tx.send(true);
                }
                None => {
                    info!("All endpoints completed");
                    return Ok(());
                }
            }
        }
    }

    // Phase 2: drain remaining endpoints, timeout measured from now. With no
    // timeout configured (graceful drain, unbounded) the deadline arm never
    // fires and we wait for every endpoint to finish on its own.
    let deadline = connection_close_timeout.map(|t| tokio::time::Instant::now() + t);
    if let Some(timeout) = connection_close_timeout {
        info!("Draining remaining endpoints (timeout: {timeout:?})");
    } else {
        info!("Draining remaining endpoints (no timeout: waiting for graceful drain)");
    }

    loop {
        tokio::select! {
            res = endpoints.join_next() => {
                match res {
                    Some(Ok(Ok(()))) => info!("Endpoint shut down successfully"),
                    Some(Ok(Err(e))) => error!("Endpoint returned error during shutdown: {e:?}"),
                    Some(Err(e)) => error!("Endpoint task failed: {e}"),
                    None => {
                        info!("All endpoints shut down gracefully");
                        return Ok(());
                    }
                }
            }
            _ = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                warn!(
                    "Connection close timeout ({connection_close_timeout:?}) exceeded, \
                     force-closing remaining endpoints"
                );
                endpoints.shutdown().await;
                return Ok(());
            }
        }
    }
}

/// Counts termination signals into `termination_tx`. The first starts the
/// shutdown; a second during the lame-duck period ends that period early.
async fn listen_for_termination(termination_tx: tokio::sync::watch::Sender<u32>) -> Result<()> {
    #[cfg(unix)]
    let (ctrl_c, sigterm) = {
        use tokio::signal::unix::SignalKind;
        use tokio::signal::unix::signal;
        (
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
        )
    };

    // Only `Some` is a signal. A stream that has closed yields `None` at once,
    // so it disables its branch instead of spinning or counting fake signals;
    // with both closed the stream ends.
    #[cfg(unix)]
    let signals =
        futures::stream::unfold((ctrl_c, sigterm), |(mut ctrl_c, mut sigterm)| async move {
            let name = tokio::select! {
                Some(()) = ctrl_c.recv() => "SIGINT",
                Some(()) = sigterm.recv() => "SIGTERM",
                else => return None,
            };
            Some((name, (ctrl_c, sigterm)))
        });

    // One persistent listener, so no signal is lost between two registrations.
    #[cfg(windows)]
    let signals = match tokio::signal::windows::ctrl_c() {
        Ok(ctrl_c) => futures::stream::unfold(ctrl_c, |mut ctrl_c| async move {
            ctrl_c.recv().await.map(|()| ("CTRL-C", ctrl_c))
        }),
        Err(err) => {
            // As before the lame-duck phase: a server that cannot hear a
            // shutdown signal shuts down rather than run unstoppable.
            error!("Unable to listen for shutdown signal: {err}");
            termination_tx.send_modify(|count| *count = count.saturating_add(1));
            return Ok(());
        }
    };

    crate::drain::count_termination_signals(signals, termination_tx).await;
    Ok(())
}

impl From<QuicSettings> for QuinnConfigBuilder {
    fn from(settings: QuicSettings) -> Self {
        let mut builder = QuinnConfigBuilder::default().num_listeners(settings.num_listeners);

        if let Some(v) = settings.idle_timeout {
            builder = builder.idle_timeout(Duration::from_millis(v));
        };

        if let Some(v) = settings.keep_alive {
            builder = builder.keep_alive(Duration::from_millis(v));
        };

        if let Some(v) = settings.max_bidi_streams {
            builder = builder.max_bidi_streams(v);
        };

        if let Some(v) = settings.transport_bits_per_second {
            builder = builder.transport_bits_per_second(v);
        }

        if let Some(v) = settings.transport_rtt {
            builder = builder.transport_rtt(v);
        }

        builder
    }
}

/// Requests a connection may hold in handling, defaulting to the capacity of its streams' pools.
fn connection_inflight_limit(settings: &QuicSettings, process_limit: usize) -> usize {
    settings.connection_inflight_limit.unwrap_or_else(|| {
        let streams = settings.max_bidi_streams.unwrap_or(STREAM_COUNT as u64);
        process_limit.saturating_mul(streams as usize)
    })
}

#[allow(clippy::too_many_arguments)]
async fn launch_quinn_server(
    name: &'static str,
    stream_handler_factory: Box<dyn StreamHandlerFactory>,
    metrics_frequency: Duration,
    quic_settings: QuicSettings,
    generate_ephemeral_cert: bool,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    connection_registry: Arc<QuinnConnectionRegistry>,
    drain_timeouts: Option<DrainTimeouts>,
) -> Result<()> {
    let span = info_span!("QUIC server", name);

    async {
        let cert_settings = match quic_settings.certificate.clone() {
            Some(cert_settings) => cert_settings,
            None if generate_ephemeral_cert => generate_ephemeral_certificate(name)?,
            None => return Err(anyhow!("Missing QUIC certificate config")),
        };

        let client_verifier = if quic_settings.verify_client_certs {
            let ca_path = cert_settings
                .cert_chain
                .clone()
                .ok_or(anyhow!("Missing cert chain"))?;
            build_cert_verifier(ca_path)?
        } else {
            Arc::new(NoClientAuth {})
        };

        let addr = SocketAddr::from_str(
            format!("{}:{}", quic_settings.host, quic_settings.port).as_str(),
        )?;

        let mut settings_builder: QuinnConfigBuilder = quic_settings.into();

        settings_builder = settings_builder
            .server_metrics_name(name)
            .address(addr)
            .cert_chain(cert_settings.cert_chain)
            .cert_file(cert_settings.cert_file)
            .pkey_file(cert_settings.pkey_file)
            .client_cert_verifier(client_verifier)
            .stream_handler_factory(stream_handler_factory)
            .metrics_frequency(metrics_frequency)
            .connection_registry(connection_registry.clone());

        info!(address = %addr, "server starting");
        let server = QuinnServer::start(settings_builder.build()?)?;

        // Wait for the shutdown signal. With graceful drain enabled, first
        // refuse new connections and wait for established ones to finish;
        // then close the endpoint. close() sends CONNECTION_CLOSE frames to
        // all peers and causes accept() loops to return None.
        let _ = shutdown_rx.wait_for(|&v| v).await;
        if let Some(timeouts) = drain_timeouts {
            run_drain(
                &connection_registry,
                timeouts.drain_timeout,
                timeouts.stall_timeout,
            )
            .await;
        }
        info!("closing endpoint");
        server.close().await;

        Ok(())
    }
    .instrument(span)
    .await
}

/// Returns the optional build features and active runtime capabilities exposed
/// through `ServerInfo`.
///
/// The two domain capabilities do **not** share one condition. Mounting the
/// private service is what makes the proof-namespace lifecycle reachable, but a
/// receipt is only written by a governed mutation, and a cell with enforcement
/// off performs none — see
/// [`crate::grpc::server::domain_operation_receipt_capability_available`].
#[lore_macro::test_pub]
fn compiled_features(
    domain_operation_service_available: bool,
    domain_enforcement_enabled: bool,
) -> Vec<String> {
    let mut features = Vec::new();
    if cfg!(feature = "failure_generator") {
        features.push("failure_generator".to_string());
    }
    if cfg!(feature = "oodle") {
        features.push("oodle".to_string());
    }
    if cfg!(feature = "seeding") {
        features.push("seeding".to_string());
    }
    if crate::grpc::server::domain_operation_receipt_capability_available(
        domain_operation_service_available,
        domain_enforcement_enabled,
    ) {
        features.push("domain_operation_receipt_v2".to_string());
    }
    if domain_operation_service_available {
        features.push("domain_operation_proof_namespace_lifecycle_v1".to_string());
    }
    features
}

#[allow(clippy::too_many_arguments)]
async fn launch_grpc_server(
    immutable_store: Arc<dyn ImmutableStore>,
    local_store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
    lock_store: Option<Arc<dyn LockStore>>,
    domain_context: Option<Arc<crate::domain::DomainContext>>,
    jwt_verifier: Option<JwtVerifier>,
    repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    repository_catalog: Arc<dyn RepositoryCatalog>,
    settings: Settings,
    notification_sender: Arc<dyn NotificationSender>,
    notification_service: Option<NotificationService>,
    hook_dispatcher: Arc<HookDispatcher>,
    user_agent_filter: Arc<UserAgentFilter>,
    forwarded_requests: Option<Arc<dyn ForwardedRequests>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    drain_state: Arc<DrainState>,
    graceful_drain: bool,
) -> Result<()> {
    let grpc_settings = settings
        .server
        .grpc
        .clone()
        .ok_or(anyhow!("Missing gRPC settings"))?;
    let service_settings = settings.server.grpc_public_services.clone();
    // Enforce the JWT permission vector on write RPCs (default ON; ADR-00011).
    // No-op when auth is OFF — `with_jwt_verifier` gates it on token presence.
    let enforce_write_permission = settings
        .server
        .auth
        .as_ref()
        .is_none_or(|auth| auth.enforce_write_permission);

    let addr =
        SocketAddr::from_str(format!("{}:{}", grpc_settings.host, grpc_settings.port).as_str())?;

    let locks = lock_store.is_some() && service_settings.lock_service.enabled;

    info!(
        "Starting Lore GRPC Server: {}, Auth: {} Locks: {}",
        &addr,
        jwt_verifier.as_ref().map_or("disabled", |_| "enabled"),
        if locks { "enabled" } else { "disabled" },
    );

    // The settings map has no relevant entries to surface yet, so it stays empty.
    // ServerInfo reports both optional build features (for example
    // failure_generator) and runtime capabilities whose services are mounted.
    let settings_map: HashMap<String, String> = HashMap::new();
    let domain_operation_service_available =
        crate::grpc::server::domain_operation_service_available(
            domain_context.is_some(),
            settings
                .environment
                .as_ref()
                .and_then(|environment| environment.endpoint.as_ref())
                .and_then(|endpoint| endpoint.auth_url.as_deref()),
            jwt_verifier.is_some(),
        );
    let mut features_list = compiled_features(
        domain_operation_service_available,
        domain_context
            .as_ref()
            .is_some_and(|domain| domain.enforcement_enabled()),
    );

    features_list.push("outcome_unknown_v1".to_string());
    if grpc_settings.caller_capability_policy
        == crate::grpc::caller_capabilities::CallerCapabilityPolicy::RequireOutcomeUnknownV1
    {
        features_list.push("requires_outcome_unknown_v1".to_string());
    }

    let (cert_path, key_path, cert_chain_path) =
        if let Some(cert_settings) = grpc_settings.certificate {
            (
                Some(cert_settings.cert_file),
                Some(cert_settings.pkey_file),
                cert_settings.cert_chain,
            )
        } else {
            (None, None, None)
        };

    let mut environment = settings.environment.clone().unwrap_or_default();
    let feature = settings.feature.clone().unwrap_or_default();

    // Enforce store limits
    if let Some(limit) = immutable_store.max_query_batch() {
        let mut config = environment.config.unwrap_or_default();
        let previous_limit = config.max_query_batch.unwrap_or_default();
        config.max_query_batch = Some(if previous_limit == 0 || limit < previous_limit {
            limit
        } else {
            previous_limit
        });
        environment.config = Some(config);
    }

    GrpcServerBuilder::new()
        .with_environment(environment)
        .with_feature(feature)
        .with_immutable_store(immutable_store, local_store)
        .with_mutable_store(mutable_store)
        .with_lock_store(lock_store)
        .with_domain_context(domain_context)
        .with_notification(notification_sender, notification_service)
        .with_hook_dispatcher(hook_dispatcher)
        .with_tls_config(cert_path, key_path, cert_chain_path)?
        .with_admin_endpoints(settings_map, features_list)
        .with_http2_config(
            grpc_settings
                .http2_keepalive_interval_seconds
                .map(Duration::from_secs),
            grpc_settings
                .http2_keepalive_timeout_seconds
                .map(Duration::from_secs),
            GrpcTimeouts {
                request_handler: Duration::from_secs(grpc_settings.request_handler_timeout_seconds),
                authorization: Duration::from_secs(grpc_settings.authorization_timeout_seconds),
            },
            service_settings,
            user_agent_filter,
            forwarded_requests,
        )
        .with_caller_capability_policy(grpc_settings.caller_capability_policy)
        .with_drain_state(graceful_drain.then(|| drain_state.clone()))
        .with_jwt_verifier(
            jwt_verifier,
            enforce_write_permission,
            repository_authorizer,
            repository_catalog,
        )?
        .serve(addr, async move {
            let _ = shutdown_rx.wait_for(|&v| v).await;
            // Under graceful drain, keep the public gRPC surface up until the
            // QUIC endpoints are empty. A push issues its finalizing
            // `branch_push` RPC AFTER the fragment transfer, so tearing gRPC
            // down at SIGTERM (while QUIC drains the transfer) fails exactly
            // the in-flight work the drain exists to protect.
            if graceful_drain {
                info!("Draining gRPC server: serving until active transfers finish");
                drain_state.wait_quic_idle().await;
            }
        })
        .await
}

/// Outcome of [`validate_endpoint_security`]: either the endpoint is
/// locked down with mTLS, or it is starting unauthenticated and the
/// caller must surface a warning at startup.
#[lore_macro::test_pub]
#[derive(Debug, PartialEq, Eq)]
enum EndpointSecurity {
    Mtls,
    Untrusted,
}

/// Decide whether a server-to-server endpoint may start, and on what
/// terms. Used by the gRPC internal server and the internal QUIC
/// listener — both grant blanket access to the storage layer and rely
/// solely on mTLS for authentication. The only way to start without
/// mTLS is the explicit `verify_client_certs = false` opt-in.
///
/// `label` is the config-section path used in error messages
/// (e.g. `"[server.grpc_internal]"` or `"[server.quic_internal]"`).
///
/// Returns:
/// - `Ok(Mtls)` when `verify_client_certs = true` and `certificate`
///   carries a full triple (`cert_file` + `pkey_file` + `cert_chain`).
/// - `Ok(Untrusted)` when `verify_client_certs = false`. The caller is
///   responsible for emitting a startup warning.
/// - `Err` when `verify_client_certs = true` but the certificate is
///   missing or only partially configured.
#[lore_macro::test_pub]
fn validate_endpoint_security(
    label: &str,
    certificate: Option<&crate::tls::CertificateSettings>,
    verify_client_certs: bool,
) -> Result<EndpointSecurity> {
    if !verify_client_certs {
        return Ok(EndpointSecurity::Untrusted);
    }
    match certificate {
        Some(cert) if cert.cert_chain.is_some() => Ok(EndpointSecurity::Mtls),
        Some(_) => Err(anyhow!(
            "{label} certificate is partially configured: \
             certificate.cert_file and certificate.pkey_file are set but \
             certificate.cert_chain (the CA used to verify client certs) \
             is missing. The endpoint requires mTLS, not server-only TLS"
        )),
        None => Err(anyhow!(
            "{label} requires mTLS to start (verify_client_certs = true). \
             Configure certificate.cert_file, certificate.pkey_file, and \
             certificate.cert_chain, or set verify_client_certs = false \
             to explicitly accept the security exposure"
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn launch_grpc_internal_server(
    settings: Settings,
    user_agent_filter: Arc<UserAgentFilter>,
    immutable_store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
    notification_sender: Arc<dyn NotificationSender>,
    hook_dispatcher: Arc<HookDispatcher>,
    domain_context: Option<Arc<crate::domain::DomainContext>>,
    stream_reset_service: Option<Arc<crate::event_relay::reset_service::StreamResetHandler>>,
    jwt_verifier: Option<JwtVerifier>,
    repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let grpc_settings = settings
        .server
        .grpc_internal
        .ok_or(anyhow!("Missing gRPC internal settings"))?;

    let addr =
        SocketAddr::from_str(format!("{}:{}", grpc_settings.host, grpc_settings.port).as_str())?;

    info!("Starting Lore gRPC internal server: {}", &addr);

    let (cert_path, key_path, cert_chain_path) =
        if let Some(cert_settings) = grpc_settings.certificate {
            (
                Some(cert_settings.cert_file),
                Some(cert_settings.pkey_file),
                cert_settings.cert_chain,
            )
        } else {
            (None, None, None)
        };

    let rpc_timeout = Duration::from_secs(grpc_settings.request_handler_timeout_seconds);

    GrpcInternalServerBuilder::new()
        .with_components(
            local_store().ok_or(anyhow!(
                "Cannot configure gRPC internal server, no local store"
            ))?,
            immutable_store,
            mutable_store,
            notification_sender,
            hook_dispatcher,
            settings.environment.clone().unwrap_or_default(),
            domain_context,
            jwt_verifier,
            repository_authorizer,
        )?
        .with_stream_reset_service(stream_reset_service)
        .with_tls_config(cert_path, key_path, cert_chain_path)?
        .with_http2_config(
            grpc_settings
                .http2_keepalive_interval_seconds
                .map(Duration::from_secs),
            grpc_settings
                .http2_keepalive_timeout_seconds
                .map(Duration::from_secs),
            user_agent_filter,
            rpc_timeout,
        )?
        .serve(addr, async move {
            let _ = shutdown_rx.wait_for(|&v| v).await;
        })
        .await
}

#[lore_macro::test_pub]
fn build_lore_http_settings(
    http_settings: &HttpSettings,
    user_agent_filter: Arc<UserAgentFilter>,
) -> LoreHttpServerSettings {
    LoreHttpServerSettings {
        caller_capability_policy: Default::default(),
        port: http_settings.port,
        host: http_settings.host.clone(),
        max_file_size: http_settings.max_file_size,
        request_timeout_seconds: http_settings.request_timeout_seconds,
        request_body_timeout_seconds: http_settings.request_body_timeout_seconds,
        available_interval_seconds: http_settings.available_interval_seconds,
        available_timeout_seconds: http_settings.available_timeout_seconds,
        store_health_check: http_settings.store_health_check,
        presign: PresignSettings {
            hmac_key: http_settings.presigned_url_hmac_key.clone(),
            min_ttl_seconds: http_settings.presigned_url_min_ttl_seconds,
            default_ttl_seconds: http_settings.presigned_url_default_ttl_seconds,
            max_ttl_seconds: http_settings.presigned_url_max_ttl_seconds,
            content_type_policy: ContentTypePolicy {
                extra: http_settings.presigned_url_extra_content_types.clone(),
                denied: http_settings.presigned_url_denied_content_types.clone(),
            },
        },
        user_agent_filter,
        // FORK-LOCAL (Tideshift): fail closed here; the launcher sets the
        // configured `[server.auth] enforce_write_permission`.
        enforce_write_permission: true,
    }
}

/// The facet handles the HTTP surface reports on, grouped so the launcher keeps
/// a readable signature as facets are added.
///
/// They are deliberately separate facets rather than one aggregate health flag:
/// CR-032 requires broker or relay trouble to be reportable without pulling a
/// node that is serving reads perfectly well out of the load balancer.
struct HttpSurfaceFacets {
    /// Aggregate drain view, behind `/health_check` and `/drain_status`.
    drain_state: Arc<DrainState>,
    /// Whether graceful drain is enabled, which decides how long this surface
    /// outlives the shutdown signal.
    graceful_drain: bool,
    /// CR-032's event-plane facets, behind `/event_readiness`.
    event_relay: Option<Arc<crate::event_relay::readiness::EventRelayReadiness>>,
    /// WP-114 CD-6's terminal write-claim prune facet, reported on the same
    /// route. It shares that endpoint rather than `/health_check` for exactly
    /// the reason the route exists: an undrained internal table is a condition
    /// an operator must see and a load balancer must not act on.
    fragment_prune: Option<Arc<crate::fragment_prune::FragmentPruneReadiness>>,
    /// WP-114 CD-8's cell-scale retention facet, on the same route and by the
    /// same rule as the prune facet above.
    cell_retention: Option<Arc<lore_object_dispatch::cell_retention::CellRetentionReadiness>>,
    write_behind: Option<Arc<crate::fragment_write_behind::FragmentWriteBehindReadiness>>,
}

async fn launch_http_server(
    settings: LoreHttpServerSettings,
    immutable_store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
    jwt_verifier: Option<JwtVerifier>,
    repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    facets: HttpSurfaceFacets,
) -> Result<()> {
    let HttpSurfaceFacets {
        drain_state,
        graceful_drain,
        event_relay,
        fragment_prune,
        cell_retention,
        write_behind,
    } = facets;
    LoreHttpServer::serve(
        settings,
        immutable_store,
        mutable_store,
        jwt_verifier,
        repository_authorizer,
        Some(drain_state.clone()),
        crate::http::server::HealthFacets {
            event_relay,
            fragment_prune,
            cell_retention,
            write_behind,
        },
        async move {
            let _ = shutdown_rx.wait_for(|&v| v).await;
            // Under graceful drain, keep the health/status surface up until
            // QUIC and public gRPC work have finished so the load balancer keeps seeing
            // the draining 503 and a deploy controller can poll
            // /drain_status through the whole drain.
            if graceful_drain {
                drain_state.wait_idle().await;
            }
        },
    )
    .await
}

/// Start a minimal gRPC server in maintenance mode on the address described by
/// `grpc_settings`.
///
/// The server registers only the environment service, which returns
/// `UNAVAILABLE` to signal that the node is intentionally in a reduced state.
/// No storage, replication, or admin services are exposed.
///
/// Infrastructure health checks (load-balancers, service meshes, deployment controllers) may
/// probe the internal port to determine whether the node is ready to receive
/// peer traffic.  Binding the maintenance server on every exposed port ensures those
/// checks can reach it and observe `UNAVAILABLE`, rather than hitting a refused
/// connection that a probe might misinterpret as a hard failure.
async fn launch_maintenance_grpc_server(
    grpc_settings: GrpcSettings,
    environment: EnvironmentConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let addr =
        SocketAddr::from_str(format!("{}:{}", grpc_settings.host, grpc_settings.port).as_str())?;

    info!("Starting Lore maintenance gRPC Server: {}", &addr);

    let (cert_path, key_path, cert_chain_path) =
        if let Some(cert_settings) = grpc_settings.certificate {
            (
                Some(cert_settings.cert_file),
                Some(cert_settings.pkey_file),
                cert_settings.cert_chain,
            )
        } else {
            (None, None, None)
        };

    crate::grpc::server::serve_maintenance(
        environment,
        addr,
        cert_path,
        key_path,
        cert_chain_path,
        async move {
            let _ = shutdown_rx.wait_for(|&v| v).await;
        },
    )
    .await
}

/// The policy the public QUIC services enforce: the configured gRPC policy, else the
/// compatible default.
#[lore_macro::test_pub]
fn quic_caller_capability_policy(
    settings: &Settings,
) -> crate::grpc::caller_capabilities::CallerCapabilityPolicy {
    settings
        .server
        .grpc
        .as_ref()
        .map(|grpc| grpc.caller_capability_policy)
        .unwrap_or_default()
}

#[lore_macro::test_pub]
struct QuicPublicStreamHandler {
    service_store: ServiceStore,
}

impl QuicPublicStreamHandler {
    #[allow(clippy::too_many_arguments)]
    #[lore_macro::test_pub]
    fn new(
        immutable_store: Arc<dyn ImmutableStore>,
        local_store: Arc<dyn ImmutableStore>,
        mutable_store: Arc<dyn MutableStore>,
        jwt_verifier: Option<JwtVerifier>,
        enforce_write_permission: bool,
        repository_authorizer: Arc<dyn RepositoryAuthorizer>,
        limits: AdmissionLimits,
        user_agent_filter: Arc<UserAgentFilter>,
        caller_capability_policy: crate::grpc::caller_capabilities::CallerCapabilityPolicy,
    ) -> Self {
        let mut service_store = ServiceStore::default();

        let make_storage_handler =
            |immutable_store: Arc<dyn ImmutableStore>,
             local_store: Arc<dyn ImmutableStore>,
             mutable_store: Arc<dyn MutableStore>,
             jwt_verifier: Option<JwtVerifier>,
             repository_authorizer: Arc<dyn RepositoryAuthorizer>| {
                Box::new(move |context: Arc<AttributeMap>| {
                    let storage_protocol = StorageService::new(
                        Arc::new(jwt_verifier.clone()),
                        repository_authorizer.clone(),
                        immutable_store.clone(),
                        local_store.clone(),
                        mutable_store.clone(),
                        enforce_write_permission,
                    )
                    .with_caller_capability_policy(caller_capability_policy);
                    Box::new(StreamHandler::new(
                        Arc::new(storage_protocol),
                        context,
                        limits,
                    )) as Box<dyn StreamDataHandler>
                }) as StreamDataHandlerBuilder
            };

        service_store.add_service(
            "urc/0.2",
            make_storage_handler(
                immutable_store.clone(),
                local_store.clone(),
                mutable_store.clone(),
                jwt_verifier.clone(),
                repository_authorizer.clone(),
            ),
        );
        {
            let immutable_store = immutable_store.clone();
            let local_store = local_store.clone();
            let mutable_store = mutable_store.clone();
            let jwt_verifier = jwt_verifier.clone();
            let repository_authorizer = repository_authorizer.clone();
            let user_agent_filter = user_agent_filter.clone();
            service_store.add_service(
                StorageClient::ALPN,
                Box::new(move |context: Arc<AttributeMap>| {
                    let v4_service = crate::quic::storage_service_v4::StorageServiceV4::new(
                        Arc::new(jwt_verifier.clone()),
                        repository_authorizer.clone(),
                        immutable_store.clone(),
                        local_store.clone(),
                        mutable_store.clone(),
                        enforce_write_permission,
                        user_agent_filter.clone(),
                    )
                    .with_caller_capability_policy(caller_capability_policy);
                    Box::new(StreamHandler::new(Arc::new(v4_service), context, limits))
                        as Box<dyn StreamDataHandler>
                }) as StreamDataHandlerBuilder,
            );
        }

        Self { service_store }
    }
}

impl StreamHandlerFactory for QuicPublicStreamHandler {
    fn supported_protocols(&self) -> Vec<String> {
        self.service_store.get_supported_services()
    }

    fn get_stream_handler_builder(
        &self,
        protocol: &str,
    ) -> Option<(&&'static str, &StreamDataHandlerBuilder)> {
        self.service_store.get_stream_builder(protocol)
    }
    fn name(&self) -> &'static str {
        "QuicPublicStreamHandler"
    }
}

struct QuicInternalStreamHandler {
    service_store: ServiceStore,
}

impl QuicInternalStreamHandler {
    fn new(
        immutable_store: Arc<dyn ImmutableStore>,
        local_store: Option<Arc<dyn ImmutableStore>>,
        limits: AdmissionLimits,
        user_agent_filter: Arc<UserAgentFilter>,
    ) -> Self {
        let mut service_store = ServiceStore::default();
        {
            service_store.add_service(
                ReplicationStoreClient::ALPN,
                Box::new(move |context: Arc<AttributeMap>| {
                    let protocol = match &local_store {
                        Some(local_store) => ReplicationStoreService::new(
                            immutable_store.clone(),
                            local_store.clone(),
                            user_agent_filter.clone(),
                        ),
                        None => ReplicationStoreService::without_local_store(
                            immutable_store.clone(),
                            user_agent_filter.clone(),
                        ),
                    };
                    Box::new(StreamHandler::new(Arc::new(protocol), context, limits))
                }),
            );
        }

        Self { service_store }
    }
}

impl StreamHandlerFactory for QuicInternalStreamHandler {
    fn supported_protocols(&self) -> Vec<String> {
        self.service_store.get_supported_services()
    }

    fn get_stream_handler_builder(
        &self,
        protocol: &str,
    ) -> Option<(&&'static str, &StreamDataHandlerBuilder)> {
        self.service_store.get_stream_builder(protocol)
    }
    fn name(&self) -> &'static str {
        "QuicInternalStreamHandler"
    }
}

async fn configure_immutable_store_via_plugin(
    registry: &PluginRegistry,
    settings: &Settings,
    topology: Option<Arc<dyn Topology + Send + Sync>>,
    fragment_activation: Option<plugins::postgres::FragmentProviderActivation>,
    write_behind_observer: Option<lore_postgres::domain::fragments::FragmentStageObserver>,
) -> Result<(
    Arc<dyn ImmutableStore>,
    Option<FragmentCellRetentionHandle>,
    Option<Arc<FragmentWriteBehindHandle>>,
)> {
    let mode = &settings.immutable_store.mode;

    // Only the Postgres plugin path can produce a retention handle: it is the
    // one mode that opens a dispatch pool, and only when the governed fragment
    // route is enabled. Every other mode returns `None` rather than a facet it
    // has nothing behind.
    let store = match mode.as_str() {
        store_mode::LOCAL => {
            let local_settings = settings
                .immutable_store
                .local
                .as_ref()
                .ok_or(anyhow!("Missing local immutable store settings"))?;

            configure_local_immutable_store(local_settings).await
        }
        store_mode::COMPOSITE => {
            let composite_settings = settings
                .immutable_store
                .composite
                .as_ref()
                .ok_or(anyhow!("Missing composite store settings"))?;

            configure_composite_store(registry, composite_settings, settings, topology).await
        }
        store_mode::REPLICATED => {
            let replicated_settings = settings
                .immutable_store
                .replicated
                .as_ref()
                .ok_or(anyhow!("Missing replicated store settings"))?;

            configure_replicated_immutable_store(replicated_settings).await
        }
        store_mode::REMOTE => {
            let remote_settings = settings
                .immutable_store
                .remote
                .as_ref()
                .ok_or(anyhow!("Missing remote immutable store settings"))?;

            configure_remote_immutable_store(remote_settings)
        }
        _ => {
            // All other modes use the plugin system
            let plugin_config =
                resolve_plugin_config_with_fallback(&settings.plugins, mode, "immutable_store")
                    .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));

            info!(mode, "Creating immutable store via plugin system");

            if mode == "postgres" {
                // WP-114 CD-7's staging tier is opened here, before the store,
                // and the handle is kept rather than only handed over. The
                // store's own documentation is explicit that it never queries
                // for pending staged rows and never starts a drain: the
                // composing server owes `note_pending_staged` and
                // `note_drain_heartbeat` from a recurring task, and a
                // once-at-boot observation of either is the exact per-process
                // check that lets a second replica demote healthy fragments.
                //
                // `open` proves the root by writing, fsyncing, renaming and
                // unlinking a probe file through the real finalization path, so
                // a mount that cannot fsync a directory fails startup here
                // rather than at the first acknowledged PUT.
                // Only the staging half of the block is consumed here. The
                // spool root the same block carries is the drain worker's
                // input, and the drain worker is composed further out, so it is
                // read there from this same settings reader rather than
                // threaded through a store constructor that has no use for it.
                let composition = postgres_write_behind_settings(settings)?;
                let write_behind = if let Some(config) = composition.as_ref() {
                    let config = config.clone();
                    Some(lore_base::lore_spawn_blocking!("write-behind-open", move || -> Result<_> {
                        std::fs::create_dir_all(&config.settings.root)?;
                        std::fs::create_dir_all(&config.shared_spool_root)?;
                        let stage_root = std::fs::canonicalize(&config.settings.root)?;
                        let spool_root = std::fs::canonicalize(&config.shared_spool_root)?;
                        if stage_root.starts_with(&spool_root) || spool_root.starts_with(&stage_root) {
                            return Err(anyhow!("write-behind canonical roots must be separate, non-nested trees"));
                        }
                        WriteBehindStage::open(config.settings).map_err(Into::into)
                    }).await??)
                } else {
                    None
                };
                let store = plugins::postgres::connect_immutable_store(
                    &plugin_config,
                    fragment_activation,
                    write_behind.clone(),
                )
                .await
                .map_err(|e| anyhow!("Failed to create immutable store plugin '{mode}': {e}"))?;
                // Taken before the concrete store is erased behind the trait
                // object: WP-114 CD-8's client is reachable only from the
                // concrete Postgres store, and only on the coordinated route.
                let cell_retention = store.cell_retention().map_err(|error| {
                    anyhow!("Failed to take the cell retention client: {error}")
                })?;
                let worker = if let Some(config) = composition {
                    Some(
                        store
                            .create_write_behind_handle(
                                config.shared_spool_root,
                                config.cell_id,
                                config.policy_revision,
                                config.policy_digest,
                                write_behind_observer.ok_or_else(|| {
                                    anyhow!(
                                        "write-behind requires the domain connection reserved for its observer"
                                    )
                                })?,
                            )
                            .await
                            .map_err(|error| {
                                anyhow!("Failed to construct write-behind worker: {error}")
                            })?,
                    )
                } else {
                    None
                };
                return Ok((Arc::new(store), cell_retention, worker));
            }

            registry
                .create_immutable_store(mode, &plugin_config)
                .map_err(|e| anyhow!("Failed to create immutable store plugin '{mode}': {e}"))
        }
    }?;

    Ok((store, None, None))
}

/// WP-114 CD-7's reviewed staging settings, or `None` on a cell that opens no
/// staging tier.
///
/// Reads the same resolved immutable-store configuration as the two scheduler
/// settings readers above, because the `write_behind` block lives beside
/// `fragment_provider` and its enablement is decided in the same place.
pub(crate) fn postgres_write_behind_settings(
    settings: &Settings,
) -> Result<Option<plugins::postgres::WriteBehindComposition>> {
    if settings.immutable_store.mode != "postgres" {
        return Ok(None);
    }
    let immutable_config = resolved_postgres_store_config(settings, "immutable_store")?;
    plugins::postgres::write_behind_settings(&immutable_config)
        .map_err(|error| anyhow!("Invalid Postgres write-behind configuration: {error}"))
}

fn resolved_postgres_store_config(settings: &Settings, store_type: &str) -> Result<toml::Value> {
    resolve_plugin_config_with_fallback(&settings.plugins, "postgres", store_type).ok_or_else(|| {
        anyhow!(
            "fragment_provider requires a resolved [plugins.postgres.{store_type}] configuration"
        )
    })
}

/// WP-114 CD-8's reviewed retention settings, or `None` on a cell that runs
/// none.
///
/// Reads the same resolved immutable-store configuration as
/// [`postgres_fragment_prune_settings`], and for the same reason: the
/// `fragment_provider` block is where both schedulers' enablement is decided.
fn postgres_cell_retention_settings(
    settings: &Settings,
) -> Result<Option<lore_object_dispatch::cell_retention::CellRetentionSettings>> {
    if settings.immutable_store.mode != "postgres" {
        return Ok(None);
    }
    let immutable_config = resolved_postgres_store_config(settings, "immutable_store")?;
    plugins::postgres::cell_retention_settings(&immutable_config)
        .map_err(|error| anyhow!("Invalid Postgres cell retention configuration: {error}"))
}

/// The prune scheduler's reviewed settings, or `None` on a cell that runs none.
///
/// Reads the immutable store's resolved configuration because that is where the
/// `fragment_provider` block lives and where its enablement is decided; the
/// same value `postgres_fragment_process_pool_inventory` reads two lines above.
fn postgres_fragment_prune_settings(
    settings: &Settings,
) -> Result<Option<crate::fragment_prune::FragmentPruneSettings>> {
    if settings.immutable_store.mode != "postgres" {
        return Ok(None);
    }
    let immutable_config = resolved_postgres_store_config(settings, "immutable_store")?;
    plugins::postgres::fragment_prune_settings(&immutable_config)
        .map_err(|error| anyhow!("Invalid Postgres immutable store configuration: {error}"))
}

fn postgres_fragment_process_pool_inventory(
    settings: &Settings,
) -> Result<Option<lore_postgres::domain::fragments::FragmentProcessPoolInventory>> {
    if settings.immutable_store.mode != "postgres" {
        return Ok(None);
    }
    let immutable_config = resolved_postgres_store_config(settings, "immutable_store")?;
    let provider_enabled = plugins::postgres::fragment_provider_enabled(&immutable_config)
        .map_err(|error| anyhow!("Invalid Postgres immutable store configuration: {error}"))?;
    let mutable_is_postgres = settings.mutable_store.mode == "postgres";
    let lock_is_postgres = settings
        .lock_store
        .as_ref()
        .map(|store| store.mode.as_str())
        == Some("postgres");

    // An enabled provider REQUIRES the full governed shape, and says so. This
    // is unchanged: a misconfigured provider cell must fail loudly rather than
    // fall through to a partial inventory.
    if provider_enabled && !mutable_is_postgres {
        return Err(anyhow!(
            "enabled fragment_provider requires mutable_store.mode = 'postgres' so its actual pool maximum and lifecycle coordinator are available"
        ));
    }
    if provider_enabled && !lock_is_postgres {
        return Err(anyhow!(
            "enabled fragment_provider requires lock_store.mode = 'postgres' so its actual pool maximum is available"
        ));
    }

    // Without a provider the inventory is still built, because the four store
    // and domain pools open regardless and CR-032's relay pool may join them.
    // That is the escape this closes: the ceiling used to apply only on the
    // provider path, so a relay-enabled provider-disabled cell held real
    // connections against a limit nothing evaluated.
    //
    // A non-Postgres LOCK store is not a reason to skip the ceiling: the cell
    // still opens its immutable, mutable, domain, and possibly relay pools, and
    // 10 + 10 + 4 + 5 is 29 against a limit of 20. That pool is simply absent,
    // which the inventory expresses as zero, exactly as it does for a missing
    // dispatch or relay pool.
    //
    // A non-Postgres MUTABLE store is different and does bail. Its
    // configuration is where `domain_pool_max` lives, so without it the
    // inventory cannot be built at all rather than built with a hole; the relay
    // also refuses to start against a non-Postgres mutable store, so no relay
    // pool joins that shape either. That is a real remaining narrowing, stated
    // rather than papered over.
    if !mutable_is_postgres {
        return Ok(None);
    }
    let mutable_config = resolved_postgres_store_config(settings, "mutable_store")?;
    let lock_config = if lock_is_postgres {
        Some(resolved_postgres_store_config(settings, "lock_store")?)
    } else {
        None
    };
    // `[outbox_relay]` is a top-level setting rather than a store's own, so the
    // relay's pool cannot be discovered from the store configurations above.
    // Composition is the only place that knows both, which is why the flag is
    // passed rather than read.
    let relay_enabled = settings
        .outbox_relay
        .as_ref()
        .is_some_and(|relay| relay.enabled);
    plugins::postgres::fragment_process_pool_inventory(
        &immutable_config,
        &mutable_config,
        lock_config.as_ref(),
        relay_enabled,
    )
    .map(Some)
    .map_err(|error| anyhow!("Invalid Postgres process pool inventory: {error}"))
}

async fn configure_mutable_store_via_plugin(
    registry: &PluginRegistry,
    settings: &Settings,
    immutable_store: Arc<dyn ImmutableStore>,
    context: &MutableStorePluginContext,
) -> Result<Arc<dyn MutableStore>> {
    let mode = &settings.mutable_store.mode;

    match mode.as_str() {
        store_mode::LOCAL => {
            let local_settings = settings
                .mutable_store
                .local
                .as_ref()
                .ok_or(anyhow!("Missing local mutable store settings"))?;

            configure_local_mutable_store(local_settings, immutable_store).await
        }
        store_mode::REMOTE => {
            let remote_settings = settings
                .mutable_store
                .remote
                .as_ref()
                .ok_or(anyhow!("Missing remote mutable store settings"))?;

            configure_remote_mutable_store(remote_settings)
        }
        store_mode::REPLICATED => Err(anyhow!("replicated mutable store is not implemented")),
        store_mode::COMPOSITE => Err(anyhow!(
            "Invalid settings, cannot have composite store as mutable store"
        )),
        _ => {
            // All other modes use the plugin system
            let plugin_config =
                resolve_plugin_config_with_fallback(&settings.plugins, mode, "mutable_store")
                    .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));

            info!(mode, "Creating mutable store via plugin system");

            registry
                .create_mutable_store(mode, &plugin_config, immutable_store, context)
                .map_err(|e| anyhow!("Failed to create mutable store plugin '{mode}': {e}"))
        }
    }
}

fn configure_lock_store_via_plugin(
    registry: &PluginRegistry,
    settings: &Settings,
) -> Result<Option<Arc<dyn LockStore>>> {
    if let Some(lock_settings) = &settings.lock_store {
        let mode = &lock_settings.mode;

        // The only way to opt out of a store `default.toml` sets.
        if mode == store_mode::NONE {
            info!("No lock store configured, LockService will not register");
            return Ok(None);
        }

        if mode == store_mode::LOCAL {
            info!("Creating local (in-memory) lock store");
            let store = crate::lock::store::LocalLockStore::default();
            return Ok(Some(Arc::new(store)));
        }

        // All other modes use the plugin system
        let plugin_config =
            resolve_plugin_config_with_fallback(&settings.plugins, mode, "lock_store")
                .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));

        info!(mode, "Creating lock store via plugin system");

        let store = registry
            .create_lock_store(mode, &plugin_config)
            .map_err(|e| anyhow!("Failed to create lock store plugin '{mode}': {e}"))?;

        return Ok(Some(store));
    }

    Ok(None)
}

static LOCAL_STORE: OnceLock<Weak<dyn ImmutableStore>> = OnceLock::new();

fn local_store() -> Option<Arc<dyn ImmutableStore>> {
    LOCAL_STORE.get().and_then(|weak| weak.upgrade())
}

/// The store behind the internal QUIC server's `ImmutableLocal*` opcodes. It
/// must be local, the property `GrpcInternalServerBuilder::with_components`
/// checks for its sibling. The main store stands in only when it is itself
/// local. Otherwise `None`, and those opcodes are refused rather than turned
/// into durable-store traffic (WP-109 D3). The server still starts, because
/// its `Immutable*` opcodes serve replicated topologies with no local store.
#[lore_macro::test_pub]
fn internal_quic_local_store(
    local_store: Option<Arc<dyn ImmutableStore>>,
    immutable_store: &Arc<dyn ImmutableStore>,
) -> Option<Arc<dyn ImmutableStore>> {
    let store = local_store.unwrap_or_else(|| immutable_store.clone());
    if store.is_local() {
        Some(store)
    } else {
        warn!(
            "No local store available for internal QUIC server, ImmutableLocal* opcodes will be \
             refused"
        );
        None
    }
}

/// Directory under the system temporary directory where the server keeps
/// zero-config artifacts (local stores and ephemeral certificates) when no
/// explicit locations are configured.
///
/// `std::env::temp_dir` hands back `TMPDIR` as it stands, which an empty one
/// makes a relative directory, so the result is resolved against the process
/// working directory.
#[lore_macro::test_pub]
fn local_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("lore-server");

    std::path::absolute(&dir).unwrap_or(dir)
}

/// Whether the configuration names a local store path.
#[lore_macro::test_pub]
fn is_path_configured(configured: &str) -> bool {
    !configured.trim().is_empty()
}

/// Where the local store lives, falling back to a directory under the system
/// temporary directory when the configuration names none.
///
/// A relative path is resolved against the process working directory, where the
/// storage layer creates it. The `disallowed_methods` fence on
/// `std::env::current_dir` guards library calls carrying a caller's directory;
/// this is the server resolving its own configuration. Resolution is lexical,
/// so the location is classified before the directory exists.
#[lore_macro::test_pub]
fn local_store_path(configured: &str) -> PathBuf {
    if !is_path_configured(configured) {
        return local_data_dir();
    }

    let path = PathBuf::from(configured);

    std::path::absolute(&path).unwrap_or(path)
}

/// A local store the configuration asks for.
#[lore_macro::test_pub]
struct LocalStoreLocation {
    /// Names the store in the log.
    label: &'static str,
    /// Where the store lands.
    path: PathBuf,
    /// Whether the configuration named the path.
    configured: bool,
    /// Whether the server writes at this path.
    reaches_disk: bool,
}

/// Marks which immutable tiers are written at.
///
/// Every local tier is handed the store the first one creates, so a tier naming
/// another path has nothing written at the path it names, and one naming the
/// same path shares the store standing there.
fn mark_shared_immutable_tiers(tiers: &mut [LocalStoreLocation]) {
    let Some((created, shared)) = tiers.split_first_mut() else {
        return;
    };

    for tier in shared {
        tier.reaches_disk = tier.path == created.path;
    }
}

/// Adds the local store `mode` names, if it names one.
fn push_local_store(
    stores: &mut Vec<LocalStoreLocation>,
    label: &'static str,
    mode: &str,
    configured: Option<&str>,
) {
    if mode == store_mode::LOCAL
        && let Some(configured) = configured
    {
        stores.push(LocalStoreLocation {
            label,
            path: local_store_path(configured),
            configured: is_path_configured(configured),
            reaches_disk: true,
        });
    }
}

/// Every local store the configuration asks for, in the order the server builds
/// them.
///
/// The process holds one local immutable store, in `LOCAL_STORE`, which the
/// first tier configured as local creates and every later local tier is handed;
/// see [`mark_shared_immutable_tiers`]. Composite tiers are built in the order
/// local, durable, replicas. The local mutable store is separate, at its own
/// path.
///
/// A remote or replicated store writes to no local path, so a `[local]` block
/// left in its configuration is not listed.
#[lore_macro::test_pub]
fn local_store_locations(
    immutable: &ImmutableStoreSettings,
    mutable: &MutableStoreSettings,
) -> Vec<LocalStoreLocation> {
    let mut stores = Vec::new();

    push_local_store(
        &mut stores,
        "immutable",
        &immutable.mode,
        immutable.local.as_ref().map(|local| local.path.as_str()),
    );

    if immutable.mode == store_mode::COMPOSITE
        && let Some(composite) = immutable.composite.as_ref()
    {
        let tiers = std::iter::once(("immutable composite local", &composite.local))
            .chain(
                composite
                    .durable
                    .as_ref()
                    .map(|tier| ("immutable composite durable", tier)),
            )
            .chain(
                composite
                    .replica
                    .iter()
                    .flatten()
                    .map(|tier| ("immutable composite replica", tier)),
            );

        for (label, tier) in tiers {
            push_local_store(
                &mut stores,
                label,
                &tier.mode,
                tier.local.as_ref().map(|local| local.path.as_str()),
            );
        }
    }

    mark_shared_immutable_tiers(&mut stores);

    push_local_store(
        &mut stores,
        "mutable",
        &mutable.mode,
        mutable.local.as_ref().map(|local| local.path.as_str()),
    );

    stores
}

/// The store paths the disk space monitor watches.
#[lore_macro::test_pub]
fn monitored_local_store_paths(stores: Vec<LocalStoreLocation>) -> Vec<PathBuf> {
    stores
        .into_iter()
        .filter(|store| store.reaches_disk)
        .map(|store| store.path)
        .collect()
}

/// Reports where every local store lands.
///
/// A store nothing is written at draws that alone: where the path points says
/// nothing an operator can act on. The remaining two conditions are independent,
/// since either can hold without the other: a path the configuration does not
/// name, and a path inside a system temporary directory.
fn report_local_store_locations(stores: &[LocalStoreLocation]) {
    for store in stores {
        if !store.reaches_disk {
            warn!(
                store = store.label,
                path = %store.path.display(),
                "The '{}' local store names {}, but every local immutable tier is handed the \
                 store the first one creates, so nothing is written there. Remove the path, or \
                 make this the first local tier.",
                store.label,
                store.path.display(),
            );
            continue;
        }

        if store.configured {
            info!(store = store.label, path = %store.path.display(), "Using configured local store path");
        } else {
            warn!(
                store = store.label,
                path = %store.path.display(),
                "No local store path is configured for the '{}' store, so the server generated {}. \
                 Configure an explicit path for production.",
                store.label,
                store.path.display(),
            );
        }

        if crate::util::local_store_monitor::is_temporary_path(&store.path) {
            warn!(
                store = store.label,
                path = %store.path.display(),
                "The '{}' local store is at {}, inside a system temporary directory. This data is \
                 EPHEMERAL and not persisted across reboots. Configure a persistent location for \
                 production.",
                store.label,
                store.path.display(),
            );
        }
    }
}

/// Build a [`CertificateSettings`](crate::tls::CertificateSettings) for an
/// endpoint that has no certificate configured by generating an ephemeral
/// self-signed certificate and writing it under the system temporary directory.
///
/// Used for QUIC endpoints that carry no mTLS requirement, so a stand alone
/// server binary with no external config can serve TLS out of the box. A
/// prominent warning is logged because these certificates are untrusted and
/// regenerated on every startup.
///
/// The file names carry the process id: several servers routinely share one
/// machine (and therefore one temporary directory), and a fixed name would let
/// them overwrite each other's certificate between the write here and the read
/// in the endpoint setup, pairing one server's certificate with another's key.
fn generate_ephemeral_certificate(endpoint: &str) -> Result<crate::tls::CertificateSettings> {
    let dir = local_data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| {
        anyhow!(
            "failed to create directory {} for ephemeral certificate: {e}",
            dir.display()
        )
    })?;

    let process_id = std::process::id();
    let cert_file = dir.join(format!("{endpoint}-{process_id}-cert.pem"));
    let pkey_file = dir.join(format!("{endpoint}-{process_id}-key.pem"));

    let generated = lore_transport::tls::generate_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])?;

    std::fs::write(&cert_file, generated.cert_pem).map_err(|e| {
        anyhow!(
            "failed to write ephemeral certificate {}: {e}",
            cert_file.display()
        )
    })?;
    std::fs::write(&pkey_file, generated.key_pem).map_err(|e| {
        anyhow!(
            "failed to write ephemeral private key {}: {e}",
            pkey_file.display()
        )
    })?;

    warn!(
        endpoint,
        cert = %cert_file.display(),
        key = %pkey_file.display(),
        "No TLS certificate configured for the '{endpoint}' QUIC endpoint; generated an \
         EPHEMERAL SELF-SIGNED certificate. This is untrusted, regenerated on every restart, \
         and intended for local development only. Configure a real certificate for production."
    );

    Ok(crate::tls::CertificateSettings {
        cert_chain: None,
        cert_file,
        pkey_file,
    })
}

async fn create_local_store(
    settings: &LocalImmutableStoreSettings,
    flush_background: bool,
) -> Result<Arc<dyn ImmutableStore>> {
    let default_settings = lore_storage::local::immutable_store::ImmutableStoreSettings::default();
    let store_path = local_store_path(&settings.path);

    let options = ImmutableStoreCreateOptions {
        max_capacity: settings.max_capacity,
        eviction_delay: settings
            .eviction_delay
            .map(|ms| std::time::Duration::from_millis(ms as u64)),
        max_size: settings.max_size,
        compaction_delay: settings
            .compaction_delay
            .map(|ms| std::time::Duration::from_millis(ms as u64)),
    };

    let store = lore_storage::local::immutable_store::create(
        Some(store_path.as_path()),
        options,
        true,  /* Server mode, deserialize all buckets immediately */
        lore_storage::local::immutable_store::ImmutableStoreSettings {
            protect_local_fragment: false, /* Server mode, no need to try protect local fragments from eviction */
            implicit_durable_stored: true, /* Server mode, consider all fragments as durably stored */
            isolate_partitions: true, /* Server mode, one process holds content for every tenant */
            flush_background,
            flush_delay_seconds: settings.flush_delay_seconds as u64,
            target_capacity_percentage: settings.target_capacity_percentage.unwrap_or(default_settings.target_capacity_percentage),
            target_size_percentage: settings.target_size_percentage.unwrap_or(default_settings.target_size_percentage),
            compaction_parallel_groups: settings.compaction_parallel_groups.unwrap_or(default_settings.compaction_parallel_groups),
            verify_write: false,
            atime: true,
            initial_fan_out_level: lore_storage::local::fan_out::FAN_OUT_LEVEL_MAX, /* Server mode, full 256-bucket layout from the start */
            fan_out_threshold: lore_storage::local::fan_out::FAN_OUT_THRESHOLD_DEFAULT,
        },
    )
    .await
    .map_err(anyhow::Error::from)?;

    lore_storage::maintenance::spawn_gc(&store, &options);

    Ok(store)
}

async fn configure_local_immutable_store(
    settings: &LocalImmutableStoreSettings,
) -> Result<Arc<dyn ImmutableStore>> {
    if let Some(local_store) = local_store() {
        return Ok(local_store.clone());
    }

    info!("Wiring up local immutable store");

    let store = create_local_store(settings, true /* flush background */).await?;

    let weak_store = Arc::downgrade(&store);

    // Only time this returns an error is if the value is already set.
    let _ = LOCAL_STORE.set(weak_store.clone());

    Ok(store)
}

async fn configure_local_mutable_store(
    settings: &LocalMutableStoreSettings,
    immutable_store: Arc<dyn ImmutableStore>,
) -> Result<Arc<dyn MutableStore>> {
    info!("Wiring up local mutable store");

    let store_path = local_store_path(&settings.path);

    Ok(lore_storage::local::mutable_store::create(
        Some(store_path.as_path()),
        lore_storage::MutableStoreSettings {
            flush_delay_seconds: settings.flush_delay_seconds as u64,
            initial_fan_out_level: lore_storage::local::fan_out::FAN_OUT_LEVEL_MAX, /* Server mode, full 256-bucket layout from the start */
            fan_out_threshold: lore_storage::local::fan_out::FAN_OUT_THRESHOLD_DEFAULT,
            authoritative: true, /* Server local store is the source of truth, not a cache */
        },
        immutable_store,
    )
    .await?)
}

fn configure_remote_immutable_store(
    settings: &RemoteStoreSettings,
) -> Result<Arc<dyn ImmutableStore>> {
    info!(
        "Wiring up remote immutable store to {}",
        settings.remote_url
    );

    Ok(Arc::new(RemoteImmutableStore::new(
        settings.remote_url.as_str(),
        settings.auth_url.as_deref(),
    )))
}

async fn configure_replicated_immutable_store(
    settings: &ReplicatedStoreSettings,
) -> Result<Arc<dyn ImmutableStore>> {
    info!(
        "Wiring up replicated immutable store to {}",
        settings.remote_url
    );

    let certs = if let Some(setting_certs) = &settings.certs {
        let setting_certs = setting_certs.clone();
        client::CertificateSettings {
            custom_ca: setting_certs.cert_chain,
            client: Some(ClientCerts {
                cert_file: setting_certs.cert_file,
                pkey_file: setting_certs.pkey_file,
            }),
        }
    } else {
        client::CertificateSettings {
            custom_ca: None,
            client: None,
        }
    };

    let mut factory = client_container::QuicClientFactory::new(settings.remote_url.clone(), certs);
    if let Some(client_max_reconnects) = settings.client_max_reconnects {
        factory.quic_max_reconnects = Some(client_max_reconnects);
    } else {
        factory.quic_max_reconnects = Some(5);
    }
    if let Some(client_message_limit) = settings.client_message_limit {
        factory.command_behavior.message_limit = client_message_limit;
    }
    if let Some(max_bandwidth_bytes_per_second) = settings.max_bandwidth_bytes_per_second {
        factory.transport_config.max_bytes_bandwidth_per_second = max_bandwidth_bytes_per_second;
    }
    if let Some(expected_rtt_ms) = settings.expected_rtt_ms {
        factory.transport_config.expected_rtt_ms = expected_rtt_ms;
    }
    factory.user_agent = Some(make_user_agent_with_component(
        user_agent_product(),
        "replicated-immutable-store",
    ));

    let container_config = ClientContainerConfig {
        regenerate_retry_policy: (&settings.regenerate_retry).into(),
        connection_lost_sleep: Duration::from_secs(1),
    };

    let store = ReplicatedStore::new(
        Arc::new(factory),
        container_config,
        Duration::from_secs(settings.periodic_client_refresh_secs),
        Duration::from_secs(settings.client_metrics_interval_seconds),
    )
    .await?;
    Ok(store)
}

fn configure_remote_mutable_store(settings: &RemoteStoreSettings) -> Result<Arc<dyn MutableStore>> {
    info!("Wiring up remote mutable store to {}", settings.remote_url);

    // TODO(mjansson): Identity handling
    let identity = None::<&str>;

    Ok(Arc::new(RemoteMutableStore::new(
        settings.remote_url.as_str(),
        identity,
    )))
}

async fn configure_composite_store(
    registry: &PluginRegistry,
    settings: &CompositeStoreSettings,
    global_settings: &Settings,
    topology: Option<Arc<dyn Topology + Send + Sync>>,
) -> Result<Arc<dyn ImmutableStore>> {
    info!("Wiring up Composite store");

    let mut composite_store_builder = CompositeStoreBuilder::default()
        .with_cache_metadata(
            settings.cache_metadata.unwrap_or_default(),
            settings.cache_metadata_semaphore_size,
        )
        .with_record_copy_out_of_band(settings.record_copy_out_of_band);

    let store = Box::pin(configure_composite_substore(
        registry,
        &settings.local.mode,
        global_settings,
        &settings.local,
    ))
    .await?;
    composite_store_builder =
        composite_store_builder.with_local(settings.local.mode.clone(), store)?;

    if let Some(durable_settings) = settings.durable.as_ref() {
        let store = Box::pin(configure_composite_substore(
            registry,
            &durable_settings.mode,
            global_settings,
            durable_settings,
        ))
        .await?;
        composite_store_builder =
            composite_store_builder.with_durable(durable_settings.mode.clone(), store)?;
        if let Some(delay) = settings.durable_store_delay_ms {
            composite_store_builder =
                composite_store_builder.with_durable_delay(Duration::from_millis(delay));
        }
    }

    if let Some(replicas) = settings.replica.as_ref() {
        for store_settings in replicas.as_slice() {
            let store = Box::pin(configure_composite_substore(
                registry,
                &store_settings.mode,
                global_settings,
                store_settings,
            ))
            .await?;

            let read =
                store_settings.replication_mode.unwrap_or_default() != ReplicationMode::Write;
            let write =
                store_settings.replication_mode.unwrap_or_default() != ReplicationMode::Read;

            composite_store_builder = composite_store_builder.with_replica(
                store_settings.mode.clone(),
                store,
                read,
                write,
            );
        }
    }

    if let Some(factory_settings) = &settings.replica_factory {
        let (sni_override, quic_certs, grpc_tls) = if let Some(tls_settings) = &factory_settings.tls
        {
            info!(?tls_settings, "Loading Replica Client TLS certs");
            let quic_certs = client::CertificateSettings {
                custom_ca: tls_settings.client_certs.cert_chain.clone(),
                client: Some(ClientCerts {
                    cert_file: tls_settings.client_certs.cert_file.clone(),
                    pkey_file: tls_settings.client_certs.pkey_file.clone(),
                }),
            };
            let mut grpc_tls = load_client_tls(tls_settings.client_certs.clone())?;
            if let Some(server_sni) = &tls_settings.server_sni {
                grpc_tls = grpc_tls.domain_name(server_sni.clone());
            }
            (tls_settings.server_sni.clone(), quic_certs, Some(grpc_tls))
        } else {
            info!("No Replica client TLS defined");
            let quic_certs = client::CertificateSettings {
                custom_ca: None,
                client: None,
            };
            (None, quic_certs, None)
        };
        let mut factory = ReplicationStoreTargetFactory::new(
            grpc_tls,
            quic_certs,
            sni_override,
            factory_settings.client_message_buffer,
            factory_settings.read_replicas_enabled,
            factory_settings.use_grpc_write_replication,
        );
        factory.quic_monitor_interval =
            Duration::from_secs(factory_settings.quic_client_monitor_interval_seconds);
        factory.enable_same_region_write = factory_settings.enable_same_region_write;

        composite_store_builder = composite_store_builder.with_replica_builder(Arc::new(factory));
    }

    let store = Arc::new(composite_store_builder.build()?);

    if let Some(topology) = &topology {
        store
            .clone()
            .set_topology_subscription(topology.clone())
            .await;
    }

    Ok(store)
}

async fn configure_composite_substore(
    registry: &PluginRegistry,
    mode: &str,
    global_settings: &Settings,
    settings: &CompositeSubStoreSettings,
) -> Result<Arc<dyn ImmutableStore>> {
    match mode {
        store_mode::LOCAL => {
            let local_settings = settings
                .local
                .as_ref()
                .ok_or(anyhow!("Missing composite local store settings"))?;

            configure_local_immutable_store(local_settings).await
        }
        store_mode::REMOTE => {
            let remote_settings = settings
                .remote
                .as_ref()
                .ok_or(anyhow!("Missing composite remote store settings"))?;

            configure_remote_immutable_store(remote_settings)
        }
        store_mode::COMPOSITE => Err(anyhow!(
            "Composite store not supported as a composite substore"
        )),
        store_mode::REPLICATED => {
            let replicated_settings = settings
                .replicated
                .as_ref()
                .ok_or(anyhow!("Missing composite replicated store settings"))?;

            configure_replicated_immutable_store(replicated_settings).await
        }
        _ => {
            // All other modes use the plugin system
            let plugin_config = resolve_plugin_config_with_fallback(
                &global_settings.plugins,
                mode,
                "immutable_store",
            )
            .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));

            info!(mode, "Creating composite substore via plugin system");

            let store = registry
                .create_immutable_store(mode, &plugin_config)
                .map_err(|e| anyhow!("Failed to create {mode} immutable store: {e}"))?;

            Ok(store)
        }
    }
}

/// Build the notification sender, and the local public service when there is
/// one.
///
/// `durable_receiver` is `SCHEMA-119`'s live-receiver path: when the relay's
/// preparation built a [`ReceiverRuntime`], the `remote` plugin is constructed
/// through `factory::create_with_receiver` instead of through the registry, and
/// the receiver's readiness facet comes back as the third return value for the
/// relay readiness surface to report. Every other cell is unchanged — `local`
/// mode and `remote` without a receiver take exactly the paths they did before.
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
async fn configure_notification(
    endpoints: &mut JoinSet<Result<()>>,
    registry: &PluginRegistry,
    environment: &Option<EnvironmentConfig>,
    notification_settings: &Option<NotificationSettings>,
    immutable_store: Option<&Arc<dyn ImmutableStore>>,
    plugins: &HashMap<String, toml::Value>,
    durable_receiver: Option<(
        crate::event_relay::wiring::DurableReceiverWiring,
        tokio::sync::watch::Receiver<bool>,
    )>,
    repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    authorization_timeout: Duration,
) -> Result<(
    Arc<dyn NotificationSender>,
    Option<NotificationService>,
    Option<Arc<crate::plugins::remote_notification::ReceiverReadiness>>,
)> {
    let mode = notification_settings
        .as_ref()
        .map_or("local", |ns| ns.mode.as_ref());
    match mode {
        "local" => {
            // Unreachable with a receiver: the relay refuses to prepare one
            // under any mode but `remote`. Checked rather than assumed, because
            // silently dropping the runtime here would produce a cell that
            // reports its receiver absent while its configuration declares one.
            if durable_receiver.is_some() {
                return Err(anyhow::anyhow!(
                    "a durable receiver runtime was built for [notification] mode = \"local\", \
                     which mounts the local public service and runs no durable receiver"
                ));
            }
            info!("Starting local notification service");
            let sender = Arc::new(crate::notification::local::NotificationSender::default());
            Ok((
                sender.clone(),
                Some(NotificationService::new(
                    sender,
                    repository_authorizer,
                    authorization_timeout,
                )),
                None,
            ))
        }
        plugin_name => {
            info!(plugin_name = plugin_name, "Creating notification plugin");

            // Get the plugin config from the plugins section
            let plugin_config = plugins
                .get(plugin_name)
                .cloned()
                .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));

            let mut receiver_readiness = None;
            let output = match durable_receiver {
                Some((wiring, shutdown))
                    if plugin_name == crate::plugins::remote_notification::PLUGIN_NAME =>
                {
                    // Deliberately not through the registry. The factory trait
                    // returns a plugin and nothing else, and the receiver's
                    // readiness facet has to reach the relay's readiness
                    // surface; a registry lookup could not carry it back. The
                    // same `[plugins.remote]` table is parsed and bounded by
                    // the same code either way, so nothing is skipped.
                    let (plugin, _sender, readiness) =
                        crate::plugins::remote_notification::factory::create_with_receiver(
                            &plugin_config,
                            wiring.transport,
                            wiring.runtime,
                            shutdown,
                        )
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to create notification plugin '{plugin_name}' with a \
                                 durable receiver: {e}"
                            )
                        })?;
                    receiver_readiness = Some(readiness);
                    plugin
                }
                Some(_) => {
                    return Err(anyhow::anyhow!(
                        "a durable receiver runtime was built for [notification] mode = \
                         \"{plugin_name}\", but only the `remote` plugin runs one"
                    ));
                }
                None => {
                    let context = NotificationPluginContext {
                        environment: environment.clone(),
                        immutable_store: immutable_store.cloned(),
                    };
                    registry
                        .create_notification(plugin_name, &plugin_config, &context)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to create notification plugin '{plugin_name}': {e}"
                            )
                        })?
                }
            };

            // Spawn background tasks for the receiver tasks from the plugin.
            // With a durable receiver attached this is two tasks rather than
            // one: the live-hint worker and the receiver, both owned by the
            // server's `JoinSet`. The durable receiver observes shutdown;
            // the live-hint worker drains when its sender handles are dropped.
            for task in output.receivers {
                lore_spawn!(endpoints, async move {
                    task.await.map_err(|e| {
                        anyhow::anyhow!("Notification plugin receiver background task failed: {e}")
                    })
                });
            }

            Ok((output.sender, None, receiver_readiness))
        }
    }
}

#[cfg(target_os = "linux")]
async fn log_base_address() {
    use tracing::warn;

    let executable =
        match std::env::current_exe().map(|executable| executable.to_str().map(|s| s.to_owned())) {
            Ok(executable) => executable,
            Err(e) => {
                warn!("Could not get path to current executable: {e:?}");
                return;
            }
        };

    if let Some(executable) = executable {
        match tokio::fs::read_to_string("/proc/self/maps").await {
            Ok(maps) => {
                let mut found: bool = false;
                // The format of the maps file is documented here: https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html
                for line in maps.lines() {
                    // We're looking for the virtual address segments for our process that are
                    // readable, executable, and private.
                    if line.contains(executable.as_str()) && line.contains("r-xp") {
                        info!("Virtual address space mapping for {executable}: {}", line);
                        found = true;
                        break;
                    }
                }

                if !found {
                    warn!("Could not find mapping for {executable} in /proc/self/maps.");
                }
            }
            Err(e) => {
                warn!("Failed to read from /proc/self/maps: {e:?}");
            }
        }
    } else {
        warn!("Could not get executable path while logging base address.");
    }
}

#[cfg(feature = "seeding")]
async fn seed_local_store(settings: &LocalImmutableStoreSettings) -> Result<(), anyhow::Error> {
    const DEFAULT_BUFFER_SIZE: usize = 16_834;

    if std::env::var("LORE_SEEDING").is_ok() {
        let mut settings = settings.clone();
        // Delay flushing as long as possible during seeding to avoid unnecessary fsync's. This will
        // give us ~18 hours before we flush, so hopefully enough time for seeding to complete ;).
        settings.flush_delay_seconds = u16::MAX;
        let max_size = settings.max_size;
        let store = create_local_store(&settings, false /* flush background */).await?;

        if let Some(max_size) = max_size {
            info!("Seeding local store");
            let local_store = (store.clone() as Arc<dyn Any + Send + Sync>)
                .clone()
                .downcast::<lore_storage::local::immutable_store::LocalImmutableStore>()
                .expect("Could not downcast store");

            let margin = std::env::var("LORE_SEEDING_MARGIN")
                .map(|v| v.parse::<usize>().unwrap_or_default())
                .unwrap_or_default();

            let buffer = std::env::var("LORE_SEEDING_BUFFER").map_or(DEFAULT_BUFFER_SIZE, |v| {
                v.parse::<usize>().unwrap_or(DEFAULT_BUFFER_SIZE)
            });

            let result = lore_revision::store::seeder::seed_local_store(
                local_store,
                max_size,
                margin,
                buffer,
            )
            .await
            .map_err(anyhow::Error::from);

            info!("Done seeding local store, flushing store to disk.");
            // Since we effectively disabled background flushing, we force a flush once seeding is
            // complete
            store.flush(true).await.map_err(anyhow::Error::from)?;
            info!("Done flushing store to disk.");

            result
        } else {
            warn!("Seeding was requested, but no max size was found.");
            Err(anyhow!("Missing max size on local store settings"))
        }
    } else {
        info!("Not seeding local store");
        Ok(())
    }
}

/// Counts spawned and in-flight tasks, attributed to where each task was spawned.
struct TaskLifecycleMetrics {
    spawned_tasks: Counter<u64>,
    inflight_tasks: UpDownCounter<i64>,
}

impl TaskLifecycleObserver for TaskLifecycleMetrics {
    fn context_label(&self) -> &'static str {
        let Some(context) = lore_revision::runtime::try_execution_context() else {
            return "<no context>";
        };

        context
            .caller_state()
            .cloned()
            .and_then(|any| Arc::downcast::<ServerExecutionState>(any).ok())
            .map_or("<no server state>", |state| state.context_label)
    }

    fn on_event(&self, event: LoreTaskLifecycleEvent, spawn: &LoreTaskSpawn) {
        let labels = [
            KeyValue::new("context_label", spawn.context_label),
            KeyValue::new("spawn_file", spawn.file),
            KeyValue::new("spawn_line_number", spawn.line as i64),
        ];

        match event {
            LoreTaskLifecycleEvent::Started => {
                self.spawned_tasks.add(1, &labels);
                self.inflight_tasks.add(1, &labels);
            }
            LoreTaskLifecycleEvent::Completed | LoreTaskLifecycleEvent::Dropped => {
                self.inflight_tasks.add(-1, &labels);
            }
        }
    }
}

fn observe_task_lifecycles() {
    let meter = lore_telemetry::meter("lore.runtime");
    let observer = TaskLifecycleMetrics {
        spawned_tasks: meter
            .u64_counter("lore.runtime.tasks.spawned.total")
            .build(),
        inflight_tasks: meter
            .i64_up_down_counter("lore.runtime.tasks.running.total")
            .build(),
    };

    if !set_task_lifecycle_observer(Box::new(observer)) {
        error!("Failed to set task events callback");
    }
}

/// [`ResourceDetectorProvider`] that augments an optional caller-supplied
/// provider with the resource detectors contributed by every compiled-in plugin.
///
/// The base server has no caller-supplied provider (`inner` is `None`); derived
/// binaries may set [`ServerConfig::resource_detector_provider`] to add detectors
/// on top of the plugin-contributed ones.
struct PluginResourceDetectorProvider<'a> {
    inner: Option<&'a dyn ResourceDetectorProvider>,
    registry: &'a PluginRegistry,
}

impl ResourceDetectorProvider for PluginResourceDetectorProvider<'_> {
    fn detectors(&self, runtime_handle: Handle) -> Vec<Box<dyn ResourceDetector>> {
        let mut detectors = self
            .inner
            .map(|provider| provider.detectors(runtime_handle.clone()))
            .unwrap_or_default();
        detectors.extend(self.registry.resource_detectors(runtime_handle));
        detectors
    }
}

async fn async_main(settings: (Settings, StringHash), config: ServerConfig) -> Result<()> {
    // Initialize metrics and tracing telemetry, returns a guard that will cleanup when it falls out
    // of scope
    let (mut settings, settings_hash) = settings;
    crate::grpc::caller_capabilities::validate_settings(&settings)?;
    let runtime = runtime();
    let telemetry = settings.telemetry.clone().unwrap_or_default();
    let metrics_config = telemetry.metrics.clone().unwrap_or_default();
    let ua = &settings.server.user_agent;
    let user_agent_filter = Arc::new(
        UserAgentFilter::new(&ua.user_agent_patterns)
            .map_err(|e| anyhow::anyhow!("Invalid user_agent_patterns: {e}"))?
            .with_unknown_sample_rate(ua.unknown_user_agent_sample_rate),
    );

    // Initialize the plugin registry before telemetry: start with the
    // pre-populated registry from config, then register any build.rs-discovered
    // plugins. This must happen first so that every compiled-in plugin can
    // contribute OpenTelemetry resource detectors describing the deployment
    // environment it implies (e.g. AWS region, Nomad allocation).
    let mut plugin_registry = config.plugin_registry;
    plugins::register_all_plugins(&mut plugin_registry);

    let _guard = {
        let resource_detector_provider = PluginResourceDetectorProvider {
            inner: config.resource_detector_provider.as_deref(),
            registry: &plugin_registry,
        };
        TelemetryInitializer::from_config(
            &telemetry,
            runtime.clone(),
            Some(&resource_detector_provider),
        )?
        .init()?
    };

    observe_task_lifecycles();

    let up_gauge = lore_telemetry::meter("urc.server")
        .u64_gauge("urc.server.up")
        .build();
    let up_attributes = [
        KeyValue::new("version", LORE_LIBRARY_VERSION.to_string()),
        KeyValue::new("settings_hash", settings_hash.to_string()),
    ];
    up_gauge.record(0, &up_attributes);

    // We use /procfs to read the virtual address space of the process to ensure we're able to
    // calculate the correct offsets when symbolicating crashes. /procfs does not exist outside of
    // Linux.
    #[cfg(target_os = "linux")]
    log_base_address().await;

    let execution = execution_context();
    let frequency = Duration::from_millis(metrics_config.export_interval_millis);
    let meter = lore_telemetry::meter("tokio_runtime");

    // Both recorders run on core so monitoring never competes with net's
    // transport work; each bridge holds its own handle, so that does not skew
    // what it reports.
    for (label, handle) in [
        ("core", lore_base::runtime::core_runtime()),
        ("net", lore_base::runtime::net_runtime()),
    ] {
        let runtime_monitor = tokio_metrics::RuntimeMonitor::new(&handle);
        let metrics_bridge =
            OtelTokioRuntimeMetrics::new(&meter, handle, vec![KeyValue::new("runtime", label)]);
        lore_spawn!(LORE_CONTEXT.scope(execution.clone(), async move {
            for metrics in runtime_monitor.intervals() {
                metrics_bridge.record(metrics);
                tokio::time::sleep(frequency).await;
            }
        }));
    }

    if let Some(mode) = settings
        .environment
        .as_ref()
        .and_then(|env| env.config.as_ref())
        .and_then(|cfg| cfg.compression_mode.as_ref())
    {
        COMPRESSION_MODE.store(*mode as u32, std::sync::atomic::Ordering::Release);
    }

    info!(
        "Registered plugins - immutable stores: {:?}, mutable stores: {:?}, lock stores: {:?}, topology: {:?}, notification: {:?}",
        plugin_registry.list_immutable_store_plugins(),
        plugin_registry.list_mutable_store_plugins(),
        plugin_registry.list_lock_store_plugins(),
        plugin_registry.list_topology_plugins(),
        plugin_registry.list_notification_plugins(),
    );

    let local_stores = local_store_locations(&settings.immutable_store, &settings.mutable_store);
    report_local_store_locations(&local_stores);

    #[cfg(feature = "seeding")]
    {
        let mode = &settings.immutable_store.mode;

        // We're ok assuming that local store settings are present when seeding is enabled, if it's
        // not let it panic, and we can fix the configuration.
        let local_store_settings = match mode.as_str() {
            store_mode::LOCAL => settings
                .immutable_store
                .local
                .clone()
                .ok_or(anyhow!("Missing local immutable store settings")),
            store_mode::COMPOSITE => settings
                .immutable_store
                .composite
                .as_ref()
                .and_then(|s| s.local.local.clone())
                .ok_or(anyhow!("Missing composite store settings")),
            _ => {
                // If store mode is not local or composite, there's no local store settings to be
                // had.
                Err(anyhow!("No local store settings found"))
            }
        }?;

        seed_local_store(&local_store_settings).await?;
    }

    // Configure topology using plugin registry
    let topology_provider = settings
        .topology
        .as_ref()
        .and_then(|t| t.provider.plugin_name());

    let topology = configure_topology_with_registry(
        &plugin_registry,
        settings.topology.as_ref(),
        &settings.plugins,
    )?;

    if let Some(ref topo) = topology {
        info!(
            "Using topology plugin: {}",
            topology_provider.unwrap_or("none")
        );
        info!(
            "Topology supports refresh loop: {}",
            topo.supports_refresh_loop()
        );
    } else {
        info!("Running in single-node mode (no topology configured)");
    }

    // Only an enabled governed fragment route needs the lifecycle coordinator
    // before immutable-store construction. Absent and disabled configurations
    // preserve the legacy boot order exactly: immutable first, domain second.
    // Validated for every Postgres-mode cell, so the ceiling applies to a
    // provider-disabled one too. Only a cell whose checked budget actually
    // carries a dispatch pool takes the provider boot order below, and that
    // question is asked of the validated budget rather than re-derived from a
    // raw field — one place decides what a zero dispatch maximum means.
    let fragment_process_pool_inventory = postgres_fragment_process_pool_inventory(&settings)?
        .map(lore_postgres::domain::fragments::FragmentProcessPoolInventory::validate)
        .transpose()
        .map_err(|error| anyhow!("Invalid Postgres process pool inventory: {error}"))?;
    // The concrete store creates an opaque worker handle before trait erasure.
    let (immutable_store, cell_retention_handle, write_behind_handle, configured_domain) =
        if let Some(process_pool_inventory) = fragment_process_pool_inventory
            .filter(|inventory| inventory.budget().opens_dispatch_pool())
        {
            let configured_domain = crate::domain::configure_domain_context(&settings).await?;
            let coordinator = configured_domain
            .fragment_coordinator
            .clone()
            .ok_or_else(|| {
                anyhow!(
                    "enabled fragment_provider requires the Postgres fragment lifecycle coordinator"
                )
            })?;
            let expected_database_identity =
                configured_domain.database_identity.clone().ok_or_else(|| {
                    anyhow!(
                        "enabled fragment_provider requires the attested Postgres database identity"
                    )
                })?;
            let fragment_activation = plugins::postgres::FragmentProviderActivation::new(
                coordinator,
                process_pool_inventory,
                expected_database_identity,
            );
            let (immutable_store, cell_retention_handle, write_behind_stage) =
                configure_immutable_store_via_plugin(
                    &plugin_registry,
                    &settings,
                    topology.clone(),
                    Some(fragment_activation),
                    configured_domain.fragment_stage_observer.clone(),
                )
                .await?;
            (
                immutable_store,
                cell_retention_handle,
                write_behind_stage,
                configured_domain,
            )
        } else {
            let (immutable_store, cell_retention_handle, write_behind_stage) =
                configure_immutable_store_via_plugin(
                    &plugin_registry,
                    &settings,
                    topology.clone(),
                    None,
                    None,
                )
                .await?;
            let configured_domain = crate::domain::configure_domain_context(&settings).await?;
            (
                immutable_store,
                cell_retention_handle,
                write_behind_stage,
                configured_domain,
            )
        };

    // A retention handle is published only by the constructed Postgres store's
    // coordinated route. Merely configuring a domain coordinator does not prove it.
    if let Some(grpc) = &settings.server.grpc {
        crate::grpc::caller_capabilities::validate_serving_fragment_route(
            grpc.caller_capability_policy,
            settings.immutable_store.mode == "postgres",
            cell_retention_handle.is_some(),
        )?;
    }

    // CR-029: the domain coordinator is built before mutable-store publication
    // on both branches, so readiness still arms the one enforcement handle the
    // concrete Postgres mutable store must receive.
    let mutable_context = MutableStorePluginContext {
        domain_enforcement: configured_domain.mutable_enforcement.clone(),
    };
    let mutable_store = configure_mutable_store_via_plugin(
        &plugin_registry,
        &settings,
        immutable_store.clone(),
        &mutable_context,
    )
    .await?;

    crate::util::local_store_monitor::start_local_store_monitor(
        monitored_local_store_paths(local_stores),
        &settings.server.local_store_monitor,
    );

    let lock_store = configure_lock_store_via_plugin(&plugin_registry, &settings)?;
    // Kept before the partial move below. This is the identity every CR-007
    // pool was positively proven to share, and it is what the CR-032 relay pool
    // is checked against: a relay reading a different database would report an
    // empty backlog that means nothing.
    let configured_domain_identity = configured_domain.database_identity.clone();
    // Also kept before the partial move. WP-114 CD-6's prune scheduler runs on
    // this same coordinator and pool; a cell whose governed fragment route is
    // off has no claims to prune and gets no task.
    let configured_fragment_coordinator = configured_domain.fragment_coordinator.clone();
    let domain_context = configured_domain.context;
    if settings.server.grpc.as_ref().is_some_and(|grpc| {
        grpc.caller_capability_policy
            == crate::grpc::caller_capabilities::CallerCapabilityPolicy::RequireOutcomeUnknownV1
    }) {
        anyhow::ensure!(
            domain_context
                .as_ref()
                .is_some_and(|domain| domain.enforcement_enabled()),
            "required caller capability policy requires governed domain enforcement"
        );
    }
    // The internal forwarding endpoint reaches the same repository handlers, so
    // it gets the same coordinator handle rather than an ungoverned bypass.
    let internal_domain_context = domain_context.clone();

    let connection_close_timeout =
        Duration::from_secs(settings.server.connection_close_timeout_seconds as u64);

    // Graceful drain (CR semantics): opt-in via [server] graceful_drain. When
    // enabled, the QUIC endpoints refuse new connections on shutdown but let
    // established connections finish (bounded by drain_timeout_seconds, 0 =
    // unbounded; stalled connections are culled by the stall guard). The
    // endpoint-join force-abort deadline is lifted accordingly; disabled, the
    // historic connection_close_timeout semantics apply unchanged.
    let graceful_drain = settings.server.graceful_drain;
    let drain_timeouts = graceful_drain.then(|| DrainTimeouts {
        drain_timeout: (settings.server.drain_timeout_seconds > 0)
            .then(|| Duration::from_secs(settings.server.drain_timeout_seconds as u64)),
        stall_timeout: (settings.server.drain_stall_timeout_seconds > 0)
            .then(|| Duration::from_secs(settings.server.drain_stall_timeout_seconds as u64)),
    });
    if let Some(timeouts) = drain_timeouts
        && timeouts.drain_timeout.is_none()
        && timeouts.stall_timeout.is_none()
    {
        warn!(
            "graceful_drain is enabled with drain_timeout_seconds = 0 AND \
             drain_stall_timeout_seconds = 0: shutdown has no backstop and will \
             wait forever for a wedged or idle peer. Set a stall timeout unless \
             an external controller enforces its own drain ceiling"
        );
    }
    let endpoint_join_timeout = if graceful_drain {
        drain_timeouts
            .and_then(|t| t.drain_timeout)
            .map(|d| d + connection_close_timeout)
    } else {
        Some(connection_close_timeout)
    };
    let drain_state = DrainState::new();

    let is_maintenance = if std::env::var("LORE_SERVER_MAINTENANCE").is_ok_and(|v| v == "1") {
        info!(
            "Server is running in maintenance mode - only environment and health endpoints will be served"
        );
        true
    } else {
        false
    };

    let jwt_verifier = match settings.server.auth.as_ref() {
        Some(auth) => {
            let jwk = auth.jwk.clone().unwrap_or_default();
            let jwk_service = JwkServiceImpl::with_issuers(jwk, Some(&auth.jwt_issuer))?;
            jwk_service
                .fetch_new_keys(None /* fetch all keys */)
                .await?;
            Some(JwtVerifier {
                jwk_service: Arc::new(jwk_service),
                jwt_issuer: Some(auth.jwt_issuer.clone()),
                jwt_audience: Some(auth.jwt_audience.clone()),
                jwt_typ: auth.jwt_typ.clone(),
                identity_claim: auth.identity_claim.clone(),
            })
        }
        None => None,
    };

    if let Some(auth) = settings.server.auth.as_ref() {
        let auth_url = settings
            .environment
            .as_ref()
            .and_then(|environment| environment.endpoint.as_ref())
            .and_then(|endpoint| endpoint.auth_url.as_deref());
        let oidc = advertised_oidc(auth, auth_url).await?;
        settings.environment.get_or_insert_default().oidc = oidc;
    }

    // One shared authorizer, selected by the configuration (D8's four-way
    // flowchart), threaded into the gRPC, QUIC and HTTP servers.
    let auth_url = settings
        .environment
        .as_ref()
        .and_then(|environment| environment.endpoint.as_ref())
        .and_then(|endpoint| endpoint.auth_url.clone());
    // FORK-LOCAL (Tideshift): refuse GlobalGrants here too, not only at config
    // load, so a `Settings` built by any other path still cannot start a server
    // that lets every verified token reach every repository.
    crate::authnz::repository_authorizer::refuse_global_grants(
        crate::authnz::repository_authorizer::select_repository_authorizer(
            settings.server.auth.as_ref(),
            auth_url.as_deref(),
        )?,
    )?;
    let repository_authorizer = crate::authnz::repository_authorizer::repository_authorizer(
        settings.server.auth.as_ref(),
        auth_url.clone(),
    )?;
    let repository_catalog = crate::authnz::repository_catalog::repository_catalog(
        settings.server.auth.as_ref(),
        auth_url.as_deref(),
        immutable_store.clone(),
        mutable_store.clone(),
    )?;

    let forwarded_requests: Option<Arc<dyn ForwardedRequests>> =
        if let Some(forwarded_requests_settings) =
            &settings.server.grpc_public_services.forwarded_requests
        {
            let factory = GrpcForwardedRequests::new(forwarded_requests_settings).await?;
            Some(Arc::new(factory))
        } else {
            None
        };

    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    let (termination_tx, termination_rx) = tokio::sync::watch::channel(0u32);
    let mut endpoints = JoinSet::new();

    // Spawn signal listener outside the endpoint JoinSet so the drain
    // timeout only starts after the signal fires.
    lore_spawn!(listen_for_termination(termination_tx));

    // The signal flips the aggregate draining flag at once, so the health
    // check goes 503 and the LB starts pulling the node. With a lame-duck
    // period every endpoint keeps admitting work for that long before the
    // shutdown signal (and so every drain and its timeout) starts.
    let lame_duck = (settings.server.lame_duck_seconds > 0)
        .then(|| Duration::from_secs(settings.server.lame_duck_seconds as u64));
    lore_spawn!(crate::drain::lame_duck_then_shutdown(
        termination_rx,
        shutdown_tx.clone(),
        drain_state.clone(),
        graceful_drain,
        lame_duck,
    ));

    // Declared outside the maintenance branch so the HTTP surface below can
    // report the facets whether or not a relay was built. A maintenance-mode
    // node runs no relay and reports `configured: false`, which is the honest
    // answer rather than a green one.
    let mut event_relay_handles: Option<crate::event_relay::wiring::EventRelayHandles> = None;
    // Declared beside the relay handles and for the same reason: the HTTP
    // surface reports the facet whether or not a scheduler was started, and a
    // maintenance node runs neither.
    let mut fragment_prune_readiness: Option<Arc<crate::fragment_prune::FragmentPruneReadiness>> =
        None;
    // WP-114 CD-8's facet, declared here for the same reason as the two above.
    let mut cell_retention_readiness: Option<
        Arc<lore_object_dispatch::cell_retention::CellRetentionReadiness>,
    > = None;
    let mut write_behind_readiness = None;

    if !is_maintenance {
        write_behind_readiness = crate::fragment_write_behind::configure_fragment_write_behind(
            write_behind_handle,
            postgres_write_behind_settings(&settings)?.map(|config| config.runtime),
            &mut endpoints,
            _shutdown_rx.clone(),
        )?;
        // CR-032 / WP-119 Step B, in two halves.
        //
        // The preparation runs FIRST and spawns nothing. It owns the whole
        // fail-closed startup sequence — notification mode, `[plugins.remote]`,
        // Postgres mode, co-location, schema state, cutover — and it builds the
        // relay's pool and gateway transport. A misconfigured notification mode
        // is still reported by its own mode check rather than by a confusing
        // gateway-connect failure, because that check runs before any I/O.
        //
        // It runs before `configure_notification` for one reason: a cell that
        // declares `[plugins.remote.receiver]` needs that pool and that channel
        // handed to the notification plugin at construction, since the durable
        // receiver is one of the plugin's own `receivers`. Returns `None` on
        // every cell that has not set `[outbox_relay] enabled = true`.
        let event_relay_prepared = crate::event_relay::wiring::prepare_event_relay(
            &settings,
            configured_domain_identity.as_ref(),
            domain_context.as_ref(),
        )
        .await?;

        // Subscribe authorizes from the request body, so its check is made in
        // the handler rather than by the partition-access layer. It is the
        // same kind of check either way, so it answers to the same
        // authorization budget as that layer rather than to the longer
        // request-handler budget. Without a gRPC endpoint the service is
        // unreachable and the fallback is moot.
        let notification_authorization_timeout = Duration::from_secs(
            settings
                .server
                .grpc
                .as_ref()
                .map_or_else(default_authorization_timeout_seconds, |grpc| {
                    grpc.authorization_timeout_seconds
                }),
        );
        let (notification, notification_service, receiver_readiness) = configure_notification(
            &mut endpoints,
            &plugin_registry,
            &settings.environment,
            &settings.notification,
            local_store().as_ref(),
            &settings.plugins,
            event_relay_prepared
                .as_ref()
                .and_then(|prepared| prepared.durable_receiver())
                .map(|wiring| (wiring, _shutdown_rx.clone())),
            repository_authorizer.clone(),
            notification_authorization_timeout,
        )
        .await?;

        // The second half: attach the admission gate and the receiver's
        // readiness facet, then start the tasks. Still before the gRPC surface,
        // so a cell that cannot relay never accepts a mutation that would
        // append a row nothing will publish.
        if let Some(prepared) = event_relay_prepared {
            event_relay_handles = Some(crate::event_relay::wiring::spawn_event_relay(
                prepared,
                receiver_readiness,
                &mut endpoints,
                _shutdown_rx.clone(),
            )?);
        }

        // WP-114 CD-6, beside the relay worker and on the same drain signal.
        // Inert unless the governed fragment route is enabled: that route is
        // the only writer of the claims this removes.
        fragment_prune_readiness = crate::fragment_prune::configure_fragment_prune(
            configured_fragment_coordinator.as_ref(),
            postgres_fragment_prune_settings(&settings)?,
            &mut endpoints,
            _shutdown_rx.clone(),
        );

        // WP-114 CD-8, on the same drain signal and inert on the same cells.
        // Unlike the prune this one can refuse startup: it proves the retention
        // layer is installed before spawning, because a cell without it would
        // fail every pass and report the reason only through the facet, several
        // ticks later.
        cell_retention_readiness = crate::fragment_retention::configure_cell_retention(
            cell_retention_handle,
            postgres_cell_retention_settings(&settings)?,
            &mut endpoints,
            _shutdown_rx.clone(),
        )
        .await?;

        // Build hook dispatcher: register build.rs-discovered hooks then config-provided hooks
        let hook_ctx = HookRegistrationContext {
            notification_sender: notification.clone(),
        };
        let mut hook_registry = HookRegistry::new();
        crate::hooks::register_all_hooks(&mut hook_registry, &hook_ctx);
        for callback in config.hook_registration_callbacks {
            callback(&mut hook_registry, &hook_ctx);
        }

        let enabled_hooks = hook_registry
            .create_enabled_hooks(&settings.hooks)
            .expect("Failed to create hooks from configuration");

        let hook_dispatcher = Arc::new(HookDispatcher::from_hooks_default(enabled_hooks));

        lore_spawn!(endpoints, {
            let immutable_store = immutable_store.clone();
            let mutable_store = mutable_store.clone();
            let lock_store = lock_store.clone();
            let jwt_verifier = jwt_verifier.clone();
            let repository_authorizer = repository_authorizer.clone();
            let repository_catalog = repository_catalog.clone();
            let settings = settings.clone();
            let notification = notification.clone();
            let user_agent_filter = user_agent_filter.clone();
            let forwarded_requests = forwarded_requests.clone();
            let shutdown_rx = _shutdown_rx.clone();
            let drain_state = drain_state.clone();

            // The main store only fills the slot. Verify is the one operation
            // that reads it, and it refuses anything but a local store (row 72).
            let local_immutable_store = local_store().unwrap_or_else(|| {
                warn!("No local store available for gRPC server, Verify will be refused unless the main store is local");
                immutable_store.clone()
            });

            launch_grpc_server(
                immutable_store,
                local_immutable_store,
                mutable_store,
                lock_store,
                domain_context,
                jwt_verifier,
                repository_authorizer,
                repository_catalog,
                settings,
                notification,
                notification_service,
                hook_dispatcher.clone(),
                user_agent_filter,
                forwarded_requests,
                shutdown_rx,
                drain_state,
                graceful_drain,
            )
        });

        if let Some(grpc_internal) = &settings.server.grpc_internal
            && grpc_internal.enabled
        {
            let security = validate_endpoint_security(
                "[server.grpc_internal]",
                grpc_internal.certificate.as_ref(),
                grpc_internal.verify_client_certs,
            )?;
            if security == EndpointSecurity::Untrusted {
                warn!(
                    "[server.grpc_internal] starting WITHOUT mTLS because verify_client_certs=false. \
                     The gRPC internal endpoint grants blanket access to every storage partition; \
                     only safe on isolated networks with no untrusted clients"
                );
            }
            lore_spawn!(endpoints, {
                let settings = settings.clone();
                let user_agent_filter = user_agent_filter.clone();
                let immutable_store = immutable_store.clone();
                let mutable_store = mutable_store.clone();
                let notification_sender = notification.clone();
                let hook_dispatcher = hook_dispatcher.clone();
                let jwt_verifier = jwt_verifier.clone();
                let repository_authorizer = repository_authorizer.clone();
                let shutdown_rx = _shutdown_rx.clone();
                // CR-032 / WP-119 Step C. `None` on every cell whose relay is
                // disabled, which is all of them today; the service is then not
                // routed at all rather than routed and refusing.
                let stream_reset_service = event_relay_handles
                    .as_ref()
                    .map(|handles| handles.reset_service.clone());
                launch_grpc_internal_server(
                    settings,
                    user_agent_filter,
                    immutable_store,
                    mutable_store,
                    notification_sender,
                    hook_dispatcher,
                    internal_domain_context,
                    stream_reset_service,
                    jwt_verifier,
                    repository_authorizer,
                    shutdown_rx,
                )
            });
        }
    } else {
        let grpc_settings = settings
            .server
            .grpc
            .clone()
            .ok_or(anyhow!("Missing gRPC settings"))?;
        let environment = settings.environment.clone().unwrap_or_default();

        lore_spawn!(endpoints, {
            let shutdown_rx = _shutdown_rx.clone();
            launch_maintenance_grpc_server(grpc_settings, environment.clone(), shutdown_rx)
        });

        if let Some(grpc_internal) = &settings.server.grpc_internal
            && grpc_internal.enabled
        {
            lore_spawn!(endpoints, {
                let grpc_settings = grpc_internal.clone();
                let shutdown_rx = _shutdown_rx.clone();
                launch_maintenance_grpc_server(grpc_settings, environment, shutdown_rx)
            });
        }
    }

    // the public facing QUIC server. Authentication is via JWT, so the
    // verify_client_certs flag is intentionally false in every shipped
    // config and is not validated here.
    if !is_maintenance
        && let Some(quic_settings) = settings.server.quic.as_ref()
        && quic_settings.enabled
    {
        let public_registry = ConnectionRegistry::new("public");
        drain_state.add_registry(public_registry.clone());

        lore_spawn!(endpoints, {
            let immutable_store = immutable_store.clone();
            let mutable_store = mutable_store.clone();
            let settings = settings.clone();
            let jwt_verifier = jwt_verifier.clone();
            let repository_authorizer = repository_authorizer.clone();
            let user_agent_filter = user_agent_filter.clone();
            let shutdown_rx = _shutdown_rx.clone();
            let connection_registry = public_registry.clone();
            // Same caller-capability policy as gRPC: required mode makes public QUIC read-only.
            // Read before `settings.server.quic` is moved out below.
            let caller_capability_policy = quic_caller_capability_policy(&settings);

            let quic_settings = settings
                .server
                .quic
                .ok_or(anyhow!("Missing Public QUIC config"))?;
            let request_handler_timeout = quic_settings
                .handler_timeout_seconds
                .map(Duration::from_secs);

            /// With the 8 streams a connection opens this amounts to 4000 commands being
            /// processed in parallel per connection.
            const DEFAULT_STREAM_MESSAGE_LIMIT: usize = 500;
            let process_limit = quic_settings
                .stream_message_limit
                .unwrap_or(DEFAULT_STREAM_MESSAGE_LIMIT);
            let limits = AdmissionLimits {
                process_limit,
                inflight_limit: connection_inflight_limit(&quic_settings, process_limit),
                handler_timeout: request_handler_timeout,
                permit_timeout: quic_settings.permit_timeout_ms.map(Duration::from_millis),
            };

            // As for the gRPC server: only Verify reads this slot, and it
            // refuses anything but a local store (row 72).
            let local_immutable_store = local_store().unwrap_or_else(|| {
                warn!("No local store available for public QUIC server, Verify will be refused unless the main store is local");
                immutable_store.clone()
            });

            info!(
                "Lore Public QUIC Server: Auth: {}",
                jwt_verifier.as_ref().map_or("no", |_| "yes")
            );

            // Same read≠write gate as the gRPC surface (default ON; a token must
            // carry `write` to mutate storage). ADR-00011.
            let enforce_write_permission = settings
                .server
                .auth
                .as_ref()
                .is_none_or(|auth| auth.enforce_write_permission);

            launch_quinn_server(
                "public",
                Box::new(QuicPublicStreamHandler::new(
                    immutable_store,
                    local_immutable_store,
                    mutable_store,
                    jwt_verifier,
                    enforce_write_permission,
                    repository_authorizer,
                    limits,
                    user_agent_filter,
                    caller_capability_policy,
                )),
                frequency,
                quic_settings,
                // User-facing endpoint: generate an ephemeral certificate when
                // none is configured so the server runs with zero config.
                true,
                shutdown_rx,
                connection_registry,
                drain_timeouts,
            )
        });
    }

    // the internal-only QUIC server. Hosts the ReplicationStoreService —
    // blanket storage access with no JWT layer — so the startup-time
    // validator demands mTLS unless verify_client_certs is explicitly
    // disabled.
    if !is_maintenance
        && let Some(quic_internal_settings) = settings.server.quic_internal.as_ref()
        && quic_internal_settings.enabled
    {
        let security = validate_endpoint_security(
            "[server.quic_internal]",
            quic_internal_settings.certificate.as_ref(),
            quic_internal_settings.verify_client_certs,
        )?;
        if security == EndpointSecurity::Untrusted {
            warn!(
                "[server.quic_internal] starting WITHOUT mTLS because verify_client_certs=false. \
                 The internal QUIC endpoint serves the replication store with blanket access \
                 to every storage partition; only safe on isolated networks with no untrusted \
                 clients"
            );
        }
        // Without mTLS the certificate is only there to satisfy the TLS
        // handshake — peers connect over `quic://` and do not validate it — so
        // an ephemeral one keeps the endpoint zero-config. Under mTLS the
        // certificate is the authentication, and a generated one would be
        // worthless, so that path keeps demanding a configured triple.
        let generate_ephemeral_cert = security == EndpointSecurity::Untrusted;
        let internal_registry = ConnectionRegistry::new("internal");
        drain_state.add_registry(internal_registry.clone());

        lore_spawn!(endpoints, {
            let immutable_store = immutable_store.clone();
            let settings = settings.clone();
            let shutdown_rx = _shutdown_rx.clone();
            let connection_registry = internal_registry.clone();
            let user_agent_filter = user_agent_filter.clone();

            let quic_settings = settings
                .server
                .quic_internal
                .ok_or(anyhow!("Missing Internal QUIC config"))?;
            let request_handler_timeout = quic_settings
                .handler_timeout_seconds
                .map(Duration::from_secs);

            let local_immutable_store = internal_quic_local_store(local_store(), &immutable_store);

            let process_limit = quic_settings
                .stream_message_limit
                .unwrap_or(replication_store_service::DEFAULT_CLIENT_MESSAGE_LIMIT);
            let limits = AdmissionLimits {
                process_limit,
                inflight_limit: connection_inflight_limit(&quic_settings, process_limit),
                handler_timeout: request_handler_timeout,
                permit_timeout: quic_settings.permit_timeout_ms.map(Duration::from_millis),
            };

            launch_quinn_server(
                "internal",
                Box::new(QuicInternalStreamHandler::new(
                    immutable_store,
                    local_immutable_store,
                    limits,
                    user_agent_filter,
                )),
                frequency,
                quic_settings,
                generate_ephemeral_cert,
                shutdown_rx,
                connection_registry,
                drain_timeouts,
            )
        });
    }

    if !is_maintenance {
        if let Some(http_settings) = settings.server.http.as_ref()
            && http_settings.enabled
        {
            let mut lore_http_settings =
                build_lore_http_settings(http_settings, user_agent_filter.clone());
            lore_http_settings.caller_capability_policy = settings
                .server
                .grpc
                .as_ref()
                .map(|grpc| grpc.caller_capability_policy)
                .unwrap_or_default();
            // FORK-LOCAL (Tideshift): the same read≠write gate as the gRPC and
            // QUIC surfaces (default ON). ADR-00011.
            lore_http_settings.enforce_write_permission = settings
                .server
                .auth
                .as_ref()
                .is_none_or(|auth| auth.enforce_write_permission);
            let immutable_store = immutable_store.clone();
            let mutable_store = mutable_store.clone();
            let shutdown_rx = _shutdown_rx.clone();
            let drain_state = drain_state.clone();
            let event_relay_readiness = event_relay_handles
                .as_ref()
                .map(|handles| handles.readiness.clone());

            lore_spawn!(
                endpoints,
                launch_http_server(
                    lore_http_settings,
                    immutable_store,
                    mutable_store,
                    jwt_verifier,
                    repository_authorizer,
                    shutdown_rx,
                    HttpSurfaceFacets {
                        drain_state,
                        graceful_drain,
                        event_relay: event_relay_readiness,
                        fragment_prune: fragment_prune_readiness,
                        cell_retention: cell_retention_readiness,
                        write_behind: write_behind_readiness,
                    },
                )
            );
        }
    } else if let Some(http_settings) = settings.server.http.as_ref()
        && http_settings.enabled
    {
        lore_spawn!(endpoints, {
            let host = http_settings.host.clone();
            let port = http_settings.port;
            let user_agent_filter = user_agent_filter.clone();
            let shutdown_rx = _shutdown_rx.clone();
            LoreHttpServer::serve_maintenance(host, port, user_agent_filter, async move {
                let _ = shutdown_rx.clone().wait_for(|&v| v).await;
            })
        });
    }

    if let Some(topology) = &topology
        && topology.supports_refresh_loop()
    {
        let topology = topology.clone();
        lore_spawn!(endpoints, async move {
            topology.refresh_loop().await.map_err(anyhow::Error::from)
        });
    }

    lore_spawn!(async move {
        if let Some(store) = local_store() {
            crate::store::memory_stats_reporter(
                Arc::downgrade(&store),
                telemetry
                    .metrics
                    .map(|m| Duration::from_millis(m.sample_interval_millis)),
            )
            .await;
        }
    });

    spawn_drain_metrics(drain_state.clone(), frequency);

    up_gauge.record(1, &up_attributes);
    wait_for_shutdown(endpoints, shutdown_tx, endpoint_join_timeout).await?;
    up_gauge.record(0, &up_attributes);

    info!("Flushing stores");
    let _ = immutable_store.flush(true).await;
    let _ = mutable_store.flush(true).await;

    Ok(())
}

fn server_log_dispatch(level: lore_base::log::LoreLogLevel, location: &str, message: &str) {
    let correlation_id = lore_revision::lore::try_execution_context()
        .map(|e| e.dispatcher.correlation_id.clone())
        .unwrap_or_default();

    match level {
        lore_base::log::LoreLogLevel::None | lore_base::log::LoreLogLevel::Trace => {
            trace!(correlation_id, target = location, "{}", message);
        }
        lore_base::log::LoreLogLevel::Debug => {
            debug!(correlation_id, target = location, "{}", message);
        }
        lore_base::log::LoreLogLevel::Info => {
            info!(correlation_id, target = location, "{}", message);
        }
        lore_base::log::LoreLogLevel::Warn => {
            warn!(correlation_id, target = location, "{}", message);
        }
        lore_base::log::LoreLogLevel::Error => {
            error!(correlation_id, target = location, "{}", message);
        }
    }
}

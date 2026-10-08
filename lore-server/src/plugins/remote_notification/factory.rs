// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The `NotificationPluginFactory` for mode `remote`.
//!
//! `[notification] mode = "remote"` makes common server construction look this
//! name up in the plugin registry and hand it the `[plugins.remote]` table.
//! Selecting a plugin means no local public `NotificationService` is mounted,
//! which is exactly what the contract requires of a multi-replica cell.
//!
//! Registration itself is **not** done here. See
//! [`super::register`] for why, and for the exact call WP-119's `SCHEMA-119`
//! window must add.

use async_trait::async_trait;

use super::client::PrivateGatewayClient;
use super::client::PublishTransport;
use super::config::INSECURE_TRANSPORT_BANNER;
use super::config::PLUGIN_NAME;
use super::config::RemoteNotificationConfig;
use super::error::RemoteNotificationError;
use super::mode::PluginMode;
use super::receiver::DurableReceiver;
use super::receiver::ReceiverReadiness;
use super::receiver::ReceiverRuntime;
use super::sender;
use crate::plugins::NotificationPlugin;
use crate::plugins::NotificationPluginContext;
use crate::plugins::NotificationPluginFactory;
use crate::plugins::PluginError;

/// The factory WP-119 registers under the name `remote`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RemoteNotificationPluginFactory;

#[async_trait]
impl NotificationPluginFactory for RemoteNotificationPluginFactory {
    /// Parses and bounds every setting, and rejects an incompatible private
    /// transport version or durable payload-version range, without any I/O.
    ///
    /// # Errors
    /// [`PluginError::PluginConfigError`] naming the offending field. No
    /// message carries credential material.
    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError> {
        RemoteNotificationConfig::parse(config)
            .map(|_| ())
            .map_err(|e| e.into_plugin_error(PLUGIN_NAME))
    }

    /// Builds the sender and its single bounded worker.
    ///
    /// The gateway channel is lazy, so a gateway that is down at boot does not
    /// stop the cell from starting and serving storage. The notification
    /// plane's own readiness is a separate facet.
    ///
    /// # Errors
    /// [`PluginError::PluginConfigError`] for a configuration fault, or
    /// [`PluginError::PluginInitError`] when the mTLS material cannot be read
    /// or the endpoint is rejected.
    async fn create(
        &self,
        config: &toml::Value,
        _context: &NotificationPluginContext,
    ) -> Result<NotificationPlugin, PluginError> {
        let config = RemoteNotificationConfig::parse(config)
            .map_err(|e| e.into_plugin_error(PLUGIN_NAME))?;
        let client =
            PrivateGatewayClient::connect(&config).map_err(|e| e.into_plugin_error(PLUGIN_NAME))?;
        Ok(build_plugin(&config, client, PluginMode::Remote, None).0)
    }

    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }
}

/// Builds the plugin over a supplied transport, so a component test can drive
/// the whole sender against [`super::fake_gateway::FakeGateway`].
///
/// Returns the plugin the server would receive **and** the concrete sender, so
/// a test can read the queue diagnostics and control when the last sender
/// handle drops.
///
/// # Errors
/// Returns the same configuration faults [`NotificationPluginFactory::create`]
/// does.
pub fn create_with_transport(
    config: &toml::Value,
    transport: std::sync::Arc<dyn PublishTransport>,
) -> Result<
    (
        NotificationPlugin,
        std::sync::Arc<sender::RemoteNotificationSender>,
    ),
    PluginError,
> {
    let config =
        RemoteNotificationConfig::parse(config).map_err(|e| e.into_plugin_error(PLUGIN_NAME))?;
    let client = PrivateGatewayClient::with_transport(&config, transport);
    Ok(build_plugin(&config, client, PluginMode::Remote, None))
}

/// Build the plugin with a live durable receiver attached.
///
/// This is the entry point `SCHEMA-119` calls once it holds the Postgres pool
/// and the durable stream. Everything the receiver needs that this component
/// cannot reach on its own arrives through [`ReceiverRuntime`], and the
/// receiver task comes back as a second entry in `NotificationPlugin.receivers`
/// so the server's `JoinSet` owns its lifecycle exactly as it owns the live-hint
/// worker's.
/// The shutdown signal lets the receiver finish its current work and checkpoint
/// before returning to that join set.
///
/// Returns the plugin, the concrete sender, and the receiver's readiness facet
/// — which is a handle rather than a value, so an aggregator can keep reading
/// it as the receiver moves between generations.
///
/// # Errors
/// The same configuration faults [`NotificationPluginFactory::create`] returns.
pub fn create_with_receiver(
    config: &toml::Value,
    transport: std::sync::Arc<dyn PublishTransport>,
    runtime: ReceiverRuntime,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<
    (
        NotificationPlugin,
        std::sync::Arc<sender::RemoteNotificationSender>,
        std::sync::Arc<ReceiverReadiness>,
    ),
    PluginError,
> {
    let config =
        RemoteNotificationConfig::parse(config).map_err(|e| e.into_plugin_error(PLUGIN_NAME))?;
    if config.receiver.is_none() {
        return Err(RemoteNotificationError::field(
            "receiver",
            "a durable receiver runtime was supplied but `[plugins.remote.receiver]` is absent; \
             the cell must declare its membership identity, lifecycle generation, and lag \
             readiness threshold before a receiver can run",
        )
        .into_plugin_error(PLUGIN_NAME));
    }
    let client = PrivateGatewayClient::with_transport(&config, transport);
    let (plugin, sender, readiness) = build_plugin_with_readiness(
        &config,
        client,
        PluginMode::Remote,
        Some(runtime),
        Some(shutdown),
    );
    let readiness = readiness.ok_or_else(|| {
        RemoteNotificationError::field(
            "receiver",
            "the durable receiver did not start despite a supplied runtime",
        )
        .into_plugin_error(PLUGIN_NAME)
    })?;
    Ok((plugin, sender, readiness))
}

/// Build the observation-only branch of `local-shadow-remote`.
///
/// The branch publishes `SHADOW_OBSERVATION` to `.shadow` subjects and starts
/// **no** durable receiver — the rule lives in
/// [`PluginMode::runs_durable_receiver`] and is applied here rather than
/// remembered. The returned `NotificationPlugin`'s sender is meant to sit
/// beside Lore's local sender under a server-level multiplexer, not to replace
/// it: this function deliberately cannot unmount the public service, because
/// it never touches server construction.
///
/// # Errors
/// The same configuration faults [`NotificationPluginFactory::create`] returns.
pub fn create_shadow_branch(
    config: &toml::Value,
    transport: std::sync::Arc<dyn PublishTransport>,
) -> Result<
    (
        NotificationPlugin,
        std::sync::Arc<sender::RemoteNotificationSender>,
    ),
    PluginError,
> {
    let config =
        RemoteNotificationConfig::parse(config).map_err(|e| e.into_plugin_error(PLUGIN_NAME))?;
    let client = PrivateGatewayClient::with_transport(&config, transport);
    Ok(build_plugin(
        &config,
        client,
        PluginMode::LocalShadowRemote,
        None,
    ))
}

fn build_plugin(
    config: &RemoteNotificationConfig,
    client: PrivateGatewayClient,
    mode: PluginMode,
    runtime: Option<ReceiverRuntime>,
) -> (
    NotificationPlugin,
    std::sync::Arc<sender::RemoteNotificationSender>,
) {
    let (plugin, sender, _) = build_plugin_with_readiness(config, client, mode, runtime, None);
    (plugin, sender)
}

fn build_plugin_with_readiness(
    config: &RemoteNotificationConfig,
    client: PrivateGatewayClient,
    mode: PluginMode,
    runtime: Option<ReceiverRuntime>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) -> (
    NotificationPlugin,
    std::sync::Arc<sender::RemoteNotificationSender>,
    Option<std::sync::Arc<ReceiverReadiness>>,
) {
    if config.mtls.is_none() {
        tracing::warn!("{INSECURE_TRANSPORT_BANNER}");
    }
    for (key, value) in config.diagnostics() {
        tracing::info!(setting = key, value = %value, "remote notification plugin setting");
    }
    tracing::info!(mode = %mode, "remote notification plugin mode");

    let (sender, worker) = sender::build(config, client, mode.publishes_shadow_only());
    let mut receivers: Vec<crate::plugins::NotificationReceiver> = vec![Box::pin(worker.run())];
    let mut readiness = None;

    match runtime {
        Some(runtime) if mode.runs_durable_receiver() => {
            if let Some(receiver) = DurableReceiver::new(config, runtime) {
                readiness = Some(receiver.readiness());
                receivers.push(match shutdown {
                    Some(shutdown) => Box::pin(receiver.run_with_shutdown(shutdown)),
                    None => Box::pin(receiver.run()),
                });
            } else {
                tracing::warn!(
                    "a durable receiver runtime was supplied but no `[plugins.remote.receiver]` \
                 is configured; no receiver started"
                );
            }
        }
        Some(_) => tracing::warn!(
            mode = %mode,
            "a durable receiver runtime was supplied for a mode that must not consume durable \
             invalidations; no receiver started"
        ),
        None if config.receiver.is_some() && mode.runs_durable_receiver() => {
            // Unreachable through `SCHEMA-119`'s server construction, and kept
            // as a loud diagnostic rather than deleted.
            //
            // `event_relay::wiring::prepare_event_relay` builds the
            // `ReceiverRuntime` for any cell that declares this table, and
            // refuses startup outright when the relay it needs is disabled, so
            // the only way to reach this arm is a caller that took the plain
            // registry path with a receiver configured. That caller would
            // otherwise get a cell with no receiver, no checkpoint, and nothing
            // in the log to distinguish it from one that is caught up.
            tracing::warn!(
                "`[plugins.remote.receiver]` is configured but this plugin was built without a \
                 durable stream source; the durable invalidation receiver did not start and the \
                 cell must not be treated as required-event ready"
            );
        }
        None => {}
    }

    (
        NotificationPlugin {
            sender: sender.clone(),
            receivers,
        },
        sender,
        readiness,
    )
}

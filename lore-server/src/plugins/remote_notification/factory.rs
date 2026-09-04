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
    let (plugin, sender, readiness) =
        build_plugin_with_readiness(&config, client, PluginMode::Remote, Some(runtime));
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
    let (plugin, sender, _) = build_plugin_with_readiness(config, client, mode, runtime);
    (plugin, sender)
}

fn build_plugin_with_readiness(
    config: &RemoteNotificationConfig,
    client: PrivateGatewayClient,
    mode: PluginMode,
    runtime: Option<ReceiverRuntime>,
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
            match DurableReceiver::new(config, runtime) {
                Some(receiver) => {
                    readiness = Some(receiver.readiness());
                    receivers.push(Box::pin(receiver.run()));
                }
                None => tracing::warn!(
                    "a durable receiver runtime was supplied but no `[plugins.remote.receiver]` \
                     is configured; no receiver started"
                ),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use lore_base::types::RepositoryId;
    use lore_revision::lore::BranchId;
    use lore_revision::notification::NotificationSender as _;

    use super::super::fake_gateway::FakeGateway;
    use super::super::fake_gateway::ScriptedResponse;
    use super::super::sender::RemoteNotificationSender;
    use super::*;

    const TEST_CONFIG: &str = r#"
        gateway_uri = "http://127.0.0.1:1"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "loreserver-sfo3-cell-a-2"
        allow_insecure_transport_for_test = true
        queue_capacity = 8
        request_timeout_ms = 200
        drain_timeout_ms = 5000

        [retry]
        initial_backoff_ms = 1
        max_backoff_ms = 2
        max_attempts = 2
    "#;

    fn config() -> toml::Value {
        toml::from_str(TEST_CONFIG).expect("test config parses")
    }

    fn repository(byte: u8) -> RepositoryId {
        let mut id = RepositoryId::default();
        *id.data_mut() = [byte; 16];
        id
    }

    fn plugin_for(gateway: &FakeGateway) -> (NotificationPlugin, Arc<RemoteNotificationSender>) {
        create_with_transport(&config(), Arc::new(gateway.clone())).expect("plugin builds")
    }

    /// Drives the plugin's worker to completion in the current task.
    ///
    /// Nothing is spawned: the queue is filled first, every sender handle is
    /// dropped, and the worker then drains what was accepted and returns. That
    /// makes each assertion deterministic rather than a race against a
    /// background task, and keeps these tests off the shared lore runtime.
    async fn drain(plugin: NotificationPlugin) {
        let worker = plugin
            .receivers
            .into_iter()
            .next()
            .expect("the plugin supplies exactly one worker");
        drop(plugin.sender);
        let outcome = tokio::time::timeout(Duration::from_secs(20), worker).await;
        assert!(
            outcome.is_ok(),
            "the live-hint worker did not finish draining"
        );
    }

    #[tokio::test]
    async fn the_factory_validates_its_own_test_config() {
        RemoteNotificationPluginFactory
            .validate_config(&config())
            .expect("test config is valid");
        assert_eq!(RemoteNotificationPluginFactory.name(), "remote");
    }

    #[tokio::test]
    async fn a_branch_push_reaches_the_gateway_as_one_live_hint() {
        let gateway = FakeGateway::accepting();
        let (plugin, sender) = plugin_for(&gateway);
        sender
            .branch_pushed(
                repository(0x9f),
                BranchId::default(),
                "user-1",
                lore_base::types::Hash::default(),
                417,
            )
            .await;
        drop(sender);
        drain(plugin).await;

        assert_eq!(gateway.request_count(), 1);
        let request = gateway.request(0).expect("one request");
        assert_eq!(request.transport_version, 1);
        assert_eq!(request.cell_id, "sfo3-cell-a");
        assert_eq!(request.placement_epoch, 12);
        assert_eq!(request.repository.as_ref(), &[0x9fu8; 16]);
        assert_eq!(request.producer_instance_id, "loreserver-sfo3-cell-a-2");
    }

    #[tokio::test]
    async fn one_stable_event_id_survives_every_retry() {
        // Two transient failures then an acceptance: three requests, one id.
        let gateway = FakeGateway::scripted([
            ScriptedResponse::unavailable(),
            ScriptedResponse::rate_limited(),
            ScriptedResponse::accept(),
        ]);
        let (plugin, sender) = plugin_for(&gateway);
        sender
            .branch_created(repository(0x9f), BranchId::default())
            .await;
        drop(sender);
        drain(plugin).await;

        assert_eq!(gateway.request_count(), 3);
        assert_eq!(
            gateway.distinct_event_ids().len(),
            1,
            "a retry must reuse the original stable event id"
        );
    }

    #[tokio::test]
    async fn an_exhausted_retry_budget_drops_the_hint_and_stops() {
        // `max_attempts = 2` means two RETRIES, so three sends and no more.
        let gateway = FakeGateway::always(ScriptedResponse::unavailable());
        let (plugin, sender) = plugin_for(&gateway);
        sender
            .branch_created(repository(0x9f), BranchId::default())
            .await;
        drop(sender);
        drain(plugin).await;
        assert_eq!(gateway.request_count(), 3);
    }

    #[tokio::test]
    async fn a_terminal_status_is_not_retried() {
        let gateway = FakeGateway::always(ScriptedResponse::invalid_argument());
        let (plugin, sender) = plugin_for(&gateway);
        sender
            .branch_created(repository(0x9f), BranchId::default())
            .await;
        drop(sender);
        drain(plugin).await;
        assert_eq!(
            gateway.request_count(),
            1,
            "an event-specific rejection must not consume the retry budget"
        );
    }

    #[tokio::test]
    async fn a_refused_credential_is_retried_rather_than_treated_as_poison() {
        // Credential rotation is an explicit step of the contract's
        // reassignment procedure, so a refused credential must not be terminal.
        // `max_attempts = 2` means two retries, so three sends.
        let gateway = FakeGateway::always(ScriptedResponse::permission_denied());
        let (plugin, sender) = plugin_for(&gateway);
        sender
            .branch_created(repository(0x9f), BranchId::default())
            .await;
        drop(sender);
        drain(plugin).await;
        assert_eq!(gateway.request_count(), 3);
    }

    #[tokio::test]
    async fn an_unversioned_ack_is_not_retried_and_never_counts_as_acceptance() {
        let gateway = FakeGateway::always(ScriptedResponse::unversioned_ack());
        let (plugin, sender) = plugin_for(&gateway);
        sender
            .branch_created(repository(0x9f), BranchId::default())
            .await;
        drop(sender);
        drain(plugin).await;
        assert_eq!(
            gateway.request_count(),
            1,
            "a response that does not prove acceptance is retained by the caller, not retried here"
        );
    }

    #[tokio::test]
    async fn a_full_queue_drops_hints_without_failing_the_mutation() {
        // The worker is not running yet, so the bounded queue fills and every
        // further enqueue is a counted drop. Each of these calls must return.
        let gateway = FakeGateway::accepting();
        let (plugin, sender) = plugin_for(&gateway);
        for _ in 0..200 {
            sender
                .branch_created(repository(0x9f), BranchId::default())
                .await;
        }
        assert_eq!(sender.capacity(), 8);
        assert_eq!(sender.queued(), 8);
        drop(sender);
        drain(plugin).await;
        assert_eq!(
            gateway.request_count(),
            8,
            "exactly the bounded queue's worth reaches the gateway; the rest are dropped hints"
        );
    }

    /// The drain bound must bound the *drain*, not be spent waiting on an idle
    /// queue. A worker asked to drain with nothing queued has to return
    /// promptly even while a sender handle is still held, which is the shape a
    /// real shutdown sequence uses.
    #[tokio::test]
    async fn begin_drain_on_an_idle_worker_returns_without_burning_the_drain_bound() {
        // `drain_timeout_ms` is 5000 here, so a worker that blocks waiting for
        // an event it will never receive takes five seconds. This asserts one.
        let gateway = FakeGateway::accepting();
        let (plugin, sender) = plugin_for(&gateway);
        let worker = plugin.receivers.into_iter().next().expect("one worker");
        // Both handles stay alive, so the queue is NOT closed. Only
        // `begin_drain` can stop the worker.
        sender.begin_drain();

        let started = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .expect("the idle worker must stop on begin_drain, not on the drain bound")
            .expect("the worker must not return an Err");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stopping an idle worker took {:?}; it waited on the drain bound instead of returning",
            started.elapsed()
        );
        assert_eq!(gateway.request_count(), 0);
        drop(sender);
        drop(plugin.sender);
    }

    /// A drain bound of zero abandons every accepted hint instead of publishing
    /// it, and counts each one. This is the path `abandon` exists for.
    #[tokio::test]
    async fn a_zero_drain_bound_abandons_accepted_hints_rather_than_publishing_them() {
        let gateway = FakeGateway::accepting();
        let config: toml::Value =
            toml::from_str(&TEST_CONFIG.replace("drain_timeout_ms = 5000", "drain_timeout_ms = 0"))
                .expect("test config parses");
        let (plugin, sender) =
            create_with_transport(&config, Arc::new(gateway.clone())).expect("plugin builds");
        let worker = plugin.receivers.into_iter().next().expect("one worker");

        for _ in 0..4 {
            sender
                .branch_created(repository(0x9f), BranchId::default())
                .await;
        }
        assert_eq!(sender.queued(), 4);
        // Drain begins with work already accepted and no time to publish it.
        sender.begin_drain();

        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .expect("the worker must stop at a zero drain bound")
            .expect("the worker must not return an Err");
        assert_eq!(
            gateway.request_count(),
            0,
            "a zero drain bound publishes nothing; every accepted hint is abandoned"
        );
        drop(sender);
        drop(plugin.sender);
    }

    #[tokio::test]
    async fn a_gateway_that_never_answers_trips_the_clients_own_deadline() {
        // Longer than `request_timeout_ms = 200`, so the client's own timeout
        // ends each attempt. Two retries plus the first send is three attempts.
        let gateway = FakeGateway::always(ScriptedResponse::Hang(Duration::from_secs(30)));
        let (plugin, sender) = plugin_for(&gateway);
        sender
            .branch_created(repository(0x9f), BranchId::default())
            .await;
        drop(sender);
        drain(plugin).await;
        assert_eq!(gateway.request_count(), 3);
    }

    #[tokio::test]
    async fn an_obliterate_hint_never_fails_the_obliterate_that_already_happened() {
        // The gateway rejects terminally and the queue is irrelevant: the
        // contract result must still be `Ok`.
        let gateway = FakeGateway::always(ScriptedResponse::invalid_argument());
        let (plugin, sender) = plugin_for(&gateway);
        let result = sender
            .obliterate(repository(0x9f), lore_base::types::Address::default())
            .await;
        assert!(result.is_ok());
        drop(sender);
        drain(plugin).await;
        assert_eq!(gateway.request_count(), 1);
    }
}

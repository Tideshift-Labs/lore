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
        Ok(build_plugin(&config, client).0)
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
    Ok(build_plugin(&config, client))
}

fn build_plugin(
    config: &RemoteNotificationConfig,
    client: PrivateGatewayClient,
) -> (
    NotificationPlugin,
    std::sync::Arc<sender::RemoteNotificationSender>,
) {
    if config.mtls.is_none() {
        tracing::warn!("{INSECURE_TRANSPORT_BANNER}");
    }
    for (key, value) in config.diagnostics() {
        tracing::info!(setting = key, value = %value, "remote notification plugin setting");
    }

    let (sender, worker) = sender::build(config, client, false);

    // TODO(WP-111 Phase 3): the durable invalidation receiver attaches here as a
    // second `NotificationReceiver`, and a required receiver's failure becomes an
    // event-readiness failure. It consumes `config.receiver`, which is already
    // parsed and bounded above.
    (
        NotificationPlugin {
            sender: sender.clone(),
            receivers: vec![Box::pin(worker.run())],
        },
        sender,
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

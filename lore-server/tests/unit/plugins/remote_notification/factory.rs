// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use lore_base::types::RepositoryId;
use lore_revision::lore::BranchId;
use lore_revision::notification::NotificationSender as _;
use lore_server::plugins::NotificationPlugin;
use lore_server::plugins::NotificationPluginFactory;
use lore_server::plugins::remote_notification::factory::*;
use lore_server::plugins::remote_notification::fake_gateway::FakeGateway;
use lore_server::plugins::remote_notification::fake_gateway::ScriptedResponse;
use lore_server::plugins::remote_notification::sender::RemoteNotificationSender;

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

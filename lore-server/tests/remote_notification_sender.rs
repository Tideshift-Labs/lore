// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! External, component-level tests for CR-027 / WP-111 Phase 1-2's bounded `LIVE_HINT` sender and
//! the `remote` `NotificationPluginFactory`, exercised through the crate's `pub` boundary
//! (`lore_server::plugins::*`) rather than the internal `#[cfg(test)]` module.
//!
//! `sender.rs`'s own `factory::tests` module (co-located, internal) already exercises the bounded
//! queue, stable-event-id-across-retry, exhausted-retry-drop, terminal-not-retried, and
//! unversioned-ack-not-retried properties end-to-end against the same [`FakeGateway`] this file
//! uses. This file does not re-derive that matrix. What it adds:
//!
//! 1. the same class of properties proven through the crate's **public** surface only
//!    (`lore_server::plugins::{NotificationPluginFactory, NotificationPlugin}` and a `Box<dyn
//!    NotificationPluginFactory>`, the shape a real `PluginRegistry` consumes) — a regression that
//!    breaks the public contract while an internal test keeps privileged access would show up here
//!    even if it didn't there;
//! 2. every `NotificationSender` event variant reaches the gateway with the correct embedded
//!    `lore.notification.Event` oneof payload, not just `branch_created`/`branch_pushed` (the two
//!    the internal tests exercise);
//! 3. `compliance_check` is a deliberate no-op for this sender (no
//!    `lore.notification.Event` variant exists for it) — a regression guard, since a future change
//!    could plausibly try to wire it up incorrectly;
//! 4. an explicit `begin_drain()` stop path (rather than dropping the sender handle, which is what
//!    the internal tests' `drain()` helper does), proving no publish reaches the gateway after
//!    drain begins and the worker task actually terminates rather than leaking;
//! 5. the factory's config-fault-to-`PluginError` boundary translation (item 4) driven through the
//!    trait object, for both the incompatible-version and missing-mTLS cases `config.rs`'s own
//!    tests already pin at the parser level.

use std::sync::Arc;
use std::time::Duration;

use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;
use lore_proto::lore::notification;
use lore_revision::lore::BranchId;
use lore_revision::notification::NotificationSender as _;
use lore_server::plugins::NotificationPlugin;
use lore_server::plugins::NotificationPluginContext;
use lore_server::plugins::NotificationPluginFactory;
use lore_server::plugins::remote_notification::factory::RemoteNotificationPluginFactory;
use lore_server::plugins::remote_notification::factory::create_with_transport;
use lore_server::plugins::remote_notification::fake_gateway::FakeGateway;
use lore_server::plugins::remote_notification::fake_gateway::ScriptedResponse;
use lore_server::plugins::remote_notification::sender::RemoteNotificationSender;
use lore_server::plugins::remote_notification::wire;
use prost::Message;

const TEST_CONFIG: &str = r#"
    gateway_uri = "http://127.0.0.1:1"
    cell_id = "sfo3-cell-a"
    placement_epoch = 12
    producer_instance_id = "loreserver-sfo3-cell-a-2"
    allow_insecure_transport_for_test = true
    queue_capacity = 8
    request_timeout_ms = 200
    drain_timeout_ms = 2000

    [retry]
    initial_backoff_ms = 1
    max_backoff_ms = 2
    max_attempts = 2
"#;

fn config() -> toml::Value {
    toml::from_str(TEST_CONFIG).expect("test config parses")
}

fn repository() -> RepositoryId {
    RepositoryId::from([0x9fu8; 16])
}

/// Drives a plugin's single worker to completion by dropping every sender handle (closing the
/// queue) and awaiting the worker future, bounded so a hang fails the test instead of hanging it.
///
/// Both `plugin.sender` (the type-erased `Arc<dyn NotificationSender>` a real server holds) and
/// the concrete `sender` `create_with_transport` also returns are clones of the same underlying
/// `Arc` allocation (unsizing coercion shares the strong count); the worker's queue only closes
/// once both are dropped.
async fn drop_and_drain(plugin: NotificationPlugin, sender: Arc<RemoteNotificationSender>) {
    let worker = plugin
        .receivers
        .into_iter()
        .next()
        .expect("the remote plugin supplies exactly one worker");
    drop(sender);
    drop(plugin.sender);
    tokio::time::timeout(Duration::from_secs(20), worker)
        .await
        .expect("the live-hint worker must finish draining within the bound")
        .expect("the worker must not return an Err");
}

/// Decodes the embedded `lore.notification.Event` from a captured `LIVE_HINT` request.
fn embedded_event(request: &wire::PrivateEnvelopeV1) -> notification::Event {
    let wire::private_envelope_v1::Body::LoreEvent(bytes) =
        request.body.clone().expect("live hint carries a body")
    else {
        panic!("expected a LoreEvent body on a LIVE_HINT envelope");
    };
    notification::Event::decode(bytes).expect("embedded event decodes")
}

#[tokio::test]
async fn every_notification_sender_event_variant_reaches_the_gateway_with_its_own_payload() {
    let gateway = FakeGateway::accepting();
    let (plugin, sender) =
        create_with_transport(&config(), Arc::new(gateway.clone())).expect("plugin");
    let repo = repository();
    let branch = BranchId::default();

    sender.branch_created(repo, branch).await;
    sender
        .branch_pushed(repo, branch, "user-1", Hash::default(), 417)
        .await;
    sender.branch_deleted(repo, branch).await;
    sender
        .resource_locked(repo, branch, "user-1", &[LockResource::default()])
        .await;
    sender
        .resource_unlocked(repo, branch, "user-1", &[LockResource::default()])
        .await;
    sender
        .obliterate(repo, lore_base::types::Address::default())
        .await
        .expect("obliterate enqueue never fails the caller");

    drop_and_drain(plugin, sender).await;

    assert_eq!(
        gateway.request_count(),
        6,
        "every call above must produce one live hint"
    );
    let requests = gateway.requests();
    let variants: Vec<&'static str> = requests
        .iter()
        .map(|r| match embedded_event(r).event {
            Some(notification::event::Event::BranchCreated(_)) => "branch_created",
            Some(notification::event::Event::BranchPushed(_)) => "branch_pushed",
            Some(notification::event::Event::BranchDeleted(_)) => "branch_deleted",
            Some(notification::event::Event::ResourceLocked(_)) => "resource_locked",
            Some(notification::event::Event::ResourceUnlocked(_)) => "resource_unlocked",
            Some(notification::event::Event::Obliterate(_)) => "obliterate",
            other => panic!("unexpected embedded event variant: {other:?}"),
        })
        .collect();
    assert_eq!(
        variants,
        vec![
            "branch_created",
            "branch_pushed",
            "branch_deleted",
            "resource_locked",
            "resource_unlocked",
            "obliterate",
        ],
        "each call must map to its own distinct lore.notification.Event variant, in order"
    );

    // Every envelope must also carry the same repository, unconditionally, per the contract.
    for request in &requests {
        assert_eq!(request.repository.as_ref(), repo.data().as_slice());
        assert_eq!(
            embedded_event(request).repository.as_ref(),
            repo.data().as_slice()
        );
    }
}

#[tokio::test]
async fn compliance_check_is_a_deliberate_no_op_and_never_reaches_the_gateway() {
    // sender.rs's own doc: "Compliance-check events have no lore.notification.Event variant... "
    // Local mode no-ops too; this pins the remote sender stays aligned rather than silently
    // diverging (e.g. a future change that tries to synthesize some payload for it).
    let gateway = FakeGateway::accepting();
    let (plugin, sender) =
        create_with_transport(&config(), Arc::new(gateway.clone())).expect("plugin");
    sender
        .compliance_check(
            "stream",
            repository(),
            BranchId::default(),
            "user-1",
            Hash::default(),
            1,
            Some("203.0.113.7".to_string()),
        )
        .await;
    drop_and_drain(plugin, sender).await;
    assert_eq!(gateway.request_count(), 0);
}

#[tokio::test]
async fn explicit_begin_drain_stops_new_enqueue_and_the_worker_publishes_nothing_after_it() {
    // Distinct stop path from `drop_and_drain`/the internal tests' `drain()` helper (which stops
    // by dropping the sender handle): this calls `begin_drain()` directly while the sender handle
    // is still held, the shape a real shutdown sequence uses. Two hints are queued BEFORE drain
    // begins (so the worker has real, already-accepted work to drain); a third attempted AFTER
    // `begin_drain()` must be refused, never counted, and never reach the gateway.
    let gateway = FakeGateway::accepting();
    let (plugin, sender) =
        create_with_transport(&config(), Arc::new(gateway.clone())).expect("plugin");
    let repo = repository();

    sender.branch_created(repo, BranchId::default()).await;
    sender.branch_created(repo, BranchId::default()).await;
    assert_eq!(sender.queued(), 2, "both pre-drain hints must be accepted");

    sender.begin_drain();
    sender.branch_created(repo, BranchId::default()).await;
    assert_eq!(
        sender.queued(),
        2,
        "an enqueue attempt after begin_drain() must be refused, not accepted"
    );

    let worker = plugin
        .receivers
        .into_iter()
        .next()
        .expect("exactly one worker");
    drop(sender);
    drop(plugin.sender);

    tokio::time::timeout(Duration::from_secs(20), worker)
        .await
        .expect("the worker must terminate within the drain bound, proving no leaked task")
        .expect("the worker must not return an Err");

    assert_eq!(
        gateway.request_count(),
        2,
        "exactly the two pre-drain hints reach the gateway; the post-drain attempt never does"
    );

    // No leaked background activity: the gateway's count observed right after the worker future
    // resolved must still hold after a short further wait.
    let count_at_join = gateway.request_count();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        gateway.request_count(),
        count_at_join,
        "no publish may occur after the worker future has resolved"
    );
}

#[tokio::test]
async fn a_successful_publish_reaches_the_gateway_exactly_once() {
    let gateway = FakeGateway::always(ScriptedResponse::accept());
    let (plugin, sender) =
        create_with_transport(&config(), Arc::new(gateway.clone())).expect("plugin");
    sender
        .branch_created(repository(), BranchId::default())
        .await;
    drop_and_drain(plugin, sender).await;
    assert_eq!(
        gateway.request_count(),
        1,
        "a successful publish must be counted once, not retried past acceptance"
    );
}

#[tokio::test]
async fn the_factory_trait_object_validates_config_the_same_way_the_concrete_type_does() {
    // `PluginRegistry` (registry.rs) only ever holds a `Box<dyn NotificationPluginFactory>`; a
    // real cell never touches `RemoteNotificationPluginFactory` concretely. Route every assertion
    // through the trait object to prove the boundary, not just the inherent methods.
    let factory: Box<dyn NotificationPluginFactory> = Box::new(RemoteNotificationPluginFactory);
    assert_eq!(factory.name(), "remote");
    factory.validate_config(&config()).expect("valid config");
}

#[tokio::test]
async fn the_factory_trait_object_rejects_an_incompatible_private_transport_version() {
    let factory: Box<dyn NotificationPluginFactory> = Box::new(RemoteNotificationPluginFactory);
    let bad = toml::from_str::<toml::Value>(&format!(
        "{TEST_CONFIG}\n[contract]\nprivate_transport_version = 2\n"
    ))
    .expect("valid TOML");
    let err = factory
        .validate_config(&bad)
        .expect_err("an incompatible transport version must be rejected at startup");
    assert!(
        err.is_plugin_config_error(),
        "an incompatible transport version is a configuration fault, not an init fault"
    );
}

#[tokio::test]
async fn the_factory_trait_object_rejects_a_durable_payload_range_excluding_this_build() {
    let factory: Box<dyn NotificationPluginFactory> = Box::new(RemoteNotificationPluginFactory);
    let bad = toml::from_str::<toml::Value>(&format!(
        "{TEST_CONFIG}\n[contract]\ndurable_payload_version_min = 2\ndurable_payload_version_max = 3\n"
    ))
    .expect("valid TOML");
    let err = factory
        .validate_config(&bad)
        .expect_err("a durable payload version range excluding this build must be rejected");
    assert!(err.is_plugin_config_error());
}

#[tokio::test]
async fn the_factory_trait_object_rejects_missing_mtls_identity_when_not_explicitly_insecure() {
    let factory: Box<dyn NotificationPluginFactory> = Box::new(RemoteNotificationPluginFactory);
    let bad = toml::from_str::<toml::Value>(
        r#"
        gateway_uri = "https://gateway.internal:8443"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "loreserver-sfo3-cell-a-2"
    "#,
    )
    .expect("valid TOML");
    let err = factory
        .validate_config(&bad)
        .expect_err("missing mTLS material must be rejected without the explicit test escape");
    assert!(err.is_plugin_config_error());
}

#[tokio::test]
async fn the_factory_trait_objects_create_path_is_reachable_and_produces_one_worker() {
    // `create` (not `create_with_transport`) is what a real `PluginRegistry` calls; this proves
    // the trait-object path compiles and runs end to end for a syntactically valid config with a
    // gateway that is simply unreachable (the channel is lazy per `GrpcPublishTransport::connect_lazy`'s
    // own doc, so this must succeed rather than blocking or erroring at construction).
    let factory: Box<dyn NotificationPluginFactory> = Box::new(RemoteNotificationPluginFactory);
    let context = NotificationPluginContext {
        environment: None,
        immutable_store: None,
    };
    let plugin = factory
        .create(&config(), &context)
        .await
        .expect("a lazy channel must not fail plugin construction even with no gateway listening");
    assert_eq!(
        plugin.receivers.len(),
        1,
        "the remote plugin supplies exactly one live-hint worker receiver"
    );
}

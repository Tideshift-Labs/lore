// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! CR-027 / WP-111 Phase 4: the `local` / `remote` / `local-shadow-remote`
//! mode ladder, proven at the factory entry points `mode.rs`'s own
//! co-located tests do not reach.
//!
//! `mode.rs`'s unit tests already pin the closed `PluginMode` decision table
//! in isolation: `mounts_local_public_service`, `runs_durable_receiver`,
//! `publishes_shadow_only`, and `require_selectable`'s per-mode rejection
//! messages. This file does not duplicate those. It proves the SAME rules
//! hold once wired through the actual construction entry points --
//! `factory::create_with_transport`, `factory::create_with_receiver`, and
//! `factory::create_shadow_branch` -- which had no test coverage of their own
//! before this file (the co-located `factory.rs` tests only exercise the
//! plain live-hint sender path via `create_with_transport`).
//!
//! No live Postgres or gateway needed: every mode decision here is either a
//! config-time refusal or driven by in-process fakes (`FakeGateway`,
//! `InMemoryReceiverStore`, `FakeDurableStream`).

use std::sync::Arc;
use std::time::Duration;

use lore_base::types::RepositoryId;
use lore_revision::lore::BranchId;
use lore_revision::notification::NotificationSender as _;
use lore_server::plugins::remote_notification::FakeDurableStream;
use lore_server::plugins::remote_notification::InMemoryReceiverStore;
use lore_server::plugins::remote_notification::ReceiverRuntime;
use lore_server::plugins::remote_notification::RecordingInvalidationTarget;
use lore_server::plugins::remote_notification::StreamPlacement;
use lore_server::plugins::remote_notification::factory::create_shadow_branch;
use lore_server::plugins::remote_notification::factory::create_with_receiver;
use lore_server::plugins::remote_notification::factory::create_with_transport;
use lore_server::plugins::remote_notification::fake_gateway::FakeGateway;
use lore_server::plugins::remote_notification::wire;

const TEST_CONFIG_REMOTE: &str = r#"
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

    [receiver]
    membership_identity = "loreserver-sfo3-cell-a-2"
    lifecycle_generation = 1
    lag_readiness_threshold = 5000
    checkpoint_interval_ms = 100
    checkpoint_every_events = 1
    idle_poll_ms = 5
"#;

const TEST_CONFIG_LOCAL: &str = r#"
    mode = "local"
    gateway_uri = "http://127.0.0.1:1"
    cell_id = "sfo3-cell-a"
    placement_epoch = 12
    producer_instance_id = "loreserver-sfo3-cell-a-2"
    allow_insecure_transport_for_test = true
"#;

fn remote_config() -> toml::Value {
    toml::from_str(TEST_CONFIG_REMOTE).expect("remote test config parses")
}

fn local_config() -> toml::Value {
    toml::from_str(TEST_CONFIG_LOCAL).expect("local test config parses")
}

fn repository(byte: u8) -> RepositoryId {
    let mut id = RepositoryId::default();
    *id.data_mut() = [byte; 16];
    id
}

/// Poll `predicate` on a bounded real-time budget. Only used to observe the
/// durable receiver's readiness transition once it is actually running.
async fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// This plugin is never constructed for `local` mode: `mode.rs`'s
/// `require_selectable` names Lore's built-in service as the owner, and
/// `RemoteNotificationConfig::parse` applies that rule before either factory
/// entry point ever builds a gateway client or a receiver runtime. Proven
/// here at both entry points, with the fake gateway's own call count as the
/// independent witness that nothing was constructed.
#[tokio::test]
async fn local_mode_is_refused_before_any_gateway_client_or_receiver_is_built() {
    let gateway = FakeGateway::accepting();
    let config = local_config();

    // `NotificationPlugin` (the Ok side) does not implement `Debug` -- it is
    // common WP-119 territory, not this component's to add a derive to -- so
    // `expect_err` (which requires `T: Debug` to print the unexpected Ok
    // value) does not compile here. Match instead.
    let transport_err = match create_with_transport(&config, Arc::new(gateway.clone())) {
        Err(error) => error,
        Ok(_) => panic!("this plugin must never be constructed for local mode"),
    };
    assert!(
        transport_err.to_string().contains("built-in"),
        "unexpected error: {transport_err}"
    );
    assert_eq!(
        gateway.request_count(),
        0,
        "a refused local-mode config must never reach the gateway transport"
    );

    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let target = RecordingInvalidationTarget::new();
    let receiver_err = match create_with_receiver(
        &config,
        Arc::new(gateway.clone()),
        ReceiverRuntime {
            store: Arc::new(store),
            stream: Arc::new(stream),
            target: Arc::new(target),
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("local mode must not accept a receiver runtime either"),
    };
    assert!(
        receiver_err.to_string().contains("built-in"),
        "unexpected error: {receiver_err}"
    );
    assert_eq!(
        gateway.request_count(),
        0,
        "no receiver bootstrap or gateway call happens for a refused local-mode config"
    );
}

/// `remote` mode is the only mode that spawns a durable receiver, and
/// `create_with_receiver` is the entry point `SCHEMA-119` calls to do it.
/// This proves the receiver task actually runs and reaches readiness against
/// an in-process store and stream, not just that the plugin's `receivers`
/// vector has the right length.
#[tokio::test]
async fn remote_mode_spawns_a_durable_receiver_that_reaches_readiness() {
    let gateway = FakeGateway::accepting();
    let store = InMemoryReceiverStore::new("sfo3-cell-a");
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-sfo3-cell-a", 8), 900);
    let target = RecordingInvalidationTarget::new();

    let (plugin, sender, readiness) = create_with_receiver(
        &remote_config(),
        Arc::new(gateway.clone()),
        ReceiverRuntime {
            store: Arc::new(store),
            stream: Arc::new(stream),
            target: Arc::new(target),
        },
    )
    .expect("remote mode builds a receiver runtime");

    assert_eq!(
        plugin.receivers.len(),
        2,
        "remote mode must spawn both the live-hint worker and the durable receiver"
    );
    assert!(
        !readiness.is_ready(),
        "a receiver that has not bootstrapped yet must not read as ready"
    );

    let mut receivers = plugin.receivers;
    let receiver_task = receivers.remove(1);
    drop(receivers); // the unpolled live-hint worker future is simply dropped, unstarted
    drop(sender);
    let receiver_handle = lore_base::lore_spawn!(receiver_task);

    let reached_ready = wait_until(|| readiness.is_ready(), Duration::from_secs(5)).await;
    assert!(
        reached_ready,
        "the durable receiver must reach readiness against the in-memory store and fake stream"
    );
    assert_eq!(readiness.snapshot().generation, Some(1));

    receiver_handle.abort();
}

/// `local-shadow-remote`'s shadow branch publishes `SHADOW_OBSERVATION` and
/// starts no durable receiver -- structurally guaranteed by
/// `create_shadow_branch`'s own signature, since it takes no
/// `ReceiverRuntime` at all, so there is no checkpoint pathway for it to
/// advance even in principle. `mode.rs`'s unit tests already pin
/// `runs_durable_receiver() == false` for this mode in isolation; this
/// proves the wired factory entry point agrees.
#[tokio::test]
async fn shadow_branch_publishes_marked_hints_and_starts_no_receiver() {
    let gateway = FakeGateway::accepting();
    let (plugin, sender) = create_shadow_branch(&remote_config(), Arc::new(gateway.clone()))
        .expect("shadow branch builds");

    assert_eq!(
        plugin.receivers.len(),
        1,
        "shadow mode must never start a durable receiver; only the bounded shadow sender worker \
         runs, and no checkpoint pathway exists for it to advance"
    );

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
    let worker = plugin
        .receivers
        .into_iter()
        .next()
        .expect("the shadow worker");
    drop(plugin.sender);
    tokio::time::timeout(Duration::from_secs(20), worker)
        .await
        .expect("the shadow worker drains")
        .expect("the shadow worker must not return an Err");

    assert_eq!(gateway.request_count(), 1);
    let request = gateway.request(0).expect("one published envelope");
    assert_eq!(
        request.delivery_class,
        wire::DeliveryClassV1::ShadowObservation as i32,
        "shadow mode publishes SHADOW_OBSERVATION, never a live hint or a durable invalidation"
    );
}

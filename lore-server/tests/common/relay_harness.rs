// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Shared live-Postgres test harness for WP-119 Step B's `event_relay`
//! tests (`event_relay_publish.rs`, `event_relay_failover.rs`,
//! `event_relay_readiness.rs`).
//!
//! Checked against the landed `lore-server/src/event_relay/` source
//! (`config.rs`, `worker.rs`, `readiness.rs`, `envelope_map.rs`,
//! `publisher.rs`), not guessed. `EventRelayConfig`'s fields are `pub`, so
//! [`fast_test_config`] builds one directly with a short `claim_lease`
//! rather than going through `EventRelayConfig::from_settings`, which
//! enforces a 5..=300s bound that would make a fast reclaim-after-expiry
//! test slow. `EventRelayWorker::process_claimed` takes no client parameter
//! -- it checks out its own pooled connections internally (see the module's
//! own "no pooled connection held across a publish" invariant) -- so a
//! caller only needs `relay::claim_batch` externally to obtain the
//! `ClaimedEvent`s to hand it.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::AdmissionLimits;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::pool::Pool;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_server::event_relay::EnvelopeSource;
use lore_server::event_relay::EventRelayConfig;
use lore_server::event_relay::EventRelayReadiness;
use lore_server::event_relay::RelayBackoff;
use lore_server::event_relay::RetentionConfig;
use lore_server::plugins::remote_notification::client::PrivateGatewayClient;
use lore_server::plugins::remote_notification::config::RemoteNotificationConfig;
use lore_server::plugins::remote_notification::fake_gateway::FakeGateway;
use uuid::Uuid;

pub const TEST_CELL_ID: &str = "sfo3-cell-a";
pub const TEST_PLACEMENT_EPOCH: u64 = 12;
pub const TEST_PRODUCER_INSTANCE_ID: &str = "loreserver-sfo3-cell-a-2";

pub fn envelope_source() -> EnvelopeSource {
    EnvelopeSource {
        cell_id: TEST_CELL_ID.to_string(),
        placement_epoch: TEST_PLACEMENT_EPOCH,
        producer_instance_id: TEST_PRODUCER_INSTANCE_ID.to_string(),
    }
}

/// A minimal, valid `[plugins.remote]` config -- mirrors
/// `remote_notification_durable_publish.rs`'s own `minimal_config()`
/// fixture, kept in sync on cell_id/placement_epoch/producer_instance_id
/// with [`envelope_source`] so a mismatch there cannot masquerade as an
/// unrelated `MapFailure::CellIdMismatch`-shaped bug in this harness.
pub fn minimal_remote_notification_config() -> RemoteNotificationConfig {
    let toml_text = format!(
        r#"
        gateway_uri = "https://gateway.internal:8443"
        cell_id = "{TEST_CELL_ID}"
        placement_epoch = {TEST_PLACEMENT_EPOCH}
        producer_instance_id = "{TEST_PRODUCER_INSTANCE_ID}"
        client_cert_path = "/secrets/tls.crt"
        client_key_path = "/secrets/tls.key"
        trust_roots_path = "/secrets/ca.crt"
        "#
    );
    let table: toml::Value = toml::from_str(&toml_text).expect("valid TOML");
    RemoteNotificationConfig::parse(&table).expect("valid minimal config")
}

/// A `PrivateGatewayClient` wired over `gateway`; usable directly as an
/// `Arc<dyn DurablePublisher>` (the trait is implemented for
/// `PrivateGatewayClient` in `event_relay::publisher`).
pub fn publisher_over(gateway: FakeGateway) -> Arc<PrivateGatewayClient> {
    Arc::new(PrivateGatewayClient::with_transport(
        &minimal_remote_notification_config(),
        Arc::new(gateway),
    ))
}

/// A relay config for tests, built by direct struct literal (every field on
/// `EventRelayConfig` is `pub`). `claim_lease`/`publish_deadline` are
/// deliberately SHORT (300ms/100ms) rather than CR-032's real 30s/10s
/// defaults, so a reclaim-after-lease-expiry case does not need a real
/// 30-second wait; `idle_interval`/`readiness_probe_interval` are irrelevant
/// to every test in this suite, since none of them drive the full
/// `EventRelayWorker::run` loop -- each drives `relay::claim_batch` plus
/// `EventRelayWorker::process_claimed` directly for a deterministic
/// single-pass proof.
pub fn fast_test_config(owner: &str) -> EventRelayConfig {
    EventRelayConfig {
        enabled: true,
        owner: owner.to_string(),
        batch_size: 100,
        claim_lease: Duration::from_millis(300),
        publish_deadline: Duration::from_millis(100),
        idle_interval: Duration::from_millis(20),
        backoff: RelayBackoff {
            base: Duration::from_millis(10),
            cap: Duration::from_secs(1),
        },
        readiness_probe_interval: Duration::from_millis(50),
        max_oldest_unpublished: Duration::from_secs(30),
        admission: AdmissionLimits::default(),
        // WP-119 Phase 8 added the retention schedule to this struct. The
        // reviewed defaults are right for every case here: nothing in this
        // harness runs the retention sweep, and the store refuses a window
        // below CR-032's floor regardless of what this said.
        retention: RetentionConfig::default(),
    }
}

pub fn build_worker(
    pool: Pool,
    gateway: FakeGateway,
    owner: &str,
) -> lore_server::event_relay::EventRelayWorker {
    let publisher = publisher_over(gateway);
    let config = fast_test_config(owner);
    // The third argument must match the config's own publish_deadline (a
    // second reviewer fix round: the staleness bound is now
    // `2 * probe_interval + publish_deadline`, so a mismatched value here
    // would silently test a different bound than the worker actually runs
    // with).
    let readiness = Arc::new(EventRelayReadiness::new(
        Duration::from_secs(30),
        Duration::from_secs(5),
        config.publish_deadline,
    ));
    lore_server::event_relay::EventRelayWorker::new(
        pool,
        publisher,
        config,
        readiness,
        envelope_source(),
    )
}

/// Bootstrap the CR-007/CR-029/CR-032 domain schema (including the outbox
/// tables `append`/`claim_batch`/`admission_check` all need) inside a fresh
/// `CaseNamespace` schema.
///
/// `PostgresDomainStore::connect` is what actually runs the bootstrap
/// (`ensure_schema` under its own advisory lock, then `ensure_state_rows`
/// seeding `lore_outbox_schema_state`); this only needs to call it and drop
/// the result. Idempotent -- safe to call more than once per namespace --
/// so [`test_pool`] and [`append_pending`] both call it rather than relying
/// on every test to remember to.
pub async fn ensure_schema_bootstrapped(url: &str) {
    let _ = PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap the domain schema (including outbox tables) for this namespace");
}

pub async fn raw_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test access");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

pub async fn test_pool(url: &str) -> Pool {
    ensure_schema_bootstrapped(url).await;
    build_pool(url, 8, &TlsConfig::default()).expect("build pool")
}

/// Append one pending row via the real production `append()` path, matching
/// WP-119 Step A's own `domain_outbox_relay.rs` helper.
pub async fn append_pending(
    url: &str,
    repository_id: &[u8],
    event_kind: &str,
    aggregate_kind: &str,
    aggregate_id: &[u8],
    ordinal: u64,
) -> Uuid {
    ensure_schema_bootstrapped(url).await;
    let mut client = raw_client(url).await;
    let version = AggregateVersion::ordinal_only(ordinal).encode();
    let tx = client.transaction().await.expect("begin append tx");
    let event = OutboxEvent {
        cell_id: TEST_CELL_ID,
        repository_id,
        repository_generation: 1,
        event_kind,
        aggregate_kind,
        aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(&tx, &event).await.expect("append pending event");
    tx.commit().await.expect("commit append");
    appended.event_id
}

pub async fn append_n_pending(url: &str, repository_id: &[u8], n: u64) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        // 16 bytes: map_event's own MapFailure::AggregateIdentityNotTransportable
        // triggers on empty/over-wide values, not on width alone, but a real
        //16-byte identity keeps every seeded row well-formed by construction.
        let aggregate_id: [u8; 16] = rand::random();
        ids.push(
            append_pending(
                url,
                repository_id,
                "branch.pushed",
                "branch",
                &aggregate_id,
                i + 1,
            )
            .await,
        );
    }
    ids
}

pub fn rand_repository_id() -> [u8; 16] {
    // map_event refuses the all-zero repository (MapFailure::ZeroRepository),
    // so every caller needs a genuinely random 16 bytes, not zero-initialised.
    rand::random()
}

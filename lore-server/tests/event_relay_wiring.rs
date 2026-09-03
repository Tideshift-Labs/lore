// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Step B: settings parsing, startup gating, and plugin registration
//! for `lore-server/src/event_relay/`.
//!
//! `config.rs`'s own `#[cfg(test)]` module already exhaustively covers
//! `EventRelayConfig::from_settings`'s bound validation (batch size, claim
//! lease, publish deadline, the cross-field deadline/lease bound, owner
//! width) and `RelayBackoff::next_delay`'s jitter/cap/floor behavior by
//! constructing `OutboxRelaySettings` directly -- this file does not
//! duplicate that. What it adds: parsing from REALISTIC TOML text (the src
//! tests never call `toml::from_str`), the `enabled`-defaults-to-false-when-
//! omitted serde behavior, and everything needing a real Postgres database
//! (startup gating) or a real plugin registry (registration).

#[path = "common/case_namespace.rs"]
mod case_namespace;

use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::OUTBOX_RELAY_SCHEMA_VERSION;
use lore_postgres::pool::TlsConfig;
use lore_server::event_relay::EventRelayConfig;
use lore_server::event_relay::StartupRefusal;
use lore_server::event_relay::enforce_startup_preconditions;
use lore_server::plugins::NotificationPluginFactory;
use lore_server::plugins::PluginRegistry;
use lore_server::plugins::remote_notification::config::PLUGIN_NAME as REMOTE_NOTIFICATION_PLUGIN_NAME;
use lore_server::plugins::remote_notification::factory::RemoteNotificationPluginFactory;
use lore_server::settings::OutboxRelaySettings;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

// ---------------------------------------------------------------------------
// Settings parsing (offline)
// ---------------------------------------------------------------------------

/// A realistic `[outbox_relay]` TOML table parses to the CR-032 pinned
/// defaults, cross-checked against `OutboxRelaySettings::default()` itself
/// (which `config.rs`'s own tests already prove `from_settings` accepts and
/// derives correctly) so this test's only job is proving the TOML layer,
/// not restating the bound-validation logic.
#[test]
fn a_realistic_outbox_relay_toml_table_parses_to_the_default_settings() {
    let toml_text = r#"
        enabled = true
        owner = "loreserver-sfo3-cell-a-2"
        batch_size = 100
        claim_lease_seconds = 30
        publish_deadline_seconds = 10
        idle_interval_millis = 500
        backoff_base_millis = 250
        backoff_cap_seconds = 30
        readiness_probe_interval_seconds = 5
        max_oldest_unpublished_seconds = 30
        admission_max_oldest_pending_age_seconds = 300
        admission_max_pending_rows = 1000000
        admission_max_pending_bytes = 5368709120
    "#;
    let parsed: OutboxRelaySettings =
        toml::from_str(toml_text).expect("valid [outbox_relay] TOML must parse");
    let default_with_enabled = OutboxRelaySettings {
        enabled: true,
        owner: Some("loreserver-sfo3-cell-a-2".to_string()),
        ..OutboxRelaySettings::default()
    };
    assert_eq!(parsed.enabled, default_with_enabled.enabled);
    assert_eq!(parsed.owner, default_with_enabled.owner);
    assert_eq!(parsed.batch_size, default_with_enabled.batch_size);
    assert_eq!(
        parsed.claim_lease_seconds,
        default_with_enabled.claim_lease_seconds
    );
    assert_eq!(
        parsed.publish_deadline_seconds,
        default_with_enabled.publish_deadline_seconds
    );
    assert_eq!(
        parsed.admission_max_pending_rows,
        default_with_enabled.admission_max_pending_rows
    );
    assert_eq!(
        parsed.admission_max_pending_bytes,
        default_with_enabled.admission_max_pending_bytes
    );

    // And the parsed value is itself accepted end to end -- proves the TOML
    // layer produces something from_settings actually likes, not just a
    // struct that happens to compare equal field-by-field.
    assert!(EventRelayConfig::from_settings(&parsed).is_ok());
}

/// `enabled` (and every other field) defaults when omitted from the TOML
/// table entirely -- a serde behavior `config.rs`'s own tests never
/// exercise, since they always build the struct directly in Rust.
#[test]
fn an_empty_outbox_relay_toml_table_parses_to_every_field_default() {
    let parsed: OutboxRelaySettings = toml::from_str("").expect("an empty table must parse");
    assert!(
        !parsed.enabled,
        "enabled must default to false when omitted"
    );
    assert_eq!(parsed.owner, None);
    assert_eq!(parsed.batch_size, OutboxRelaySettings::default().batch_size);
    assert_eq!(
        parsed.claim_lease_seconds,
        OutboxRelaySettings::default().claim_lease_seconds
    );
}

// ---------------------------------------------------------------------------
// Startup gating (needs live Postgres for the schema-state row)
// ---------------------------------------------------------------------------

async fn connected_domain_store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

async fn raw_client(url: &str) -> tokio_postgres::Client {
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

/// Startup fails when `lore_outbox_schema_state` has no row -- deleted here
/// after a normal connect (which seeds it null), since nothing in this
/// crate's bootstrap otherwise produces that state on a fresh database.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn startup_fails_when_the_outbox_schema_state_row_is_absent() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "no-state-row").await;
    let url = namespace.pg_url().to_owned();

    let domain = connected_domain_store(&url).await;
    let raw = raw_client(&url).await;
    raw.execute("DELETE FROM lore_outbox_schema_state WHERE id = 1", &[])
        .await
        .expect("delete the singleton schema-state row");

    let pool = lore_postgres::pool::build_pool(&url, 2, &TlsConfig::default())
        .expect("build pool for startup check");

    let result = enforce_startup_preconditions(&pool, &domain).await;
    match result {
        Err(StartupRefusal::SchemaStateAbsent) => {}
        other => panic!("expected StartupRefusal::SchemaStateAbsent, got {other:?}"),
    }
    namespace.release().await;
}

/// Startup fails when `relay_compat_floor` exceeds this binary's supported
/// version.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn startup_fails_when_the_relay_compat_floor_exceeds_this_binarys_supported_version() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "floor-too-high").await;
    let url = namespace.pg_url().to_owned();

    let domain = connected_domain_store(&url).await;
    let raw = raw_client(&url).await;
    let forced_floor = OUTBOX_RELAY_SCHEMA_VERSION + 1;
    raw.execute(
        "UPDATE lore_outbox_schema_state SET relay_compat_floor = $1, \
         cutover_at = clock_timestamp() WHERE id = 1",
        &[&forced_floor],
    )
    .await
    .expect("force an unsupported relay_compat_floor");

    let pool = lore_postgres::pool::build_pool(&url, 2, &TlsConfig::default())
        .expect("build pool for startup check");

    let result = enforce_startup_preconditions(&pool, &domain).await;
    match result {
        Err(StartupRefusal::RelayCompatFloorTooHigh { floor, supported }) => {
            assert_eq!(floor, forced_floor);
            assert_eq!(supported, OUTBOX_RELAY_SCHEMA_VERSION);
        }
        other => panic!("expected StartupRefusal::RelayCompatFloorTooHigh, got {other:?}"),
    }
    namespace.release().await;
}

/// Startup fails with `CutoverIncomplete` when `cutover_at` has never been
/// stamped -- per `startup.rs`'s own `PIN(WP-119)` note, nothing in the tree
/// writes it yet, and that is deliberate fail-closed behaviour.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn startup_fails_when_cutover_has_not_been_stamped() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "no-cutover").await;
    let url = namespace.pg_url().to_owned();

    let domain = connected_domain_store(&url).await;
    let pool = lore_postgres::pool::build_pool(&url, 2, &TlsConfig::default())
        .expect("build pool for startup check");

    // A fresh connect seeds lore_outbox_schema_state but never stamps
    // cutover_at, so no extra setup is needed here.
    let result = enforce_startup_preconditions(&pool, &domain).await;
    match result {
        Err(StartupRefusal::CutoverIncomplete) => {}
        other => panic!("expected StartupRefusal::CutoverIncomplete, got {other:?}"),
    }
    namespace.release().await;
}

/// A present, compatible, cutover-stamped schema-state row starts
/// successfully and returns the state that was read.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn startup_succeeds_with_a_present_compatible_cutover_stamped_schema_state() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "startup-ok").await;
    let url = namespace.pg_url().to_owned();

    let domain = connected_domain_store(&url).await;
    let raw = raw_client(&url).await;
    raw.execute(
        "UPDATE lore_outbox_schema_state SET cutover_at = clock_timestamp() WHERE id = 1",
        &[],
    )
    .await
    .expect("stamp cutover_at");

    let pool = lore_postgres::pool::build_pool(&url, 2, &TlsConfig::default())
        .expect("build pool for startup check");

    let state = enforce_startup_preconditions(&pool, &domain)
        .await
        .expect("startup must succeed once cutover is stamped and the floor is compatible");
    assert!(state.cutover_at.is_some());
    assert_eq!(state.relay_compat_floor, OUTBOX_RELAY_SCHEMA_VERSION);
    namespace.release().await;
}

// ---------------------------------------------------------------------------
// Enabling the relay under [notification] mode = "local"
// ---------------------------------------------------------------------------

/// The minimal valid `Settings` TOML, matching `settings.rs`'s own
/// `test_settings_empty_plugins_and_hooks` fixture shape (the smallest shape
/// that `Settings` itself accepts), with `[outbox_relay] enabled = true`
/// added and no `[notification]` section -- `configure_event_relay` treats
/// an absent section as mode `"local"`.
fn minimal_settings_with_relay_enabled_and_no_notification_section()
-> lore_server::settings::Settings {
    let toml_text = r#"
        [server]
        runtime_shutdown_timeout_seconds = 0

        [server.http]
        enabled = false
        host = "127.0.0.1"
        max_file_size = 1024
        port = 8080
        request_timeout_seconds = 30
        request_body_timeout_seconds = 30
        available_interval_seconds = 5
        available_timeout_seconds = 30
        store_health_check = false

        [immutable_store]
        mode = "local"

        [immutable_store.local]
        path = "/tmp/immutable"
        flush_delay_seconds = 5

        [mutable_store]
        mode = "local"

        [mutable_store.local]
        path = "/tmp/mutable"
        flush_delay_seconds = 5

        [outbox_relay]
        enabled = true
    "#;
    toml::from_str(toml_text).expect("minimal Settings TOML must parse")
}

/// `configure_event_relay` (`event_relay::wiring`) is `[outbox_relay]
/// enabled = true` combined with `Settings.notification`. With no
/// `[notification]` section (mode defaults to `"local"` inside
/// `configure_event_relay` itself), this must fail typed BEFORE the
/// function ever looks at Postgres -- proven here by passing
/// `database_identity: None` and getting a `NotificationModeNotRemote`
/// refusal rather than the `NotPostgresMode` refusal that omitted argument
/// would otherwise trip, which is the ordering `wiring.rs`'s own module
/// docs state explicitly (notification mode is checked before Postgres
/// mode).
#[tokio::test]
async fn relay_enabled_with_no_remote_notification_mode_fails_startup_typed() {
    let settings = minimal_settings_with_relay_enabled_and_no_notification_section();
    let mut endpoints = tokio::task::JoinSet::new();
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let result = lore_server::event_relay::wiring::configure_event_relay(
        &settings,
        None,
        &mut endpoints,
        shutdown_rx,
    )
    .await;
    let error = match result {
        Ok(_) => panic!("relay enabled under [notification] mode != remote must refuse"),
        Err(error) => error,
    };
    let refusal = error
        .downcast_ref::<StartupRefusal>()
        .unwrap_or_else(|| panic!("expected a StartupRefusal, got: {error:#}"));
    match refusal {
        StartupRefusal::NotificationModeNotRemote(mode) => assert_eq!(mode, "local"),
        other => panic!("expected NotificationModeNotRemote, got {other:?}"),
    }
    assert!(
        endpoints.is_empty(),
        "no worker task may be spawned on a refused configuration"
    );
}

// ---------------------------------------------------------------------------
// Plugin registration (offline)
// ---------------------------------------------------------------------------

/// The remote-notification plugin factory is registered by the server's
/// real boot-time entry point (`register_all_plugins`), not by calling
/// `remote_notification::register()` in isolation. This is the mirror image
/// of `plugins/remote_notification.rs`'s own
/// `the_factory_is_not_registered_until_wp_119_wires_it` tripwire test,
/// verified independently here so a rename/removal of that tripwire cannot
/// silently drop this coverage.
///
/// **This is EXPECTED to fail (red) until the SCHEMA-119 registration line
/// lands in `plugins/remote_notification.rs`'s `register()`.** As of this
/// writing that function is still the documented no-op, so this test
/// currently reports the pending work rather than a bug in the test.
#[test]
fn the_remote_notification_plugin_factory_is_registered_at_boot() {
    let mut registry = PluginRegistry::new();
    lore_server::plugins::register_all_plugins(&mut registry);
    assert!(
        registry
            .list_notification_plugins()
            .iter()
            .any(|name| name == REMOTE_NOTIFICATION_PLUGIN_NAME),
        "expected \"{REMOTE_NOTIFICATION_PLUGIN_NAME}\" among the registered notification \
         plugins once WP-119's SCHEMA-119 wiring lands; got {:?}",
        registry.list_notification_plugins()
    );
    assert_eq!(
        RemoteNotificationPluginFactory.name(),
        REMOTE_NOTIFICATION_PLUGIN_NAME
    );
}

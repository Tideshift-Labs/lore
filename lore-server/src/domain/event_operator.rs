// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Supported offline fresh event setup. This never fabricates receiver readiness.
use anyhow::Result;
use anyhow::anyhow;
use lore_postgres::domain::outbox::initialization::FreshEventInitialization;
use lore_postgres::domain::outbox::initialization::FreshEventInitializationOutcome;
use lore_postgres::domain::outbox::initialization::initialize_empty;

use crate::plugins::postgres::assert_domain_store_colocated;
use crate::plugins::postgres::connect_domain_store;
use crate::plugins::postgres::connect_relay_pool;
use crate::plugins::remote_notification::RemoteNotificationConfig;
use crate::settings::Settings;
use crate::store::configuration::resolve_plugin_config_with_fallback;

pub async fn initialize(
    settings: &Settings,
    stream_identity: &str,
    stream_epoch: i64,
    broker_last_sequence: i64,
    confirm_writers_stopped: bool,
    json: bool,
) -> Result<()> {
    anyhow::ensure!(
        confirm_writers_stopped,
        "event initialization requires --confirm-writers-stopped; exclude all producers and receiver writers before observing the broker"
    );
    anyhow::ensure!(
        settings
            .outbox_relay
            .as_ref()
            .is_some_and(|relay| relay.enabled),
        "event initialization requires configured outbox relay"
    );
    let remote = RemoteNotificationConfig::parse(
        settings
            .plugins
            .get("remote")
            .ok_or_else(|| anyhow!("event initialization requires [plugins.remote]"))?,
    )?;
    anyhow::ensure!(
        remote.placement_epoch == 1,
        "fresh event initialization requires initial placement_epoch = 1"
    );
    let input = FreshEventInitialization::new(
        remote.cell_id.clone(),
        stream_identity.to_owned(),
        stream_epoch,
        broker_last_sequence,
    )?;
    super::lock_fencing_settings_preconditions(settings)?;
    let mut configs = Vec::new();
    for (store_type, mode) in [
        ("mutable_store", settings.mutable_store.mode.as_str()),
        ("immutable_store", settings.immutable_store.mode.as_str()),
        (
            "lock_store",
            settings
                .lock_store
                .as_ref()
                .map(|store| store.mode.as_str())
                .unwrap_or(""),
        ),
    ] {
        anyhow::ensure!(
            mode == "postgres",
            "event initialization requires {store_type}.mode = postgres"
        );
        let config = resolve_plugin_config_with_fallback(&settings.plugins, "postgres", store_type)
            .ok_or_else(|| anyhow!("missing Postgres configuration for {store_type}"))?;
        configs.push((store_type, config));
    }
    let store = connect_domain_store(&configs[0].1)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    for (label, config) in &configs {
        assert_domain_store_colocated(&store, label, config)
            .await
            .map_err(|e| anyhow!("{e}"))?;
    }
    anyhow::ensure!(
        super::resolve_enforcement(&store.schema_state().await?)?
            && super::resolve_lock_fencing(&store.lock_coordinator().readiness().await?, settings)?,
        "event initialization requires domain and lock cutover"
    );
    anyhow::ensure!(
        store
            .fragment_coordinator()
            .readiness()
            .await?
            .ready_for_lifecycle(),
        "event initialization requires ready fragment lifecycle"
    );
    let pool = connect_relay_pool(&configs[0].1, 2).map_err(|e| anyhow!("{e}"))?;
    let outcome = initialize_empty(&pool, &input).await?;
    let status = match outcome {
        FreshEventInitializationOutcome::Initialized => "initialized",
        FreshEventInitializationOutcome::AlreadyInitialized => "already_initialized",
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": status, "cell_id": remote.cell_id, "stream_identity": stream_identity,
                "stream_epoch": stream_epoch, "placement_revision": 1,
                "receiver_readiness": "not_asserted", "restart_required": true,
            })
        );
    } else {
        println!(
            "Event initialization: {status}. Start receivers to capture, baseline and establish readiness."
        );
    }
    Ok(())
}

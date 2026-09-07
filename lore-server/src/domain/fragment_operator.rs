// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Offline empty-cell initialization. No endpoint or provider write path opens.

use anyhow::Result;
use anyhow::anyhow;
use lore_postgres::domain::fragments::initialization::CleanCellInitialization;
use lore_postgres::domain::fragments::initialization::CleanCellInitializationOutcome;

use crate::plugins::postgres::assert_domain_store_colocated;
use crate::plugins::postgres::connect_clean_namespace_inspector;
use crate::plugins::postgres::connect_domain_store;
use crate::settings::Settings;
use crate::store::configuration::resolve_plugin_config_with_fallback;

/// Initialize only after external writer exclusion and the supported domain and
/// lock cutover. The flag records an operator attestation, not credential proof.
pub async fn initialize(
    settings: &Settings,
    authority_revision: &str,
    confirm_legacy_writers_excluded: bool,
    json: bool,
) -> Result<()> {
    if !confirm_legacy_writers_excluded {
        return Err(anyhow!(
            "clean initialization requires --confirm-legacy-writers-excluded: stop old writers, revoke their provider write authority and configure fresh scoped credentials first"
        ));
    }
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
                .unwrap_or_default(),
        ),
    ] {
        if mode != "postgres" {
            return Err(anyhow!(
                "clean initialization requires {store_type}.mode = postgres"
            ));
        }
        let config = resolve_plugin_config_with_fallback(&settings.plugins, "postgres", store_type)
            .ok_or_else(|| anyhow!("missing Postgres configuration for {store_type}"))?;
        configs.push((store_type, config));
    }
    let store = connect_domain_store(&configs[0].1)
        .await
        .map_err(|error| anyhow!("{error}"))?;
    for (label, config) in &configs {
        assert_domain_store_colocated(&store, label, config)
            .await
            .map_err(|error| anyhow!("{error}"))?;
    }
    let enforcement = super::resolve_enforcement(&store.schema_state().await?)?;
    let fencing =
        super::resolve_lock_fencing(&store.lock_coordinator().readiness().await?, settings)?;
    if !enforcement || !fencing {
        return Err(anyhow!(
            "clean initialization requires completed domain and lock cutover with enforcement and fencing enabled; run the supported domain cutover first"
        ));
    }
    let inspector = connect_clean_namespace_inspector(&configs[1].1, authority_revision)
        .await
        .map_err(|error| anyhow!("{error}"))?;
    let input = CleanCellInitialization::new(
        inspector.namespace_identity().to_owned(),
        authority_revision.to_owned(),
    )?;
    let coordinator = store.fragment_coordinator();
    coordinator.bootstrap().await?;
    // Exact persisted completion is checked before bucket emptiness. Legitimate
    // uploads after initialization must not turn a completed rerun into failure.
    let complete = coordinator.initialization_status(&input).await?;
    inspector.attest_unversioned().await?;
    if !complete {
        inspector.attest_empty().await?;
    }
    // Rechecks under SQL locks, including completed reruns. No database resource
    // is held across the preceding read-only provider calls.
    let outcome = coordinator.initialize_empty(&input).await?;
    let status = match outcome {
        CleanCellInitializationOutcome::Initialized => "initialized",
        CleanCellInitializationOutcome::AlreadyInitialized => "already_initialized",
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": status,
                "namespace_identity": inspector.namespace_identity(),
                "provider_write_authority_revision": authority_revision,
                "legacy_writers_excluded_attested": true,
                "restart_required": true,
            })
        );
    } else {
        println!(
            "Fragment lifecycle: {status}. Restart the cell to load the enabled route. Legacy writer exclusion is an operator attestation."
        );
    }
    Ok(())
}

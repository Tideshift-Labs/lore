// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `fragment_retention` tests, moved out of the inline
//! `tests` module when upstream set `[lib] test = false`.

use lore_object_dispatch::cell_retention::CellRetentionSettings;
use lore_server::fragment_retention::*;
use tokio::sync::watch;
use tokio::task::JoinSet;

fn settings() -> CellRetentionSettings {
    CellRetentionSettings::new(Some(1_000), Some(10), Some(60_000), Some(2))
        .expect("bounded settings")
}

/// No settings means no task and no facet: an unconfigured cell must not
/// report a green retention pass it is not running.
#[tokio::test]
async fn a_cell_with_no_retention_settings_spawns_nothing() {
    let mut endpoints = JoinSet::new();
    let (_tx, shutdown) = watch::channel(false);
    let readiness = configure_cell_retention(None, None, &mut endpoints, shutdown)
        .await
        .expect("an unconfigured cell is not an error");
    assert!(readiness.is_none());
    assert!(endpoints.is_empty());
}

/// Enabled settings with no dispatch pool must not start a
/// scheduler-shaped nothing, and must not be downgraded to a warning.
#[tokio::test]
async fn enabled_settings_with_no_dispatch_pool_refuse_startup() {
    let mut endpoints = JoinSet::new();
    let (_tx, shutdown) = watch::channel(false);
    let error = configure_cell_retention(None, Some(settings()), &mut endpoints, shutdown)
        .await
        .expect_err("retention without a pool must refuse");
    assert_eq!(
        error.downcast_ref::<CellRetentionWiringError>(),
        Some(&CellRetentionWiringError::NoDispatchPool),
    );
    assert!(endpoints.is_empty());
}

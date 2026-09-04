// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Scheduling for WP-114 CD-8's cell-scale retention pass.
//!
//! `lore-object-dispatch`'s `cell_retention` module owns the decision, the
//! bounds, the pass and the progress rule; its module doc is the account of all
//! four and is not restated here. This module is only the composition around
//! [`CellRetentionTask::run`]: read four configuration keys, prove the retention
//! layer is installed, spawn, and publish the facet.
//!
//! # Why this lives in `lore-server` and not beside the pool
//!
//! The pool the pass runs on is opened inside `lore-fragment-provider`, and it
//! reaches here through `lore-postgres`, which may not depend on
//! `lore-object-dispatch`. So the client crosses that crate inside an opaque
//! [`FragmentCellRetentionHandle`] and is opened here, at the composition root
//! that may name it. No second pool is opened anywhere on this path, so the
//! CR-033 D8 process connection inventory is unchanged.
//!
//! # Inert unless the governed fragment path is enabled
//!
//! Dispatch evidence rows exist only on WP-118's governed route. A cell with
//! `fragment_provider` absent or `enabled = false` opened no dispatch pool and
//! wrote none, so no task is spawned and the facet reports unconfigured — the
//! same honest answer `/event_readiness` gives for an unconfigured relay, and
//! for the same reason: "no scheduler is running" and "the table is drained"
//! are different states.
//!
//! # A missing retention layer fails startup
//!
//! [`CellRetentionClient::read_state`] is called before anything is spawned. A
//! cell whose schema lacks migrations 0023/0024 has no retention procedures to
//! call, so every pass would fail and the facet would go false several ticks
//! later with the reason buried in a log line. Refusing at boot names the
//! actual condition once, at the place an operator is already looking.

use std::sync::Arc;

use anyhow::Result;
use anyhow::anyhow;
use lore_base::lore_spawn;
use lore_object_dispatch::cell_retention::CellRetentionReadiness;
use lore_object_dispatch::cell_retention::CellRetentionSettings;
use lore_object_dispatch::cell_retention::CellRetentionTask;
use lore_object_dispatch::dispatch_client::DispatchAuthorityError;
use lore_postgres::domain::fragments::FragmentCellRetentionHandle;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

/// A cell that asked for retention but cannot run it.
///
/// Both variants are boot-time refusals. Neither is a condition a later tick
/// could clear, so neither is left to the facet.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CellRetentionWiringError {
    /// Retention is enabled but the governed fragment route is not, so no
    /// dispatch pool exists to run a pass on.
    ///
    /// Unreachable through the settings path — `cell_retention_settings`
    /// returns `None` for exactly the configurations that produce no handle —
    /// and reported rather than assumed away.
    #[error(
        "cell retention is enabled but this cell has no governed fragment provider, so there is \
         no dispatch pool to run a retention pass on"
    )]
    NoDispatchPool,
    /// The retention layer is absent, incomplete, or unreachable.
    ///
    /// Carries the authority's own typed refusal rather than its rendering:
    /// `lore-server` may name `lore-object-dispatch`'s error, and every variant
    /// of it is a fixed shape carrying no connection string, diagnostic or
    /// identifier, so nothing is gained by flattening it to a string.
    #[error("the cell dispatch schema has no usable retention layer (0023/0024)")]
    LayerUnavailable(#[source] DispatchAuthorityError),
}

/// Prove the retention layer, then spawn the pass on the server's drain signal.
///
/// `settings` is `None` for every cell whose `fragment_provider` block is
/// absent, disabled, or has `cell_retention_enabled = false`; those cells get no
/// task and no facet. `handle` is `None` on the legacy route.
///
/// # Errors
///
/// Returns [`CellRetentionWiringError::NoDispatchPool`] when retention is
/// configured without a governed provider, and
/// [`CellRetentionWiringError::LayerUnavailable`] when the readback refuses.
/// Both fail the server's startup.
pub async fn configure_cell_retention(
    handle: Option<FragmentCellRetentionHandle>,
    settings: Option<CellRetentionSettings>,
    endpoints: &mut JoinSet<Result<()>>,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<Arc<CellRetentionReadiness>>> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let Some(handle) = handle else {
        return Err(anyhow!(CellRetentionWiringError::NoDispatchPool));
    };
    let client = handle.into_client();
    // Before anything is spawned: a cell without the layer is refused here
    // rather than discovered one failed pass at a time.
    let installed = client
        .read_state()
        .await
        .map_err(|error| anyhow!(CellRetentionWiringError::LayerUnavailable(error)))?;
    info!(
        schema_revision = %installed.schema_revision,
        install_revision = installed.install_revision,
        installed_at_unix_ms = installed.installed_at_unix_ms,
        "Cell retention layer attested"
    );
    let readiness = Arc::new(CellRetentionReadiness::new(&settings));
    let task = CellRetentionTask::new(client, settings, Arc::clone(&readiness));
    // `run` returns nothing and never fails by construction; the endpoint
    // `JoinSet` takes a `Result`, and an `Ok` is the honest shape for a task
    // whose every failure mode is already counted into the facet.
    lore_spawn!(endpoints, async move {
        task.run(shutdown).await;
        Ok(())
    });
    Ok(Some(readiness))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

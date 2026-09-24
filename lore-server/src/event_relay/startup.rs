// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Startup enforcement for required-event mode (CR-032; WP-119 Phase 4).
//!
//! CR-032: "Startup fails when required-event mode is enabled but the outbox is
//! absent, incomplete, wrapped behind an unsupported protocol, or connected to
//! a different database." This module is that sentence, and every check fails
//! **closed**.
//!
//! Failing open would be worse than it looks. A relay that boots against a
//! database with no outbox does not sit idle and harmless: it reports itself
//! running, its backlog probe sees zero pending rows, and both readiness facets
//! go green — a cell that is publishing nothing looks identical to a cell that
//! is perfectly caught up. The only moment that misconfiguration is visible is
//! boot.
//!
//! # PIN(WP-119): nothing in this tree writes `cutover_at`
//!
//! `lore_outbox_schema_state.cutover_at` is created by `OUTBOX_SCHEMA` and
//! seeded null by `PostgresDomainStore::ensure_state_rows`; no code path sets
//! it. CR-032 puts the cutover procedure and its operator commands in Step C,
//! so until that lands, enabling `[outbox_relay]` on a cell refuses to boot
//! with [`StartupRefusal::CutoverIncomplete`] until an operator stamps the
//! marker. That is the intended fail-closed state for a feature that is
//! default-off, and it is deliberately not softened by a bypass flag: a bypass
//! on this gate is the only thing that could let required-event mode run
//! against a cell whose producers and consumers were never verified compatible.

use lore_postgres::domain::DatabaseIdentity;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::outbox::OutboxSchemaState;
use lore_postgres::domain::outbox::relay;
use lore_postgres::domain::outbox::schema::OUTBOX_RELAY_SCHEMA_VERSION;
use lore_postgres::domain::outbox::schema::relay_is_compatible;
use lore_postgres::domain::store::read_database_identity;
use lore_postgres::pool::Pool;

/// The label the co-location check reports the relay pool under.
const RELAY_POOL_LABEL: &str = "outbox relay pool";

/// Why a loreserver refused to start with the relay enabled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupRefusal {
    /// The relay is enabled but this cell's notification mode is not `remote`,
    /// so there is no private gateway client to publish through.
    #[error(
        "[outbox_relay] enabled requires [notification] mode = \"remote\" (the relay publishes \
         through that plugin's private gateway client), but this cell is in mode `{0}`"
    )]
    NotificationModeNotRemote(String),
    /// The relay is enabled but this cell is not in Postgres mode, so there is
    /// no outbox to relay from.
    #[error(
        "[outbox_relay] enabled requires the Postgres domain coordinator, which this cell does \
         not have; the outbox lives in cell Postgres"
    )]
    NotPostgresMode,
    /// The `[plugins.remote]` section is missing or invalid.
    #[error("[outbox_relay] enabled requires a valid [plugins.remote] section: {0}")]
    RemoteConfig(String),
    /// A durable receiver is declared on a cell that runs no relay.
    ///
    /// Refused rather than ignored. The receiver runs on the relay's own
    /// Postgres pool and its gateway channel, both of which exist only when the
    /// relay is enabled, so the alternative is a cell that silently starts no
    /// receiver while its configuration says it has one — and a cell with no
    /// receiver and a cell whose receiver is caught up report the same empty
    /// checkpoint vector.
    #[error(
        "[plugins.remote.receiver] declares a durable invalidation receiver, but [outbox_relay] \
         is not enabled on this cell. The receiver consumes on the relay's own Postgres pool and \
         gateway channel, so it cannot run without one: either enable the relay or remove the \
         receiver section"
    )]
    ReceiverWithoutRelay,
    /// The outbox schema state row (or its table) is absent.
    #[error(
        "the outbox schema state is absent from this cell's database: either the outbox schema \
         was never applied, or its singleton row was never seeded"
    )]
    SchemaStateAbsent,
    /// This build speaks an older relay contract than the cell demands.
    #[error(
        "this build speaks relay contract version {supported}, but the cell's \
         relay_compat_floor is {floor}; it must not publish work it cannot represent"
    )]
    RelayCompatFloorTooHigh {
        /// The cell's floor.
        floor: i32,
        /// What this binary supports.
        supported: i32,
    },
    /// The cutover marker has not been set.
    #[error(
        "this cell's outbox cutover marker is incomplete (cutover_at is unset), so required-event \
         mode must not run: producers and consumers have not been proven compatible"
    )]
    CutoverIncomplete,
    /// The relay pool addresses a different database from the coordinator.
    #[error("the outbox relay pool is not co-located with the domain coordinator: {0}")]
    DifferentDatabase(String),
    /// The schema-state read itself failed.
    #[error("could not read this cell's outbox schema state: {0}")]
    Probe(String),
    /// A `remote` cell did not name its event plane (contract amendment A-32).
    #[error(
        "[notification] mode = \"remote\" requires [notification] event_plane = \"live_only\" or \
         \"durable\"; it has no default, so a cell cannot change plane by omission"
    )]
    EventPlaneMissing,
    /// The event plane is not one of the two spellings.
    #[error("[notification] event_plane must be \"live_only\" or \"durable\", got {0:?}")]
    EventPlaneInvalid(String),
    /// An event plane on a cell that is not in `remote` mode, where it means
    /// nothing.
    #[error(
        "[notification] event_plane is set, but this cell is in mode `{0}`; an event plane is \
         meaningful only with mode = \"remote\""
    )]
    EventPlaneWithoutRemote(String),
    /// `live_only` with `[outbox_relay] enabled`.
    #[error(
        "[notification] event_plane = \"live_only\" produces no outbox rows, so [outbox_relay] \
         must not be enabled; disable it or run event_plane = \"durable\""
    )]
    LiveOnlyForbidsRelay,
    /// `live_only` with a durable receiver declared.
    #[error(
        "[notification] event_plane = \"live_only\" runs no durable receiver, so \
         [plugins.remote.receiver] must not be declared; remove it or run event_plane = \"durable\""
    )]
    LiveOnlyForbidsReceiver,
    /// The configured plane differs from the cell's marker in Postgres.
    ///
    /// Boot never writes the marker. A fresh `live_only` cell refuses here
    /// until an operator runs the named command.
    #[error(
        "this loreserver is configured for event_plane = \"{configured}\" but the cell's marker \
         is \"{marker}\"{absent}; stop every replica of this cell, run `{remedy}`, then start \
         the replicas again (or fix the configuration)",
        absent = if *marker_absent { " (no transition recorded, which means durable)" } else { "" }
    )]
    EventPlaneMismatch {
        /// The configured plane.
        configured: &'static str,
        /// The marker's plane.
        marker: &'static str,
        /// Whether the cell has no transition row at all.
        marker_absent: bool,
        /// The exact command that moves the marker to the configured plane.
        remedy: &'static str,
    },
    /// A `live_only` cell still holds outbox rows.
    ///
    /// `set-plane live-only` leaves no row, a `live_only` process appends none,
    /// and `requeue-dead-letter` and `replay` refuse on a `live_only` cell. A
    /// row can still arrive by a direct write or a defect, so the refusal names
    /// the supported exit: `set-plane durable` carries a stray pending row into
    /// the plane that publishes it.
    #[error(
        "event_plane = \"live_only\" and the cell's marker agrees, but the cell holds outbox rows; \
         a live_only cell must hold none. Inspect them with `loreserver outbox inspect`, then, \
         with every replica stopped, run `loreserver outbox set-plane durable --actor <who> \
         --reason <why>` and start the cell with event_plane = \"durable\" so the relay publishes \
         them; drain, and switch back with `set-plane live-only`"
    )]
    LiveOnlyWithOutboxRows,
    /// The marker could not be read.
    #[error("could not read this cell's event plane marker: {0}")]
    EventPlaneProbe(String),
}

/// Prove the cell is fit to run the relay, or refuse to boot.
///
/// Order matters and is not arbitrary: co-location is checked **first**,
/// because every later check reads the relay pool's own database and a
/// misconfigured pool would otherwise report an absent or incompatible outbox
/// while the real one sits healthy in the coordinator's database. Diagnosing
/// that from "schema state absent" would send an operator to the wrong cell.
pub async fn enforce_startup_preconditions(
    pool: &Pool,
    domain: &PostgresDomainStore,
) -> Result<OutboxSchemaState, StartupRefusal> {
    domain
        .assert_same_database(pool, RELAY_POOL_LABEL)
        .await
        .map_err(|e| StartupRefusal::DifferentDatabase(e.to_string()))?;
    read_and_check(pool).await
}

/// The same gate, against an already-attested database identity.
///
/// Server composition holds the coordinator's `DatabaseIdentity` but not the
/// coordinator itself, so this variant reads the relay pool's own identity and
/// compares the two. It is the same proof as
/// [`enforce_startup_preconditions`]: `assert_same_database` is exactly a read
/// of the other pool's identity followed by an equality test, and comparing
/// URLs or configuration sections would not be.
pub async fn enforce_startup_preconditions_against_identity(
    pool: &Pool,
    expected: &DatabaseIdentity,
) -> Result<OutboxSchemaState, StartupRefusal> {
    let observed = read_database_identity(pool)
        .await
        .map_err(|e| StartupRefusal::Probe(format!("relay pool identity: {e}")))?;
    if observed != *expected {
        return Err(StartupRefusal::DifferentDatabase(format!(
            "the {RELAY_POOL_LABEL} addresses {} but the domain coordinator addresses {}",
            observed.as_marker(),
            expected.as_marker()
        )));
    }
    read_and_check(pool).await
}

async fn read_and_check(pool: &Pool) -> Result<OutboxSchemaState, StartupRefusal> {
    let client = pool
        .get()
        .await
        .map_err(|e| StartupRefusal::Probe(format!("relay pool: {e}")))?;
    let state = relay::schema_state(&**client)
        .await
        .map_err(|e| StartupRefusal::Probe(e.to_string()))?
        .ok_or(StartupRefusal::SchemaStateAbsent)?;

    check_state(&state)?;
    Ok(state)
}

/// The two facts on the schema-state row, separated from the I/O so they are
/// decidable without a database.
pub fn check_state(state: &OutboxSchemaState) -> Result<(), StartupRefusal> {
    if !relay_is_compatible(state.relay_compat_floor) {
        return Err(StartupRefusal::RelayCompatFloorTooHigh {
            floor: state.relay_compat_floor,
            supported: OUTBOX_RELAY_SCHEMA_VERSION,
        });
    }
    if state.cutover_at.is_none() {
        return Err(StartupRefusal::CutoverIncomplete);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    fn state() -> OutboxSchemaState {
        OutboxSchemaState {
            migration_version: i64::from(OUTBOX_RELAY_SCHEMA_VERSION),
            backfill_version: 0,
            producer_compat_floor: OUTBOX_RELAY_SCHEMA_VERSION,
            relay_compat_floor: OUTBOX_RELAY_SCHEMA_VERSION,
            consumer_compat_floor: OUTBOX_RELAY_SCHEMA_VERSION,
            cutover_at: Some(SystemTime::UNIX_EPOCH),
            retention_policy_version: None,
            updated_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_cut_over_cell_at_this_builds_contract_version_passes() {
        assert_eq!(check_state(&state()), Ok(()));
    }

    #[test]
    fn a_cell_demanding_a_newer_relay_contract_is_refused() {
        let mut state = state();
        state.relay_compat_floor = OUTBOX_RELAY_SCHEMA_VERSION + 1;
        assert_eq!(
            check_state(&state),
            Err(StartupRefusal::RelayCompatFloorTooHigh {
                floor: OUTBOX_RELAY_SCHEMA_VERSION + 1,
                supported: OUTBOX_RELAY_SCHEMA_VERSION,
            })
        );
    }

    /// A floor *below* this build's version is the ordinary rolling-upgrade
    /// case and must not be refused.
    #[test]
    fn a_cell_at_an_older_floor_is_accepted() {
        let mut state = state();
        state.relay_compat_floor = 1;
        assert_eq!(check_state(&state), Ok(()));
    }

    #[test]
    fn an_unstamped_cutover_marker_refuses_the_boot() {
        let mut state = state();
        state.cutover_at = None;
        assert_eq!(check_state(&state), Err(StartupRefusal::CutoverIncomplete));
    }

    /// Compatibility is checked before the marker, so an operator upgrading a
    /// cell is told about the version wall rather than being sent to stamp a
    /// marker that would not have helped.
    #[test]
    fn an_incompatible_cell_reports_the_version_even_with_no_marker() {
        let mut state = state();
        state.relay_compat_floor = OUTBOX_RELAY_SCHEMA_VERSION + 1;
        state.cutover_at = None;
        assert!(matches!(
            check_state(&state),
            Err(StartupRefusal::RelayCompatFloorTooHigh { .. })
        ));
    }
}

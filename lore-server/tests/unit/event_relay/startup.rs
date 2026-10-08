// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::SystemTime;

use lore_postgres::domain::outbox::OutboxSchemaState;
use lore_postgres::domain::outbox::schema::OUTBOX_RELAY_SCHEMA_VERSION;
use lore_server::event_relay::startup::StartupRefusal;
use lore_server::event_relay::startup::check_state;

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

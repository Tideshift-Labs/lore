// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The configured event plane and its boot gates (contract amendment A-32).
//!
//! `[notification] event_plane` selects one of two planes on a `remote`-mode
//! cell:
//!
//! * `durable` — CR-032 exactly as before this module: producers append,
//!   `[outbox_relay]` and `[plugins.remote.receiver]` behave as they always
//!   did.
//! * `live_only` — producers append **no** outbox row, and the relay and the
//!   durable receiver are refused at boot. The `LIVE_HINT` sender still runs.
//!   With no relay there is no outbox admission gate, so no notification state
//!   can refuse a write.
//!
//! The setting is required when `mode = "remote"` and has no default: a cell
//! must say which plane it runs, so an existing durable cell never flips to
//! `live_only` by omission. It is refused on any other mode, where it would
//! mean nothing.
//!
//! # Outbox production is its own predicate
//!
//! [`outbox_production_enabled`] is what producers consult. It is deliberately
//! not modelled as an absent cell identity: the `LIVE_HINT` envelope still needs
//! that identity, and a future consumer of it must not silently stop producing
//! because a plane switch removed it.
//!
//! # The marker in cell Postgres is the authority
//!
//! Configuration says what this process intends; the latest row of
//! `lore_outbox_event_plane_transitions` says what the cell is. [`check_marker`]
//! refuses to boot when they differ, and refuses a `live_only` boot while the
//! cell still holds outbox rows. `loreserver outbox set-plane` is the only way
//! to move the marker.

use lore_postgres::domain::outbox::EventPlane;
use lore_postgres::domain::outbox::EventPlaneBootFacts;

use crate::event_relay::startup::StartupRefusal;
use crate::settings::NotificationSettings;
use crate::settings::Settings;

/// The `[notification] mode` a plane is meaningful on.
const REMOTE_NOTIFICATION_MODE: &str = "remote";

/// Resolve `[notification] event_plane`.
///
/// `Ok(None)` on every cell whose notification mode is not `remote` and which
/// sets no plane: such a cell has no event plane, exactly as before.
///
/// # Errors
/// A missing plane on a `remote` cell, an unknown spelling, or a plane on a
/// cell that is not in `remote` mode.
pub fn configured_event_plane(settings: &Settings) -> Result<Option<EventPlane>, StartupRefusal> {
    resolve_section(settings.notification.as_ref())
}

/// [`configured_event_plane`] over the `[notification]` section alone.
fn resolve_section(
    notification: Option<&NotificationSettings>,
) -> Result<Option<EventPlane>, StartupRefusal> {
    let mode = notification.map_or("local", |ns| ns.mode.as_str());
    let raw = notification.and_then(|ns| ns.event_plane.as_deref());
    match (mode == REMOTE_NOTIFICATION_MODE, raw) {
        (false, None) => Ok(None),
        (false, Some(_)) => Err(StartupRefusal::EventPlaneWithoutRemote(mode.to_string())),
        (true, None) => Err(StartupRefusal::EventPlaneMissing),
        (true, Some(value)) => EventPlane::parse(value)
            .map(Some)
            .ok_or_else(|| StartupRefusal::EventPlaneInvalid(value.to_string())),
    }
}

/// Whether governed mutations append CR-032 outbox rows under this plane.
///
/// `false` only for `live_only`. A cell with no plane (not `remote`) keeps the
/// behavior it had before planes existed: it produces exactly when a cell
/// identity is configured.
pub fn outbox_production_enabled(plane: Option<EventPlane>) -> bool {
    plane != Some(EventPlane::LiveOnly)
}

/// Decide whether the configured plane may run against the cell's marker.
///
/// # Errors
/// The configured plane differs from the marker, or a `live_only` cell still
/// holds outbox rows.
pub fn check_marker(
    configured: EventPlane,
    facts: &EventPlaneBootFacts,
) -> Result<(), StartupRefusal> {
    if facts.marker.plane != configured {
        return Err(StartupRefusal::EventPlaneMismatch {
            configured: configured.as_str(),
            marker: facts.marker.plane.as_str(),
        });
    }
    if configured == EventPlane::LiveOnly && facts.has_outbox_rows {
        return Err(StartupRefusal::LiveOnlyWithOutboxRows);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lore_postgres::domain::outbox::EventPlaneMarker;

    use super::*;

    fn facts(plane: EventPlane, has_outbox_rows: bool) -> EventPlaneBootFacts {
        EventPlaneBootFacts {
            marker: EventPlaneMarker {
                plane,
                transition_seq: 0,
                transitioned_at: None,
            },
            has_outbox_rows,
        }
    }

    fn resolve(
        mode: Option<&str>,
        plane: Option<&str>,
    ) -> Result<Option<EventPlane>, StartupRefusal> {
        let notification = mode.map(|mode| NotificationSettings {
            mode: mode.to_owned(),
            event_plane: plane.map(str::to_owned),
        });
        resolve_section(notification.as_ref())
    }

    #[test]
    fn a_remote_cell_must_name_its_plane() {
        assert_eq!(
            resolve(Some("remote"), None),
            Err(StartupRefusal::EventPlaneMissing)
        );
        assert_eq!(
            resolve(Some("remote"), Some("live_only")),
            Ok(Some(EventPlane::LiveOnly))
        );
        assert_eq!(
            resolve(Some("remote"), Some("durable")),
            Ok(Some(EventPlane::Durable))
        );
        assert_eq!(
            resolve(Some("remote"), Some("live-only")),
            Err(StartupRefusal::EventPlaneInvalid("live-only".into()))
        );
    }

    #[test]
    fn a_non_remote_cell_has_no_plane_and_may_not_set_one() {
        assert_eq!(resolve(None, None), Ok(None));
        assert_eq!(resolve(Some("local"), None), Ok(None));
        assert_eq!(
            resolve(Some("local"), Some("durable")),
            Err(StartupRefusal::EventPlaneWithoutRemote("local".into()))
        );
    }

    #[test]
    fn only_live_only_stops_outbox_production() {
        assert!(outbox_production_enabled(None));
        assert!(outbox_production_enabled(Some(EventPlane::Durable)));
        assert!(!outbox_production_enabled(Some(EventPlane::LiveOnly)));
    }

    #[test]
    fn the_marker_must_match_the_configured_plane() {
        assert_eq!(
            check_marker(EventPlane::Durable, &facts(EventPlane::Durable, true)),
            Ok(())
        );
        assert_eq!(
            check_marker(EventPlane::LiveOnly, &facts(EventPlane::LiveOnly, false)),
            Ok(())
        );
        assert_eq!(
            check_marker(EventPlane::LiveOnly, &facts(EventPlane::Durable, false)),
            Err(StartupRefusal::EventPlaneMismatch {
                configured: "live_only",
                marker: "durable",
            })
        );
        assert_eq!(
            check_marker(EventPlane::Durable, &facts(EventPlane::LiveOnly, false)),
            Err(StartupRefusal::EventPlaneMismatch {
                configured: "durable",
                marker: "live_only",
            })
        );
    }

    #[test]
    fn a_live_only_cell_may_not_hold_outbox_rows() {
        assert_eq!(
            check_marker(EventPlane::LiveOnly, &facts(EventPlane::LiveOnly, true)),
            Err(StartupRefusal::LiveOnlyWithOutboxRows)
        );
    }
}

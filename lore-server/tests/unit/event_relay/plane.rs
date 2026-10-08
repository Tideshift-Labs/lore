// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_postgres::domain::outbox::EventPlane;
use lore_postgres::domain::outbox::EventPlaneBootFacts;
use lore_postgres::domain::outbox::EventPlaneMarker;
use lore_server::event_relay::plane::*;
use lore_server::event_relay::startup::StartupRefusal;
use lore_server::settings::NotificationSettings;

/// A marker at `transition_seq`. Sequence 0 is a cell with no transition
/// row, which only ever reads as `durable`.
fn facts_at(plane: EventPlane, transition_seq: i64, has_outbox_rows: bool) -> EventPlaneBootFacts {
    EventPlaneBootFacts {
        marker: EventPlaneMarker {
            plane,
            transition_seq,
            transitioned_at: (transition_seq > 0).then_some(std::time::SystemTime::UNIX_EPOCH),
        },
        has_outbox_rows,
    }
}

fn facts(plane: EventPlane, has_outbox_rows: bool) -> EventPlaneBootFacts {
    facts_at(plane, 1, has_outbox_rows)
}

fn resolve(mode: Option<&str>, plane: Option<&str>) -> Result<Option<EventPlane>, StartupRefusal> {
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
            marker_absent: false,
            remedy: "loreserver outbox set-plane live-only --actor <who> --reason <why>",
        })
    );
    assert_eq!(
        check_marker(EventPlane::Durable, &facts(EventPlane::LiveOnly, false)),
        Err(StartupRefusal::EventPlaneMismatch {
            configured: "durable",
            marker: "live_only",
            marker_absent: false,
            remedy: "loreserver outbox set-plane durable --actor <who> --reason <why>",
        })
    );
}

/// Boot never writes the marker: a fresh `live_only` cell refuses and
/// names the exact command, and an existing cell with no marker boots
/// `durable` unchanged.
#[test]
fn an_absent_marker_is_durable_and_a_live_only_boot_names_the_command() {
    assert_eq!(
        check_marker(EventPlane::Durable, &facts_at(EventPlane::Durable, 0, true)),
        Ok(())
    );
    let refusal = check_marker(
        EventPlane::LiveOnly,
        &facts_at(EventPlane::Durable, 0, false),
    )
    .expect_err("a live_only boot on an absent marker must refuse");
    assert_eq!(
        refusal,
        StartupRefusal::EventPlaneMismatch {
            configured: "live_only",
            marker: "durable",
            marker_absent: true,
            remedy: "loreserver outbox set-plane live-only --actor <who> --reason <why>",
        }
    );
    let message = refusal.to_string();
    assert!(message.contains("no transition recorded"), "{message}");
    assert!(
        message.contains("loreserver outbox set-plane live-only --actor"),
        "{message}"
    );
}

#[test]
fn a_live_only_cell_may_not_hold_outbox_rows() {
    assert_eq!(
        check_marker(EventPlane::LiveOnly, &facts(EventPlane::LiveOnly, true)),
        Err(StartupRefusal::LiveOnlyWithOutboxRows)
    );
}

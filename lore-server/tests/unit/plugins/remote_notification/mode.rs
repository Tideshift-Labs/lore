// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_server::plugins::remote_notification::mode::*;

#[test]
fn every_mode_round_trips_through_its_configuration_string() {
    for mode in [
        PluginMode::Local,
        PluginMode::Remote,
        PluginMode::LocalShadowRemote,
    ] {
        assert_eq!(PluginMode::parse(mode.as_str()), Ok(mode));
    }
}

#[test]
fn an_unknown_mode_names_the_closed_set_rather_than_defaulting() {
    let error = PluginMode::parse("remote-only").expect_err("an unknown mode is rejected");
    let message = error.to_string();
    assert!(message.contains("mode"));
    assert!(message.contains("local-shadow-remote"));
}

/// The rule the contract states as fail-closed: remote multi-replica
/// operation and a mounted local public service cannot coexist.
#[test]
fn only_remote_mode_unmounts_the_local_public_service() {
    assert!(!PluginMode::Remote.mounts_local_public_service());
    assert!(PluginMode::Local.mounts_local_public_service());
    assert!(PluginMode::LocalShadowRemote.mounts_local_public_service());
}

/// Shadow mode publishes and observes; it never consumes.
#[test]
fn shadow_mode_publishes_remotely_but_runs_no_durable_receiver() {
    assert!(PluginMode::LocalShadowRemote.publishes_remotely());
    assert!(PluginMode::LocalShadowRemote.publishes_shadow_only());
    assert!(
        !PluginMode::LocalShadowRemote.runs_durable_receiver(),
        "a shadow branch that consumed durable invalidations would change the system it \
         exists to observe"
    );
}

#[test]
fn only_remote_mode_runs_a_durable_receiver() {
    assert!(PluginMode::Remote.runs_durable_receiver());
    assert!(!PluginMode::Local.runs_durable_receiver());
    assert!(!PluginMode::LocalShadowRemote.runs_durable_receiver());
}

#[test]
fn selecting_this_plugin_for_a_composed_mode_is_refused_with_its_owner_named() {
    assert!(PluginMode::Remote.require_selectable().is_ok());

    let shadow = PluginMode::LocalShadowRemote
        .require_selectable()
        .expect_err("shadow mode is not selectable here");
    assert!(shadow.to_string().contains("server-level composition"));

    let local = PluginMode::Local
        .require_selectable()
        .expect_err("local mode is not selectable here");
    assert!(local.to_string().contains("built-in"));
}

#[test]
fn remote_is_the_default_because_it_is_the_mode_this_plugin_exists_for() {
    assert_eq!(PluginMode::default(), PluginMode::Remote);
}

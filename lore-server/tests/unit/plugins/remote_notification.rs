// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

mod apply;
mod client;
mod config;
mod envelope;
mod error;
mod factory;
mod faults;
mod frontier;
mod metrics;
mod mode;
mod receiver;
mod receiver_store;
mod stream;
mod wire;

use lore_server::plugins::PluginRegistry;
use lore_server::plugins::remote_notification::*;

/// The other side of WP-111's handoff tripwire.
///
/// It previously pinned that this component shipped **unregistered**, which
/// was the `PLUGIN-COMPONENT-READY` contract with WP-119. `SCHEMA-119`
/// added the registration line, so the assertion is inverted rather than
/// deleted: the tripwire's job now is to catch a later refactor that drops
/// the registration and leaves `mode = "remote"` failing at boot with an
/// unknown-plugin error that reads like a configuration typo.
#[test]
fn schema_119_registered_the_factory_under_its_plugin_name() {
    let mut registry = PluginRegistry::new();
    register(&mut registry);
    assert!(
        registry
            .list_notification_plugins()
            .iter()
            .any(|name| name == PLUGIN_NAME),
        "`[notification] mode = \"remote\"` resolves through this registration; without it \
         a correctly configured cell fails at boot with an unknown-plugin error"
    );
}

#[test]
fn the_registry_name_matches_the_factory_name() {
    use lore_server::plugins::NotificationPluginFactory;
    assert_eq!(RemoteNotificationPluginFactory.name(), PLUGIN_NAME);
    assert_eq!(PLUGIN_NAME, "remote");
}

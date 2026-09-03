// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-027 / WP-111: the remote notification plugin.
//!
//! In a multi-replica cell, Lore's local notification mode cannot work: it keeps
//! a per-repository Tokio broadcast sender inside one process, so a mutation on
//! one loreserver never reaches a subscriber on another. This component
//! implements the alternative the contract names — a `NotificationPlugin` that
//! publishes to Lorehub's private notification gateway over mTLS, and that
//! mounts no public notification service of its own.
//!
//! ## What is here, and what is not
//!
//! Phases 1 and 2 of WP-111 only: the pinned private contract and the bounded
//! best-effort `LIVE_HINT` sender, plus the durable Publish entry point CR-032's
//! relay calls.
//!
//! | Module | Role |
//! | --- | --- |
//! | [`wire`] | the vendored private protobuf, hand-transcribed, plus its `.proto` of record |
//! | [`envelope`] | the typed envelope, every contract bound, and the Lore-event mapping |
//! | [`config`] | `[plugins.remote]`, parsed and bounded before any I/O |
//! | [`client`] | one Publish attempt, and the closed classification of the answer |
//! | [`sender`] | the bounded queue, the single drain worker, and the retry budget |
//! | [`factory`] | the `NotificationPluginFactory` for mode `remote` |
//! | [`fake_gateway`] | a request-counting, scriptable, in-process gateway for tests |
//! | [`error`] | the layered error types and the closed failure classification |
//!
//! Not here, by design: the durable invalidation **receiver**, checkpointing,
//! `local-shadow-remote` composition, and the migration modes. Those are WP-111
//! Phase 3 onward. Every attachment point carries a `TODO(WP-111 Phase 3)`.
//!
//! ## This component is not mutation authority
//!
//! A synchronous plugin Publish is not atomic with cell Postgres, so it can
//! never be the only record of a correctness-sensitive mutation. CR-032 owns the
//! mutation transaction, the durable outbox row, and the relay. This component
//! produces best-effort live hints, and offers the relay a durable publish
//! entry point that classifies but never retries.
//!
//! ## Registration is deliberately deferred
//!
//! [`register`] is a no-op. `build.rs` auto-discovers this module and emits the
//! call into the generated `plugins/mod.rs`, but wiring the factory into the
//! registry belongs to WP-119's serialized `SCHEMA-119` window, which owns the
//! common settings, server-construction, readiness, and drain files this plugin
//! must be threaded through. See [`register`] for the exact line that window
//! adds.

pub mod client;
pub mod config;
pub mod envelope;
pub mod error;
pub mod factory;
pub mod fake_gateway;
mod metrics;
pub mod sender;
pub mod wire;

pub use client::BrokerAcceptance;
pub use client::MAX_DURABLE_PUBLISH_DEADLINE;
pub use client::PrivateGatewayClient;
pub use client::PublishTransport;
pub use config::PLUGIN_NAME;
pub use config::RemoteNotificationConfig;
pub use envelope::AggregateVersion;
pub use envelope::DurableEnvelopeV1;
pub use envelope::DurableInvalidationBody;
pub use envelope::EnvelopeCommon;
pub use envelope::EventId;
pub use envelope::HintEnvelopeV1;
pub use error::NotAcceptedReason;
pub use error::PublishFailure;
pub use error::RemoteNotificationError;
pub use error::TerminalClass;
pub use error::TransientClass;
pub use factory::RemoteNotificationPluginFactory;
pub use sender::RemoteNotificationSender;

use crate::plugins::PluginRegistry;

/// Plugin registration hook, auto-discovered by `build.rs`.
///
/// **Deliberately a no-op.** WP-111 publishes this component with a clean
/// owned-file diff; WP-119 alone integrates common `lore-server` settings,
/// server construction, readiness, and drain during its serialized
/// `SCHEMA-119` window, and registration is part of that integration rather
/// than of this component.
///
/// The one line that window adds, in place of this comment:
///
/// ```ignore
/// registry.register_notification_plugin(Box::new(
///     crate::plugins::remote_notification::RemoteNotificationPluginFactory,
/// ));
/// ```
///
/// Nothing else is needed to select the plugin: `configure_notification` in
/// `server.rs` already routes any `[notification] mode` that is not `"local"`
/// to a registry lookup by that name, hands the factory the `[plugins.<mode>]`
/// table, and spawns each returned receiver into the server's `JoinSet`. So
/// `mode = "remote"` plus `[plugins.remote]` works the moment the line above
/// exists.
pub fn register(_registry: &mut PluginRegistry) {
    // TODO(WP-119 SCHEMA-119): register `RemoteNotificationPluginFactory` here.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handoff tripwire, not a behavioural assertion.
    ///
    /// It pins that this component ships **unregistered**, which is the
    /// `PLUGIN-COMPONENT-READY` contract with WP-119. When `SCHEMA-119` adds
    /// the registration line, this test fails and is meant to: flipping it to
    /// assert the factory IS registered is part of that wiring step.
    #[test]
    fn the_factory_is_not_registered_until_wp_119_wires_it() {
        let mut registry = PluginRegistry::new();
        register(&mut registry);
        assert!(
            !registry
                .list_notification_plugins()
                .iter()
                .any(|name| name == PLUGIN_NAME),
            "registration is WP-119's SCHEMA-119 step; if this now fails, update the assertion \
             rather than removing the registration"
        );
    }

    #[test]
    fn the_registry_name_matches_the_factory_name() {
        use crate::plugins::NotificationPluginFactory;
        assert_eq!(RemoteNotificationPluginFactory.name(), PLUGIN_NAME);
        assert_eq!(PLUGIN_NAME, "remote");
    }
}

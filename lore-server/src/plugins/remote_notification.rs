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
//! WP-111 Phases 1 through 4: the pinned private contract, the bounded
//! best-effort `LIVE_HINT` sender, the durable Publish entry point CR-032's
//! relay calls, the durable invalidation **receiver**, and the mode ladder.
//!
//! | Module | Role |
//! | --- | --- |
//! | [`wire`] | the vendored private protobuf, hand-transcribed, plus its `.proto` of record |
//! | [`envelope`] | the typed envelope, every contract bound, and the Lore-event mapping |
//! | [`config`] | `[plugins.remote]`, parsed and bounded before any I/O |
//! | [`client`] | one Publish attempt, and the closed classification of the answer |
//! | [`sender`] | the bounded queue, the single drain worker, and the retry budget |
//! | [`mode`] | the `local` / `remote` / `local-shadow-remote` ladder |
//! | [`stream`] | the durable stream seam the receiver consumes, and its fake |
//! | [`receiver_store`] | WP-119's Step C membership and checkpoint API, narrowed to six calls |
//! | [`frontier`] | the contiguous acknowledgement frontier and its blockers |
//! | [`apply`] | version comparison, envelope decoding, and the invalidation target |
//! | [`receiver`] | the ordered bootstrap, the steady state, and the readiness facet |
//! | [`factory`] | the `NotificationPluginFactory` for mode `remote` |
//! | [`fake_gateway`] | a request-counting, scriptable, in-process gateway for tests |
//! | [`error`] | the layered error types and the closed failure classification |
//!
//! # What the receiver does not connect to yet
//!
//! The private gateway's frozen schema pins exactly one method, `Publish`.
//! There is no receiver-side subscribe or acknowledge RPC: WP-110 Phases 6-8
//! own "public `Subscribe`, bounded replay, durable receiver" and have not
//! landed. So the receiver runs against [`stream::DurableStreamSource`], which
//! carries the three operations the contract's lifecycle needs. See that
//! module's `BLOCKED(WP-111)` note. When the RPC is pinned, one more
//! implementation of that trait lands and nothing in [`receiver`] changes.
//!
//! Also not here, by design: `local-shadow-remote`'s **composition**. This
//! module supplies its shadow branch through
//! [`factory::create_shadow_branch`]; aggregating that branch with the local
//! sender and the mounted public service is `SCHEMA-119`'s, because it owns
//! the common construction, readiness, and drain files both branches thread
//! through.
//!
//! ## This component is not mutation authority
//!
//! A synchronous plugin Publish is not atomic with cell Postgres, so it can
//! never be the only record of a correctness-sensitive mutation. CR-032 owns the
//! mutation transaction, the durable outbox row, and the relay. This component
//! produces best-effort live hints, and offers the relay a durable publish
//! entry point that classifies but never retries.
//!
//! ## Registration
//!
//! [`register`] wires [`RemoteNotificationPluginFactory`] into the registry, so
//! `[notification] mode = "remote"` resolves. `build.rs` auto-discovers this
//! module and emits the call into the generated `plugins/mod.rs`. WP-111
//! shipped it as a no-op and `SCHEMA-119` added the line, because that window
//! owns the common settings, server-construction, readiness, and drain files
//! this plugin threads through. A test in this module pins the registered
//! state, so a later refactor that drops the line fails there rather than at a
//! cell's boot.
//!
//! Registration alone starts no durable receiver. That needs a
//! [`receiver::ReceiverRuntime`], which only `SCHEMA-119` can build, through
//! [`factory::create_with_receiver`].

pub mod apply;
pub mod client;
pub mod config;
pub mod envelope;
pub mod error;
pub mod factory;
pub mod fake_gateway;
pub mod frontier;
mod metrics;
pub mod mode;
pub mod receiver;
pub mod receiver_store;
pub mod sender;
pub mod stream;
pub mod wire;

pub use apply::DecodedDelivery;
pub use apply::DeliveryViolation;
pub use apply::InvalidationTarget;
pub use apply::NoopInvalidationTarget;
pub use apply::RecordingInvalidationTarget;
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
pub use frontier::AckFrontier;
pub use mode::PluginMode;
pub use receiver::BootstrapFailure;
pub use receiver::DurableReceiver;
pub use receiver::ReceiverReadiness;
pub use receiver::ReceiverReadinessSnapshot;
pub use receiver::ReceiverRuntime;
pub use receiver::ReceiverSession;
pub use receiver::StepOutcome;
pub use receiver_store::InMemoryReceiverStore;
pub use receiver_store::PostgresReceiverStore;
pub use receiver_store::ReceiverStore;
pub use receiver_store::ReceiverStoreError;
pub use sender::RemoteNotificationSender;
pub use stream::CapturedStreamPosition;
pub use stream::DeliveredEnvelope;
pub use stream::DurableStreamSource;
pub use stream::FakeDurableStream;
pub use stream::StreamDelivery;
pub use stream::StreamError;
pub use stream::StreamPlacement;

use crate::plugins::PluginRegistry;

/// Plugin registration hook, auto-discovered by `build.rs`.
///
/// Wired by WP-119's `SCHEMA-119` window, which owns the common `lore-server`
/// settings, server-construction, readiness, and drain files this plugin
/// threads through. WP-111 shipped it unregistered so its own diff stayed
/// clean; this is the one line that handoff reserved.
///
/// Nothing else is needed to select the plugin: `configure_notification` in
/// `server.rs` routes any `[notification] mode` that is not `"local"` to a
/// registry lookup by that name, hands the factory the `[plugins.<mode>]`
/// table, and spawns each returned receiver into the server's `JoinSet`. So
/// `mode = "remote"` plus `[plugins.remote]` now works.
///
/// Registration alone starts no relay. CR-032's durable path additionally
/// requires `[outbox_relay] enabled = true`, and that gate is separate on
/// purpose: a cell may publish best-effort `LIVE_HINT` traffic through this
/// plugin long before it is cut over to required-event mode.
pub fn register(registry: &mut PluginRegistry) {
    registry.register_notification_plugin(Box::new(
        crate::plugins::remote_notification::RemoteNotificationPluginFactory,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use crate::plugins::NotificationPluginFactory;
        assert_eq!(RemoteNotificationPluginFactory.name(), PLUGIN_NAME);
        assert_eq!(PLUGIN_NAME, "remote");
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-027's three notification modes, as one closed type.
//!
//! # The migration ladder
//!
//! | Mode | Public delivery | Durable receiver | Purpose |
//! | --- | --- | --- | --- |
//! | [`PluginMode::Local`] | Lore's mounted local `NotificationService` | none | development and rollback, one loreserver owning every subscription |
//! | [`PluginMode::LocalShadowRemote`] | still local | **none** | observation before endpoint cutover |
//! | [`PluginMode::Remote`] | the gateway's public `Subscribe` | one per replica | the multi-replica target |
//!
//! A migration is therefore config-only in both directions, and each step is a
//! restart. There is no in-process cutover, and none is wanted: a mode change
//! moves which process owns public fan-out, and doing that live would mean two
//! owners for the length of the switch.
//!
//! # Shadow mode is a composition, not a selection
//!
//! `local-shadow-remote` keeps the local sender and the mounted public service
//! and adds a *second*, separately bounded sender that publishes
//! `SHADOW_OBSERVATION` to `.shadow` subjects only. Selecting the ordinary
//! remote plugin in place of the local one does not implement it: that would
//! unmount the public service, which is the one thing shadow mode exists not
//! to do.
//!
//! So this module owns the *decision* and the two rules that fall out of it —
//! [`PluginMode::mounts_local_public_service`] and
//! [`PluginMode::runs_durable_receiver`] — while `SCHEMA-119` owns the
//! server-level construction that acts on them. The plugin honours both rules
//! itself: [`super::factory::create_shadow_branch`] builds the shadow sender
//! and starts no receiver, and that is enforced here rather than remembered
//! there.
//!
//! # Why shadow must never consume
//!
//! A shadow branch exists to be compared against the live one. If it also
//! applied durable invalidations, the comparison would be against a system
//! the shadow had already changed, and a mismatch could no longer be read as
//! evidence about the remote path. Worse, two receivers under one membership
//! identity would each report a frontier for the same generation. The rule is
//! therefore structural: shadow mode returns no receiver at all, and
//! [`PluginMode::runs_durable_receiver`] is the single place that says so.

use super::error::RemoteNotificationError;

/// The `local` mode string.
pub const MODE_LOCAL: &str = "local";
/// The `remote` mode string.
pub const MODE_REMOTE: &str = "remote";
/// The `local-shadow-remote` mode string.
pub const MODE_LOCAL_SHADOW_REMOTE: &str = "local-shadow-remote";

/// The notification mode a cell runs in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PluginMode {
    /// Lore's built-in local sender and mounted public service.
    Local,
    /// The remote plugin only. The default for this plugin, which exists to
    /// serve exactly this mode.
    #[default]
    Remote,
    /// Local public delivery plus a bounded shadow publication.
    LocalShadowRemote,
}

impl PluginMode {
    /// Parse a `[notification] mode` string.
    ///
    /// # Errors
    /// [`RemoteNotificationError::ConfigField`] naming `mode`, for any value
    /// outside the closed set. An unknown mode is rejected rather than
    /// defaulted: defaulting would silently choose who owns public fan-out.
    pub fn parse(mode: &str) -> Result<Self, RemoteNotificationError> {
        match mode {
            MODE_LOCAL => Ok(Self::Local),
            MODE_REMOTE => Ok(Self::Remote),
            MODE_LOCAL_SHADOW_REMOTE => Ok(Self::LocalShadowRemote),
            other => Err(RemoteNotificationError::field(
                "mode",
                format!(
                    "unknown mode `{other}`; the modes are `{MODE_LOCAL}`, `{MODE_REMOTE}`, and \
                     `{MODE_LOCAL_SHADOW_REMOTE}`"
                ),
            )),
        }
    }

    /// The configuration string for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => MODE_LOCAL,
            Self::Remote => MODE_REMOTE,
            Self::LocalShadowRemote => MODE_LOCAL_SHADOW_REMOTE,
        }
    }

    /// True when Lore's own public `NotificationService` stays mounted.
    ///
    /// The contract's fail-closed rule attaches here: enabling remote
    /// multi-replica operation while a local public service is mounted is
    /// rejected at startup, because two owners of public fan-out is exactly
    /// the split-brain the plane exists to remove.
    pub fn mounts_local_public_service(self) -> bool {
        matches!(self, Self::Local | Self::LocalShadowRemote)
    }

    /// True when this mode publishes anything to the private gateway.
    pub fn publishes_remotely(self) -> bool {
        matches!(self, Self::Remote | Self::LocalShadowRemote)
    }

    /// True when this mode's remote publication is observation-only.
    pub fn publishes_shadow_only(self) -> bool {
        matches!(self, Self::LocalShadowRemote)
    }

    /// True when this mode runs a durable invalidation receiver.
    ///
    /// Only `remote` does. Shadow mode must never consume or produce a durable
    /// side effect, and local mode has no durable plane at all.
    pub fn runs_durable_receiver(self) -> bool {
        matches!(self, Self::Remote)
    }

    /// Whether this plugin implements the mode itself.
    ///
    /// `local` is Lore's built-in path and `local-shadow-remote` is a
    /// server-level composition of two branches; this plugin supplies one
    /// branch of the latter through
    /// [`super::factory::create_shadow_branch`] but does not compose it.
    pub fn is_implemented_by_this_plugin(self) -> bool {
        matches!(self, Self::Remote)
    }

    /// Reject a mode that this plugin cannot serve by being selected.
    ///
    /// # Errors
    /// [`RemoteNotificationError::ConfigField`] explaining which component
    /// owns the mode instead. The message names the owner rather than saying
    /// "unsupported", because every rejection here is a correct mode chosen in
    /// the wrong place.
    pub fn require_selectable(self) -> Result<(), RemoteNotificationError> {
        match self {
            Self::Remote => Ok(()),
            Self::Local => Err(RemoteNotificationError::field(
                "mode",
                "`local` is Lore's built-in notification service, selected by \
                 `[notification] mode = \"local\"`. This plugin is never constructed for it",
            )),
            Self::LocalShadowRemote => Err(RemoteNotificationError::field(
                "mode",
                "`local-shadow-remote` is a server-level composition of a local sender and a \
                 separate bounded shadow sender. Selecting this plugin does not implement it; \
                 it is wired in common server construction, not here",
            )),
        }
    }
}

impl std::fmt::Display for PluginMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

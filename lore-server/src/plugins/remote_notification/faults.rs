// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Receiver-side fault injection for the durable invalidation stream.
//!
//! # Why this exists as its own seam
//!
//! `lore-postgres`'s `domain::fragments::failpoints` covers the producer half
//! of the event plane — the outbox claim and accept anchors WP-109's cases D
//! and E kill on. It cannot cover this half. Its `failpoint!` macro is
//! `pub(crate)` to that crate, so a receiver-side anchor is not merely absent,
//! it is inexpressible from `lore-server`.
//!
//! The consequence was recorded in the two-process harness itself: a genuine
//! broker-sequence gap needs the broker to skip one delivery to this consumer
//! while delivering a later one, which a single `JetStream` durable consumer does
//! not do under ordinary operation. WP-119 Phase 10's gap/refetch row stayed
//! OPEN for exactly that reason, and its stand-in case wrote the checkpoint
//! projection directly rather than making a live receiver observe a real gap.
//!
//! This module closes that. It injects at the ONE seam the receiver already
//! has — [`DurableStreamSource`] — so a live `loreserver` keeps its real
//! gateway channel, its real `Consume` stream, its real broker, and its real
//! Postgres projection, and only the delivery sequence reaching
//! [`super::receiver::DurableReceiver::step`] is perturbed.
//!
//! # Why a decorator rather than an anchor macro
//!
//! A failpoint anchor suspends or aborts at a point in a control flow. Every
//! fault this module needs is instead a statement about the *stream of
//! deliveries*: one is missing, one arrives twice, one is corrupt, one read
//! fails. Those are not points in the receiver's code — they are inputs to it,
//! and a decorator expresses them without the receiver knowing it is under
//! test. Nothing in `receiver.rs` changes, so every outcome the harness
//! observes is the shipped classification path.
//!
//! # The default build must not be able to name this
//!
//! The whole decorator lives behind `#[cfg(feature = "failure_generator")]`,
//! the same feature `lore-postgres`'s failpoints use and the same one the
//! two-process runner already builds `loreserver` with. In a default build the
//! inner module is not compiled at all, so a call site that reached for the
//! decorator is a compile error — E0432 on a `use` of it, E0433 on a path —
//! rather than a silently inert call. The
//! `lore-postgres` module records why that distinction is load-bearing; it
//! holds identically here.
//!
//! # The grammar
//!
//! `LORE_RECEIVER_FAULTS` is a comma-separated list of `anchor=trigger`. Every
//! anchor fires **at most once** and is spent afterwards. One-shot rather than
//! sticky is deliberate: a fault that keeps firing proves the receiver notices
//! it, and a fault that stops proves the receiver *recovers* from it, which is
//! the half WP-119 Phase 10 actually needs.
//!
//! *At most* once, not exactly once, and the difference is reachable:
//! `receiver.stream.poison` declines a delivery that is not a
//! `DURABLE_INVALIDATION`, because corrupting one would perturb nothing. A
//! declined anchor is NOT spent, so an `Armed` trigger simply fires on the next
//! eligible delivery — but an `Ordinal` trigger has only that one delivery to
//! fire at, so an ordinal aimed at an ineligible one never fires at all. That
//! is deliberate: firing anyway would spend the shot and write a `.fired`
//! marker for a fault that changed nothing.
//!
//! A trigger is one of two things:
//!
//! - A positive 1-based **ordinal**: fire at exactly that call. Deterministic
//!   in a unit test, where the caller scripts every delivery.
//! - The literal **`next`**: fire at the next opportunity after the harness
//!   arms it at runtime, by creating `<anchor>.arm` under
//!   [`FAULT_DIR_ENV`]. This is the same rendezvous idiom
//!   `LORE_FRAGMENT_FAILPOINT_DIR` uses for a `pause` anchor, and it exists
//!   because a live case cannot know an ordinal in advance: how many
//!   deliveries a receiver has seen by the time a case is ready to inject
//!   depends on how many outbox rows each producing mutation happened to
//!   append. An ordinal guessed from that is a proof that silently becomes
//!   vacuous the day a producer appends one more row.
//!
//!   On firing, the arm file is removed and `<anchor>.fired` is written in its
//!   place. The case waits for that marker before asserting anything, which is
//!   what separates "the receiver handled the fault" from "the fault never
//!   fired and the receiver had nothing to handle".
//!
//! | Anchor | Counts | Effect |
//! |---|---|---|
//! | `receiver.stream.drop` | message deliveries | Swallow that message and answer `CaughtUp`. It is never acknowledged, so the broker redelivers it after `ack_wait`. |
//! | `receiver.stream.duplicate` | message deliveries | Deliver that message, then a byte-identical copy of it on the next read. |
//! | `receiver.stream.poison` | message deliveries | Corrupt that message so `decode_durable_delivery` refuses it. |
//! | `receiver.stream.transient` | `next` calls | Answer `StreamError::Transient` once. |
//! | `receiver.ack.transient` | `ack` calls | Answer `StreamError::Transient` once. |
//!
//! # An armed anchor fires on TRAFFIC, not on wall-clock time
//!
//! Every anchor above is evaluated inside a call the receiver makes, and
//! against a live gateway an idle receiver is BLOCKED inside
//! [`DurableStreamSource::next`] waiting for the `Consume` stream to answer. It
//! does not poll. So arming `receiver.stream.transient` on a quiet cell fires
//! nothing at all until a mutation wakes that call, and a case that arms and
//! then waits reads as a sixty-second timeout that looks like a broken
//! decorator. **Arm, then produce the traffic** — never the other way round.
//! The message-counted anchors (`drop`, `duplicate`, `poison`) and
//! `receiver.ack.transient` have the same property for a simpler reason: there
//! is no message to drop, duplicate, poison, or acknowledge until one arrives.
//!
//! A malformed entry, an unknown anchor, or a non-positive ordinal is warned
//! about and dropped; the rest of the spec still applies and nothing is fatal.
//! That mirrors `failpoints.rs`: a fault harness that panics on its own
//! configuration turns a test-setup mistake into a process crash.
//!
//! # Evidence lines
//!
//! Every firing logs one line beginning [`EVIDENCE_PREFIX`], naming the anchor,
//! the ordinal, and the broker sequence where one applies. A live harness reads
//! them out of the process log to prove the fault actually fired — the
//! distinction between "it held" and "it never ran" that a green exit code
//! cannot make. `LORE_RECEIVER_FAULT_TRACE` adds the same treatment to the
//! invalidation target, so an apply or a refetch on one replica is visible as
//! an artifact rather than inferred from a frontier moving.

use std::sync::Arc;

use super::apply::InvalidationTarget;
// Only the default build's arm of `invalidation_target` names this; under
// `failure_generator` the inner module chooses between it and the tracing one.
#[cfg(not(feature = "failure_generator"))]
use super::apply::NoopInvalidationTarget;
use super::stream::DurableStreamSource;

/// Names the comma-separated `anchor=ordinal` fault spec.
pub const FAULTS_ENV: &str = "LORE_RECEIVER_FAULTS";

/// Set to `1` to trace every invalidation-target call as an evidence line.
pub const FAULT_TRACE_ENV: &str = "LORE_RECEIVER_FAULT_TRACE";

/// The rendezvous directory a `next` trigger arms and reports through.
pub const FAULT_DIR_ENV: &str = "LORE_RECEIVER_FAULT_DIR";

/// Suffix of the file a harness creates to arm a `next` trigger.
pub const ARM_SUFFIX: &str = ".arm";

/// Suffix of the file the decorator writes once that trigger has fired.
///
/// A case waits for this before asserting. Without it a passing assertion
/// cannot tell "the receiver handled the injected fault" from "the fault never
/// fired and there was nothing to handle" — the two outcomes a fault-injection
/// proof exists to separate.
pub const FIRED_SUFFIX: &str = ".fired";

/// The prefix every evidence line this module emits begins with.
///
/// A harness greps for this rather than for prose, so it is a constant and not
/// a format string with the words rearranged per call site.
pub const EVIDENCE_PREFIX: &str = "RECEIVER_FAULT";

/// Logged once at wiring when this build can inject receiver faults.
///
/// The counterpart of `lore-postgres`'s fragment-failpoint banner, and for the
/// same reason: a binary that CAN inject faults must say so, because the one
/// mistake this whole tier is vulnerable to is a harness that set the
/// environment variable against a binary built without the feature and read the
/// resulting silence as a pass.
pub const RECEIVER_FAULTS_COMPILED_BANNER: &str = "this loreserver was built with \
     `--features failure_generator`: the durable receiver honours LORE_RECEIVER_FAULTS and can \
     drop, duplicate, poison, or fail deliveries. NEVER run this build in production.";

/// Wrap the durable stream with the fault decorator, when this build carries
/// `failure_generator` **and** [`FAULTS_ENV`] names at least one usable anchor.
///
/// Returns the source unchanged in every other case, including a default build,
/// so the production wiring is one unconditional call rather than a `cfg` at
/// the call site.
#[must_use]
pub fn wrap_stream(stream: Arc<dyn DurableStreamSource>) -> Arc<dyn DurableStreamSource> {
    #[cfg(feature = "failure_generator")]
    {
        injected::wrap_stream(stream)
    }
    #[cfg(not(feature = "failure_generator"))]
    {
        stream
    }
}

/// The invalidation target a `remote`-mode cell should install.
///
/// [`NoopInvalidationTarget`] ordinarily, because such a cell keeps no
/// repository-scoped derived state this plane feeds. Under `failure_generator`
/// with [`FAULT_TRACE_ENV`] set, a target that logs one evidence line per call
/// instead — still discarding nothing, because there is nothing to discard, but
/// making "replica B applied repository R at ordinal N" an artifact a harness
/// can assert on.
#[must_use]
pub fn invalidation_target() -> Arc<dyn InvalidationTarget> {
    #[cfg(feature = "failure_generator")]
    {
        injected::invalidation_target()
    }
    #[cfg(not(feature = "failure_generator"))]
    {
        Arc::new(NoopInvalidationTarget)
    }
}

/// Whether this build can inject receiver faults at all.
///
/// Read by the wiring to decide whether to log
/// [`RECEIVER_FAULTS_COMPILED_BANNER`].
#[must_use]
pub const fn faults_compiled() -> bool {
    cfg!(feature = "failure_generator")
}

#[cfg(feature = "failure_generator")]
pub use injected::Anchor;
#[cfg(feature = "failure_generator")]
pub use injected::FaultConfig;
#[cfg(feature = "failure_generator")]
pub use injected::FaultyDurableStream;
#[cfg(feature = "failure_generator")]
pub use injected::TracingInvalidationTarget;
#[cfg(feature = "failure_generator")]
pub use injected::Trigger;

#[cfg(feature = "failure_generator")]
mod injected {
    use std::sync::Arc;
    use std::sync::LazyLock;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use async_trait::async_trait;
    use lore_base::types::RepositoryId;
    use tracing::warn;

    use super::super::apply::InvalidationTarget;
    use super::super::apply::NoopInvalidationTarget;
    use super::super::envelope::DurableInvalidationBody;
    use super::super::stream::CaptureRequest;
    use super::super::stream::CapturedStreamPosition;
    use super::super::stream::DeliveredEnvelope;
    use super::super::stream::DurableStreamSource;
    use super::super::stream::StreamDelivery;
    use super::super::stream::StreamError;
    use super::super::wire;
    use super::EVIDENCE_PREFIX;
    use super::FAULT_TRACE_ENV;
    use super::FAULTS_ENV;

    /// The closed set of receiver-side fault anchors.
    ///
    /// Closed, and parsed from a table rather than matched on a free string, so
    /// a typo in a harness's spec is a dropped entry with a warning naming the
    /// legal set — not a fault that silently never fires.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum Anchor {
        /// Swallow one message delivery entirely.
        StreamDrop,
        /// Deliver one message twice.
        StreamDuplicate,
        /// Corrupt one message so the receiver must park it.
        StreamPoison,
        /// Fail one `next` call transiently.
        StreamTransient,
        /// Fail one `ack` call transiently.
        AckTransient,
    }

    impl Anchor {
        /// The spec spelling of every anchor, in one place.
        const TABLE: &'static [(&'static str, Anchor)] = &[
            ("receiver.stream.drop", Anchor::StreamDrop),
            ("receiver.stream.duplicate", Anchor::StreamDuplicate),
            ("receiver.stream.poison", Anchor::StreamPoison),
            ("receiver.stream.transient", Anchor::StreamTransient),
            ("receiver.ack.transient", Anchor::AckTransient),
        ];

        /// Parse one anchor name, or `None` when it is not in the table.
        #[must_use]
        pub fn parse(name: &str) -> Option<Self> {
            Self::TABLE
                .iter()
                .find(|(spelling, _)| *spelling == name)
                .map(|(_, anchor)| *anchor)
        }

        /// The spec spelling, for evidence lines.
        #[must_use]
        pub const fn name(self) -> &'static str {
            match self {
                Self::StreamDrop => "receiver.stream.drop",
                Self::StreamDuplicate => "receiver.stream.duplicate",
                Self::StreamPoison => "receiver.stream.poison",
                Self::StreamTransient => "receiver.stream.transient",
                Self::AckTransient => "receiver.ack.transient",
            }
        }

        /// Every legal spelling, for a warning that has to be actionable.
        fn legal_set() -> String {
            Self::TABLE
                .iter()
                .map(|(spelling, _)| *spelling)
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    /// When an armed anchor fires.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Trigger {
        /// At exactly this 1-based call. Deterministic where the caller
        /// scripts every delivery, which is true in a unit test and false in a
        /// live cell.
        Ordinal(u64),
        /// At the next opportunity after the harness creates
        /// `<anchor>.arm` under [`super::FAULT_DIR_ENV`].
        Armed,
    }

    /// One parsed fault spec: at most one trigger per anchor.
    ///
    /// At most one because a second entry for the same anchor would have to
    /// mean either "also fire there" or "replace"; neither reading is obviously
    /// right, so the parser refuses the ambiguity and keeps the first.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct FaultConfig {
        /// When to swallow one delivery.
        pub stream_drop: Option<Trigger>,
        /// When to deliver one message a second time.
        pub stream_duplicate: Option<Trigger>,
        /// When to corrupt one delivery.
        pub stream_poison: Option<Trigger>,
        /// When to fail one `next` call.
        pub stream_transient: Option<Trigger>,
        /// When to fail one `ack` call.
        pub ack_transient: Option<Trigger>,
    }

    impl FaultConfig {
        /// Parse a spec string. Never fails: every unusable entry is warned
        /// about and dropped.
        #[must_use]
        pub fn parse(spec: &str) -> Self {
            let mut config = Self::default();
            for entry in spec.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let Some((name, ordinal)) = entry.split_once('=') else {
                    warn!(
                        entry,
                        legal = %Anchor::legal_set(),
                        "{FAULTS_ENV} entry is not `anchor=ordinal`; dropping it"
                    );
                    continue;
                };
                let name = name.trim();
                let Some(anchor) = Anchor::parse(name) else {
                    warn!(
                        entry,
                        legal = %Anchor::legal_set(),
                        "{FAULTS_ENV} names an anchor that does not exist; dropping it"
                    );
                    continue;
                };
                let trigger = match Trigger::parse(ordinal.trim()) {
                    Some(trigger) => trigger,
                    None => {
                        warn!(
                            entry,
                            "{FAULTS_ENV} triggers are `next` or a positive 1-based ordinal; \
                             dropping this entry"
                        );
                        continue;
                    }
                };
                if trigger == Trigger::Armed && std::env::var_os(super::FAULT_DIR_ENV).is_none() {
                    warn!(
                        entry,
                        "{FAULTS_ENV} uses the `next` trigger but {} is unset, so nothing could \
                         ever arm it; dropping this entry",
                        super::FAULT_DIR_ENV
                    );
                    continue;
                }
                let slot = config.slot_mut(anchor);
                if let Some(existing) = *slot {
                    warn!(
                        anchor = anchor.name(),
                        ?existing,
                        ignored = ?trigger,
                        "{FAULTS_ENV} names one anchor twice; keeping the first trigger"
                    );
                    continue;
                }
                *slot = Some(trigger);
            }
            config.warn_about_shadowing();
            config
        }

        /// Warn when one anchor's effect would hide another's.
        ///
        /// `drop` returns before `poison` and `duplicate` are considered, so a
        /// spec arming two of them at the SAME ordinal silently never fires the
        /// later one — and because an unfired anchor writes no `.fired` marker,
        /// a harness waiting on it sees a timeout rather than a configuration
        /// mistake. Refusing outright would be worse: the anchors are
        /// independently useful at different ordinals, and a `next` trigger has
        /// no ordinal to compare at all.
        fn warn_about_shadowing(&self) {
            let Some(Trigger::Ordinal(dropped)) = self.stream_drop else {
                return;
            };
            for (anchor, trigger) in [
                (Anchor::StreamPoison, self.stream_poison),
                (Anchor::StreamDuplicate, self.stream_duplicate),
            ] {
                if trigger == Some(Trigger::Ordinal(dropped)) {
                    warn!(
                        anchor = anchor.name(),
                        ordinal = dropped,
                        "{FAULTS_ENV} arms {} at the same delivery as {}; the delivery is \
                         swallowed first, so {} will never fire",
                        anchor.name(),
                        Anchor::StreamDrop.name(),
                        anchor.name()
                    );
                }
            }
        }

        fn slot_mut(&mut self, anchor: Anchor) -> &mut Option<Trigger> {
            match anchor {
                Anchor::StreamDrop => &mut self.stream_drop,
                Anchor::StreamDuplicate => &mut self.stream_duplicate,
                Anchor::StreamPoison => &mut self.stream_poison,
                Anchor::StreamTransient => &mut self.stream_transient,
                Anchor::AckTransient => &mut self.ack_transient,
            }
        }

        /// True when no anchor is armed, so wrapping would only add a layer.
        #[must_use]
        pub const fn is_empty(&self) -> bool {
            self.stream_drop.is_none()
                && self.stream_duplicate.is_none()
                && self.stream_poison.is_none()
                && self.stream_transient.is_none()
                && self.ack_transient.is_none()
        }

        /// The armed anchors, for the evidence line logged at wiring.
        fn armed(&self) -> String {
            let mut armed = Vec::new();
            for (anchor, trigger) in [
                (Anchor::StreamDrop, self.stream_drop),
                (Anchor::StreamDuplicate, self.stream_duplicate),
                (Anchor::StreamPoison, self.stream_poison),
                (Anchor::StreamTransient, self.stream_transient),
                (Anchor::AckTransient, self.ack_transient),
            ] {
                if let Some(trigger) = trigger {
                    armed.push(format!("{}={}", anchor.name(), trigger.spelling()));
                }
            }
            armed.join(",")
        }
    }

    impl Trigger {
        /// The spec spelling of `next`.
        pub const NEXT: &'static str = "next";

        /// Parse one trigger, or `None` when it is neither `next` nor a
        /// positive 1-based ordinal.
        #[must_use]
        pub fn parse(value: &str) -> Option<Self> {
            if value.eq_ignore_ascii_case(Self::NEXT) {
                return Some(Self::Armed);
            }
            match value.parse::<u64>() {
                Ok(ordinal) if ordinal > 0 => Some(Self::Ordinal(ordinal)),
                _ => None,
            }
        }

        /// How this trigger is written in a spec.
        #[must_use]
        pub fn spelling(self) -> String {
            match self {
                Self::Ordinal(ordinal) => ordinal.to_string(),
                Self::Armed => Self::NEXT.to_owned(),
            }
        }
    }

    /// Read once per process, like `LORE_FRAGMENT_FAILPOINTS`.
    ///
    /// Once rather than per call because the receiver reads its stream from one
    /// task for the life of the generation, and a spec that could change under
    /// it would make an observed outcome unattributable to a configuration.
    static CONFIG: LazyLock<FaultConfig> = LazyLock::new(|| {
        let spec = std::env::var(FAULTS_ENV).unwrap_or_default();
        let config = FaultConfig::parse(&spec);
        if !config.is_empty() {
            // `armed=` rather than `anchor=`, deliberately: a harness counting
            // firings greps `RECEIVER_FAULT anchor=`, and a startup banner
            // naming the same anchors under that key would be counted as a
            // firing that never happened.
            warn!("{EVIDENCE_PREFIX} armed=<{}>", config.armed());
        }
        config
    });

    /// Wrap only when something is armed.
    pub(super) fn wrap_stream(
        stream: Arc<dyn DurableStreamSource>,
    ) -> Arc<dyn DurableStreamSource> {
        if CONFIG.is_empty() {
            return stream;
        }
        Arc::new(FaultyDurableStream::new(stream, *CONFIG))
    }

    pub(super) fn invalidation_target() -> Arc<dyn InvalidationTarget> {
        match std::env::var(FAULT_TRACE_ENV) {
            Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => {
                Arc::new(TracingInvalidationTarget)
            }
            _ => Arc::new(NoopInvalidationTarget),
        }
    }

    /// A [`DurableStreamSource`] that perturbs the delivery sequence.
    ///
    /// Transparent except at the armed ordinals. It holds no generation state
    /// of its own beyond the counters and the one buffered duplicate, because
    /// the receiver owns position and this owns only what it did to the stream.
    pub struct FaultyDurableStream {
        inner: Arc<dyn DurableStreamSource>,
        config: FaultConfig,
        /// Message deliveries observed from the inner source.
        deliveries: AtomicU64,
        /// `next` calls made against this decorator.
        next_calls: AtomicU64,
        /// `ack` calls made against this decorator.
        ack_calls: AtomicU64,
        /// The copy a `duplicate` anchor owes the next read.
        pending_duplicate: Mutex<Option<DeliveredEnvelope>>,
        /// Anchors whose one shot has been spent. Consulted for BOTH trigger
        /// kinds so the one-shot rule has one implementation rather than one
        /// per trigger: an ordinal is naturally one-shot because the counter
        /// only passes it once, and an arm file is not.
        spent: Mutex<Vec<Anchor>>,
        /// The rendezvous directory, when one is configured.
        fault_dir: Option<std::path::PathBuf>,
    }

    impl std::fmt::Debug for FaultyDurableStream {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FaultyDurableStream")
                .field("config", &self.config)
                .field("deliveries", &self.deliveries.load(Ordering::Relaxed))
                .finish_non_exhaustive()
        }
    }

    impl FaultyDurableStream {
        /// Decorate `inner` with `config`.
        #[must_use]
        pub fn new(inner: Arc<dyn DurableStreamSource>, config: FaultConfig) -> Self {
            Self::with_dir(
                inner,
                config,
                std::env::var_os(super::FAULT_DIR_ENV).map(std::path::PathBuf::from),
            )
        }

        /// Decorate `inner`, naming the rendezvous directory explicitly.
        ///
        /// A test uses this rather than the environment so concurrent cases
        /// cannot see each other's arm files, and so a case that never uses a
        /// `next` trigger needs no directory at all.
        #[must_use]
        pub fn with_dir(
            inner: Arc<dyn DurableStreamSource>,
            config: FaultConfig,
            fault_dir: Option<std::path::PathBuf>,
        ) -> Self {
            Self {
                inner,
                config,
                deliveries: AtomicU64::new(0),
                next_calls: AtomicU64::new(0),
                ack_calls: AtomicU64::new(0),
                pending_duplicate: Mutex::new(None),
                spent: Mutex::new(Vec::new()),
                fault_dir,
            }
        }

        /// How many message deliveries this decorator has seen. Diagnostics.
        #[must_use]
        pub fn deliveries_seen(&self) -> u64 {
            self.deliveries.load(Ordering::Relaxed)
        }

        /// Whether `anchor` fires on this call, spending its one shot if so.
        ///
        /// One function for both trigger kinds, and the spend happens here
        /// rather than at the call site, so no anchor can grow a second
        /// firing by a caller forgetting to record the first.
        ///
        /// Only for anchors whose effect cannot fail. `receiver.stream.poison`
        /// uses [`Self::is_due`] plus [`Self::commit`] instead, because its
        /// effect CAN be a no-op and spending a shot on a no-op would leave a
        /// `.fired` marker a harness reads as a real firing.
        fn fires(&self, anchor: Anchor, trigger: Option<Trigger>, ordinal: u64) -> bool {
            self.is_due(anchor, trigger, ordinal) && self.commit(anchor)
        }

        /// Whether `anchor` is due on this call, WITHOUT spending it.
        ///
        /// Checks `spent` as well as the trigger: an `Armed` trigger's arm file
        /// is removed by [`Self::commit`], but a caller that declined to commit
        /// leaves it in place, and this must not then report due forever.
        fn is_due(&self, anchor: Anchor, trigger: Option<Trigger>, ordinal: u64) -> bool {
            let Some(trigger) = trigger else {
                return false;
            };
            if self.already_spent(anchor) {
                return false;
            }
            match trigger {
                Trigger::Ordinal(at) => at == ordinal,
                Trigger::Armed => self.arm_file(anchor).is_some_and(|path| path.exists()),
            }
        }

        /// Spend `anchor`'s one shot, WITHOUT leaving the `.fired` marker.
        ///
        /// Returns false when it was already spent, so the check and the spend
        /// are one atomic decision under the lock rather than two. This is the
        /// only place `spent` grows, and every effect must be guarded by a
        /// `true` from here — a fault that lands outside a successful spend can
        /// land more than once, and a fault that lands after a `false` lands
        /// without the marker that is supposed to witness it.
        ///
        /// Split from the marker for `receiver.stream.duplicate`, whose effect
        /// happens one call LATER than its decision: see the replay branch of
        /// [`DurableStreamSource::next`].
        fn spend(&self, anchor: Anchor) -> bool {
            let mut spent = match self.spent.lock() {
                Ok(spent) => spent,
                Err(poisoned) => poisoned.into_inner(),
            };
            if spent.contains(&anchor) {
                return false;
            }
            spent.push(anchor);
            true
        }

        /// Spend `anchor`'s one shot and leave the `.fired` marker.
        fn commit(&self, anchor: Anchor) -> bool {
            if !self.spend(anchor) {
                return false;
            }
            self.mark_fired(anchor);
            true
        }

        fn already_spent(&self, anchor: Anchor) -> bool {
            match self.spent.lock() {
                Ok(spent) => spent.contains(&anchor),
                Err(poisoned) => poisoned.into_inner().contains(&anchor),
            }
        }

        /// The one evidence line a firing writes.
        ///
        /// One function rather than a `warn!` per call site, and a plain
        /// message rather than `tracing` fields, because a harness greps this
        /// out of a process log: every firing must render identically, and
        /// `RECEIVER_FAULT anchor=` must match a FIRING and nothing else — not
        /// the armed banner, which names the same anchors at startup.
        fn log_firing(anchor: Anchor, ordinal: u64, sequence: Option<i64>) {
            match sequence {
                Some(sequence) => warn!(
                    "{EVIDENCE_PREFIX} anchor={} ordinal={ordinal} broker_sequence={sequence}",
                    anchor.name()
                ),
                None => warn!(
                    "{EVIDENCE_PREFIX} anchor={} ordinal={ordinal}",
                    anchor.name()
                ),
            }
        }

        /// A blocking `exists()` inside an async call, deliberately.
        ///
        /// One `stat` per `next`/`ack`, only in a `failure_generator` build with
        /// an anchor armed, against a path in the harness's own temporary
        /// directory. Making it async would mean an executor round trip per
        /// read on a path that is almost always absent, for a check that exists
        /// only to let a test harness pick a moment.
        fn arm_file(&self, anchor: Anchor) -> Option<std::path::PathBuf> {
            self.fault_dir
                .as_ref()
                .map(|dir| dir.join(format!("{}{}", anchor.name(), super::ARM_SUFFIX)))
        }

        /// Consume the arm file and leave the `.fired` marker a case waits on.
        ///
        /// Both halves are best effort: a fault harness that panicked on its
        /// own bookkeeping would turn a filesystem hiccup into a receiver
        /// retirement, and the evidence line in the log is the primary record
        /// either way.
        fn mark_fired(&self, anchor: Anchor) {
            let Some(dir) = self.fault_dir.as_ref() else {
                return;
            };
            if let Some(arm) = self.arm_file(anchor) {
                let _ = std::fs::remove_file(arm);
            }
            let fired = dir.join(format!("{}{}", anchor.name(), super::FIRED_SUFFIX));
            let _ = std::fs::write(fired, anchor.name());
        }

        /// Take the copy a previous `duplicate` firing left behind.
        fn take_pending(&self) -> Option<DeliveredEnvelope> {
            match self.pending_duplicate.lock() {
                Ok(mut pending) => pending.take(),
                // A poisoned mutex here means a previous read panicked. The
                // decorator is a test aid, so degrading to "no duplicate" is
                // strictly better than propagating a panic into the receiver's
                // own loop and turning a fault-injection bug into a retirement.
                Err(poisoned) => poisoned.into_inner().take(),
            }
        }

        /// Drop any stashed replay copy, because the generation it belonged to
        /// has ended.
        fn discard_pending(&self) {
            if let Some(delivered) = self.take_pending() {
                warn!(
                    "{EVIDENCE_PREFIX} discarded anchor={} broker_sequence={} \
                     reason=generation_recaptured",
                    Anchor::StreamDuplicate.name(),
                    delivered.broker_sequence
                );
            }
        }

        fn stash_pending(&self, delivered: DeliveredEnvelope) {
            match self.pending_duplicate.lock() {
                Ok(mut pending) => *pending = Some(delivered),
                Err(poisoned) => *poisoned.into_inner() = Some(delivered),
            }
        }
    }

    /// Corrupt one envelope so `decode_durable_delivery` must park it.
    ///
    /// Pushes `payload_version` out of every cell's configured range rather
    /// than mangling bytes: the class the receiver parks under is then
    /// `UNSUPPORTED_SCHEMA` deterministically, on any build, without the
    /// harness having to know this module's validation order. A corruption
    /// whose poison class depended on which check happened to fire first would
    /// make the assertion fragile against an unrelated reordering.
    /// Whether corrupting this envelope would actually perturb anything.
    ///
    /// A PURE predicate, deliberately separate from [`poison`], so eligibility
    /// can be decided BEFORE the anchor is spent and the mutation can then
    /// happen only on a successful spend. The first shape of this fix mutated
    /// first and spent second, which let a concurrent reader corrupt several
    /// deliveries while only one of them got the `.fired` marker — the same
    /// "a fault landed with nothing witnessing it" defect in mirror image.
    ///
    /// An envelope that is not a `DURABLE_INVALIDATION` has no
    /// `payload_version` to push out of range, and the receiver already parks
    /// it as an unexpected delivery class on its own.
    fn poison_would_take(envelope: &wire::PrivateEnvelopeV1) -> bool {
        use wire::private_envelope_v1::Body;
        matches!(envelope.body, Some(Body::DurableInvalidation(_)))
    }

    /// Corrupt one envelope so `decode_durable_delivery` must park it.
    ///
    /// Infallible, and only ever called after [`poison_would_take`] said yes
    /// and the anchor's shot was spent.
    fn poison(envelope: &mut wire::PrivateEnvelopeV1) {
        use wire::private_envelope_v1::Body;
        if let Some(Body::DurableInvalidation(body)) = envelope.body.as_mut() {
            body.payload_version = u32::MAX;
        }
    }

    #[async_trait]
    impl DurableStreamSource for FaultyDurableStream {
        async fn capture(
            &self,
            request: &CaptureRequest,
        ) -> Result<CapturedStreamPosition, StreamError> {
            // Capture is never perturbed. The contract's capture-time races are
            // already covered by the stream's own scripted failures and by the
            // live gateway's refusals; injecting here would only duplicate them
            // while making the position this generation is pinned to ambiguous.
            //
            // It does, however, END a generation. A copy stashed for replay
            // belongs to the generation that saw it, and serving it as the first
            // delivery of the NEXT generation would hand a freshly baselined
            // receiver a message at a broker sequence its new capture never
            // covered — a fault the real stream cannot produce, which is the one
            // thing this decorator must never do. Drop it.
            self.discard_pending();
            self.inner.capture(request).await
        }

        async fn next(&self) -> Result<StreamDelivery, StreamError> {
            let call = self.next_calls.fetch_add(1, Ordering::Relaxed) + 1;

            if self.fires(Anchor::StreamTransient, self.config.stream_transient, call) {
                Self::log_firing(Anchor::StreamTransient, call, None);
                return Err(StreamError::Transient(
                    "injected by LORE_RECEIVER_FAULTS".to_string(),
                ));
            }

            // A pending duplicate is served before the inner source is read, so
            // the copy lands on the very next delivery rather than an arbitrary
            // number of reads later. It deliberately does NOT advance the
            // delivery counter: it is the same delivery, seen twice.
            if let Some(delivered) = self.take_pending() {
                // The marker goes here, where the effect actually lands, not at
                // the stash. A case waits on `.fired` before asserting, so it
                // must not be able to see the marker for a duplicate that was
                // stashed and then discarded.
                self.mark_fired(Anchor::StreamDuplicate);
                warn!(
                    "{EVIDENCE_PREFIX} replay anchor={} broker_sequence={}",
                    Anchor::StreamDuplicate.name(),
                    delivered.broker_sequence
                );
                return Ok(StreamDelivery::Message(Box::new(delivered)));
            }

            let delivery = self.inner.next().await?;
            let StreamDelivery::Message(delivered) = delivery else {
                return Ok(delivery);
            };
            let mut delivered = *delivered;
            let ordinal = self.deliveries.fetch_add(1, Ordering::Relaxed) + 1;
            let sequence = delivered.broker_sequence;

            if self.fires(Anchor::StreamDrop, self.config.stream_drop, ordinal) {
                Self::log_firing(Anchor::StreamDrop, ordinal, Some(sequence));
                // `CaughtUp` rather than an error: the receiver must see a
                // healthy stream that simply never carried this sequence, which
                // is what a lost delivery looks like from inside.
                return Ok(StreamDelivery::CaughtUp);
            }

            // Eligibility, then the spend, then the effect — in that order, so
            // the corruption happens if and only if this call is the one that
            // spent the anchor's single shot. See `poison_would_take`.
            if self.is_due(Anchor::StreamPoison, self.config.stream_poison, ordinal) {
                if !poison_would_take(&delivered.envelope) {
                    // Declined, not fired: the anchor stays armed and no
                    // `.fired` marker appears, so a case waiting on the marker
                    // keeps waiting rather than asserting against an envelope
                    // nothing touched.
                    warn!(
                        "{EVIDENCE_PREFIX} skipped anchor={} ordinal={ordinal} \
                         broker_sequence={sequence} reason=not_a_durable_invalidation",
                        Anchor::StreamPoison.name()
                    );
                } else if self.commit(Anchor::StreamPoison) {
                    poison(&mut delivered.envelope);
                    Self::log_firing(Anchor::StreamPoison, ordinal, Some(sequence));
                }
            }

            // `spend`, not `commit`: the duplicate's EFFECT is the replay on the
            // next call, so the `.fired` marker is written there and not here.
            // Marking at stash time let a case wait on `.fired`, assert "applied
            // exactly once", and pass having never been delivered a duplicate at
            // all — for instance when `capture` discarded the stashed copy in
            // between. The spend still happens here, so the anchor cannot arm
            // twice while a copy is pending.
            if self.is_due(
                Anchor::StreamDuplicate,
                self.config.stream_duplicate,
                ordinal,
            ) && self.spend(Anchor::StreamDuplicate)
            {
                Self::log_firing(Anchor::StreamDuplicate, ordinal, Some(sequence));
                self.stash_pending(delivered.clone());
            }

            Ok(StreamDelivery::Message(Box::new(delivered)))
        }

        async fn ack(&self, broker_sequence: i64) -> Result<(), StreamError> {
            let call = self.ack_calls.fetch_add(1, Ordering::Relaxed) + 1;
            if self.fires(Anchor::AckTransient, self.config.ack_transient, call) {
                Self::log_firing(Anchor::AckTransient, call, Some(broker_sequence));
                return Err(StreamError::Transient(
                    "injected by LORE_RECEIVER_FAULTS".to_string(),
                ));
            }
            self.inner.ack(broker_sequence).await
        }
    }

    /// An invalidation target that logs what it was told, and discards nothing.
    ///
    /// A `remote`-mode cell keeps no repository-scoped derived state, so there
    /// is nothing for a target to evict and
    /// [`NoopInvalidationTarget`] is the correct production choice. This is not
    /// a different behaviour, only a visible one: without it, "replica B
    /// consumed replica A's mutation" can only be inferred from a frontier
    /// advancing, which does not name the repository or the ordinal.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct TracingInvalidationTarget;

    #[async_trait]
    impl InvalidationTarget for TracingInvalidationTarget {
        async fn baseline(&self) {
            warn!("{EVIDENCE_PREFIX} target=baseline");
        }

        async fn refetch_repository(&self, repository: RepositoryId) {
            warn!(
                "{EVIDENCE_PREFIX} target=refetch repository={}",
                hex(repository)
            );
        }

        async fn apply_invalidation(
            &self,
            repository: RepositoryId,
            body: &DurableInvalidationBody,
        ) {
            warn!(
                "{EVIDENCE_PREFIX} target=apply repository={} event_kind={} aggregate_kind={} \
                 aggregate_identity={} ordinal={}",
                hex(repository),
                body.event_kind,
                body.aggregate_kind,
                body.aggregate_identity,
                body.aggregate_version.ordinal
            );
        }
    }

    /// Lowercase hex of a repository id, the spelling the harness greps for.
    fn hex(repository: RepositoryId) -> String {
        repository
            .data()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

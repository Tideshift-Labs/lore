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
//! while delivering a later one, which a single JetStream durable consumer does
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
//! anchor fires **exactly once** and is spent afterwards. One-shot rather than
//! sticky is deliberate: a fault that keeps firing proves the receiver notices
//! it, and a fault that stops proves the receiver *recovers* from it, which is
//! the half WP-119 Phase 10 actually needs.
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

        /// Spend `anchor`'s one shot and leave the `.fired` marker.
        ///
        /// Returns false when it was already spent, so the check and the spend
        /// are one atomic decision under the lock rather than two.
        fn commit(&self, anchor: Anchor) -> bool {
            {
                let mut spent = match self.spent.lock() {
                    Ok(spent) => spent,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if spent.contains(&anchor) {
                    return false;
                }
                spent.push(anchor);
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
    /// Returns whether the envelope was actually corrupted.
    ///
    /// The bool is load-bearing, not a convenience. An envelope that is not a
    /// `DURABLE_INVALIDATION` has no `payload_version` to push out of range,
    /// and the receiver already parks it as an unexpected delivery class on its
    /// own — so this would perturb nothing. Reporting that lets the caller
    /// decline to spend the anchor, because a firing that is logged, spends its
    /// one shot, and writes a `.fired` marker while changing nothing is exactly
    /// the "it held / it never ran" confusion the marker exists to prevent.
    fn poison(envelope: &mut wire::PrivateEnvelopeV1) -> bool {
        use wire::private_envelope_v1::Body;
        match envelope.body.as_mut() {
            Some(Body::DurableInvalidation(body)) => {
                body.payload_version = u32::MAX;
                true
            }
            _ => false,
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

            // Two-phase, unlike every other anchor: corrupt FIRST and spend the
            // shot only if the corruption took. See `poison`'s own doc comment.
            if self.is_due(Anchor::StreamPoison, self.config.stream_poison, ordinal) {
                if poison(&mut delivered.envelope) {
                    if self.commit(Anchor::StreamPoison) {
                        Self::log_firing(Anchor::StreamPoison, ordinal, Some(sequence));
                    }
                } else {
                    warn!(
                        "{EVIDENCE_PREFIX} skipped anchor={} ordinal={ordinal} \
                         broker_sequence={sequence} reason=not_a_durable_invalidation",
                        Anchor::StreamPoison.name()
                    );
                }
            }

            if self.fires(
                Anchor::StreamDuplicate,
                self.config.stream_duplicate,
                ordinal,
            ) {
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

/// Co-located unit tests: the spec grammar, and the decorator's own contract
/// against [`super::stream::FakeDurableStream`] directly. Receiver-level
/// proof (a real `DurableReceiver` disposing each outcome class) lives in
/// `lore-server/tests/remote_notification_receiver_faults.rs`, a separate
/// crate, because that tier needs [`FakeDurableStream`] to be `pub` rather
/// than `#[cfg(test)]`.
///
/// `#[cfg(all(test, feature = "failure_generator"))]`, not just
/// `#[cfg(test)]`: this module sits OUTSIDE [`injected`] at the top level of
/// `faults.rs`, which is compiled in every build. A plain `#[cfg(test)]`
/// would therefore try to compile these tests -- which name `Anchor`,
/// `FaultConfig`, `FaultyDurableStream`, `Trigger` -- into `cargo test
/// -p lore-server`'s DEFAULT build too, where none of those types exist. That
/// is exactly the failure the module doc above spends a whole section on
/// preventing for production call sites; a test module gets no exemption.
#[cfg(all(test, feature = "failure_generator"))]
mod tests {
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use bytes::Bytes;
    use lore_base::types::RepositoryId;

    use super::super::envelope::AggregateVersion;
    use super::super::envelope::DurableEnvelopeV1;
    use super::super::envelope::DurableInvalidationBody;
    use super::super::envelope::EnvelopeCommon;
    use super::super::envelope::EventId;
    use super::super::stream::CaptureRequest;
    use super::super::stream::DurableStreamSource;
    use super::super::stream::FakeDurableStream;
    use super::super::stream::StreamDelivery;
    use super::super::stream::StreamError;
    use super::super::stream::StreamPlacement;
    use super::super::wire;
    use super::*;

    const CELL: &str = "sfo3-cell-a";
    const IDENTITY: &str = "loreserver-sfo3-cell-a-2";

    fn repository(byte: u8) -> RepositoryId {
        let mut id = RepositoryId::default();
        *id.data_mut() = [byte; 16];
        id
    }

    /// One valid durable envelope for `repository_byte`, at `ordinal`. Every
    /// call shares the same event/aggregate identity, so a run of these is
    /// always one `AggregateKey`.
    fn durable(repository_byte: u8, ordinal: u64) -> wire::PrivateEnvelopeV1 {
        DurableEnvelopeV1 {
            common: EnvelopeCommon {
                cell_id: CELL.to_string(),
                placement_epoch: 12,
                event_id: EventId::from_bytes([ordinal as u8; 16]),
                repository: repository(repository_byte),
                producer_instance_id: IDENTITY.to_string(),
                produced_at: UNIX_EPOCH,
            },
            body: DurableInvalidationBody {
                payload_version: 1,
                idempotency_key: [7; 32],
                event_kind: "branch.pushed".to_string(),
                repository_generation: 1,
                aggregate_kind: "branch".to_string(),
                aggregate_identity: "0123456789abcdef".to_string(),
                aggregate_version: AggregateVersion {
                    ordinal,
                    identity: None,
                },
                payload: Bytes::new(),
                committed_at: UNIX_EPOCH,
                actor: None,
            },
        }
        .encode(1..=1)
        .expect("the test envelope is inside every contract bound")
    }

    /// A minimal envelope with no body, for tests that only care which
    /// delivery a fault landed on (by broker sequence), not its content --
    /// mirrors `stream.rs`'s own `envelope()` test helper.
    fn bare_envelope() -> wire::PrivateEnvelopeV1 {
        wire::PrivateEnvelopeV1 {
            transport_version: wire::TRANSPORT_VERSION,
            ..Default::default()
        }
    }

    /// A fresh, unscripted fake, captured at `start_sequence`.
    fn fake(start_sequence: i64) -> FakeDurableStream {
        FakeDurableStream::at(
            StreamPlacement::new("DURABLE-sfo3-cell-a", 8),
            start_sequence,
        )
    }

    // -----------------------------------------------------------------
    // Spec parsing (`FaultConfig::parse`, `Anchor::parse`)
    // -----------------------------------------------------------------

    #[test]
    fn every_anchor_name_parses_to_its_own_variant() {
        for (name, anchor) in [
            ("receiver.stream.drop", Anchor::StreamDrop),
            ("receiver.stream.duplicate", Anchor::StreamDuplicate),
            ("receiver.stream.poison", Anchor::StreamPoison),
            ("receiver.stream.transient", Anchor::StreamTransient),
            ("receiver.ack.transient", Anchor::AckTransient),
        ] {
            assert_eq!(Anchor::parse(name), Some(anchor), "{name} must parse");
        }
        assert_eq!(Anchor::parse("receiver.stream.bogus"), None);
        assert_eq!(Anchor::parse(""), None);
    }

    #[test]
    fn the_parser_accepts_every_anchor_armed_at_once() {
        let config = FaultConfig::parse(
            "receiver.stream.drop=1,receiver.stream.duplicate=2,receiver.stream.poison=3,\
             receiver.stream.transient=4,receiver.ack.transient=5",
        );
        assert_eq!(config.stream_drop, Some(Trigger::Ordinal(1)));
        assert_eq!(config.stream_duplicate, Some(Trigger::Ordinal(2)));
        assert_eq!(config.stream_poison, Some(Trigger::Ordinal(3)));
        assert_eq!(config.stream_transient, Some(Trigger::Ordinal(4)));
        assert_eq!(config.ack_transient, Some(Trigger::Ordinal(5)));
        assert!(!config.is_empty());
    }

    #[test]
    fn an_unknown_anchor_is_dropped_and_the_rest_of_the_spec_still_applies() {
        let config = FaultConfig::parse("bogus.anchor=1,receiver.stream.drop=2");
        assert_eq!(config.stream_drop, Some(Trigger::Ordinal(2)));
        assert_eq!(config.stream_duplicate, None);
    }

    #[test]
    fn a_zero_ordinal_is_dropped() {
        assert!(FaultConfig::parse("receiver.stream.drop=0").is_empty());
    }

    #[test]
    fn a_non_numeric_ordinal_is_dropped() {
        assert!(FaultConfig::parse("receiver.stream.drop=x").is_empty());
    }

    #[test]
    fn an_entry_with_no_equals_sign_is_dropped() {
        assert!(FaultConfig::parse("receiver.stream.drop").is_empty());
    }

    #[test]
    fn empty_entries_and_stray_separators_are_skipped_not_fatal() {
        assert!(FaultConfig::parse("").is_empty());
        assert!(FaultConfig::parse(",, ,").is_empty());
        let config = FaultConfig::parse("  ,receiver.stream.drop=1,  ,");
        assert_eq!(config.stream_drop, Some(Trigger::Ordinal(1)));
    }

    #[test]
    fn whitespace_around_names_and_ordinals_is_trimmed() {
        let config = FaultConfig::parse(" receiver.stream.drop = 3 , receiver.ack.transient = 7 ");
        assert_eq!(config.stream_drop, Some(Trigger::Ordinal(3)));
        assert_eq!(config.ack_transient, Some(Trigger::Ordinal(7)));
    }

    /// A second entry for an already-armed anchor is dropped, keeping the
    /// first trigger.
    #[test]
    fn a_duplicated_anchor_keeps_the_first_trigger_and_warns() {
        let config = FaultConfig::parse("receiver.stream.drop=2,receiver.stream.drop=9");
        assert_eq!(config.stream_drop, Some(Trigger::Ordinal(2)));
    }

    #[test]
    fn an_empty_or_absent_spec_wraps_nothing() {
        assert!(FaultConfig::parse("").is_empty());
        assert!(FaultConfig::default().is_empty());
    }

    // -----------------------------------------------------------------
    // The `Trigger` grammar itself
    // -----------------------------------------------------------------

    #[test]
    fn trigger_next_parses_case_insensitively_and_every_spelling_round_trips() {
        assert_eq!(Trigger::parse("next"), Some(Trigger::Armed));
        assert_eq!(Trigger::parse("NEXT"), Some(Trigger::Armed));
        assert_eq!(Trigger::parse("NeXt"), Some(Trigger::Armed));
        assert_eq!(Trigger::parse("3"), Some(Trigger::Ordinal(3)));
        assert_eq!(Trigger::parse("0"), None, "an ordinal must be positive");
        assert_eq!(Trigger::parse("x"), None);
        assert_eq!(Trigger::parse(""), None);
        assert_eq!(Trigger::Armed.spelling(), "next");
        assert_eq!(Trigger::Ordinal(7).spelling(), "7");
    }

    /// A `next` trigger with no configured rendezvous directory could never
    /// fire, so the parser drops it at parse time rather than arming
    /// something inert.
    ///
    /// A reviewer flagged the previous version of this test: it read the REAL
    /// process environment directly (`std::env::var_os(FAULT_DIR_ENV)`)
    /// outside of any `temp_env` lock, while the sibling test below mutates
    /// that same variable through `temp_env`. Under the default multi-thread
    /// test harness those two race -- `testing.md` requires isolated tests,
    /// and a `#[serial]` bandage would not fix the actual defect, which is
    /// touching the real environment at all. `temp_env::with_var(..., None,
    /// ...)` both guarantees the unset state for the duration of this
    /// closure AND takes the same global lock `with_vars` does below, so the
    /// two tests can never observe each other's mutation, needing no
    /// `#[serial]`.
    #[test]
    fn a_next_trigger_is_dropped_when_the_fault_dir_env_is_unset() {
        temp_env::with_var(FAULT_DIR_ENV, None::<&str>, || {
            let config = FaultConfig::parse("receiver.stream.drop=next");
            assert!(
                config.is_empty(),
                "a `next` trigger with LORE_RECEIVER_FAULT_DIR unset can never fire and must be \
                 dropped rather than armed"
            );
        });
    }

    /// The other side of the same rule, over a scoped `temp_env` mutation
    /// (this crate's own established pattern, e.g. `telemetry::resource`'s
    /// tests) rather than a raw `std::env::set_var`, so no state escapes.
    #[test]
    fn a_next_trigger_is_accepted_when_the_fault_dir_env_is_set() {
        temp_env::with_vars([(FAULT_DIR_ENV, Some("/some/rendezvous/dir"))], || {
            let config = FaultConfig::parse("receiver.stream.drop=next");
            assert_eq!(config.stream_drop, Some(Trigger::Armed));
        });
    }

    // -----------------------------------------------------------------
    // Decorator behaviour against `FakeDurableStream` directly
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn with_nothing_armed_the_decorator_is_fully_transparent() {
        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        inner.push_error(StreamError::Transient("down".to_string()));
        inner.push_caught_up();
        let decorated =
            FaultyDurableStream::with_dir(Arc::new(inner.clone()), FaultConfig::default(), None);

        assert!(matches!(
            decorated.next().await,
            Ok(StreamDelivery::Message(_))
        ));
        assert_eq!(
            decorated.next().await,
            Err(StreamError::Transient("down".to_string()))
        );
        assert_eq!(decorated.next().await, Ok(StreamDelivery::CaughtUp));
        assert!(decorated.ack(1).await.is_ok());
        assert_eq!(inner.acked(), vec![1], "acks pass straight through");
    }

    #[tokio::test]
    async fn capture_is_never_perturbed_by_any_armed_fault() {
        let inner = fake(900);
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            FaultConfig {
                stream_drop: Some(Trigger::Ordinal(1)),
                stream_duplicate: Some(Trigger::Ordinal(1)),
                stream_poison: Some(Trigger::Ordinal(1)),
                stream_transient: Some(Trigger::Ordinal(1)),
                ack_transient: Some(Trigger::Ordinal(1)),
            },
            None,
        );
        let placement = StreamPlacement::new("DURABLE-sfo3-cell-a", 8);
        let request = CaptureRequest {
            receiver_identity: "r".to_string(),
            membership_generation: 1,
            placement: placement.clone(),
            placement_revision: 1,
            resume_from: None,
        };
        let captured = decorated
            .capture(&request)
            .await
            .expect("capture is never perturbed, even with every anchor armed at ordinal 1");
        assert_eq!(captured.start_sequence, 900);
        assert_eq!(inner.captures(), vec![("r".to_string(), 1)]);
    }

    #[tokio::test]
    async fn stream_drop_swallows_exactly_the_nth_delivery_and_is_spent_after() {
        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        inner.push_envelope(2, durable(1, 11));
        inner.push_envelope(3, durable(1, 12));
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            FaultConfig {
                stream_drop: Some(Trigger::Ordinal(2)),
                ..Default::default()
            },
            None,
        );

        assert!(
            matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
            "the 1st delivery is untouched"
        );
        assert_eq!(
            decorated.next().await,
            Ok(StreamDelivery::CaughtUp),
            "the 2nd delivery is swallowed and reported as CaughtUp"
        );
        assert!(
            matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
            "the fault is one-shot; the 3rd delivery is untouched"
        );
        assert_eq!(decorated.deliveries_seen(), 3);
        assert!(
            inner.acked().is_empty(),
            "the decorator never acks on the caller's behalf"
        );
    }

    #[tokio::test]
    async fn stream_duplicate_replays_the_nth_delivery_once_without_advancing_the_counter() {
        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        inner.push_envelope(2, durable(1, 11));
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner.clone()),
            FaultConfig {
                stream_duplicate: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        );

        let Ok(StreamDelivery::Message(first)) = decorated.next().await else {
            panic!("expected the 1st delivery");
        };
        let Ok(StreamDelivery::Message(replay)) = decorated.next().await else {
            panic!("expected the replay");
        };
        assert_eq!(
            first, replay,
            "the replay must be byte-identical to the original"
        );
        let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
            panic!("expected the real 2nd delivery");
        };
        assert_eq!(second.broker_sequence, 2);
        assert_eq!(
            decorated.deliveries_seen(),
            2,
            "the replay must not advance the delivery counter -- only 2 real deliveries occurred"
        );
    }

    #[tokio::test]
    async fn stream_poison_corrupts_exactly_the_nth_delivery() {
        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_poison: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        );

        let Ok(StreamDelivery::Message(delivered)) = decorated.next().await else {
            panic!("expected a message");
        };
        let Some(wire::private_envelope_v1::Body::DurableInvalidation(body)) =
            delivered.envelope.body.as_ref()
        else {
            panic!("expected a durable invalidation body");
        };
        assert_eq!(
            body.payload_version,
            u32::MAX,
            "the injected corruption pushes payload_version out of every cell's configured range"
        );
    }

    #[tokio::test]
    async fn stream_transient_fails_exactly_the_nth_next_call_and_is_spent_after() {
        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        inner.push_envelope(2, durable(1, 11));
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_transient: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        );

        assert!(matches!(
            decorated.next().await,
            Err(StreamError::Transient(_))
        ));
        assert!(
            matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
            "the fault is spent; the next call reads cleanly"
        );
        assert!(matches!(
            decorated.next().await,
            Ok(StreamDelivery::Message(_))
        ));
    }

    #[tokio::test]
    async fn ack_transient_fails_exactly_the_nth_ack_call_and_is_spent_after() {
        let inner = fake(1);
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                ack_transient: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        );

        assert!(matches!(
            decorated.ack(900).await,
            Err(StreamError::Transient(_))
        ));
        assert!(
            decorated.ack(901).await.is_ok(),
            "the fault is spent after its one call"
        );
    }

    /// One-shot is enforced centrally so that recreating the arm file after
    /// a firing does not re-arm an already-spent anchor.
    #[tokio::test]
    async fn an_armed_trigger_fires_once_even_if_the_arm_file_is_recreated() {
        let dir = tempfile::tempdir().expect("a temp rendezvous directory");
        let arm = dir
            .path()
            .join(format!("{}{}", Anchor::StreamDrop.name(), ARM_SUFFIX));
        let fired = dir
            .path()
            .join(format!("{}{}", Anchor::StreamDrop.name(), FIRED_SUFFIX));

        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        inner.push_envelope(2, durable(1, 11));
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_drop: Some(Trigger::Armed),
                ..Default::default()
            },
            Some(dir.path().to_path_buf()),
        );

        std::fs::write(&arm, b"arm").expect("arm the anchor");
        assert_eq!(
            decorated.next().await,
            Ok(StreamDelivery::CaughtUp),
            "the armed drop fires on the first delivery it sees"
        );
        assert!(
            fired.exists(),
            "a firing must leave the .fired marker a live case waits on"
        );
        assert!(!arm.exists(), "the arm file must be consumed on firing");

        // Recreate the arm file. The anchor is already spent and must not
        // fire a second time no matter how many times it is re-armed.
        std::fs::write(&arm, b"arm").expect("re-arm the anchor");
        assert!(
            matches!(decorated.next().await, Ok(StreamDelivery::Message(_))),
            "the anchor is spent; recreating the arm file must not fire it again"
        );
    }

    /// WP-119 case O's own live lesson, pinned: an armed trigger fires on
    /// whatever delivery is next, not on some "intended" one a harness
    /// assumed. Two deliveries are already queued -- both already "in
    /// flight" -- before the anchor is armed, and the fault lands on the
    /// first, never the second.
    #[tokio::test]
    async fn an_armed_trigger_fires_on_whatever_delivery_is_next_not_the_intended_one() {
        let dir = tempfile::tempdir().expect("a temp rendezvous directory");
        let inner = fake(900);
        inner.push_envelope(900, bare_envelope());
        inner.push_envelope(901, bare_envelope());
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_drop: Some(Trigger::Armed),
                ..Default::default()
            },
            Some(dir.path().to_path_buf()),
        );
        std::fs::write(
            dir.path()
                .join(format!("{}{}", Anchor::StreamDrop.name(), ARM_SUFFIX)),
            b"arm",
        )
        .expect("arm the anchor");

        assert_eq!(
            decorated.next().await,
            Ok(StreamDelivery::CaughtUp),
            "the armed drop fires on the FIRST delivery it sees, broker sequence 900 -- a \
             harness cannot assume it lands on some later, 'intended' delivery"
        );
        let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
            panic!("expected the second, untouched delivery");
        };
        assert_eq!(
            second.broker_sequence, 901,
            "the anchor is already spent; the second delivery proves the fault landed on the \
             first, not on this one"
        );
    }

    /// The module doc's own "An armed anchor fires on TRAFFIC, not on
    /// wall-clock time" section, pinned: this decorator has no background
    /// task and no timer, so `fires()` can only ever run synchronously
    /// inside a `next()`/`ack()` call. Real time passing with nothing
    /// calling either must leave the anchor unfired; only an actual call
    /// fires it. A future change that added polling to "help" a live
    /// harness would break the documented arm-then-produce-traffic contract,
    /// and this is the test that would catch it.
    #[tokio::test]
    async fn an_armed_trigger_never_fires_on_wall_clock_time_only_on_a_next_or_ack_call() {
        let dir = tempfile::tempdir().expect("a temp rendezvous directory");
        let fired = dir.path().join(format!(
            "{}{}",
            Anchor::StreamTransient.name(),
            FIRED_SUFFIX
        ));
        let inner = fake(1);
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_transient: Some(Trigger::Armed),
                ..Default::default()
            },
            Some(dir.path().to_path_buf()),
        );
        std::fs::write(
            dir.path()
                .join(format!("{}{}", Anchor::StreamTransient.name(), ARM_SUFFIX)),
            b"arm",
        )
        .expect("arm the anchor");

        // Real time passes with nothing calling next() or ack().
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !fired.exists(),
            "an armed anchor must never fire on wall-clock time alone; nothing has called \
             next() or ack() yet, so fires() has never run"
        );

        // Traffic arrives: the anchor fires on THIS call, not before it.
        assert!(matches!(
            decorated.next().await,
            Err(StreamError::Transient(_))
        ));
        assert!(
            fired.exists(),
            "the anchor fires once traffic (an actual next() call) arrives"
        );
    }

    /// Reviewer defect 1, pinned: `poison` must not report a firing that
    /// perturbed nothing. A non-`DurableInvalidation` delivery at the armed
    /// ordinal must leave the envelope byte-identical, the anchor UNSPENT
    /// (no `.fired`, arm file untouched), and the next ELIGIBLE delivery
    /// must still be poisoned. `Trigger::Armed` is required here rather than
    /// `Trigger::Ordinal`: an ordinal trigger only ever equals the delivery
    /// counter once, so if it were declined on that one delivery it could
    /// never become due again -- exactly the scenario `is_due`/`commit`'s
    /// two-phase split exists to keep armed through.
    #[tokio::test]
    async fn poison_declines_a_non_durable_invalidation_delivery_and_stays_armed_for_the_next_one()
    {
        let dir = tempfile::tempdir().expect("a temp rendezvous directory");
        let arm = dir
            .path()
            .join(format!("{}{}", Anchor::StreamPoison.name(), ARM_SUFFIX));
        let fired = dir
            .path()
            .join(format!("{}{}", Anchor::StreamPoison.name(), FIRED_SUFFIX));

        let inner = fake(1);
        inner.push_envelope(1, bare_envelope()); // not a DurableInvalidation
        inner.push_envelope(2, durable(1, 10)); // a real one
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_poison: Some(Trigger::Armed),
                ..Default::default()
            },
            Some(dir.path().to_path_buf()),
        );
        std::fs::write(&arm, b"arm").expect("arm the anchor");

        let Ok(StreamDelivery::Message(first)) = decorated.next().await else {
            panic!("expected the 1st delivery");
        };
        assert!(
            first.envelope.body.is_none(),
            "a declined firing must leave a non-DurableInvalidation body unchanged"
        );
        assert!(
            !fired.exists(),
            "a declined firing must not write the .fired marker -- nothing was perturbed"
        );
        assert!(
            arm.exists(),
            "a declined firing must leave the anchor armed, not consume the arm file"
        );

        let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
            panic!("expected the 2nd delivery");
        };
        let Some(wire::private_envelope_v1::Body::DurableInvalidation(body)) =
            second.envelope.body.as_ref()
        else {
            panic!("expected a durable invalidation body");
        };
        assert_eq!(
            body.payload_version,
            u32::MAX,
            "the next ELIGIBLE delivery must still be poisoned; the anchor was never spent"
        );
        assert!(
            fired.exists(),
            "this firing DID perturb something and must write .fired"
        );
    }

    /// Reviewer defect 2, pinned: a stashed duplicate replay belongs to the
    /// generation that saw it. `capture()` ends a generation, so it must
    /// discard any pending replay rather than letting it leak into the next
    /// generation's first delivery carrying a broker sequence the new
    /// capture never covered -- a fault the real stream cannot produce.
    #[tokio::test]
    async fn capture_discards_a_pending_duplicate_so_it_never_leaks_into_the_next_generation() {
        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        inner.push_envelope(2, durable(1, 11));
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_duplicate: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            None,
        );

        // Delivery 1 fires the duplicate anchor and stashes a replay of
        // broker sequence 1.
        let Ok(StreamDelivery::Message(first)) = decorated.next().await else {
            panic!("expected the 1st delivery");
        };
        assert_eq!(first.broker_sequence, 1);

        // A recapture ends this generation. It must discard the stashed
        // replay rather than serving it to the next one.
        let request = CaptureRequest {
            receiver_identity: "r".to_string(),
            membership_generation: 2,
            placement: StreamPlacement::new("DURABLE-sfo3-cell-a", 8),
            placement_revision: 1,
            resume_from: None,
        };
        decorated
            .capture(&request)
            .await
            .expect("capture passes through");

        // The next delivery must be the inner source's own next one, never
        // the discarded replay of broker sequence 1 from the prior
        // generation.
        let Ok(StreamDelivery::Message(second)) = decorated.next().await else {
            panic!("expected the inner source's real 2nd delivery");
        };
        assert_eq!(
            second.broker_sequence, 2,
            "the stashed replay must be discarded on capture, not served as this generation's \
             first delivery"
        );
    }

    /// Reviewer defect 4, pinned at the parser: `drop` and a message-counted
    /// anchor armed at the SAME ordinal is a warning, not a refusal -- both
    /// stay in the parsed config, because the two anchors are independently
    /// useful at different ordinals and a `next` trigger has no ordinal to
    /// compare in the first place.
    #[test]
    fn warn_about_shadowing_does_not_drop_either_anchor_from_the_config() {
        let config = FaultConfig::parse("receiver.stream.drop=3,receiver.stream.poison=3");
        assert_eq!(config.stream_drop, Some(Trigger::Ordinal(3)));
        assert_eq!(
            config.stream_poison,
            Some(Trigger::Ordinal(3)),
            "shadowing is a warning, not a refusal -- both anchors stay armed at their \
             configured ordinal even though poison can never reach delivery 3"
        );

        let config = FaultConfig::parse("receiver.stream.drop=5,receiver.stream.duplicate=5");
        assert_eq!(config.stream_drop, Some(Trigger::Ordinal(5)));
        assert_eq!(config.stream_duplicate, Some(Trigger::Ordinal(5)));
    }

    /// The other half of reviewer defect 4: `drop` actually does shadow
    /// `poison` at the decorator, not just in the warning. `drop` returns
    /// before `poison`'s `is_due` is ever consulted, so poison's `.fired`
    /// marker must never appear.
    #[tokio::test]
    async fn drop_shadows_poison_at_the_same_ordinal_and_poison_never_fires() {
        let dir = tempfile::tempdir().expect("a temp rendezvous directory");
        let poison_fired =
            dir.path()
                .join(format!("{}{}", Anchor::StreamPoison.name(), FIRED_SUFFIX));

        let inner = fake(1);
        inner.push_envelope(1, durable(1, 10));
        let decorated = FaultyDurableStream::with_dir(
            Arc::new(inner),
            FaultConfig {
                stream_drop: Some(Trigger::Ordinal(1)),
                stream_poison: Some(Trigger::Ordinal(1)),
                ..Default::default()
            },
            Some(dir.path().to_path_buf()),
        );

        assert_eq!(
            decorated.next().await,
            Ok(StreamDelivery::CaughtUp),
            "drop fires first and swallows the delivery"
        );
        assert!(
            !poison_fired.exists(),
            "poison is shadowed at the same ordinal and must never reach its own firing decision"
        );
    }
}

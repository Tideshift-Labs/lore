// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift), WP-115 K11: eject a `role = "stage"` replica whose
//! own mount of the shared stage is stale, but only while a peer is seen
//! writing it.
//!
//! In the multi-host cell every web replica hard-mounts one NFS stage. A stage
//! fault is normally cell-wide, and `/lb_health` must not eject on a cell-wide
//! signal: ejecting replicas one after another refuses the whole cell (see
//! `lorehub/docs/learnings/backpressure-routed-into-a-binary-liveness-verdict-ejects-every-replica-at-once.md`).
//! But one host's mount can go stale alone, and that host then keeps taking
//! connections whose uploads hang. A peer that keeps writing the same stage
//! is the evidence that the fault is local.
//!
//! Three parts:
//!
//! 1. **Probe.** One dedicated OS thread (not the tokio pool: a hard-mount write
//!    can block forever) writes, fsyncs and removes one small file under
//!    `<stage>/liveness/`. Each full success adds one to this process's
//!    progress count. If a write hangs, the thread hangs with it. No second
//!    thread is ever started, so at most one probe is in flight.
//! 2. **Exchange.** A tokio task publishes the count, with this process's
//!    incarnation id, to Postgres and reads every peer's. The database never
//!    lowers a stored count, and accepts a higher one only if the success is
//!    at most [`PUBLISH_FRESH`] old when sent and the statement runs within
//!    [`PUBLISH_DEADLINE`] of being sent (see the module docs of
//!    `lore-postgres/src/domain/fragments/stage_liveness.rs` and
//!    `PostgresFragmentCoordinator::exchange_stage_liveness`).
//! 3. **Decision.** This replica is stale after [`STALE_AFTER`] with no own
//!    success, on its monotonic clock. The first peer view taken after that is
//!    the baseline. A later view in which a peer of the same incarnation has a
//!    higher count, accepted after the baseline view and within
//!    [`PROGRESS_WINDOW`], proves the stage still works for that peer: 503
//!    `stage_unavailable_local`. Anything else is 200. When the peer stops
//!    too, its last increase leaves the window and the replica is readmitted.
//!
//! One own success brings the replica back.
//!
//! ## What an eject proves
//!
//! Write `S` = [`STALE_AFTER`] (15 s), `F` = [`PUBLISH_FRESH`] (4 s) and
//! `D` = [`PUBLISH_DEADLINE`] (2 s).
//!
//! **Guarantee.** If replica A answers `stage_unavailable_local`, then a peer
//! made a real probe success at least `S - F - D` (9 s) after A's last own
//! success. It does NOT say that the peer still works now.
//!
//! **Assumptions.** The proof holds only while all of these hold:
//!
//! - (A1) The database clock and every replica's monotonic clock run at the
//!   same rate. Their offsets may differ.
//! - (A2) There is one database clock and it never goes back: no failover to
//!   a server with another clock, and no backward step.
//! - (A3) Replica ids are unique: one process at a time publishes under one
//!   id. A duplicate is logged, not prevented.
//! - (A4) A probe returns success only when the stage really worked for that
//!   process: the write and the fsync reached the server.
//! - (A5) One replica's exchanges are serialized: an exchange starts only
//!   after the previous one ended, so the clock anchor it sends came from a
//!   reply received before the send.
//!
//! **Proof.** All times below are real times; A1 lets us move a difference
//! between clocks without change.
//!
//! 1. A ejects at its view V2 only if V2 holds a peer B with the same
//!    incarnation as A's baseline view V1, a higher count, and a stored
//!    `progressed_at` `p` later than V1's database clock `c1`.
//! 2. V1 is the first view after A went stale, so V1's exchange started at
//!    least `S` after A's last success `L`. `c1` is read during that exchange,
//!    so `c1 >= L + S`.
//! 3. By A2, `p > c1` means the statement that stamped `p` ran after `c1`.
//!    `p` is never the epoch stamp (0), so that statement passed the
//!    fresh-and-on-time test. Every stamp other than the epoch passes that
//!    test, also on a new incarnation's first write. The test and the stamp
//!    are one `clock_timestamp()` read (the `stamp` CTE and the `take`
//!    predicate in `PostgresFragmentCoordinator::exchange_stage_liveness`;
//!    the rule is in the module docs of
//!    `lore-postgres/src/domain/fragments/stage_liveness.rs`).
//! 4. Deadline: `p <= anchor + (sent - received) + D` on the database clock.
//!    The anchor was read no later than `received` (A5), so by A1 and A2
//!    `p <= sent + D`. So `sent >= p - D`. The stamp is read before any wait
//!    for the row lock; a later commit only hides the increase from views
//!    taken before it, which errs toward "no eject".
//! 5. Freshness: the success it reports, at `g`, was at most `F` old at
//!    `sent`. So `g >= sent - F >= p - D - F > c1 - F - D >= L + S - F - D`.
//! 6. By A3 and A4, `g` is a real success of B's own process. So B
//!    succeeded at least 9 s after `L`.
//!
//! **No double eject.** By the guarantee, at any moment the replica with the
//! latest own success is not ejected: no peer can have succeeded 9 s after
//! it. So the whole cell is never ejected at once, and in a two-replica cell
//! the two never both eject. A fault that hits every host within 9 s ejects
//! nobody.
//!
//! **Known limits.**
//!
//! - Staggered hang. If the fault hits host B more than about 9 s after it
//!   hits host A, B's successes in that gap eject A, although B is failing
//!   too by then. A stays ejected until B's last increase leaves
//!   [`PROGRESS_WINDOW`]. A live probe showed this: A's last success was 12 s
//!   before the hang reached B, and A was ejected for about 10 s.
//! - Flapping. A peer that succeeds less often than once per
//!   [`PROGRESS_WINDOW`] readmits the stale replica between its successes.
//!   With a success every 12 s, the stale replica is ejected for about 10 s
//!   and readmitted for about 2 s, again and again. A longer window would
//!   shorten that gap, but it would also make the staggered-hang eject and
//!   the readmit after a cell-wide fault longer, so it is left as is.
//! - The proof does not hold if an assumption fails, for example after a
//!   database failover with a clock step, or with two processes sharing one
//!   replica id.
//!
//! ## Shared-stage guard
//!
//! Two stage replicas that each mount a valid but DIFFERENT stage lose data:
//! a replica reads a peer's staged fragment, finds no file, and marks it
//! `Missing` (WP-115 D1, 179 fragments), and its own staged files are never
//! seen by the drain. K6's mount lock stops a silent local fallback, but not
//! two good mounts of two directories.
//!
//! 1. **Marker.** Each stage replica's probe thread, and the drain worker's
//!    marker thread, keep `<stage>/liveness/<replica>.present` holding the
//!    process's incarnation. The file is rewritten when it is missing or
//!    holds another value, and removed when the thread stops.
//! 2. **Drain row.** The liveness row carries `role`. The drain worker
//!    publishes `drain` only while a read-back of its own marker, at most
//!    [`ANCHOR_VERIFY_MAX_AGE`] old, shows its current incarnation; else it
//!    publishes `drain_unverified`, raises [`STAGE_ANCHOR_UNVERIFIED`] in its
//!    own snapshot, the `stage_share_anchor_unverified` gauge and a log line.
//!    A drain row runs no probe, so its count never rises: it is never a K11
//!    eject peer (also not for an older binary), and the drain is never held
//!    or ejected itself.
//! 3. **Anchor proof.** A stage replica opens staging only when the cell has
//!    a `drain` row published within [`SHARE_PEER_FRESH`] and this replica
//!    has seen the marker of every such drain, holding its current
//!    incarnation. That proof latches for the life of the process.
//! 4. **Until then, direct writes.** Before the proof (no exchange yet, no
//!    fresh `drain` row, or a drain marker not seen yet) the stage writes
//!    every new fragment directly to the object store (`DirectFallback`), so
//!    nothing is staged into a directory nobody has verified, and nothing is
//!    refused. A PUT that chose `Stage` and re-checks after the gate rose
//!    refuses with `SlowDown`; its retry writes directly. The gate only ever
//!    opens, so this re-check is a defence, not a path production takes. A
//!    staged read that finds no file answers `SlowDown`, never "absent", so
//!    nothing is demoted to `Missing`.
//! 5. **`/lb_health`.** 200 with no exchange yet (inside [`SHARE_GRACE`]),
//!    and 200 with no fresh `drain` row: the replica serves, only without
//!    staging. With a fresh `drain` row whose marker this replica has not
//!    seen, 503 [`STAGE_SHARE_UNVERIFIED`], and [`STAGE_NOT_SHARED`] after
//!    [`SHARE_GRACE`]. With no successful exchange for [`SHARE_GRACE`] since
//!    boot, 503 [`STAGE_SHARE_PENDING`].
//! 6. **"Cannot decide" is 200.** Only a marker read that completes and
//!    finds no matching marker (the file is absent or holds another
//!    incarnation) counts toward the 503 words above. A read that fails with
//!    any other I/O error (a stale handle, `EIO`, a permission fault) and a
//!    probe-thread step that has hung for [`MARKER_STUCK_AFTER`] (an NFS
//!    hard mount whose server is gone) say nothing about which directory
//!    this is. The verdict is then [`ShareVerdict::Undecided`]: `/lb_health`
//!    answers 200, staging stays off (new fragments are written directly,
//!    and a staged read that finds no file is not evidence of absence), and
//!    the `stage_share_undecided` gauge is 1. The next completed read
//!    decides again.
//!
//! **Never all, never both.** A web replica answers a shared-stage 503 only
//! in two cases:
//!
//! - It is not yet anchor-proven, a fresh `drain` row exists, and its
//!   marker step completes but does not find that drain's marker. The drain
//!   row exists only while the drain itself reads its marker back (step 2),
//!   so the marker is really there. Replicas that are anchor-proven are
//!   never held again, so no later fault (NFS hang, Postgres outage, drain
//!   restart, drain marker loss) touches them. A marker read fault or a hung
//!   step is "cannot decide" (step 6), so it never answers 503. So both web
//!   replicas answer 503 only if both are unproven at the same time and both
//!   READ a liveness directory that does not hold the drain's marker: a
//!   wrong mount on both hosts.
//! - No exchange has succeeded for [`SHARE_GRACE`] since boot. Both answer
//!   this only if Postgres is unreachable from both for that long, and then
//!   the cell cannot serve anyway.
//!
//! With no drain row (the drain down, its marker unverifiable, or a cell
//! that boots web-first), no replica answers a shared-stage 503 at all.
//!
//! **Limits.**
//!
//! - A drain on the wrong directory is not detected; it is the reference.
//!   Two fresh drains on two directories hold every replica that is not yet
//!   anchor-proven.
//! - While no `drain` row is fresh, unproven replicas stage nothing, so
//!   writes cost a direct object-store round trip.
//! - Start-up 503 (review probe RV3-C). A fresh drain row that this replica
//!   has not yet looked for counts as "not seen". So from the first view
//!   that names a fresh drain until the next marker step (at most one
//!   [`PROBE_INTERVAL`], about 2 s), an unproven replica answers 503
//!   [`STAGE_SHARE_UNVERIFIED`]. At a cell start both web replicas do this
//!   at once, for about 2 s.
//! - Web-only roll with an old drain. A drain worker built before this
//!   guard publishes no `drain` role, so the cell has no anchor: every web
//!   replica stays at [`ShareVerdict::NoAnchor`], answers 200 and stages
//!   nothing. Staging is then off cell-wide with no alert, only an info log
//!   per replica and `stage_share_unproven` = 1. Roll the drain worker too.
//! - A hung step is noticed only after [`MARKER_STUCK_AFTER`]; until then
//!   the last completed read stands.
//! - Turning `stage_liveness_probe` off turns this guard off too.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use lore_postgres::domain::fragments::MAX_STAGE_LIVENESS_ID_BYTES;
use lore_postgres::domain::fragments::StageLivenessClock;
use lore_postgres::domain::fragments::StageLivenessLimits;
use lore_postgres::domain::fragments::StageLivenessPublication;
use lore_postgres::domain::fragments::StageLivenessRole;
use lore_postgres::domain::fragments::StagePeerLiveness;
use lore_postgres::domain::fragments::StagePeerProgress;
use lore_postgres::domain::fragments::StageProgressRecord;
use lore_telemetry::InstrumentProvider;
use opentelemetry::metrics::Gauge;
use serde::Serialize;
use tracing::error;
use tracing::info;
use tracing::warn;

/// The `/lb_health` word for a replica whose own stage mount is stale while a
/// peer is seen writing it.
pub const STAGE_UNAVAILABLE_LOCAL: &str = "stage_unavailable_local";

/// The `/lb_health` word for a replica that has not yet seen the marker of a
/// fresh drain row in its stage, inside [`SHARE_GRACE`].
pub const STAGE_SHARE_UNVERIFIED: &str = "stage_share_unverified";

/// The `/lb_health` word for a replica that has not seen a fresh drain's
/// marker for [`SHARE_GRACE`]: its stage is very likely not the cell's
/// shared stage.
pub const STAGE_NOT_SHARED: &str = "stage_not_shared";

/// The `/lb_health` word for a replica whose first liveness exchange has not
/// succeeded within [`SHARE_GRACE`] of boot.
pub const STAGE_SHARE_PENDING: &str = "stage_share_pending";

/// The drain worker's own fault word (its `/health_check` snapshot; its
/// `/lb_health` answers `drain_role` anyway): no read-back of its own stage
/// marker within [`ANCHOR_VERIFY_MAX_AGE`] showed its incarnation, so it
/// publishes `drain_unverified` and anchors nobody.
pub const STAGE_ANCHOR_UNVERIFIED: &str = "stage_anchor_unverified";

/// A drain row counts for the shared-stage check only if it was published
/// within this window, on database time. Five exchange intervals.
pub const SHARE_PEER_FRESH: Duration = Duration::from_secs(10);

/// How old the drain's last good read-back of its own marker may be while
/// it still publishes `drain`. Three marker intervals, so one slow step does
/// not withdraw the anchor, but a hung marker thread does within seconds.
pub const ANCHOR_VERIFY_MAX_AGE: Duration = Duration::from_secs(6);

/// A probe-thread step (probe plus marker reads) running longer than this
/// is hung: the shared-stage check cannot decide, so it answers 200. Three
/// probe intervals.
pub const MARKER_STUCK_AFTER: Duration = Duration::from_secs(6);

/// How long an unseen drain marker reads as "unverified" before it reads as
/// "not shared". Both words answer 503 and both keep staging off; only the
/// word and the log level differ, so a long grace costs nothing in safety.
///
/// It covers a peer that has published but not yet written its marker, and
/// NFS caching. Our stage mounts use `lookupcache=positive`, so a lookup of a
/// missing name always asks the server and a new marker is seen at once;
/// `open` revalidates attributes (close-to-open), so new content is seen too.
/// Under the default `lookupcache=all`, a cached negative entry can hide a
/// new file until the directory's attributes expire (`acdirmax`, 60 s by
/// default). 90 s covers that with one more probe interval to spare.
pub const SHARE_GRACE: Duration = Duration::from_secs(90);

/// The marker file suffix under `<stage>/liveness/`.
pub const SHARE_MARKER_SUFFIX: &str = ".present";

/// The longest marker content read, in bytes. An incarnation is shorter.
const MARKER_READ_LIMIT: u64 = 256;

/// How often the probe thread writes its file.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// A replica is stale after this long with no good probe.
///
/// 15 s is about seven probe intervals: a single slow NFS round trip, or a
/// short server hiccup that every host sees, does not eject anyone. It is
/// also well under the time a hard mount stays hung after a real fault.
pub const STALE_AFTER: Duration = Duration::from_secs(15);
/// How often this replica publishes and reads peers.
pub const EXCHANGE_INTERVAL: Duration = Duration::from_secs(2);
/// The budget for one exchange, and its transaction's `statement_timeout`.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);
/// A peer view older than this is "cannot decide". Five exchange intervals,
/// so a few slow exchanges do not drop the evidence, but a Postgres outage
/// does within seconds.
pub const PEER_VIEW_MAX_AGE: Duration = Duration::from_secs(10);
/// The oldest success an accepted increase may report, measured when the
/// statement is sent. A success is published by the next exchange, at most
/// one [`EXCHANGE_INTERVAL`] plus a checkout ([`EXCHANGE_TIMEOUT`]) later.
pub const PUBLISH_FRESH: Duration = Duration::from_secs(4);
/// How long after it is sent an increase may still run. The client has given
/// up on the exchange by then, so a later run changes nothing.
pub const PUBLISH_DEADLINE: Duration = EXCHANGE_TIMEOUT;
/// A peer's increase counts only while it is this recent, on database time,
/// so when the peer stops too (the fault became cell-wide) the stale replica
/// is readmitted. Long enough to cover the gap between a slow peer's
/// successes (a 4 s probe every 6 s) plus one exchange.
///
/// Known limit (flapping): a peer whose successes are further apart than
/// this window readmits the stale replica between them. With a peer success
/// every 12 s, the stale replica is ejected for about 10 s, then readmitted
/// for about 2 s, in a loop. The no-double-eject proof in the module docs
/// does not use this window.
pub const PROGRESS_WINDOW: Duration = Duration::from_secs(10);
/// Rows not published for this long are deleted, so restarts do not grow the
/// table.
pub const RETAIN: Duration = Duration::from_secs(3600);

const WARN_EVERY: Duration = Duration::from_secs(30);

struct LivenessInstrumentProvider;
impl InstrumentProvider for LivenessInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.fragment.write_behind"
    }
}

struct Instruments {
    /// 1 while this replica answers `stage_unavailable_local`, else 0.
    ejected: Gauge<u64>,
    /// Seconds since this replica's last good stage probe.
    probe_age: Gauge<u64>,
    /// Peers seen making progress since this replica went stale.
    progressing_peers: Gauge<u64>,
    /// 1 while this replica keeps staging off because its stage is not
    /// proven shared, else 0.
    share_unproven: Gauge<u64>,
    /// 1 while the shared-stage check cannot decide (a marker read fault or
    /// a hung step), else 0. `/lb_health` stays 200 then.
    share_undecided: Gauge<u64>,
    /// 1 while the drain worker publishes `drain_unverified` (its own marker
    /// read-back fails or is too old), else 0. Only the drain records it.
    share_anchor_unverified: Gauge<u64>,
}

fn instruments() -> &'static Instruments {
    static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();
    INSTRUMENTS.get_or_init(|| {
        let provider = LivenessInstrumentProvider;
        let meter = provider.meter();
        Instruments {
            ejected: meter
                .u64_gauge(provider.scope_name("stage_liveness_ejected"))
                .build(),
            probe_age: meter
                .u64_gauge(provider.scope_name("stage_probe_age_seconds"))
                .build(),
            progressing_peers: meter
                .u64_gauge(provider.scope_name("stage_liveness_progressing_peers"))
                .build(),
            share_unproven: meter
                .u64_gauge(provider.scope_name("stage_share_unproven"))
                .build(),
            share_undecided: meter
                .u64_gauge(provider.scope_name("stage_share_undecided"))
                .build(),
            share_anchor_unverified: meter
                .u64_gauge(provider.scope_name("stage_share_anchor_unverified"))
                .build(),
        }
    })
}

/// What the last peer view says, once its own age is taken into account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvidence {
    /// No peer view, one older than the max age (Postgres is unreachable or
    /// slow), or one taken before this replica went stale. Never ejects.
    Unknown,
    /// A recent view, taken after this replica went stale, in which no peer
    /// has made progress since the baseline view.
    NoProgress,
    /// A recent view in which at least one peer of the same incarnation has
    /// made progress that was accepted after the baseline view.
    ProgressingPeer,
}

/// The K11 rule. Pure, so every case is a table test.
pub fn decide(self_stale: bool, peers: PeerEvidence) -> Option<&'static str> {
    (self_stale && peers == PeerEvidence::ProgressingPeer).then_some(STAGE_UNAVAILABLE_LOCAL)
}

/// The thresholds of one replica. Tests scale them down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessThresholds {
    pub stale_after: Duration,
    pub peer_view_max_age: Duration,
    pub publish_fresh: Duration,
    pub publish_deadline: Duration,
    pub statement_timeout: Duration,
    pub progress_window: Duration,
    pub share_peer_fresh: Duration,
    pub share_grace: Duration,
    pub anchor_verify_max_age: Duration,
    pub marker_stuck_after: Duration,
}

impl Default for LivenessThresholds {
    fn default() -> Self {
        Self {
            stale_after: STALE_AFTER,
            peer_view_max_age: PEER_VIEW_MAX_AGE,
            publish_fresh: PUBLISH_FRESH,
            publish_deadline: PUBLISH_DEADLINE,
            statement_timeout: EXCHANGE_TIMEOUT,
            progress_window: PROGRESS_WINDOW,
            share_peer_fresh: SHARE_PEER_FRESH,
            share_grace: SHARE_GRACE,
            anchor_verify_max_age: ANCHOR_VERIFY_MAX_AGE,
            marker_stuck_after: MARKER_STUCK_AFTER,
        }
    }
}

/// The shared-stage verdict. Every verdict but [`Self::Shared`] keeps
/// staging off: new fragments are written directly to the object store, and
/// a missing staged file is not evidence of absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareVerdict {
    /// No successful exchange yet, inside the grace. `/lb_health` is 200
    /// ("cannot decide").
    Pending,
    /// No successful exchange for [`SHARE_GRACE`] since boot. `/lb_health`
    /// answers 503 [`STAGE_SHARE_PENDING`].
    PendingTooLong,
    /// No fresh `drain` row: nothing can prove this stage is the drain's.
    /// `/lb_health` is 200; the replica serves without staging.
    NoAnchor,
    /// A fresh drain's marker is not seen yet, inside the grace. 503
    /// [`STAGE_SHARE_UNVERIFIED`].
    Unverified,
    /// A fresh drain's marker has not been seen for longer than the grace.
    /// 503 [`STAGE_NOT_SHARED`].
    NotShared,
    /// A fresh drain's marker is not seen, but no completed read found it
    /// absent: every unseen marker's last read failed with an I/O error, or
    /// the probe-thread step has hung for [`MARKER_STUCK_AFTER`].
    /// `/lb_health` is 200 ("cannot decide"); staging stays off.
    Undecided,
    /// Every fresh drain's marker was seen once: latched for the life of the
    /// process. Staging is open.
    Shared,
}

impl ShareVerdict {
    /// Every verdict, for tests and docs.
    pub const ALL: [Self; 7] = [
        Self::Pending,
        Self::PendingTooLong,
        Self::NoAnchor,
        Self::Unverified,
        Self::NotShared,
        Self::Undecided,
        Self::Shared,
    ];

    /// Whether staging is off: PUTs write directly, and a missing staged
    /// file is not evidence of absence.
    pub fn holds_staging(self) -> bool {
        self != Self::Shared
    }

    /// The `/lb_health` fault, if any.
    pub fn fault(self) -> Option<&'static str> {
        match self {
            Self::PendingTooLong => Some(STAGE_SHARE_PENDING),
            Self::Unverified => Some(STAGE_SHARE_UNVERIFIED),
            Self::NotShared => Some(STAGE_NOT_SHARED),
            Self::Pending | Self::NoAnchor | Self::Undecided | Self::Shared => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PendingTooLong => "pending_too_long",
            Self::NoAnchor => "no_anchor",
            Self::Unverified => "unverified",
            Self::NotShared => "not_shared",
            Self::Undecided => "undecided",
            Self::Shared => "shared",
        }
    }
}

/// The shared-stage check's state. See the module docs.
#[derive(Debug, Default)]
struct ShareState {
    /// Whether an exchange has succeeded.
    exchanged: bool,
    /// The fresh drain anchors the last view named: replica id to
    /// incarnation. Empty when no `drain` row is fresh.
    required: BTreeMap<String, String>,
    /// (replica id, incarnation) pairs whose marker this replica has seen.
    confirmed: HashSet<(String, String)>,
    /// When each required, unconfirmed pair was first required.
    since: HashMap<(String, String), Instant>,
    /// Required, unconfirmed pairs whose last marker read failed with an I/O
    /// error other than "not found": this replica cannot decide them.
    unreadable: HashSet<(String, String)>,
    /// Latched once every fresh drain anchor's marker was seen. Only this
    /// opens staging, and nothing closes it again.
    proven: bool,
}

impl ShareState {
    fn unconfirmed(&self) -> impl Iterator<Item = (&String, &String)> {
        self.required.iter().filter(|(id, incarnation)| {
            !self
                .confirmed
                .contains(&((*id).clone(), (*incarnation).clone()))
        })
    }

    /// Whether the last view proves the share: at least one fresh drain
    /// anchor, and every one of them confirmed.
    fn anchor_proof(&self) -> bool {
        self.exchanged && !self.required.is_empty() && self.unconfirmed().next().is_none()
    }

    /// The verdict at `now`. `stuck` is whether the probe-thread step has
    /// hung for `marker_stuck_after`: then no marker read can complete, so
    /// nothing is decided.
    fn verdict(&self, now: Instant, grace: Duration, born: Instant, stuck: bool) -> ShareVerdict {
        if self.proven {
            return ShareVerdict::Shared;
        }
        if !self.exchanged {
            return if now.saturating_duration_since(born) >= grace {
                ShareVerdict::PendingTooLong
            } else {
                ShareVerdict::Pending
            };
        }
        if self.required.is_empty() {
            return ShareVerdict::NoAnchor;
        }
        if stuck {
            return ShareVerdict::Undecided;
        }
        // Only an unseen marker that was not last read with an I/O error
        // counts toward the 503 words. A marker not read yet counts (the
        // start-up 503, RV3-C in the module docs).
        let mut decided = self
            .unconfirmed()
            .filter(|(id, incarnation)| {
                !self
                    .unreadable
                    .contains(&((*id).clone(), (*incarnation).clone()))
            })
            .peekable();
        if decided.peek().is_none() {
            // Every anchor confirmed latches `proven` in the same lock
            // (`sync_gate`), so an unproven state always has one unseen;
            // here every unseen one was unreadable.
            return ShareVerdict::Undecided;
        }
        let oldest = decided
            .filter_map(|(id, incarnation)| {
                self.since.get(&(id.clone(), incarnation.clone())).copied()
            })
            .min();
        match oldest {
            Some(since) if now.saturating_duration_since(since) >= grace => ShareVerdict::NotShared,
            _ => ShareVerdict::Unverified,
        }
    }
}

/// Whether `id` is a replica id this build could have written: safe as a
/// file name. An id that is not is never confirmed.
pub fn is_marker_safe_id(id: &str) -> bool {
    sanitize_replica_id(id) == id
}

/// The marker files under `<stage>/liveness/`. Blocking; used only on the
/// probe thread.
#[derive(Debug, Clone)]
pub struct ShareMarkers {
    directory: PathBuf,
}

impl ShareMarkers {
    pub fn new(root: &std::path::Path) -> Self {
        Self {
            directory: root.join(lore_postgres::store::write_behind::root::LIVENESS_DIR),
        }
    }

    fn path(&self, replica_id: &str) -> Option<PathBuf> {
        is_marker_safe_id(replica_id).then(|| {
            self.directory
                .join(format!("{replica_id}{SHARE_MARKER_SUFFIX}"))
        })
    }

    /// The incarnation in `replica_id`'s marker, or `None` when there is no
    /// marker (or the id is not safe as a file name).
    pub fn read(&self, replica_id: &str) -> std::io::Result<Option<String>> {
        use std::io::Read as _;
        let Some(path) = self.path(replica_id) else {
            return Ok(None);
        };
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut content = String::new();
        file.take(MARKER_READ_LIMIT).read_to_string(&mut content)?;
        Ok(Some(content.trim().to_owned()))
    }

    /// Make `replica_id`'s marker hold `incarnation`. Writes only when it is
    /// missing or holds another value: a temporary file, fsync, then rename,
    /// so a reader never sees a partial marker. Returns whether it wrote.
    pub fn ensure(&self, replica_id: &str, incarnation: &str) -> std::io::Result<bool> {
        use std::io::Write as _;
        if self.read(replica_id)?.as_deref() == Some(incarnation) {
            return Ok(false);
        }
        let Some(path) = self.path(replica_id) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "replica id is not safe as a marker file name",
            ));
        };
        match std::fs::create_dir(&self.directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let temporary = self
            .directory
            .join(format!("{replica_id}{SHARE_MARKER_SUFFIX}.tmp"));
        {
            let mut handle = std::fs::File::create(&temporary)?;
            handle.write_all(incarnation.as_bytes())?;
            handle.sync_all()?;
        }
        std::fs::rename(&temporary, &path)?;
        Ok(true)
    }

    /// Remove `replica_id`'s marker if it still holds `incarnation`, so a
    /// stopped replica leaves nothing behind. A newer process's marker under
    /// the same id is kept.
    pub fn remove_if(&self, replica_id: &str, incarnation: &str) -> std::io::Result<()> {
        if self.read(replica_id)?.as_deref() != Some(incarnation) {
            return Ok(());
        }
        let Some(path) = self.path(replica_id) else {
            return Ok(());
        };
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// One probe of the stage. Blocking; runs only on the probe thread.
pub type ProbeFn = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;

/// The probe: write, fsync and remove `<root>/liveness/<replica>.probe`.
///
/// The directory is created on demand, so a purge of it, or a fresh stage,
/// heals by itself. A file already gone at remove is still a success: the
/// write and fsync reached the server, which is what the probe tests.
pub fn file_probe(root: PathBuf, replica_id: &str) -> ProbeFn {
    let directory = root.join(lore_postgres::store::write_behind::root::LIVENESS_DIR);
    let file = directory.join(format!("{replica_id}.probe"));
    Arc::new(move || {
        use std::io::Write as _;
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        {
            let mut handle = std::fs::File::create(&file)?;
            handle.write_all(b"lore-stage-liveness")?;
            handle.sync_all()?;
        }
        match std::fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    })
}

/// This replica's identity in the liveness table: host and process id.
///
/// Stable for the life of the process. In a container the host is the
/// container id and the process id is 1, so a restarted container keeps its
/// id; the incarnation tells the two processes apart.
pub fn default_replica_id() -> String {
    let host = ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown-host".to_owned());
    sanitize_replica_id(&format!("{host}-{}", std::process::id()))
}

/// Keep `[A-Za-z0-9._-]`, map anything else to `_`, and bound the length, so
/// the id is safe as a file name and fits the table.
pub fn sanitize_replica_id(raw: &str) -> String {
    let mut id: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    id.truncate(MAX_STAGE_LIVENESS_ID_BYTES);
    if id.is_empty() || id.chars().all(|c| c == '.') {
        id = "replica".to_owned();
    }
    id
}

/// What `/health_check` reports about the probe, so an operator sees why a
/// host was ejected without reading the log.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StageLivenessSnapshot {
    pub replica_id: String,
    pub incarnation: String,
    pub progress: u64,
    pub probe_age_millis: u64,
    pub probe_in_flight: bool,
    pub probe_failures: u64,
    pub peer_view_age_millis: Option<u64>,
    pub progressing_peers: Option<u64>,
    pub peers: Option<u64>,
    pub fault: Option<&'static str>,
    /// The shared-stage check: `pending`, `pending_too_long`, `no_anchor`,
    /// `unverified`, `not_shared`, `undecided` or `shared`
    /// ([`ShareVerdict::name`]).
    /// `None` when the guard is off.
    pub share: Option<&'static str>,
    /// Fresh drains whose marker this replica has not seen.
    pub share_unconfirmed: Vec<String>,
}

/// A peer as the baseline holds it: its incarnation, its count, and the
/// database time after which an increase must have run to count.
#[derive(Debug, Clone)]
struct PeerBaseline {
    incarnation: String,
    progress: i64,
    after_micros: i64,
}

/// The first view taken after this replica went stale, per peer.
#[derive(Debug, Clone)]
struct Baseline {
    /// `last_good` (nanos after origin) when the baseline was taken. A new
    /// own success changes it, which ends this stale period.
    epoch: u64,
    peers: HashMap<String, PeerBaseline>,
}

#[derive(Debug, Clone, Copy)]
struct LatestView {
    /// When the exchange that read it STARTED. That is no later than the
    /// database read, so the view's age and the "taken after self went
    /// stale" test both err toward "cannot decide".
    at: Instant,
    epoch: u64,
    after_stale: bool,
    peers: u64,
    progressing: u64,
}

#[derive(Debug, Default)]
struct PeerState {
    latest: Option<LatestView>,
    baseline: Option<Baseline>,
}

/// This process's own probe progress. Updated together so a publication
/// never pairs a count with a newer success time.
#[derive(Debug, Default, Clone, Copy)]
struct OwnProgress {
    count: u64,
}

/// One replica's stage liveness: its own progress, the peer views, and the
/// verdict over both.
pub struct StageLiveness {
    replica_id: String,
    incarnation: String,
    origin: Instant,
    /// Nanoseconds after `origin` of the last good probe. Starts at 0: the
    /// stage was proven writable at boot by `WriteBehindStage::open`.
    last_good: AtomicU64,
    own: Mutex<OwnProgress>,
    probes_started: AtomicU64,
    probe_failures: AtomicU64,
    in_flight: AtomicBool,
    /// Probe threads ever started for this replica. Never above 1.
    threads_started: AtomicUsize,
    peers: Mutex<PeerState>,
    /// The last successful exchange's database clock, for the next deadline.
    clock: Mutex<Option<StageLivenessClock>>,
    /// This process's own row as its last exchange left it. `None` until an
    /// exchange succeeds, and again after one fails, because a failed
    /// exchange may still have written the row.
    last_published: Mutex<Option<StageProgressRecord>>,
    /// The last duplicate-identity sighting: when it was last logged, and
    /// the (published, found) pair that disagreed.
    duplicate_warned: Mutex<Option<(Instant, StageProgressRecord, StageProgressRecord)>>,
    /// The last verdict, for one log line per transition.
    ejected: AtomicBool,
    thresholds: LivenessThresholds,
    /// Whether the shared-stage guard answers `/lb_health`. Off in a
    /// replica built for K11 alone (tests); on in production.
    share_guard: bool,
    share: Mutex<ShareState>,
    /// When the probe thread's current step (probe plus marker reads)
    /// started, or `None` between steps. A step that runs longer than
    /// `marker_stuck_after` is hung.
    step_started: Mutex<Option<Instant>>,
    /// `true` while staging is held. Shared with the stage; see
    /// [`Self::share_gate`].
    share_gate: Arc<AtomicBool>,
    /// The last reported share verdict, for one log line per transition.
    share_reported: Mutex<Option<ShareVerdict>>,
    /// `Stage`, or `Drain` for the drain worker: it publishes a row and a
    /// marker as the shared-stage anchor, and is never ejected or held.
    role: StageLivenessRole,
    /// The drain worker only: when a read-back of its own marker last showed
    /// its incarnation. `None` until one does, and again after one fails.
    anchor_verified: Mutex<Option<Instant>>,
    /// The drain worker only: the last reported anchor state, for one log
    /// line per transition.
    anchor_reported: Mutex<Option<bool>>,
}

impl StageLiveness {
    pub fn new(replica_id: String) -> Self {
        Self::with_thresholds(replica_id, LivenessThresholds::default())
    }

    pub fn with_thresholds(replica_id: String, thresholds: LivenessThresholds) -> Self {
        Self::with_incarnation(
            replica_id,
            uuid::Uuid::new_v4().simple().to_string(),
            thresholds,
        )
    }

    /// As [`Self::with_thresholds`], with a chosen incarnation id. A test
    /// uses it to stand in for one process across a restart.
    pub fn with_incarnation(
        replica_id: String,
        incarnation: String,
        thresholds: LivenessThresholds,
    ) -> Self {
        Self {
            replica_id,
            incarnation,
            origin: Instant::now(),
            last_good: AtomicU64::new(0),
            own: Mutex::new(OwnProgress::default()),
            probes_started: AtomicU64::new(0),
            probe_failures: AtomicU64::new(0),
            in_flight: AtomicBool::new(false),
            threads_started: AtomicUsize::new(0),
            peers: Mutex::new(PeerState::default()),
            clock: Mutex::new(None),
            last_published: Mutex::new(None),
            duplicate_warned: Mutex::new(None),
            ejected: AtomicBool::new(false),
            thresholds,
            share_guard: false,
            share: Mutex::new(ShareState::default()),
            step_started: Mutex::new(None),
            share_gate: Arc::new(AtomicBool::new(true)),
            share_reported: Mutex::new(None),
            role: StageLivenessRole::Stage,
            anchor_verified: Mutex::new(None),
            anchor_reported: Mutex::new(None),
        }
    }

    /// Publish as `role`. A `Drain` replica anchors the shared-stage check
    /// and is never held, ejected, or counted as a K11 peer.
    #[must_use]
    pub fn with_role(mut self, role: StageLivenessRole) -> Self {
        self.role = role;
        self
    }

    pub fn role(&self) -> StageLivenessRole {
        self.role
    }

    /// Turn the shared-stage guard on: its verdict joins `/lb_health`.
    #[must_use]
    pub fn with_share_guard(mut self) -> Self {
        self.share_guard = true;
        self
    }

    pub fn share_guard(&self) -> bool {
        self.share_guard
    }

    /// The "staging is off" flag to attach to the stage. Starts `true`:
    /// nothing is proven before the first exchange. It only ever goes from
    /// `true` to `false`, once, when an anchor proof latches.
    pub fn share_gate(&self) -> Arc<AtomicBool> {
        self.share_gate.clone()
    }

    /// The shared-stage verdict at `now`.
    pub fn share_verdict(&self, now: Instant) -> ShareVerdict {
        let stuck = self.step_stuck(now);
        lock(&self.share).verdict(now, self.thresholds.share_grace, self.origin, stuck)
    }

    /// Whether the probe thread's current step has run for at least
    /// `marker_stuck_after` at `now`.
    pub fn step_stuck(&self, now: Instant) -> bool {
        lock(&self.step_started).is_some_and(|started| {
            now.saturating_duration_since(started) >= self.thresholds.marker_stuck_after
        })
    }

    /// Mark the start (`Some`) or the end (`None`) of a probe-thread step.
    fn note_step(&self, started: Option<Instant>) {
        *lock(&self.step_started) = started;
    }

    /// Latch `proven` when the last view's drain anchors are all confirmed,
    /// and store it in the gate. Only an anchor proof opens staging; nothing
    /// closes it again. Called with the state lock held, so gate writes
    /// follow state changes in order.
    fn sync_gate(&self, state: &mut ShareState) {
        if !state.proven && state.anchor_proof() {
            state.proven = true;
            state.required.clear();
            state.since.clear();
            state.unreadable.clear();
        }
        self.share_gate.store(!state.proven, Ordering::Release);
    }

    /// Record the shared-stage part of a peer view.
    ///
    /// A drain worker is never held. For a stage replica the required set is
    /// every `drain` row published within [`SHARE_PEER_FRESH`], with its
    /// current incarnation. It is computed again on every view until an
    /// anchor proof latches; after that nothing is required again. With no
    /// fresh `drain` row nothing is required and nothing is proven: staging
    /// stays off and `/lb_health` stays 200.
    pub fn note_share(&self, now: Instant, view: &StagePeerLiveness) {
        let mut state = lock(&self.share);
        state.exchanged = true;
        if self.role != StageLivenessRole::Stage {
            state.proven = true;
        }
        if state.proven {
            state.required.clear();
            self.sync_gate(&mut state);
            return;
        }
        let fresh_micros =
            i64::try_from(self.thresholds.share_peer_fresh.as_micros()).unwrap_or(i64::MAX);
        let fresh = |peer: &StagePeerProgress| {
            view.db_clock_micros.saturating_sub(peer.published_micros) <= fresh_micros
        };
        let required: BTreeMap<String, String> = view
            .peers
            .iter()
            .filter(|peer| peer.role == StageLivenessRole::Drain && fresh(peer))
            .map(|peer| (peer.replica_id.clone(), peer.record.incarnation.clone()))
            .collect();
        let seen: HashSet<&str> = view
            .peers
            .iter()
            .map(|peer| peer.replica_id.as_str())
            .collect();
        state.confirmed.retain(|(id, _)| seen.contains(id.as_str()));
        state
            .since
            .retain(|key, _| required.get(&key.0) == Some(&key.1));
        state
            .unreadable
            .retain(|key| required.get(&key.0) == Some(&key.1));
        for (id, incarnation) in &required {
            let key = (id.clone(), incarnation.clone());
            if !state.confirmed.contains(&key) {
                state.since.entry(key).or_insert(now);
            }
        }
        state.required = required;
        self.sync_gate(&mut state);
    }

    /// The (peer, incarnation) pairs whose marker the probe thread should
    /// look for.
    pub fn share_checks(&self) -> Vec<(String, String)> {
        lock(&self.share)
            .unconfirmed()
            .map(|(id, incarnation)| (id.clone(), incarnation.clone()))
            .collect()
    }

    /// Record that `id`'s marker holds `incarnation`. Once seen, the pair
    /// stays confirmed while the peer keeps its row.
    pub fn note_marker_seen(&self, id: &str, incarnation: &str) {
        let mut state = lock(&self.share);
        let key = (id.to_owned(), incarnation.to_owned());
        state.since.remove(&key);
        state.unreadable.remove(&key);
        state.confirmed.insert(key);
        self.sync_gate(&mut state);
    }

    /// Record the outcome of a marker read that did not show `incarnation`:
    /// `readable` when the read completed (no file, or another value), so it
    /// counts toward the 503 words; else an I/O error, "cannot decide".
    pub fn note_marker_unseen(&self, id: &str, incarnation: &str, readable: bool) {
        let mut state = lock(&self.share);
        if state.required.get(id).map(String::as_str) != Some(incarnation) {
            return;
        }
        let key = (id.to_owned(), incarnation.to_owned());
        if readable {
            state.unreadable.remove(&key);
        } else {
            state.unreadable.insert(key);
        }
    }

    /// One marker step, on the probe or marker thread: keep this replica's
    /// own marker. A stage replica then looks for each required drain's
    /// marker. A completed read without it is "not seen"; a read that fails
    /// with an I/O error is "cannot decide" (module docs, step 6). The drain
    /// worker reads its own marker back and records whether it shows its
    /// current incarnation: only then does it publish as an anchor. Returns
    /// the own marker's write result.
    pub fn share_step(&self, markers: &ShareMarkers) -> std::io::Result<()> {
        let own = markers
            .ensure(&self.replica_id, &self.incarnation)
            .map(|_| ());
        if self.role != StageLivenessRole::Stage {
            let read_back = own.is_ok()
                && markers.read(&self.replica_id).ok().flatten().as_deref()
                    == Some(self.incarnation.as_str());
            *lock(&self.anchor_verified) = read_back.then(Instant::now);
            return own;
        }
        for (id, incarnation) in self.share_checks() {
            match markers.read(&id) {
                Ok(Some(found)) if found == incarnation => {
                    self.note_marker_seen(&id, &incarnation);
                }
                Ok(_) => self.note_marker_unseen(&id, &incarnation, true),
                Err(_) => self.note_marker_unseen(&id, &incarnation, false),
            }
        }
        own
    }

    /// The drain worker only: whether its last marker read-back showed its
    /// incarnation and is at most `anchor_verify_max_age` old at `now`.
    /// `true` for a stage replica, which anchors nobody.
    pub fn anchor_verified(&self, now: Instant) -> bool {
        if self.role == StageLivenessRole::Stage {
            return true;
        }
        lock(&self.anchor_verified).is_some_and(|at| {
            now.saturating_duration_since(at) <= self.thresholds.anchor_verify_max_age
        })
    }

    pub fn thresholds(&self) -> LivenessThresholds {
        self.thresholds
    }

    /// The bounds an exchange passes to the store.
    pub fn limits(&self) -> StageLivenessLimits {
        StageLivenessLimits {
            fresh_within: self.thresholds.publish_fresh,
            deadline: self.thresholds.publish_deadline,
            statement_timeout: self.thresholds.statement_timeout,
            retain: RETAIN,
        }
    }

    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }

    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }

    pub fn stale_after(&self) -> Duration {
        self.thresholds.stale_after
    }

    /// Fully successful probes so far.
    pub fn progress(&self) -> u64 {
        lock(&self.own).count
    }

    fn nanos_since_origin(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.origin).as_nanos()).unwrap_or(u64::MAX)
    }

    fn instant_of(&self, nanos: u64) -> Instant {
        self.origin
            .checked_add(Duration::from_nanos(nanos))
            .unwrap_or(self.origin)
    }

    /// Record a good probe at `at`: one more success. The success time never
    /// moves back.
    pub fn note_good(&self, at: Instant) {
        let mut own = lock(&self.own);
        own.count = own.count.saturating_add(1);
        self.last_good
            .fetch_max(self.nanos_since_origin(at), Ordering::Relaxed);
    }

    /// What the next exchange publishes.
    pub fn publication(&self) -> StageLivenessPublication {
        let (count, last_good) = {
            let own = lock(&self.own);
            (own.count, self.last_good.load(Ordering::Relaxed))
        };
        StageLivenessPublication {
            incarnation: self.incarnation.clone(),
            progress: count,
            last_good: self.instant_of(last_good),
            clock: *lock(&self.clock),
            role: self.published_role(Instant::now()),
        }
    }

    /// The role the next exchange publishes: the drain worker publishes
    /// `drain` (an anchor) only while its marker read-back is verified.
    fn published_role(&self, now: Instant) -> StageLivenessRole {
        if self.role == StageLivenessRole::Drain && !self.anchor_verified(now) {
            StageLivenessRole::DrainUnverified
        } else {
            self.role
        }
    }

    /// How long before `now` the last good probe was.
    pub fn last_good_age(&self, now: Instant) -> Duration {
        let last = Duration::from_nanos(self.last_good.load(Ordering::Relaxed));
        now.saturating_duration_since(self.origin)
            .saturating_sub(last)
    }

    fn is_stale_at(&self, at: Instant) -> bool {
        self.last_good_age(at) >= self.thresholds.stale_after
    }

    /// Record a peer view whose exchange started at `at`.
    ///
    /// The first view taken after this replica went stale becomes the
    /// baseline. A later view counts a peer as progressing only if it has the
    /// same incarnation as in the baseline, a higher count, and that count
    /// was accepted after the view the baseline holds for it, and within
    /// [`PROGRESS_WINDOW`] of this view. A peer that is
    /// new, restarted (another incarnation) or reappears after a gap gets a
    /// fresh baseline entry from this view. A peer absent from this view is
    /// dropped from the baseline.
    pub fn note_peers(&self, at: Instant, view: &StagePeerLiveness) {
        // A drain row is never a K11 peer: its count never rises, and its
        // stage is the reference, not a web replica's evidence.
        let stage_peers: Vec<&StagePeerProgress> = view
            .peers
            .iter()
            .filter(|peer| peer.role == StageLivenessRole::Stage)
            .collect();
        let epoch = self.last_good.load(Ordering::Relaxed);
        let after_stale = self.is_stale_at(at);
        let mut state = lock(&self.peers);
        let mut progressing = 0;
        let window_start = view.db_clock_micros.saturating_sub(
            i64::try_from(self.thresholds.progress_window.as_micros()).unwrap_or(i64::MAX),
        );
        if !after_stale {
            state.baseline = None;
        } else {
            let entry = |record: &StageProgressRecord| PeerBaseline {
                incarnation: record.incarnation.clone(),
                progress: record.progress,
                after_micros: view.db_clock_micros,
            };
            match state.baseline.as_mut() {
                Some(baseline) if baseline.epoch == epoch => {
                    let mut next = HashMap::with_capacity(stage_peers.len());
                    for peer in &stage_peers {
                        let record = &peer.record;
                        let kept = match baseline.peers.remove(&peer.replica_id) {
                            Some(base) if base.incarnation == record.incarnation => {
                                if record.progress > base.progress
                                    && record.progressed_micros > base.after_micros
                                    && record.progressed_micros > window_start
                                {
                                    progressing += 1;
                                }
                                base
                            }
                            _ => entry(record),
                        };
                        next.insert(peer.replica_id.clone(), kept);
                    }
                    baseline.peers = next;
                }
                _ => {
                    state.baseline = Some(Baseline {
                        epoch,
                        peers: stage_peers
                            .iter()
                            .map(|peer| (peer.replica_id.clone(), entry(&peer.record)))
                            .collect(),
                    });
                }
            }
        }
        state.latest = Some(LatestView {
            at,
            epoch,
            after_stale,
            peers: u64::try_from(stage_peers.len()).unwrap_or(u64::MAX),
            progressing,
        });
    }

    /// The peer evidence at `now`.
    pub fn peer_evidence(&self, now: Instant) -> PeerEvidence {
        let Some(latest) = lock(&self.peers).latest else {
            return PeerEvidence::Unknown;
        };
        if now.saturating_duration_since(latest.at) >= self.thresholds.peer_view_max_age
            || !latest.after_stale
            || latest.epoch != self.last_good.load(Ordering::Relaxed)
        {
            return PeerEvidence::Unknown;
        }
        if latest.progressing > 0 {
            PeerEvidence::ProgressingPeer
        } else {
            PeerEvidence::NoProgress
        }
    }

    /// Compare this replica's row as the exchange found it with what this
    /// process last wrote. A difference means another process publishes
    /// under the same `replica_id`, and its progress can hide this replica's
    /// stale mount (or the reverse). Warns, at most every [`WARN_EVERY`].
    pub fn note_publication(&self, now: Instant, view: &StagePeerLiveness) {
        let mut last = lock(&self.last_published);
        if let (Some(mine), Some(found)) = (last.as_ref(), view.prior.as_ref())
            && mine != found
        {
            let mut warned = lock(&self.duplicate_warned);
            let logged_at = warned
                .as_ref()
                .map(|(at, _, _)| *at)
                .filter(|at| now.saturating_duration_since(*at) < WARN_EVERY);
            let due = logged_at.is_none();
            *warned = Some((logged_at.unwrap_or(now), mine.clone(), found.clone()));
            if due {
                warn!(
                    replica_id = %self.replica_id,
                    last_published = ?mine,
                    found = ?found,
                    "another process publishes stage liveness under this replica id; \
                     give each replica a distinct id"
                );
            }
        }
        *last = view.published.clone();
    }

    /// The last duplicate-identity sighting, as (what this process last
    /// published, what the exchange found), or `None`.
    pub fn duplicate_identity_seen(&self) -> Option<(StageProgressRecord, StageProgressRecord)> {
        lock(&self.duplicate_warned)
            .as_ref()
            .map(|(_, mine, found)| (mine.clone(), found.clone()))
    }

    /// Forget what this process last wrote: a failed exchange may still have
    /// committed, so the next comparison would be a false alarm.
    fn forget_publication(&self) {
        *lock(&self.last_published) = None;
    }

    fn note_clock(&self, db_micros: i64, received: Instant) {
        *lock(&self.clock) = Some(StageLivenessClock {
            db_micros,
            received,
        });
    }

    /// The `/lb_health` fault at `now`, or `None`. A shared-stage fault comes
    /// first: a replica on the wrong stage must not serve even if its own
    /// probe is fine.
    pub fn fault(&self, now: Instant) -> Option<&'static str> {
        if self.role != StageLivenessRole::Stage {
            // The drain answers `drain_role` on `/lb_health` anyway; it has no
            // own K11 verdict and is never held. Its one fault is an anchor it
            // cannot verify, for `/health_check`.
            return (!self.anchor_verified(now)).then_some(STAGE_ANCHOR_UNVERIFIED);
        }
        self.share_fault(now)
            .or_else(|| decide(self.is_stale_at(now), self.peer_evidence(now)))
    }

    /// The shared-stage part of [`Self::fault`]. `None` when the guard is off.
    pub fn share_fault(&self, now: Instant) -> Option<&'static str> {
        if !self.share_guard {
            return None;
        }
        self.share_verdict(now).fault()
    }

    /// Probe threads started so far.
    pub fn threads_started(&self) -> usize {
        self.threads_started.load(Ordering::Relaxed)
    }

    /// Probes started so far.
    pub fn probes_started(&self) -> u64 {
        self.probes_started.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self, now: Instant) -> StageLivenessSnapshot {
        let latest = lock(&self.peers).latest;
        let (share, share_unconfirmed) = if self.share_guard {
            let stuck = self.step_stuck(now);
            let state = lock(&self.share);
            (
                Some(
                    state
                        .verdict(now, self.thresholds.share_grace, self.origin, stuck)
                        .name(),
                ),
                state.unconfirmed().map(|(id, _)| id.clone()).collect(),
            )
        } else {
            (None, Vec::new())
        };
        StageLivenessSnapshot {
            share,
            share_unconfirmed,
            replica_id: self.replica_id.clone(),
            incarnation: self.incarnation.clone(),
            progress: self.progress(),
            probe_age_millis: millis(self.last_good_age(now)),
            probe_in_flight: self.in_flight.load(Ordering::Relaxed),
            probe_failures: self.probe_failures.load(Ordering::Relaxed),
            peer_view_age_millis: latest.map(|view| millis(now.saturating_duration_since(view.at))),
            progressing_peers: latest.map(|view| view.progressing),
            peers: latest.map(|view| view.peers),
            fault: self.fault(now),
        }
    }

    /// Record the verdict in the gauges, and log a transition once.
    pub fn report(&self, now: Instant) {
        let snapshot = self.snapshot(now);
        if self.role != StageLivenessRole::Stage {
            self.report_anchor(now, &snapshot);
            return;
        }
        instruments()
            .ejected
            .record(u64::from(snapshot.fault.is_some()), &[]);
        // The transition log below is K11's own; the share guard logs its
        // own transitions in `report_share`.
        let ejected = decide(self.is_stale_at(now), self.peer_evidence(now)).is_some();
        instruments()
            .probe_age
            .record(snapshot.probe_age_millis / 1000, &[]);
        if let Some(progressing) = snapshot.progressing_peers {
            instruments().progressing_peers.record(progressing, &[]);
        }
        if self.share_guard {
            self.report_share(now, &snapshot);
        }
        if self.ejected.swap(ejected, Ordering::Relaxed) != ejected {
            if ejected {
                warn!(
                    replica_id = %snapshot.replica_id,
                    probe_age_millis = snapshot.probe_age_millis,
                    probe_in_flight = snapshot.probe_in_flight,
                    progressing_peers = snapshot.progressing_peers,
                    peers = snapshot.peers,
                    "stage mount is stale here while a peer keeps writing it; /lb_health answers stage_unavailable_local"
                );
            } else {
                info!(
                    replica_id = %snapshot.replica_id,
                    probe_age_millis = snapshot.probe_age_millis,
                    progressing_peers = snapshot.progressing_peers,
                    "stage liveness no longer ejects this replica"
                );
            }
        }
    }

    /// The drain worker's anchor gauge, and one log line per change.
    fn report_anchor(&self, now: Instant, snapshot: &StageLivenessSnapshot) {
        let verified = self.anchor_verified(now);
        instruments()
            .share_anchor_unverified
            .record(u64::from(!verified), &[]);
        let mut reported = lock(&self.anchor_reported);
        if *reported == Some(verified) {
            return;
        }
        let first = reported.is_none();
        *reported = Some(verified);
        if !verified {
            error!(
                replica_id = %snapshot.replica_id,
                "the drain cannot read back its own stage marker; it publishes \
                 drain_unverified and anchors no web replica, so unproven web replicas \
                 write directly. Check the stage mount on this host"
            );
        } else if !first {
            info!(
                replica_id = %snapshot.replica_id,
                "the drain reads back its own stage marker again; it anchors the shared-stage check"
            );
        }
    }

    /// The share gauge and one log line per share verdict change.
    fn report_share(&self, now: Instant, snapshot: &StageLivenessSnapshot) {
        let verdict = self.share_verdict(now);
        instruments()
            .share_unproven
            .record(u64::from(verdict.holds_staging()), &[]);
        instruments()
            .share_undecided
            .record(u64::from(verdict == ShareVerdict::Undecided), &[]);
        let mut reported = lock(&self.share_reported);
        if *reported == Some(verdict) {
            return;
        }
        *reported = Some(verdict);
        let unconfirmed = &snapshot.share_unconfirmed;
        match verdict {
            ShareVerdict::Pending => {}
            ShareVerdict::PendingTooLong => error!(
                replica_id = %snapshot.replica_id,
                "no stage liveness exchange has succeeded since boot; staging is off and \
                 /lb_health answers stage_share_pending. Check this host's Postgres access"
            ),
            ShareVerdict::NoAnchor => info!(
                replica_id = %snapshot.replica_id,
                "no fresh drain row proves this stage is the drain's; staging is off and new \
                 fragments are written directly until the drain's marker is seen"
            ),
            ShareVerdict::Shared => info!(
                replica_id = %snapshot.replica_id,
                "the drain's stage marker is visible; staging is open"
            ),
            ShareVerdict::Unverified => warn!(
                replica_id = %snapshot.replica_id,
                ?unconfirmed,
                "the drain's stage marker is not visible yet; staging is off and \
                 /lb_health answers stage_share_unverified"
            ),
            ShareVerdict::NotShared => error!(
                replica_id = %snapshot.replica_id,
                ?unconfirmed,
                "this replica's stage is not the drain's stage; staging is off and \
                 /lb_health answers stage_not_shared. Check the stage mount on this host"
            ),
            ShareVerdict::Undecided => warn!(
                replica_id = %snapshot.replica_id,
                ?unconfirmed,
                "the drain's stage marker cannot be read here (an I/O error or a hung stage \
                 step); staging is off, new fragments are written directly, and /lb_health \
                 stays 200. Check the stage mount on this host"
            ),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// At most one warning per `every`.
#[derive(Default)]
struct WarnEvery {
    last: Option<Instant>,
}

impl WarnEvery {
    fn allow(&mut self, now: Instant, every: Duration) -> bool {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < every)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}

/// Start the one probe thread for `liveness`. A second call starts nothing.
///
/// The thread runs `probe` every `interval` until `stop` is set. A probe that
/// never returns keeps the thread, and so all probing, parked in it: the
/// replica then ages to stale, which is the signal. Nothing replaces the
/// thread, so a hung mount costs exactly one thread.
pub fn spawn_probe_thread(
    liveness: &Arc<StageLiveness>,
    probe: ProbeFn,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<bool> {
    spawn_probe_thread_with_markers(liveness, probe, None, interval, stop)
}

/// [`spawn_probe_thread`], plus the shared-stage marker step after each
/// probe when `markers` is set. A hung probe parks the marker step too, so
/// nothing new is confirmed while the mount hangs. When the thread stops, it
/// removes this replica's own marker.
pub fn spawn_probe_thread_with_markers(
    liveness: &Arc<StageLiveness>,
    probe: ProbeFn,
    markers: Option<ShareMarkers>,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<bool> {
    if liveness
        .threads_started
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(false);
    }
    let liveness = liveness.clone();
    std::thread::Builder::new()
        .name("stage-liveness-probe".to_owned())
        .spawn(move || probe_loop(&liveness, &probe, markers.as_ref(), interval, &stop))
        .map(|_detached| true)
}

/// The drain worker's thread: keep this replica's marker and read it back,
/// every `interval`, and remove it at stop. A hung step stops the read-backs,
/// so the drain falls back to `drain_unverified` after
/// [`ANCHOR_VERIFY_MAX_AGE`]. It runs no probe and counts no progress, so the
/// drain's row never looks like K11 progress, even to an older binary.
pub fn spawn_marker_thread(
    liveness: &Arc<StageLiveness>,
    markers: ShareMarkers,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<bool> {
    if liveness
        .threads_started
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(false);
    }
    let liveness = liveness.clone();
    std::thread::Builder::new()
        .name("stage-share-marker".to_owned())
        .spawn(move || marker_loop(&liveness, &markers, interval, &stop))
        .map(|_detached| true)
}

fn marker_loop(
    liveness: &StageLiveness,
    markers: &ShareMarkers,
    interval: Duration,
    stop: &AtomicBool,
) {
    let mut warn_every = WarnEvery::default();
    while !stop.load(Ordering::Relaxed) {
        // Write the marker and read it back: the drain publishes `drain` only
        // while the read-back shows its incarnation.
        if let Err(error) = liveness.share_step(markers)
            && warn_every.allow(Instant::now(), WARN_EVERY)
        {
            warn!(%error, "stage share marker could not be written");
        }
        let wake = Instant::now() + interval;
        while !stop.load(Ordering::Relaxed) {
            let left = wake.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
    if let Err(error) = markers.remove_if(liveness.replica_id(), liveness.incarnation()) {
        warn!(%error, "stage share marker could not be removed at stop");
    }
}

fn probe_loop(
    liveness: &StageLiveness,
    probe: &ProbeFn,
    markers: Option<&ShareMarkers>,
    interval: Duration,
    stop: &AtomicBool,
) {
    let mut warn_every = WarnEvery::default();
    let mut marker_warn_every = WarnEvery::default();
    while !stop.load(Ordering::Relaxed) {
        // The step (probe plus marker reads) is timed: one that hangs makes
        // the shared-stage check "cannot decide" (module docs, step 6).
        liveness.note_step(Some(Instant::now()));
        liveness.probes_started.fetch_add(1, Ordering::Relaxed);
        liveness.in_flight.store(true, Ordering::Relaxed);
        let result = probe();
        liveness.in_flight.store(false, Ordering::Relaxed);
        let now = Instant::now();
        match result {
            Ok(()) => liveness.note_good(now),
            Err(error) => {
                let failures = liveness.probe_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if warn_every.allow(now, WARN_EVERY) {
                    warn!(%error, failures, "stage liveness probe failed");
                }
            }
        }
        if let Some(markers) = markers
            && let Err(error) = liveness.share_step(markers)
            && marker_warn_every.allow(Instant::now(), WARN_EVERY)
        {
            warn!(%error, "stage share marker could not be written");
        }
        liveness.note_step(None);
        // Sleep in short steps so `stop` is seen promptly.
        let wake = Instant::now() + interval;
        while !stop.load(Ordering::Relaxed) {
            let left = wake.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
    if let Some(markers) = markers
        && let Err(error) = markers.remove_if(liveness.replica_id(), liveness.incarnation())
    {
        warn!(%error, "stage share marker could not be removed at stop");
    }
}

/// What one tick of the exchange task did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessTick {
    /// Published and read peers.
    Exchanged,
    /// The exchange failed or timed out.
    ExchangeFailed,
    /// Draining: this tick deleted the row.
    Withdrew,
    /// Draining: the delete failed or timed out; the next tick retries.
    WithdrawFailed,
    /// Draining and already withdrawn: nothing to do.
    Withdrawn,
}

/// One tick of the exchange task.
///
/// A draining replica (lame duck or SIGTERM) never publishes again, so its
/// count stops moving and no peer can count it as progressing. It also
/// deletes its row once, so it leaves the peers' baselines.
pub async fn liveness_tick<X, XFut, W, WFut, E>(
    liveness: &StageLiveness,
    draining: bool,
    withdrawn: &mut bool,
    exchange: X,
    withdraw: W,
    timeout: Duration,
    warn_every: &mut Option<Instant>,
) -> LivenessTick
where
    X: FnOnce(StageLivenessPublication) -> XFut,
    XFut: std::future::Future<Output = Result<StagePeerLiveness, E>>,
    W: FnOnce() -> WFut,
    WFut: std::future::Future<Output = Result<bool, E>>,
    E: std::fmt::Display,
{
    if !draining {
        return if exchange_once(liveness, exchange, timeout, warn_every).await {
            LivenessTick::Exchanged
        } else {
            LivenessTick::ExchangeFailed
        };
    }
    if *withdrawn {
        return LivenessTick::Withdrawn;
    }
    match tokio::time::timeout(timeout, withdraw()).await {
        Ok(Ok(_deleted)) => {
            *withdrawn = true;
            info!(
                replica_id = %liveness.replica_id(),
                "stage liveness withdrawn for drain; peers no longer count this replica"
            );
            LivenessTick::Withdrew
        }
        Ok(Err(error)) => {
            warn!(%error, "stage liveness withdraw failed; the next tick retries");
            LivenessTick::WithdrawFailed
        }
        Err(_elapsed) => {
            warn!("stage liveness withdraw timed out; the next tick retries");
            LivenessTick::WithdrawFailed
        }
    }
}

/// One exchange: publish, read peers, record the view. A failure or a timeout
/// records nothing, so the last view ages to [`PeerEvidence::Unknown`].
///
/// The view is recorded at the instant the exchange started: no later than
/// the read it reflects. The reply's database clock becomes the anchor for
/// the next publication's deadline.
///
/// Returns whether the exchange succeeded.
pub async fn exchange_once<F, Fut, E>(
    liveness: &StageLiveness,
    exchange: F,
    timeout: Duration,
    warn_every: &mut Option<Instant>,
) -> bool
where
    F: FnOnce(StageLivenessPublication) -> Fut,
    Fut: std::future::Future<Output = Result<StagePeerLiveness, E>>,
    E: std::fmt::Display,
{
    let started = Instant::now();
    let result = tokio::time::timeout(timeout, exchange(liveness.publication())).await;
    let now = Instant::now();
    let warn = |message: String, warn_every: &mut Option<Instant>| {
        if warn_every.is_none_or(|last| now.saturating_duration_since(last) >= WARN_EVERY) {
            *warn_every = Some(now);
            warn!(error = %message, "stage liveness exchange failed; this signal cannot eject until it succeeds");
        }
    };
    match result {
        Ok(Ok(view)) => {
            liveness.note_clock(view.db_clock_micros, now);
            liveness.note_publication(now, &view);
            liveness.note_peers(started, &view);
            liveness.note_share(now, &view);
            true
        }
        Ok(Err(error)) => {
            liveness.forget_publication();
            warn(error.to_string(), warn_every);
            false
        }
        Err(_elapsed) => {
            liveness.forget_publication();
            warn(format!("timed out after {timeout:?}"), warn_every);
            false
        }
    }
}

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
//!    [`PUBLISH_DEADLINE`] of being sent (see
//!    `lore_postgres::domain::fragments::StageLivenessPublication`).
//! 3. **Decision.** This replica is stale after [`STALE_AFTER`] with no own
//!    success, on its monotonic clock. The first peer view taken after that is
//!    the baseline. A later view in which a peer of the same incarnation has a
//!    higher count, accepted after the baseline view and within
//!    [`PROGRESS_WINDOW`], proves the stage still works for that peer: 503
//!    `stage_unavailable_local`. Anything else is 200. When the peer stops
//!    too, its last increase leaves the window and the replica is readmitted.
//!
//! **Why no cell-wide fault ejects.** In a cell-wide hang no probe succeeds,
//! so no count moves after a baseline, and nobody ejects. Probe duration and
//! skew do not matter. A delayed or replayed statement cannot fake a move: an
//! accepted increase ran after the baseline, so it reports a peer success no
//! more than `PUBLISH_FRESH + PUBLISH_DEADLINE` (6 s) before the baseline,
//! which is at least [`STALE_AFTER`] after this replica's last success. So a
//! replica ejects only if a peer succeeded at least 9 s after it last did.
//! Two replicas cannot both meet that against each other, so a double eject
//! is impossible in any timing.
//!
//! One own success brings the replica back.

use std::collections::HashMap;
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
use lore_postgres::domain::fragments::StagePeerLiveness;
use lore_postgres::domain::fragments::StageProgressRecord;
use lore_telemetry::InstrumentProvider;
use opentelemetry::metrics::Gauge;
use serde::Serialize;
use tracing::info;
use tracing::warn;

/// The `/lb_health` word for a replica whose own stage mount is stale while a
/// peer is seen writing it.
pub const STAGE_UNAVAILABLE_LOCAL: &str = "stage_unavailable_local";

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
        }
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
                    let mut next = HashMap::with_capacity(view.peers.len());
                    for peer in &view.peers {
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
                        peers: view
                            .peers
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
            peers: u64::try_from(view.peers.len()).unwrap_or(u64::MAX),
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

    /// The `/lb_health` fault at `now`, or `None`.
    pub fn fault(&self, now: Instant) -> Option<&'static str> {
        decide(self.is_stale_at(now), self.peer_evidence(now))
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
        StageLivenessSnapshot {
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
        let ejected = snapshot.fault.is_some();
        instruments().ejected.record(u64::from(ejected), &[]);
        instruments()
            .probe_age
            .record(snapshot.probe_age_millis / 1000, &[]);
        if let Some(progressing) = snapshot.progressing_peers {
            instruments().progressing_peers.record(progressing, &[]);
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
        .spawn(move || probe_loop(&liveness, &probe, interval, &stop))
        .map(|_detached| true)
}

fn probe_loop(liveness: &StageLiveness, probe: &ProbeFn, interval: Duration, stop: &AtomicBool) {
    let mut warn_every = WarnEvery::default();
    while !stop.load(Ordering::Relaxed) {
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

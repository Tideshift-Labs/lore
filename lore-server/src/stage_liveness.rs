// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift), WP-115 K11: eject a `role = "stage"` replica whose
//! own mount of the shared stage is stale, but only while a peer's is fresh.
//!
//! In the multi-host cell every web replica hard-mounts one NFS stage. A stage
//! fault is normally cell-wide, and `/lb_health` must not eject on a cell-wide
//! signal: ejecting replicas one after another refuses the whole cell (see
//! `lorehub/docs/learnings/backpressure-routed-into-a-binary-liveness-verdict-ejects-every-replica-at-once.md`).
//! But one host's mount can go stale alone, and that host then keeps taking
//! connections whose uploads hang. A peer that can still write the same stage
//! is the evidence that the fault is local.
//!
//! Three parts:
//!
//! 1. **Probe.** One dedicated OS thread (not the tokio pool: a hard-mount write
//!    can block forever) writes, fsyncs and removes one small file under
//!    `<stage>/liveness/`, and records the time of each success. If a write
//!    hangs, the thread hangs with it. No second thread is ever started, so at
//!    most one probe is in flight.
//! 2. **Exchange.** A tokio task publishes how long ago the last good probe was
//!    to Postgres, and reads how many peers of the same cell are fresh. The
//!    database clock decides freshness, so host clock skew does not matter.
//! 3. **Decision.** [`decide`]: 503 `stage_unavailable_local` only when this
//!    replica is stale AND the last peer view (itself recent) shows at least
//!    one fresh peer. No fresh peer is a cell-wide fault: 200. No recent peer
//!    view (Postgres unreachable or slow) is "cannot decide": 200.
//!
//! The threshold is the hysteresis: a replica is stale only after
//! [`STALE_AFTER`] with no good probe, so one slow probe does not flap it, and
//! one good probe brings it back.

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
use lore_postgres::domain::fragments::StagePeerLiveness;
use lore_telemetry::InstrumentProvider;
use opentelemetry::metrics::Gauge;
use serde::Serialize;
use tracing::info;
use tracing::warn;

/// The `/lb_health` word for a replica whose own stage mount is stale while a
/// peer's is fresh.
pub const STAGE_UNAVAILABLE_LOCAL: &str = "stage_unavailable_local";

/// How often the probe thread writes its file.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// A replica is stale after this long with no good probe. The same window
/// decides, in SQL, whether a peer is fresh.
///
/// 15 s is about seven probe intervals: a single slow NFS round trip, or a
/// short server hiccup that every host sees, does not eject anyone. It is
/// also well under the time a hard mount stays hung after a real fault.
pub const STALE_AFTER: Duration = Duration::from_secs(15);
/// How often this replica publishes and reads peers.
pub const EXCHANGE_INTERVAL: Duration = Duration::from_secs(2);
/// The budget for one exchange.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);
/// A peer view older than this is "cannot decide". Five exchange intervals,
/// so a few slow exchanges do not drop the evidence, but a Postgres outage
/// does within seconds.
pub const PEER_VIEW_MAX_AGE: Duration = Duration::from_secs(10);
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
    /// Fresh peers in the last peer view.
    fresh_peers: Gauge<u64>,
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
            fresh_peers: meter
                .u64_gauge(provider.scope_name("stage_liveness_fresh_peers"))
                .build(),
        }
    })
}

/// What the last peer view says, once its own age is taken into account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvidence {
    /// No peer view, or one older than [`PEER_VIEW_MAX_AGE`]: Postgres is
    /// unreachable or slow. Never ejects.
    Unknown,
    /// A recent view with no fresh peer: the stage is stale for everyone.
    NoFreshPeer,
    /// A recent view with at least one fresh peer.
    FreshPeer,
}

/// The K11 rule. Pure, so every case is a table test.
pub fn decide(self_stale: bool, peers: PeerEvidence) -> Option<&'static str> {
    (self_stale && peers == PeerEvidence::FreshPeer).then_some(STAGE_UNAVAILABLE_LOCAL)
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
/// Stable for the life of the process. A restarted process on the same host
/// under systemd gets a new id; its old row ages out and is pruned. In a
/// container the host is the container id and the process id is 1, so a
/// restarted container keeps its id.
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
    pub probe_age_millis: u64,
    pub probe_in_flight: bool,
    pub probe_failures: u64,
    pub peer_view_age_millis: Option<u64>,
    pub fresh_peers: Option<u64>,
    pub peers: Option<u64>,
    pub fault: Option<&'static str>,
}

/// One replica's stage liveness: the probe's last success, the last peer
/// view, and the verdict over both.
pub struct StageLiveness {
    replica_id: String,
    origin: Instant,
    /// Nanoseconds after `origin` of the last good probe. Starts at 0: the
    /// stage was proven writable at boot by `WriteBehindStage::open`.
    last_good: AtomicU64,
    probes_started: AtomicU64,
    probe_failures: AtomicU64,
    in_flight: AtomicBool,
    /// Probe threads ever started for this replica. Never above 1.
    threads_started: AtomicUsize,
    peers: Mutex<Option<(Instant, StagePeerLiveness)>>,
    /// The last verdict, for one log line per transition.
    ejected: AtomicBool,
    stale_after: Duration,
    peer_view_max_age: Duration,
}

impl StageLiveness {
    pub fn new(replica_id: String) -> Self {
        Self::with_thresholds(replica_id, STALE_AFTER, PEER_VIEW_MAX_AGE)
    }

    pub fn with_thresholds(
        replica_id: String,
        stale_after: Duration,
        peer_view_max_age: Duration,
    ) -> Self {
        Self {
            replica_id,
            origin: Instant::now(),
            last_good: AtomicU64::new(0),
            probes_started: AtomicU64::new(0),
            probe_failures: AtomicU64::new(0),
            in_flight: AtomicBool::new(false),
            threads_started: AtomicUsize::new(0),
            peers: Mutex::new(None),
            ejected: AtomicBool::new(false),
            stale_after,
            peer_view_max_age,
        }
    }

    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }

    pub fn stale_after(&self) -> Duration {
        self.stale_after
    }

    fn nanos_since_origin(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.origin).as_nanos()).unwrap_or(u64::MAX)
    }

    /// Record a good probe at `at`. Never moves the clock back.
    pub fn note_good(&self, at: Instant) {
        self.last_good
            .fetch_max(self.nanos_since_origin(at), Ordering::Relaxed);
    }

    /// How long before `now` the last good probe was.
    pub fn last_good_age(&self, now: Instant) -> Duration {
        let last = Duration::from_nanos(self.last_good.load(Ordering::Relaxed));
        now.saturating_duration_since(self.origin)
            .saturating_sub(last)
    }

    /// Record a peer view taken at `at`.
    pub fn note_peers(&self, at: Instant, view: StagePeerLiveness) {
        *self.peers.lock().unwrap_or_else(|error| error.into_inner()) = Some((at, view));
    }

    fn peer_view(&self, now: Instant) -> Option<(Duration, StagePeerLiveness)> {
        self.peers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .map(|(at, view)| (now.saturating_duration_since(at), view))
    }

    /// The peer evidence at `now`.
    pub fn peer_evidence(&self, now: Instant) -> PeerEvidence {
        match self.peer_view(now) {
            Some((age, view)) if age < self.peer_view_max_age => {
                if view.fresh_peers > 0 {
                    PeerEvidence::FreshPeer
                } else {
                    PeerEvidence::NoFreshPeer
                }
            }
            _ => PeerEvidence::Unknown,
        }
    }

    /// The `/lb_health` fault at `now`, or `None`.
    pub fn fault(&self, now: Instant) -> Option<&'static str> {
        decide(
            self.last_good_age(now) >= self.stale_after,
            self.peer_evidence(now),
        )
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
        let view = self.peer_view(now);
        StageLivenessSnapshot {
            replica_id: self.replica_id.clone(),
            probe_age_millis: millis(self.last_good_age(now)),
            probe_in_flight: self.in_flight.load(Ordering::Relaxed),
            probe_failures: self.probe_failures.load(Ordering::Relaxed),
            peer_view_age_millis: view.map(|(age, _)| millis(age)),
            fresh_peers: view.map(|(_, view)| view.fresh_peers),
            peers: view.map(|(_, view)| view.peers),
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
        if let Some(fresh) = snapshot.fresh_peers {
            instruments().fresh_peers.record(fresh, &[]);
        }
        if self.ejected.swap(ejected, Ordering::Relaxed) != ejected {
            if ejected {
                warn!(
                    replica_id = %snapshot.replica_id,
                    probe_age_millis = snapshot.probe_age_millis,
                    probe_in_flight = snapshot.probe_in_flight,
                    fresh_peers = snapshot.fresh_peers,
                    peers = snapshot.peers,
                    "stage mount is stale here while a peer's is fresh; /lb_health answers stage_unavailable_local"
                );
            } else {
                info!(
                    replica_id = %snapshot.replica_id,
                    probe_age_millis = snapshot.probe_age_millis,
                    fresh_peers = snapshot.fresh_peers,
                    "stage liveness no longer ejects this replica"
                );
            }
        }
    }
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

/// One exchange: publish, read peers, record the view. A failure or a timeout
/// records nothing, so the last view ages to [`PeerEvidence::Unknown`].
///
/// Returns whether the exchange succeeded.
pub async fn exchange_once<F, Fut, E>(
    liveness: &StageLiveness,
    exchange: F,
    timeout: Duration,
    warn_every: &mut Option<Instant>,
) -> bool
where
    F: FnOnce(Duration) -> Fut,
    Fut: std::future::Future<Output = Result<StagePeerLiveness, E>>,
    E: std::fmt::Display,
{
    let age = liveness.last_good_age(Instant::now());
    let result = tokio::time::timeout(timeout, exchange(age)).await;
    let now = Instant::now();
    let warn = |message: String, warn_every: &mut Option<Instant>| {
        if warn_every.is_none_or(|last| now.saturating_duration_since(last) >= WARN_EVERY) {
            *warn_every = Some(now);
            warn!(error = %message, "stage liveness exchange failed; this signal cannot eject until it succeeds");
        }
    };
    match result {
        Ok(Ok(view)) => {
            liveness.note_peers(now, view);
            true
        }
        Ok(Err(error)) => {
            warn(error.to_string(), warn_every);
            false
        }
        Err(_elapsed) => {
            warn(format!("timed out after {timeout:?}"), warn_every);
            false
        }
    }
}

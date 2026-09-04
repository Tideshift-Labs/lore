// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The terminal write-claim prune scheduler (WP-114 CD-6's hand-down from
//! WP-118).
//!
//! `PostgresFragmentCoordinator::prune_terminal_write_claims` has been
//! implemented, reviewed, and proven since Lore `5540f80`, and until now
//! **nothing called it**. WP-118 fixed its forward progress and handed the
//! scheduler down explicitly: "a periodic `lore_spawn!` task on this pool,
//! fail-closed the same way CD-8 treats an unpruned evidence table". This
//! module is that task.
//!
//! # Why a scheduler is a correctness concern and not housekeeping
//!
//! `lore_fragment_write_claims` accumulates a terminal row for every settled
//! fragment write. Nothing else removes them. An unpruned claims table is the
//! shape CD-8 refuses to activate on: acceptable for a dark or staging cell for
//! a bounded, measured time, and not acceptable in production. So the failure
//! that matters is not "the prune errored once" — it is "the prune has stopped
//! removing rows it can see", which is silent, unbounded, and invisible in
//! every other signal the cell reports.
//!
//! [`FragmentPruneReadiness`] is that signal. It goes false when the pass makes
//! no progress for [`FragmentPruneSettings::stall_ticks`] consecutive ticks,
//! and — on the same fail-closed-on-silence rule the relay's readiness uses —
//! when there is no observation at all or the last one has aged out.
//!
//! # What counts as progress, and why the pass report cannot answer it alone
//!
//! The obvious rule is "`examined == 0` means the table is drained". It is
//! wrong, and wrong in the direction that matters. The prune's plan query
//! withholds a Decisive claim whose epoch evidence was never copied, and that
//! `EXISTS` never becomes true — so the row sits past its retention horizon
//! forever while every pass honestly reports `examined = 0`. A facet keyed on
//! the report alone reports green over exactly the unbounded growth this
//! module exists to catch. That is not a hypothesis: an independent review
//! reproduced it on a live database, two terminal rows past retention with
//! `examined = 0`.
//!
//! So each pass is paired with
//! `PostgresFragmentCoordinator::unblocked_terminal_write_claim_backlog`, a
//! bounded count of terminal rows past retention that **no live send barrier
//! is blocking**. The barrier case is excluded on purpose: a hash under
//! continuous write traffic legitimately withholds its Decisive claims, and
//! counting those would flip the facet on a hot hash that is behaving
//! correctly. The never-copied-evidence case is included, because it is the
//! one that never clears.
//!
//! | Observation | Progress? | Why |
//! | --- | --- | --- |
//! | `pruned > 0` | yes | Rows left. |
//! | `pruned == 0`, unblocked backlog `== 0` | yes | Nothing past the retention horizon that is not transiently blocked. The goal state, and where a healthy cell sits most of the time. |
//! | `pruned == 0`, unblocked backlog `> 0` | **no** | Rows nothing transient is blocking were not removed. Repeated, this is a real stall. |
//! | the pass errored, or the backlog probe did | **no** | A prune that cannot run cannot make progress, and a backlog it cannot measure is not evidence of a drained table. Counted with the stalls rather than on its own facet: an operator needs one question answered, "is the table draining", not two. |
//!
//! # Inert unless the governed fragment path is enabled
//!
//! Claims exist only on WP-118's governed route. A cell with
//! `fragment_provider` absent or `enabled = false` writes none, so the task is
//! not spawned at all rather than spawned to poll an empty table forever. The
//! readiness facet then reports `configured: false` — the same honest answer
//! `/event_readiness` gives for an unconfigured relay, and for the same reason:
//! "no scheduler is running" and "the table is drained" are different states.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use lore_base::lore_spawn;
use lore_postgres::domain::fragments::FragmentWriteClaimPruneBatch;
use lore_postgres::domain::fragments::FragmentWriteClaimPruneReport;
use lore_postgres::domain::fragments::MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::info;
use tracing::warn;

/// Reason the prune facet reports false. Fixed strings; never interpolated.
pub const REASON_NO_OBSERVATION: &str = "no_prune_observation";
/// The last pass is older than the staleness bound, so the facet cannot tell
/// healthy from not-looked-at-recently.
pub const REASON_STALE_OBSERVATION: &str = "stale_prune_observation";
/// Consecutive ticks made no progress against a non-empty candidate set.
pub const REASON_NOT_PROGRESSING: &str = "prune_not_progressing";

/// Smallest configurable tick. Below a second the task would spend its life
/// re-planning a bounded batch it just planned.
const MIN_INTERVAL: Duration = Duration::from_secs(1);
/// Largest configurable tick. An hour already means a full batch of arrivals
/// waits an hour to be considered; longer is an operator asking for a backlog.
const MAX_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Largest configurable terminal retention: a week of forensic history is well
/// past any window in which a settled claim is still interesting.
const MAX_TERMINAL_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Largest configurable stall tolerance. "Keep N small": at ten ticks of the
/// maximum interval, a stalled prune would go unreported for ten hours, which
/// is not a fail-closed signal in any useful sense.
const MAX_STALL_TICKS: u32 = 10;

/// Default tick. One pass a minute drains a batch-sized arrival rate with an
/// order of magnitude to spare while costing one bounded plan query a minute.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
/// Default batch.
///
/// The coordinator's maximum is 1,000, and the default is deliberately far
/// below it: `prune_terminal_write_claims` takes **one pooled connection and
/// one head-row lock per candidate**, so the batch size is a per-tick borrow
/// count against the CR-029 pool the governed mutation path is also using.
/// Sixty-four short transactions a minute is a rounding error there; a thousand
/// would not be. A cell that genuinely needs a higher rate raises
/// `prune_batch`, which is a reviewed change with a visible cost.
const DEFAULT_BATCH: u32 = 64;
/// Default terminal retention. An hour keeps a settled claim readable for the
/// span an operator would be looking at an incident, and no longer.
const DEFAULT_TERMINAL_RETENTION: Duration = Duration::from_secs(60 * 60);
/// Default stall tolerance. One non-progressing pass can be a lock held by a
/// live write; three consecutive ones cannot.
const DEFAULT_STALL_TICKS: u32 = 3;

/// A configuration value outside the reviewed bounds.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FragmentPruneSettingsError {
    /// The tick is outside `MIN_INTERVAL..=MAX_INTERVAL`.
    #[error(
        "fragment_provider.prune_interval_millis must be between {} and {} milliseconds",
        MIN_INTERVAL.as_millis(),
        MAX_INTERVAL.as_millis()
    )]
    Interval,
    /// The batch is outside the coordinator's own bound.
    #[error(
        "fragment_provider.prune_batch must be between 1 and \
         {MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH}"
    )]
    Batch,
    /// The retention is zero or past the maximum.
    #[error(
        "fragment_provider.prune_terminal_retention_millis must be between 1 and {} milliseconds",
        MAX_TERMINAL_RETENTION.as_millis()
    )]
    TerminalRetention,
    /// The stall tolerance is zero or past the maximum.
    #[error("fragment_provider.prune_stall_ticks must be between 1 and {MAX_STALL_TICKS}")]
    StallTicks,
}

/// The reviewed shape of `[plugins.postgres.*.fragment_provider]`'s prune keys.
///
/// Constructed only through [`FragmentPruneSettings::new`], so an out-of-bounds
/// value cannot reach the task: it fails the server's configuration parse
/// instead, at the same place every other impossible fragment-provider value
/// does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentPruneSettings {
    /// Time between passes.
    pub interval: Duration,
    /// Candidates one pass may plan.
    pub batch: u32,
    /// How long a settled claim is kept before it becomes a candidate.
    pub terminal_retention: Duration,
    /// Consecutive non-progressing passes that flip the facet false.
    pub stall_ticks: u32,
}

impl Default for FragmentPruneSettings {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            batch: DEFAULT_BATCH,
            terminal_retention: DEFAULT_TERMINAL_RETENTION,
            stall_ticks: DEFAULT_STALL_TICKS,
        }
    }
}

impl FragmentPruneSettings {
    /// Validate the four raw values, each `None` taking its default.
    pub fn new(
        interval_millis: Option<u64>,
        batch: Option<u32>,
        terminal_retention_millis: Option<u64>,
        stall_ticks: Option<u32>,
    ) -> Result<Self, FragmentPruneSettingsError> {
        let defaults = Self::default();
        let interval = interval_millis.map_or(defaults.interval, Duration::from_millis);
        if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&interval) {
            return Err(FragmentPruneSettingsError::Interval);
        }
        let batch = batch.unwrap_or(defaults.batch);
        if !(1..=MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH).contains(&batch) {
            return Err(FragmentPruneSettingsError::Batch);
        }
        let terminal_retention =
            terminal_retention_millis.map_or(defaults.terminal_retention, Duration::from_millis);
        if terminal_retention.is_zero() || terminal_retention > MAX_TERMINAL_RETENTION {
            return Err(FragmentPruneSettingsError::TerminalRetention);
        }
        let stall_ticks = stall_ticks.unwrap_or(defaults.stall_ticks);
        if !(1..=MAX_STALL_TICKS).contains(&stall_ticks) {
            return Err(FragmentPruneSettingsError::StallTicks);
        }
        Ok(Self {
            interval,
            batch,
            terminal_retention,
            stall_ticks,
        })
    }

    /// The staleness bound the facet decides on: two whole ticks, so one missed
    /// pass is a scheduling hiccup rather than an incident.
    fn staleness_bound(&self) -> Duration {
        self.interval.saturating_mul(2)
    }
}

/// A point-in-time view of the prune facet and the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentPruneSnapshot {
    /// The facet itself.
    pub prune_ready: bool,
    /// Why it is false, or `None` when it is true. A fixed, low-cardinality
    /// string.
    pub prune_reason: Option<&'static str>,
    /// Consecutive passes that made no progress.
    pub consecutive_stalls: u32,
    /// Claim rows the last pass deleted.
    pub last_pruned: u64,
    /// Candidates the last pass planned.
    pub last_examined: u64,
    /// Terminal rows past retention that no live barrier is blocking, at the
    /// last pass. Bounded by the batch size plus one.
    pub last_unblocked_backlog: i64,
    /// Age of the last pass, if any.
    pub observation_age: Option<Duration>,
}

#[derive(Debug, Clone)]
struct PruneObservation {
    at: Instant,
    examined: u64,
    pruned: u64,
    unblocked_backlog: i64,
}

/// Everything `snapshot` decides on, under **one** lock.
///
/// The observation and the stall count are one fact, not two: a snapshot that
/// paired a fresh observation with the previous count would report a stall run
/// that no pass ever had, and the window is exactly the interleaving two
/// separate mutexes allow.
#[derive(Debug, Default)]
struct PruneState {
    last: Option<PruneObservation>,
    consecutive_stalls: u32,
}

/// The shared prune facet. Written by the task, read by the health surface.
#[derive(Debug)]
pub struct FragmentPruneReadiness {
    state: Mutex<PruneState>,
    stall_ticks: u32,
    staleness_bound: Duration,
}

impl FragmentPruneReadiness {
    /// Build a facet for a task configured with these settings.
    pub fn new(settings: &FragmentPruneSettings) -> Self {
        Self {
            state: Mutex::new(PruneState::default()),
            stall_ticks: settings.stall_ticks,
            staleness_bound: settings.staleness_bound(),
        }
    }

    /// Record a completed pass and the backlog measured beside it.
    ///
    /// `unblocked_backlog` is
    /// `PostgresFragmentCoordinator::unblocked_terminal_write_claim_backlog`'s
    /// bounded count. See the module table for why the report alone cannot
    /// decide this.
    pub fn record_pass(&self, report: &FragmentWriteClaimPruneReport, unblocked_backlog: i64) {
        let progressed = report.pruned > 0 || unblocked_backlog == 0;
        self.record(
            PruneObservation {
                at: Instant::now(),
                examined: report.examined,
                pruned: report.pruned,
                unblocked_backlog,
            },
            progressed,
        );
    }

    /// Record a pass, or the backlog probe beside it, that could not run.
    ///
    /// The observation timestamp still advances: the task is alive and looking,
    /// which is a different condition from the task having stopped, and the
    /// stall counter is what reports the failure. Leaving the timestamp behind
    /// would report both conditions as staleness and lose the distinction.
    ///
    /// The recorded backlog is `-1` rather than `0`, so a reader of the facet
    /// cannot mistake "not measured" for "measured and empty".
    pub fn record_failure(&self) {
        self.record(
            PruneObservation {
                at: Instant::now(),
                examined: 0,
                pruned: 0,
                unblocked_backlog: -1,
            },
            false,
        );
    }

    fn record(&self, observation: PruneObservation, progressed: bool) {
        let mut state = self.lock();
        state.last = Some(observation);
        state.consecutive_stalls = if progressed {
            0
        } else {
            state.consecutive_stalls.saturating_add(1)
        };
    }

    /// The facet plus its evidence.
    pub fn snapshot(&self) -> FragmentPruneSnapshot {
        let (observation, consecutive_stalls) = {
            let state = self.lock();
            (state.last.clone(), state.consecutive_stalls)
        };
        let observation_age = observation.as_ref().map(|o| o.at.elapsed());
        let stale = observation_age.is_some_and(|age| age > self.staleness_bound);

        let prune_reason = match observation.as_ref() {
            None => Some(REASON_NO_OBSERVATION),
            Some(_) if stale => Some(REASON_STALE_OBSERVATION),
            // Fail closed on the condition CD-8 refuses to activate on: rows
            // past retention that nothing transient is blocking, not removed,
            // tick after tick.
            Some(_) if consecutive_stalls >= self.stall_ticks => Some(REASON_NOT_PROGRESSING),
            Some(_) => None,
        };

        FragmentPruneSnapshot {
            prune_ready: prune_reason.is_none(),
            prune_reason,
            consecutive_stalls,
            last_pruned: observation.as_ref().map_or(0, |o| o.pruned),
            last_examined: observation.as_ref().map_or(0, |o| o.examined),
            last_unblocked_backlog: observation.as_ref().map_or(-1, |o| o.unblocked_backlog),
            observation_age,
        }
    }

    /// The facet alone.
    pub fn prune_ready(&self) -> bool {
        self.snapshot().prune_ready
    }

    /// Same poisoning rationale as `EventRelayReadiness::lock`: a panic while
    /// holding this must not take readiness reporting down with it, and the
    /// guarded value is a plain observation with no invariant a panic could
    /// have broken halfway.
    fn lock(&self) -> MutexGuard<'_, PruneState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// The periodic prune task.
pub struct FragmentPruneTask {
    coordinator: PostgresFragmentCoordinator,
    settings: FragmentPruneSettings,
    readiness: Arc<FragmentPruneReadiness>,
}

impl FragmentPruneTask {
    /// Assemble the task. Nothing runs until [`FragmentPruneTask::run`].
    pub fn new(
        coordinator: PostgresFragmentCoordinator,
        settings: FragmentPruneSettings,
        readiness: Arc<FragmentPruneReadiness>,
    ) -> Self {
        Self {
            coordinator,
            settings,
            readiness,
        }
    }

    /// Run until `shutdown` goes true.
    ///
    /// Returns `Ok(())` on drain and **never** returns an error: this task is
    /// spawned into the server's endpoint `JoinSet`, where an error takes the
    /// process down, and a prune that cannot reach Postgres is emphatically not
    /// that. It is logged, counted into the stall tolerance, and retried on the
    /// next tick.
    ///
    /// Drain-aware in both directions. The shutdown branch is selected against
    /// the sleep, so a drain does not wait out a tick; and the check before each
    /// pass means a signal that arrived during the previous pass starts no new
    /// database work. A pass already in flight is allowed to finish — it holds
    /// one head lock and deletes by primary key, so it is short and bounded, and
    /// abandoning it mid-batch would leave the lock to time out rather than be
    /// released.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        info!(
            interval_seconds = self.settings.interval.as_secs(),
            batch = self.settings.batch,
            terminal_retention_seconds = self.settings.terminal_retention.as_secs(),
            stall_ticks = self.settings.stall_ticks,
            "Starting the WP-118 terminal write-claim prune scheduler"
        );

        // The first pass runs immediately rather than one interval in. The
        // facet fails closed on having no observation, so deferring the first
        // pass would report a healthy cell as not ready for a whole interval
        // at every boot.
        loop {
            if *shutdown.borrow() {
                break;
            }
            self.prune_once().await;
            let stop = tokio::select! {
                _ = tokio::time::sleep(self.settings.interval) => false,
                // Both outcomes of this arm mean stop: `Ok` is the predicate
                // becoming true, `Err` is every sender gone. Written as
                // `wait_for` rather than `changed()` for that second case — a
                // `changed()` that returns `Err` completes instantly and
                // forever, which would turn a dropped sender into a tight loop
                // running the prune with no interval at all.
                _ = shutdown.wait_for(|&stop| stop) => true,
            };
            if stop {
                break;
            }
        }

        info!("Terminal write-claim prune scheduler stopped");
        Ok(())
    }

    /// One pass, recorded into the facet either way.
    ///
    /// Public so a component test can drive exactly one pass without racing the
    /// interval.
    pub async fn prune_once(&self) {
        let batch = match FragmentWriteClaimPruneBatch::new(
            self.settings.batch,
            self.settings.terminal_retention,
        ) {
            Ok(batch) => batch,
            Err(error) => {
                // Unreachable: `FragmentPruneSettings::new` checked both bounds
                // against the coordinator's own maximum before the server
                // finished parsing its configuration. Recorded as a failure
                // rather than ignored, so an unreachable state that became
                // reachable shows up on the facet instead of as silence.
                warn!(%error, "Terminal write-claim prune batch was rejected by the coordinator");
                self.readiness.record_failure();
                return;
            }
        };
        let report = match self.coordinator.prune_terminal_write_claims(batch).await {
            Ok(report) => report,
            Err(error) => {
                warn!(%error, "Terminal write-claim prune pass failed");
                self.readiness.record_failure();
                return;
            }
        };
        // Measured **after** the pass, so it reports what the pass left behind
        // rather than what it found. Taken every tick rather than only when
        // `pruned == 0`, because the count is the facet's evidence and an
        // operator reading a green facet is entitled to see the number it was
        // green about.
        let backlog = match self
            .coordinator
            .unblocked_terminal_write_claim_backlog(&batch)
            .await
        {
            Ok(backlog) => backlog,
            Err(error) => {
                warn!(
                    %error,
                    pruned = report.pruned,
                    "Terminal write-claim backlog probe failed; the pass cannot be called progress"
                );
                self.readiness.record_failure();
                return;
            }
        };
        if report.pruned == 0 && backlog > 0 {
            warn!(
                examined = report.examined,
                skipped_blocked = report.skipped_blocked,
                skipped_missing_evidence = report.skipped_missing_evidence,
                unblocked_backlog = backlog,
                "Terminal write-claim prune removed nothing while unblocked rows remain past \
                 retention"
            );
        } else if report.pruned > 0 {
            debug!(
                examined = report.examined,
                pruned = report.pruned,
                unblocked_backlog = backlog,
                "Terminal write-claim prune pass"
            );
        }
        self.readiness.record_pass(&report, backlog);
    }
}

/// Spawn the scheduler when this cell runs the governed fragment path.
///
/// `settings` is `None` for every cell whose `fragment_provider` block is
/// absent, disabled, or has `prune_enabled = false`; those cells write no
/// claims, so the task is not spawned and the facet reports unconfigured.
pub fn configure_fragment_prune(
    coordinator: Option<&PostgresFragmentCoordinator>,
    settings: Option<FragmentPruneSettings>,
    endpoints: &mut JoinSet<Result<()>>,
    shutdown: watch::Receiver<bool>,
) -> Option<Arc<FragmentPruneReadiness>> {
    let settings = settings?;
    // An enabled prune with no coordinator would be a silently absent
    // scheduler, which is the state this whole module exists to end. It cannot
    // happen — the settings come from the same enabled `fragment_provider`
    // block whose boot path already refuses without a coordinator — and it is
    // logged rather than assumed away.
    let Some(coordinator) = coordinator else {
        warn!(
            "The terminal write-claim prune is enabled but this cell has no fragment lifecycle \
             coordinator; no scheduler was started"
        );
        return None;
    };
    let readiness = Arc::new(FragmentPruneReadiness::new(&settings));
    let task = FragmentPruneTask::new(coordinator.clone(), settings, readiness.clone());
    lore_spawn!(endpoints, task.run(shutdown));
    Some(readiness)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(examined: u64, pruned: u64) -> FragmentWriteClaimPruneReport {
        FragmentWriteClaimPruneReport {
            examined,
            pruned,
            skipped_blocked: examined - pruned,
            skipped_missing_evidence: 0,
        }
    }

    fn settings() -> FragmentPruneSettings {
        FragmentPruneSettings::new(Some(1_000), Some(10), Some(60_000), Some(2))
            .expect("bounded settings")
    }

    #[test]
    fn every_value_omitted_takes_its_default() {
        let parsed = FragmentPruneSettings::new(None, None, None, None).expect("defaults");
        assert_eq!(parsed, FragmentPruneSettings::default());
    }

    #[test]
    fn each_out_of_bounds_value_names_its_own_field() {
        assert_eq!(
            FragmentPruneSettings::new(Some(999), None, None, None),
            Err(FragmentPruneSettingsError::Interval)
        );
        assert_eq!(
            FragmentPruneSettings::new(None, Some(0), None, None),
            Err(FragmentPruneSettingsError::Batch)
        );
        assert_eq!(
            FragmentPruneSettings::new(
                None,
                Some(MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH + 1),
                None,
                None
            ),
            Err(FragmentPruneSettingsError::Batch)
        );
        assert_eq!(
            FragmentPruneSettings::new(None, None, Some(0), None),
            Err(FragmentPruneSettingsError::TerminalRetention)
        );
        assert_eq!(
            FragmentPruneSettings::new(None, None, None, Some(0)),
            Err(FragmentPruneSettingsError::StallTicks)
        );
        assert_eq!(
            FragmentPruneSettings::new(None, None, None, Some(MAX_STALL_TICKS + 1)),
            Err(FragmentPruneSettingsError::StallTicks)
        );
    }

    /// The bound the task actually relies on: a settings value can never be
    /// rejected by the coordinator it was validated against.
    #[test]
    fn a_validated_batch_is_always_accepted_by_the_coordinator() {
        for batch in [1, DEFAULT_BATCH, MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH] {
            let parsed = FragmentPruneSettings::new(None, Some(batch), None, None)
                .expect("a bounded batch validates");
            assert!(
                FragmentWriteClaimPruneBatch::new(parsed.batch, parsed.terminal_retention).is_ok()
            );
        }
    }

    #[test]
    fn a_fresh_facet_is_not_ready() {
        let readiness = FragmentPruneReadiness::new(&settings());
        let snapshot = readiness.snapshot();
        assert!(!snapshot.prune_ready);
        assert_eq!(snapshot.prune_reason, Some(REASON_NO_OBSERVATION));
    }

    /// The retention bound is checked too, not only the batch.
    #[test]
    fn a_validated_retention_is_always_accepted_by_the_coordinator() {
        for millis in [1, 60_000, MAX_TERMINAL_RETENTION.as_millis() as u64] {
            let parsed = FragmentPruneSettings::new(None, None, Some(millis), None)
                .expect("a bounded retention validates");
            assert!(
                FragmentWriteClaimPruneBatch::new(parsed.batch, parsed.terminal_retention).is_ok(),
                "retention {millis} ms validated here but was rejected by the coordinator"
            );
        }
    }

    /// The goal state: nothing past retention that is not transiently blocked.
    /// This is where a healthy cell sits most of the time.
    #[test]
    fn an_empty_backlog_is_progress() {
        let readiness = FragmentPruneReadiness::new(&settings());
        for _ in 0..5 {
            readiness.record_pass(&report(0, 0), 0);
        }
        let snapshot = readiness.snapshot();
        assert!(snapshot.prune_ready);
        assert_eq!(snapshot.consecutive_stalls, 0);
        assert_eq!(snapshot.last_unblocked_backlog, 0);
    }

    #[test]
    fn a_pass_that_removes_rows_is_progress_even_with_a_remaining_backlog() {
        let readiness = FragmentPruneReadiness::new(&settings());
        readiness.record_pass(&report(10, 4), 11);
        let snapshot = readiness.snapshot();
        assert!(
            snapshot.prune_ready,
            "a full batch leaves rows behind by design; that is draining, not stalling"
        );
        assert_eq!(snapshot.last_pruned, 4);
        assert_eq!(snapshot.last_examined, 10);
        assert_eq!(snapshot.last_unblocked_backlog, 11);
    }

    /// The finding this rule exists for: the plan query returns nothing while
    /// rows sit past retention, because their epoch evidence was never copied.
    /// Keyed on `examined` this reports green forever.
    #[test]
    fn an_empty_plan_over_a_non_empty_backlog_is_a_stall_not_a_drained_table() {
        let readiness = FragmentPruneReadiness::new(&settings());
        readiness.record_pass(&report(0, 0), 2);
        assert!(readiness.prune_ready(), "one pass is within tolerance");
        readiness.record_pass(&report(0, 0), 2);
        let snapshot = readiness.snapshot();
        assert!(!snapshot.prune_ready);
        assert_eq!(snapshot.prune_reason, Some(REASON_NOT_PROGRESSING));
        assert_eq!(snapshot.last_examined, 0);
        assert_eq!(snapshot.last_unblocked_backlog, 2);
    }

    /// The head-of-line shape INV-FJ fixed: candidates found, none removed.
    /// One pass is tolerated, `stall_ticks` consecutive ones are not.
    #[test]
    fn consecutive_non_progressing_passes_flip_the_facet_after_the_tolerance() {
        let readiness = FragmentPruneReadiness::new(&settings());
        readiness.record_pass(&report(10, 0), 10);
        assert!(
            readiness.prune_ready(),
            "one skipped batch can be a live write holding a lock"
        );
        readiness.record_pass(&report(10, 0), 10);
        let snapshot = readiness.snapshot();
        assert!(!snapshot.prune_ready);
        assert_eq!(snapshot.prune_reason, Some(REASON_NOT_PROGRESSING));
        assert_eq!(snapshot.consecutive_stalls, 2);
    }

    #[test]
    fn a_failed_pass_counts_towards_the_same_tolerance() {
        let readiness = FragmentPruneReadiness::new(&settings());
        readiness.record_failure();
        readiness.record_failure();
        let snapshot = readiness.snapshot();
        assert!(!snapshot.prune_ready);
        assert_eq!(snapshot.prune_reason, Some(REASON_NOT_PROGRESSING));
        assert_eq!(
            snapshot.last_unblocked_backlog, -1,
            "an unmeasured backlog must not read as an empty one"
        );
    }

    /// The counter is a run length, not a total: one good pass clears it.
    #[test]
    fn one_progressing_pass_clears_the_stall_run() {
        let readiness = FragmentPruneReadiness::new(&settings());
        readiness.record_pass(&report(10, 0), 10);
        readiness.record_pass(&report(10, 0), 10);
        assert!(!readiness.prune_ready());
        readiness.record_pass(&report(10, 1), 9);
        let snapshot = readiness.snapshot();
        assert!(snapshot.prune_ready);
        assert_eq!(snapshot.consecutive_stalls, 0);
    }

    /// The wedged-task case: a healthy observation that stopped being
    /// refreshed. A zero staleness bound makes any elapsed time stale, which is
    /// how this is provable without sleeping.
    #[test]
    fn a_stale_observation_fails_the_facet_even_though_it_looked_healthy() {
        let readiness = FragmentPruneReadiness {
            state: Mutex::new(PruneState::default()),
            stall_ticks: 3,
            staleness_bound: Duration::ZERO,
        };
        readiness.record_pass(&report(10, 10), 0);
        while readiness.snapshot().observation_age == Some(Duration::ZERO) {
            std::hint::spin_loop();
        }
        let snapshot = readiness.snapshot();
        assert!(!snapshot.prune_ready);
        assert_eq!(snapshot.prune_reason, Some(REASON_STALE_OBSERVATION));
    }

    #[test]
    fn every_reason_is_a_bounded_label() {
        for reason in [
            REASON_NO_OBSERVATION,
            REASON_STALE_OBSERVATION,
            REASON_NOT_PROGRESSING,
        ] {
            assert!(!reason.is_empty());
            assert!(reason.is_ascii());
            assert!(!reason.contains(' '));
        }
    }

    /// No settings means no task and no facet: an unconfigured cell must not
    /// report a green prune it is not running.
    #[test]
    fn a_cell_with_no_prune_settings_spawns_nothing() {
        let mut endpoints = JoinSet::new();
        let (_tx, shutdown) = watch::channel(false);
        let readiness = configure_fragment_prune(None, None, &mut endpoints, shutdown);
        assert!(readiness.is_none());
        assert!(endpoints.is_empty());
    }

    /// Enabled settings with no coordinator must not silently start a
    /// scheduler-shaped nothing.
    #[test]
    fn enabled_settings_with_no_coordinator_spawn_nothing() {
        let mut endpoints = JoinSet::new();
        let (_tx, shutdown) = watch::channel(false);
        let readiness = configure_fragment_prune(None, Some(settings()), &mut endpoints, shutdown);
        assert!(readiness.is_none());
        assert!(endpoints.is_empty());
    }
}

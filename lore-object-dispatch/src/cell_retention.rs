// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Cell-scale retention for the dispatch authority's evidence rows (WP-114 CD-8).
//!
//! # The decision, and why
//!
//! CR-033 D5 deferred retention migrations 0004 through 0006 and recorded the consequence as an
//! explicit fail-closed production activation prerequisite: without them the cell authority's
//! evidence rows grow with **no prune path at all**. WP-114 CD-8 owns closing that, and asks for an
//! explicit decision on whether those three install as-is, install resized, or are replaced.
//!
//! **They are replaced.** Not installed as-is, not resized. Their source stays exactly where D5 left
//! it -- retained, compiled, tested, uncalled, unedited -- and
//! [`crate::cell_schema_install::CELL_DEFERRED_MIGRATIONS`] and
//! [`crate::cell_schema_install::CELL_DEFERRED_PROCEDURES`] keep their membership unchanged. The
//! replacement is migrations 0023 and 0024, installed and attested through the same
//! `cell-schema-install` path as every other layer.
//!
//! Four reasons, each checkable against the artifacts rather than taken on argument.
//!
//! **1. As written they cannot run in a cell at all.** `object_store_retention_apply_transfer_v1`
//! reads its subject from `object_dispatch_full_record_ownership`, and nothing in the cell install
//! set writes that table -- CR-033 D5 already records it as one of the four inert tables 0002
//! creates. The same procedure then requires per-cell and per-tenant counter rows
//! (`scope_kind` 2 and 3), and 0003's install seeds only the global counter, so the `SELECT ... INTO
//! STRICT` raises `no_data_found` and the procedure's handler converts it to
//! `RETENTION_AUTHORITY_UNAVAILABLE`. Installing them as-is would install a retention path that
//! fails closed on its first call and prunes nothing, which is indistinguishable in effect from the
//! state CD-8 exists to leave behind.
//!
//! **2. Their transaction shape is one row per serializable transaction, strictly ordered.**
//! `object_store_retention_apply_prune_v1` requires
//! `requested_compact_sequence = watermark.pruned_through_compact_sequence + 1`, so prunes are a
//! single global sequence advanced one step at a time. That is right for a continuity ledger, whose
//! rows are cross-cell decisions. A cell writes one `object_dispatch_requests` row per logical
//! request, plus its attempts, spool objects, purges, leases and charge grants. Resizing a
//! one-row-at-a-time sequential pipeline to that arrival rate is not a parameter change.
//!
//! **3. Each prune demands external backup evidence per row** -- a backup revision, a manifest
//! digest, a durable-covered-through sequence and a restore-verified-through sequence, all checked
//! against the row being deleted. That is continuity-ledger safety, where a lost record is
//! unrecoverable cross-cell state and the operator must prove a restorable copy exists before
//! anything is removed. A cell's terminal request row is bounded-horizon idempotency state, and
//! requiring a backup manifest per fragment PUT would make retention gated on an operator process
//! that runs at a different cadence by orders of magnitude.
//!
//! **4. A cell's replay horizon is bounded by the request's own hard expiry, so a cell does not need
//! the compact tier in order to prune safely.** The reason the global design compacts before it
//! prunes is that a full record's replay answer must outlive the full record. In a cell, the answer
//! only has to outlive the window in which the same identity can still be admitted, and that window
//! is written on the row itself as `allocation_hard_expiry_unix_ms`. Past it, admission refuses the
//! identity outright, so there is no replay for a compact receipt to answer. The two-stage global
//! design therefore collapses to one bounded-batch prune keyed on the closure clock and floored by
//! the hard expiry.
//!
//! # What that leaves deferred, stated rather than implied
//!
//! The compact-receipt tier stays deferred **by this decision**, not by omission.
//! [`crate::compaction`], [`crate::full_to_compact`] and [`crate::compact_prune`] are unchanged, no
//! frozen identifier is re-spelled, no golden literal moves, and all four of 0002's inert tables
//! stay inert -- this module writes none of them. `OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID` and
//! the compact-receipt boundary projections keep their exact current bytes. If a later step needs a
//! durable compact tier in a cell -- a longer forensic horizon than the hard expiry, say -- it
//! un-defers that family on its own terms, and the audit binding CD-8 landed beside this
//! ([`crate::provider_client::BoundProviderAttemptAudit`]) is already in place for it.
//!
//! # What this module does prune, and what it deliberately does not
//!
//! One bounded batch per pass, over the rows that actually grow without bound. The first sweep
//! takes a terminal `object_dispatch_requests` row together with the `object_dispatch_attempts`,
//! `object_dispatch_spool_objects`, `object_dispatch_payload_purges` and
//! `object_dispatch_fetch_leases` rows bound to it, in one statement, so end-of-statement
//! referential integrity sees parent and children go together.
//!
//! `object_dispatch_provider_charge_grants` is pruned by an **independent** sweep in the same pass,
//! and it is worth knowing why it is not simply deleted alongside its request. It has no foreign key
//! to `object_dispatch_requests`, and 0022's charge procedure never reads a request row: the grant
//! row is the sole oracle for `ATTEMPT_ALREADY_CHARGED`. Deleting one on the request's admission
//! clock would let the same attempt identity charge again and debit the budget twice. The one
//! condition under which that is impossible is the budget configuration's own hard expiry, because
//! 0022 refuses on it *before* consulting the grant. So the sweep is keyed on that, with the
//! operator's window applied on top, and its own remaining count is a third backlog number.
//!
//! **Two things are deliberately not pruned, named rather than left to be discovered.**
//! `object_dispatch_dispatchers` grows as O(replicas x process restarts), not O(requests), and a
//! dispatcher row cannot be removed while any attempt still references its lease generation;
//! ordering two prunes against one foreign key buys nothing measurable. And grants under a budget
//! configuration that has *not* expired are retained however many there are, which is bounded by
//! rotation cadence rather than by anything here. WP-121 owns that cadence. Both are residuals, not
//! oversights, and neither is covered by the readiness facet below.
//!
//! # Why the pass report alone cannot decide readiness
//!
//! The obvious progress rule is "the pass deleted nothing, so the table is drained". It is wrong in
//! the direction that matters, and the sibling scheduler in `lore-server`'s `fragment_prune` had an
//! independent review reproduce exactly this on a live database. A closed request whose spool object
//! was never purged, whose payload purge never completed, or whose fetch lease was never closed is
//! **withheld** by the prune -- correctly, because deleting it would orphan a file, an intent, or a
//! live reader -- and it will stay withheld forever while every pass honestly reports zero examined
//! and zero pruned. A facet keyed on the report alone reports green over precisely the unbounded
//! growth this module exists to stop.
//!
//! There is a second way to get this wrong, and the first version of this module had it: making
//! `pruned > 0` short-circuit the whole rule. On a cell whose terminal requests arrive faster than
//! `batch` per `interval`, every pass removes a full batch, the table grows anyway, and the facet
//! reports green forever. Worse, `blocked` is then never even read on a cell with traffic, so the
//! orphaned-spool case above -- the one with no other red gate anywhere -- is masked by exactly the
//! throughput that makes it matter. A cold review caught it before this shipped.
//!
//! So each pass is paired with a bounded probe returning **three** counts, and the rule reads all
//! of them every time:
//!
//! | Observation | Progress? | Why |
//! | --- | --- | --- |
//! | blocked `> 0` | **no**, always | Rows past the retention horizon held back by payload evidence that is not terminal. None of those three conditions is transient past the horizon, and no amount of throughput clears them. Checked first and unconditionally. |
//! | prunable or grants at the probe limit | **no** | More than a full batch still waiting. The prune is working and losing: arrivals exceed the drain rate. |
//! | removed `> 0`, nothing blocked, not saturated | yes | Rows left and the rest is within a batch. |
//! | removed `== 0`, prunable `== 0`, grants `== 0` | yes | Nothing past the horizon at all. The goal state, and where a healthy cell sits. |
//! | removed `== 0` with something prunable | **no** | The pass could have taken rows and took none. |
//! | the pass errored, or the probe did | **no** | A prune that cannot run cannot make progress, and a backlog it cannot measure is not evidence of a drained table. |
//!
//! `removed` counts request rows and charge grants together, since the two sweeps are independent.
//! A burst legitimately saturates for a pass or two; `stall_ticks` is the tolerance, and the facet
//! reports *which* of the three causes it saw so the operator knows whether to chase an orphan or
//! raise the batch.
//!
//! # The literal phase list is load-bearing, and that was measured rather than assumed
//!
//! 0023's candidate index is partial (`WHERE phase IN (5, 6, 7)`) and 0024's candidate query spells
//! the same list as literals. The planner can use a partial index only when it can prove the query
//! predicate implies the index predicate, which it can do against literals and cannot do against a
//! bound parameter. Measured on the disposable PostgreSQL 16 this crate's live runners use, with
//! `enable_seqscan = off` so the choice is between indexes rather than against a sequential scan:
//!
//! * the literal spelling plans `Index Scan using object_dispatch_requests_cell_retention_idx`,
//!   with the ordering satisfied by the index and no sort node at all;
//! * the same query written `phase = ANY($1)` under `plan_cache_mode = force_generic_plan` cannot
//!   reach that index, falls back to a bitmap scan of 0007's non-partial `(phase,
//!   closure_committed_at_unix_ms)` index, and adds a sort.
//!
//! Both return identical rows, so nothing but the plan distinguishes them. Do not "tidy" the list
//! into a parameter or an array. The general form of this trap, and the crate that paid for it, are
//! in the `lore-postgres` skill.
//!
//! The measurement was then repeated in the shape the procedure actually runs, because a literal
//! query is not evidence about a plpgsql body: the phase list literal, the horizon and the batch
//! **bound**, under `force_generic_plan` and repeated past the five-plan custom-plan threshold. The
//! partial index still wins, still ordered, still no sort. Only `phase` participates in the
//! implication proof, so binding the horizon costs nothing -- but that is the sort of claim that
//! reads as obvious and is worth a run rather than an argument.
//!
//! # Two-sided bounds, and one pool
//!
//! [`CellRetentionSettings`] is the reviewed range and rejects a bad value at configuration parse.
//! 0024's `assert_dispatch_cell_retention_bounds_v1` is a deliberately looser outer bound enforced
//! inside the database, so a caller that somehow bypassed the reviewed check still cannot ask for a
//! zero-length retention window or an unbounded delete.
//!
//! The pass runs on the process's **existing** dispatch-runtime pool. It opens none of its own, so
//! the CR-033 D8 process connection inventory is unchanged and
//! [`crate::dispatch_pool::DISPATCH_PROCESS_CONNECTION_LIMIT`] is not renegotiated. That is why
//! 0024's procedures authenticate as `object_dispatch_retention_runtime` rather than the
//! maintenance role 0004-0006 used; 0019 set the precedent for a runtime-callable authority
//! procedure. The widening is bounded by construction: the horizon, the replay floor, the withhold
//! clauses and the batch ceiling are all computed inside `SECURITY DEFINER` procedures from the
//! database's own clock, and the tables stay unwritable by every service role.
//!
//! This is the first module in the crate to use `tracing`, which the fork's `logging.md` scopes to
//! server and tool code rather than library code. That is deliberate and narrow: everything else
//! here is a pure codec or a request-scoped client that returns its outcome to a caller, whereas
//! this module is a background task whose failures have no caller to return to. A pass that could
//! not reach PostgreSQL would otherwise be visible only as a facet going false several ticks later,
//! with nothing saying why. Nothing else in this crate should acquire a logger on this precedent.
//!
//! # What `lore-server` must wire
//!
//! Nothing here spawns, opens a connection, or reads configuration. The exact function to schedule
//! is [`CellRetentionTask::run`]; everything else below is the assembly around it.
//!
//! ```ignore
//! // Parse the four keys, failing the server's configuration parse rather than the task.
//! let settings = CellRetentionSettings::new(
//!     interval_millis, batch, terminal_retention_millis, stall_ticks,
//! )?;
//! // The pool the replica already built for the dispatch authority. Not a new one.
//! let client = CellRetentionClient::new(Arc::clone(&dispatch_pool))?;
//! // Refuse to schedule against a database where the layer is absent, rather than discovering it
//! // one failed pass at a time.
//! client.read_state().await?;
//! let readiness = Arc::new(CellRetentionReadiness::new(&settings));
//! let task = CellRetentionTask::new(client, settings, Arc::clone(&readiness));
//! lore_spawn!(endpoint_tasks, task.run(shutdown_rx));
//! ```
//!
//! Then publish [`CellRetentionReadiness::retention_ready`] on the health surface beside the
//! fragment prune's facet, and [`CellRetentionReadiness::snapshot`] wherever that facet's evidence
//! is reported: an operator who sees this go false needs the reason string and the three backlog
//! counts to know which of the causes above they are looking at.
//!
//! Two things the server owns that this module cannot decide. The task must not be spawned at all
//! on a cell where the dispatch authority is not composed, for the same reason the fragment prune
//! is not: "no scheduler is running" and "the table is drained" are different states, and a facet
//! that cannot tell them apart is worse than an absent one. And `run` returns `()` rather than a
//! `Result`, deliberately, because a retention pass that cannot reach PostgreSQL must not take the
//! process down; wrap it in whatever shape the endpoint `JoinSet` expects.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;
use std::time::Instant;

use thiserror::Error;
use tokio::sync::watch;
use tokio_postgres::types::ToSql;
use tracing::info;
use tracing::warn;

use crate::dispatch_client::DispatchAuthorityError;
use crate::dispatch_client::DispatchDisposition;
use crate::dispatch_client::int8;
use crate::dispatch_client::read_once;
use crate::dispatch_client::require;
use crate::dispatch_client::text;
use crate::dispatch_pool::DispatchPoolRole;
use crate::dispatch_pool::DispatchRuntimePool;

/// The API revision 0024's procedures require.
pub const CELL_RETENTION_API_REVISION_V1: &str = "object-store-dispatch-cell-retention-v1";

/// The reviewed batch ceiling, and 0024's own additional check on the prune's batch.
pub const MAX_CELL_RETENTION_BATCH: u32 = 1000;

const PRUNE_SQL: &str = "SELECT
  (r).result_code,
  (r).examined,
  (r).pruned_requests,
  (r).pruned_attempts,
  (r).pruned_spool_objects,
  (r).pruned_payload_purges,
  (r).pruned_fetch_leases,
  (r).pruned_charge_grants,
  (r).horizon_unix_ms,
  (r).database_now_unix_ms
FROM (SELECT object_store_retention.object_store_dispatch_cell_retention_prune_v1(
  $1, $2, $3
) AS r) q";

const BACKLOG_SQL: &str = "SELECT
  (r).result_code,
  (r).prunable_backlog,
  (r).blocked_backlog,
  (r).grant_backlog,
  (r).horizon_unix_ms,
  (r).database_now_unix_ms
FROM (SELECT object_store_retention.object_store_dispatch_cell_retention_backlog_v1(
  $1, $2, $3
) AS r) q";

const READ_STATE_SQL: &str = "SELECT
  (r).result_code,
  (r).schema_revision,
  ((r).install_revision)::text,
  (r).installed_at_unix_ms
FROM (SELECT object_store_retention.object_store_dispatch_cell_retention_read_state_v1(
  $1
) AS r) q";

/// Reason the retention facet reports false. Fixed strings; never interpolated.
pub const REASON_NO_OBSERVATION: &str = "no_cell_retention_observation";
/// The last pass is older than the staleness bound, so the facet cannot tell healthy from
/// not-looked-at-recently.
pub const REASON_STALE_OBSERVATION: &str = "stale_cell_retention_observation";
/// Consecutive ticks took nothing while there was something to take.
pub const REASON_NOT_PROGRESSING: &str = "cell_retention_not_progressing";
/// Rows past the retention horizon are held back by payload evidence that is not terminal.
///
/// Distinct from [`REASON_NOT_PROGRESSING`] because the operator action is different: this is an
/// orphaned spool object, an unfinished purge, or a lease that was never closed, and no amount of
/// retention throughput clears it.
pub const REASON_BLOCKED_BACKLOG: &str = "cell_retention_blocked_backlog";
/// More than one full batch is still waiting after a pass that took a full batch.
///
/// Also distinct, and also a different action: the prune is working and losing. The batch, the
/// interval, or the arrival rate has to change.
pub const REASON_BACKLOG_SATURATED: &str = "cell_retention_backlog_saturated";

/// Smallest configurable tick. Below a second the pass would spend its life re-planning a bounded
/// batch it just planned.
const MIN_INTERVAL: Duration = Duration::from_secs(1);
/// Largest configurable tick. An hour already means a full batch of arrivals waits an hour to be
/// considered; longer is an operator asking for a backlog.
const MAX_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Shortest configurable retention window, matching 0024's own floor. Short enough for a staging
/// cell to watch a pass work, long enough that no live request's closure falls inside it.
const MIN_TERMINAL_RETENTION: Duration = Duration::from_secs(60);
/// Longest configurable retention window. A week of forensic history on a closed cell request is
/// past any window in which it is still interesting, and the replay floor is enforced separately
/// and cannot be shortened by this setting at all.
const MAX_TERMINAL_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Largest configurable stall tolerance. At ten ticks of the maximum interval a stalled retention
/// pass would go unreported for ten hours, which is not a fail-closed signal in any useful sense.
const MAX_STALL_TICKS: u32 = 10;

/// Default tick.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
/// Default batch.
///
/// Deliberately below [`MAX_CELL_RETENTION_BATCH`]: one pass is one borrowed connection from the
/// shared dispatch pool holding one serializable transaction, and the batch size is what that
/// transaction's lock footprint scales with. Two hundred and fifty-six terminal requests a minute
/// is fifteen thousand an hour, well clear of any arrival rate a single cell sustains, at a cost
/// the governed mutation path sharing this pool will not notice. A cell that genuinely needs more
/// raises `batch`, which is a reviewed change with a visible cost.
const DEFAULT_BATCH: u32 = 256;
/// Default retention window. A day keeps a closed request readable across the span an operator
/// would be looking at an incident, and no longer.
const DEFAULT_TERMINAL_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
/// Default stall tolerance. One non-progressing pass can be a lock held by a live write; three
/// consecutive ones cannot.
const DEFAULT_STALL_TICKS: u32 = 3;

/// A configuration value outside the reviewed bounds.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CellRetentionSettingsError {
    /// The tick is outside `MIN_INTERVAL..=MAX_INTERVAL`.
    #[error(
        "cell_retention.interval_millis must be between {} and {} milliseconds",
        MIN_INTERVAL.as_millis(),
        MAX_INTERVAL.as_millis()
    )]
    Interval,
    /// The batch is outside `1..=MAX_CELL_RETENTION_BATCH`.
    #[error("cell_retention.batch must be between 1 and {MAX_CELL_RETENTION_BATCH}")]
    Batch,
    /// The retention window is outside the reviewed range.
    #[error(
        "cell_retention.terminal_retention_millis must be between {} and {} milliseconds",
        MIN_TERMINAL_RETENTION.as_millis(),
        MAX_TERMINAL_RETENTION.as_millis()
    )]
    TerminalRetention,
    /// The stall tolerance is zero or past the maximum.
    #[error("cell_retention.stall_ticks must be between 1 and {MAX_STALL_TICKS}")]
    StallTicks,
}

/// The reviewed shape of a cell's retention keys.
///
/// Constructed only through [`CellRetentionSettings::new`], so an out-of-bounds value cannot reach
/// a pass: it fails the server's configuration parse instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellRetentionSettings {
    /// Time between passes.
    pub interval: Duration,
    /// Terminal requests one pass may take.
    pub batch: u32,
    /// How long a closed request is kept before it becomes a candidate. This is the operator's
    /// window only; the replay floor is separate, is read from each row's own hard expiry, and no
    /// value here can shorten it.
    pub terminal_retention: Duration,
    /// Consecutive non-progressing passes that flip the facet false.
    pub stall_ticks: u32,
}

impl Default for CellRetentionSettings {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            batch: DEFAULT_BATCH,
            terminal_retention: DEFAULT_TERMINAL_RETENTION,
            stall_ticks: DEFAULT_STALL_TICKS,
        }
    }
}

impl CellRetentionSettings {
    /// Validate the four raw values, each `None` taking its default.
    ///
    /// # Errors
    ///
    /// Returns [`CellRetentionSettingsError`] for any value outside the reviewed range.
    pub fn new(
        interval_millis: Option<u64>,
        batch: Option<u32>,
        terminal_retention_millis: Option<u64>,
        stall_ticks: Option<u32>,
    ) -> Result<Self, CellRetentionSettingsError> {
        let defaults = Self::default();
        let interval = interval_millis.map_or(defaults.interval, Duration::from_millis);
        if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&interval) {
            return Err(CellRetentionSettingsError::Interval);
        }
        let batch = batch.unwrap_or(defaults.batch);
        if !(1..=MAX_CELL_RETENTION_BATCH).contains(&batch) {
            return Err(CellRetentionSettingsError::Batch);
        }
        let terminal_retention =
            terminal_retention_millis.map_or(defaults.terminal_retention, Duration::from_millis);
        if !(MIN_TERMINAL_RETENTION..=MAX_TERMINAL_RETENTION).contains(&terminal_retention) {
            return Err(CellRetentionSettingsError::TerminalRetention);
        }
        let stall_ticks = stall_ticks.unwrap_or(defaults.stall_ticks);
        if !(1..=MAX_STALL_TICKS).contains(&stall_ticks) {
            return Err(CellRetentionSettingsError::StallTicks);
        }
        Ok(Self {
            interval,
            batch,
            terminal_retention,
            stall_ticks,
        })
    }

    /// The staleness bound the facet decides on: two whole ticks, so one missed pass is a
    /// scheduling hiccup rather than an incident.
    fn staleness_bound(&self) -> Duration {
        self.interval.saturating_mul(2)
    }

    /// The retention window as the milliseconds 0024 takes. Every reachable value fits `i64`
    /// because [`MAX_TERMINAL_RETENTION`] is a week.
    fn retention_millis(&self) -> i64 {
        i64::try_from(self.terminal_retention.as_millis())
            .unwrap_or(MAX_TERMINAL_RETENTION.as_millis() as i64)
    }

    /// The probe counts one past a full batch, so "exactly a batch remaining" and "more than a
    /// batch remaining" are distinguishable rather than both reported as a full batch.
    fn probe_limit(&self) -> i32 {
        i32::try_from(self.batch.saturating_add(1))
            .unwrap_or(MAX_CELL_RETENTION_BATCH.saturating_add(1) as i32)
    }

    fn batch_rows(&self) -> i32 {
        i32::try_from(self.batch).unwrap_or(MAX_CELL_RETENTION_BATCH as i32)
    }
}

/// What one bounded prune pass removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellRetentionPruneReport {
    /// Candidates the pass locked. Equal to `pruned_requests` on any committed pass.
    pub examined: i64,
    /// Terminal request rows removed.
    pub pruned_requests: i64,
    /// Attempt rows removed.
    pub pruned_attempts: i64,
    /// Spool-object rows removed.
    pub pruned_spool_objects: i64,
    /// Payload-purge rows removed.
    pub pruned_payload_purges: i64,
    /// Fetch-lease rows removed.
    pub pruned_fetch_leases: i64,
    /// Provider charge-grant rows removed.
    pub pruned_charge_grants: i64,
    /// The closure timestamp at or before which a request was a candidate.
    pub horizon_unix_ms: i64,
    /// The database clock the horizon was computed from. Never the process clock.
    pub database_now_unix_ms: i64,
}

/// What the bounded probe found past the horizon after a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellRetentionBacklog {
    /// Terminal requests a further pass could take, bounded by the batch plus one.
    pub prunable: i64,
    /// Rows past the horizon held back by payload evidence that is not terminal, bounded the same
    /// way. Past the horizon this is never transient, which is why it counts against progress.
    pub blocked: i64,
    /// Charge grants whose budget configuration has expired and which the sweep has not yet taken,
    /// bounded the same way. Grants under a live configuration are correctly retained and are
    /// deliberately not counted here; their growth is a rotation-cadence question, not a stall.
    pub grants: i64,
    /// The horizon this probe used. May precede the epoch on a clock inside one retention window of
    /// it, in which case nothing is selected, which is the honest result rather than a special case.
    pub horizon_unix_ms: i64,
    /// The database clock the horizon was computed from.
    pub database_now_unix_ms: i64,
}

/// 0024's installed identity tuple, as the runtime role may read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellRetentionInstalledIdentity {
    /// The layer's schema revision.
    pub schema_revision: String,
    /// The install revision recorded when the layer was installed.
    pub install_revision: u64,
    /// When the layer was installed, on the database's clock.
    pub installed_at_unix_ms: i64,
}

/// The typed client over 0024's runtime-callable retention procedures.
///
/// Takes the process's already-built dispatch-runtime pool. It never opens one, so composing it
/// changes no connection budget.
#[derive(Debug)]
pub struct CellRetentionClient {
    pool: Arc<DispatchRuntimePool>,
}

impl CellRetentionClient {
    /// Refuses a pool that does not connect as the runtime role, so a maintenance or migrator
    /// credential cannot be routed into a retention delete.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchAuthorityError::WrongPoolRole`] for any other pool role.
    pub fn new(pool: Arc<DispatchRuntimePool>) -> Result<Self, DispatchAuthorityError> {
        if pool.role() != DispatchPoolRole::Runtime {
            return Err(DispatchAuthorityError::WrongPoolRole);
        }
        Ok(Self { pool })
    }

    /// 0024's readback: prove the retention layer is installed before anything is deleted.
    ///
    /// Read-only, and therefore never retried.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchAuthorityError`] when the layer is absent, the role is wrong, or the
    /// authority cannot be reached.
    pub async fn read_state(
        &self,
    ) -> Result<CellRetentionInstalledIdentity, DispatchAuthorityError> {
        let api = CELL_RETENTION_API_REVISION_V1;
        let params: [&(dyn ToSql + Sync); 1] = [&api];
        let row = read_once(&self.pool, READ_STATE_SQL, &params).await?;
        require(text(&row, 0)? == "READ", "cell retention read result")?;
        let schema_revision = text(&row, 1)?;
        require(
            schema_revision == "object-store-dispatch-cell-retention-schema-v1",
            "cell retention schema revision",
        )?;
        let install_revision: u64 = text(&row, 2)?.parse().map_err(|_| {
            DispatchAuthorityError::InvalidAuthorityResponse("expected a canonical uint64 in text")
        })?;
        require(install_revision > 0, "cell retention install revision")?;
        let installed_at_unix_ms = int8(&row, 3)?;
        require(installed_at_unix_ms >= 0, "cell retention install time")?;
        Ok(CellRetentionInstalledIdentity {
            schema_revision,
            install_revision,
            installed_at_unix_ms,
        })
    }

    /// One bounded prune pass.
    ///
    /// Runs through the crate's serializable mutation envelope, so its retry budget, ambiguity
    /// resolution and closed SQLSTATE decoding are the ones every other authority mutation uses.
    ///
    /// # The ambiguity disposition does not mean here what it means elsewhere
    ///
    /// [`crate::dispatch_client::DispatchDisposition::AppliedAfterAmbiguousCommit`] is documented
    /// as "the authority proved the earlier attempt had **not** committed", and for the five
    /// idempotent mutations that is true, because their authoritative read is re-issuing the
    /// identical call and a `REPLAY` proves the earlier attempt landed. **This pass is not
    /// idempotent**, so re-issuing it proves nothing about the earlier attempt: it simply runs
    /// another pass over whatever is a candidate now. That disposition therefore means only "an
    /// earlier transaction may or may not have removed a batch, and this one removed the batch
    /// reported below".
    ///
    /// That is benign and is why the pass is allowed through this envelope at all: removing a batch
    /// twice removes two disjoint batches, since the second pass cannot see rows the first deleted.
    /// The report's counts are exact for the attempt that committed. It is logged rather than
    /// returned, because there is no decision a caller would make differently -- but it is written
    /// down here so nobody reads the enum's own doc comment and concludes something stronger.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchAuthorityError`] when the authority refuses the pass, the transaction
    /// could not be committed within the envelope, or the response does not decode.
    pub async fn prune_once(
        &self,
        settings: &CellRetentionSettings,
    ) -> Result<CellRetentionPruneReport, DispatchAuthorityError> {
        let prepared = PreparedCellRetentionPrune {
            api: CELL_RETENTION_API_REVISION_V1,
            retention_millis: settings.retention_millis(),
            batch: settings.batch_rows(),
        };
        let accepted = crate::dispatch_client::run_mutation(&self.pool, &prepared).await?;
        if matches!(
            accepted.disposition,
            DispatchDisposition::AppliedAfterAmbiguousCommit
                | DispatchDisposition::ReplayedAfterAmbiguousCommit
        ) {
            warn!(
                pruned_requests = accepted.value.pruned_requests,
                pruned_charge_grants = accepted.value.pruned_charge_grants,
                "A cell retention pass resolved an ambiguous commit; an earlier attempt may also \
                 have removed a batch"
            );
        }
        Ok(accepted.value)
    }

    /// The bounded backlog probe, taken after a pass so it reports what the pass left behind.
    ///
    /// Read-only, and therefore never retried.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchAuthorityError`] when the probe is refused or does not decode.
    pub async fn backlog(
        &self,
        settings: &CellRetentionSettings,
    ) -> Result<CellRetentionBacklog, DispatchAuthorityError> {
        let api = CELL_RETENTION_API_REVISION_V1;
        let retention_millis = settings.retention_millis();
        let probe_limit = settings.probe_limit();
        let params: [&(dyn ToSql + Sync); 3] = [&api, &retention_millis, &probe_limit];
        let row = read_once(&self.pool, BACKLOG_SQL, &params).await?;
        require(text(&row, 0)? == "READ", "cell retention backlog result")?;
        let prunable = int8(&row, 1)?;
        let blocked = int8(&row, 2)?;
        let grants = int8(&row, 3)?;
        let horizon_unix_ms = int8(&row, 4)?;
        let database_now_unix_ms = int8(&row, 5)?;
        // A count above what the probe was asked to look at, or a negative one, means the response
        // is not this probe's. Bounding it here is what lets a reader treat the number as evidence,
        // and in particular what lets `prunable == probe_limit` mean "more than a batch remains"
        // rather than "some number the client did not check".
        let limit = i64::from(probe_limit);
        require(
            (0..=limit).contains(&prunable)
                && (0..=limit).contains(&blocked)
                && (0..=limit).contains(&grants),
            "cell retention backlog bound",
        )?;
        // The horizon is deliberately not required to be nonnegative: a clock inside one retention
        // window of the epoch yields a horizon before it, which selects nothing and is reported as
        // the horizon actually used. What must hold is that it is exactly one window behind the
        // clock the database reported.
        require(
            database_now_unix_ms >= 0
                && database_now_unix_ms.checked_sub(horizon_unix_ms)
                    == Some(settings.retention_millis()),
            "cell retention backlog horizon",
        )?;
        Ok(CellRetentionBacklog {
            prunable,
            blocked,
            grants,
            horizon_unix_ms,
            database_now_unix_ms,
        })
    }
}

struct PreparedCellRetentionPrune {
    api: &'static str,
    retention_millis: i64,
    batch: i32,
}

impl crate::dispatch_client::PreparedMutation for PreparedCellRetentionPrune {
    type Outcome = CellRetentionPruneReport;

    fn statement(&self) -> &'static str {
        PRUNE_SQL
    }

    fn bind(&self) -> Vec<&(dyn ToSql + Sync)> {
        vec![&self.api, &self.retention_millis, &self.batch]
    }

    fn decode(
        &self,
        row: &tokio_postgres::Row,
    ) -> Result<crate::dispatch_client::DispatchAccepted<Self::Outcome>, DispatchAuthorityError>
    {
        // The prune has one closed result code. It is not idempotent and has no replay: a second
        // pass over the same window is a different, equally valid batch, so `REPLAY` would be a
        // claim about identity this procedure never makes.
        if text(row, 0)? != "APPLIED" {
            return Err(DispatchAuthorityError::UnrecognizedResultCode);
        }
        let value = CellRetentionPruneReport {
            examined: int8(row, 1)?,
            pruned_requests: int8(row, 2)?,
            pruned_attempts: int8(row, 3)?,
            pruned_spool_objects: int8(row, 4)?,
            pruned_payload_purges: int8(row, 5)?,
            pruned_fetch_leases: int8(row, 6)?,
            pruned_charge_grants: int8(row, 7)?,
            horizon_unix_ms: int8(row, 8)?,
            database_now_unix_ms: int8(row, 9)?,
        };
        // Bound every count by what this call actually asked for. The procedure already refuses to
        // commit a pass whose request count and candidate count disagree; this is the client
        // refusing to *report* a number the request it submitted cannot explain, which is the half
        // a caller reading the report depends on.
        let batch = i64::from(self.batch);
        require(
            (0..=batch).contains(&value.examined)
                && value.pruned_requests == value.examined
                && value.pruned_attempts >= 0
                && value.pruned_spool_objects >= 0
                && value.pruned_payload_purges >= 0
                && value.pruned_fetch_leases >= 0
                // The grant sweep is independent of the request candidate set, so it is bounded by
                // the batch on its own rather than tied to `examined`.
                && (0..=batch).contains(&value.pruned_charge_grants),
            "cell retention prune counts",
        )?;
        // Not required to be nonnegative, for the same reason the probe's is not: a horizon before
        // the epoch selects nothing and is reported as used. What must hold is the exact offset.
        require(
            value.database_now_unix_ms >= 0
                && value
                    .database_now_unix_ms
                    .checked_sub(value.horizon_unix_ms)
                    == Some(self.retention_millis),
            "cell retention prune horizon",
        )?;
        Ok(crate::dispatch_client::DispatchAccepted {
            disposition: crate::dispatch_client::DispatchDisposition::Applied,
            value,
        })
    }
}

/// A point-in-time view of the retention facet and the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellRetentionSnapshot {
    /// The facet itself.
    pub retention_ready: bool,
    /// Why it is false, or `None` when it is true. A fixed, low-cardinality string.
    pub retention_reason: Option<&'static str>,
    /// Consecutive passes that made no progress.
    pub consecutive_stalls: u32,
    /// Terminal request rows the last pass removed.
    pub last_pruned: i64,
    /// Candidates the last pass locked.
    pub last_examined: i64,
    /// Rows a further pass could have taken, at the last probe. `-1` when it was not measured.
    pub last_prunable_backlog: i64,
    /// Rows past the horizon held back by non-terminal payload evidence, at the last probe. `-1`
    /// when it was not measured, which a reader must not confuse with "measured and empty".
    pub last_blocked_backlog: i64,
    /// Charge grants under an expired budget configuration still waiting, at the last probe. `-1`
    /// when it was not measured.
    pub last_grant_backlog: i64,
    /// Age of the last pass, if any.
    pub observation_age: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
struct RetentionObservation {
    at: Instant,
    examined: i64,
    pruned: i64,
    prunable_backlog: i64,
    blocked_backlog: i64,
    grant_backlog: i64,
    /// Why this pass was not progress, or `None` when it was. Carried on the observation rather
    /// than recomputed at snapshot time, because the counts it was decided from are the ones the
    /// snapshot reports and the two must not be able to disagree.
    stall_reason: Option<&'static str>,
}

/// Everything `snapshot` decides on, under **one** lock.
///
/// The observation and the stall count are one fact, not two: a snapshot pairing a fresh
/// observation with the previous count would report a stall run no pass ever had, and that window
/// is exactly the interleaving two separate mutexes allow.
#[derive(Debug, Default)]
struct RetentionState {
    last: Option<RetentionObservation>,
    consecutive_stalls: u32,
}

/// The shared cell-retention facet. Written by the task, read by the health surface.
#[derive(Debug)]
pub struct CellRetentionReadiness {
    state: Mutex<RetentionState>,
    stall_ticks: u32,
    staleness_bound: Duration,
    /// The value at which a backlog count means "more than a batch remains" rather than an exact
    /// count. Held here so [`CellRetentionReadiness::record_pass`] can decide saturation without
    /// the caller passing the settings in again and possibly passing different ones.
    probe_limit: i64,
}

impl CellRetentionReadiness {
    /// Build a facet for a task configured with these settings.
    #[must_use]
    pub fn new(settings: &CellRetentionSettings) -> Self {
        Self {
            state: Mutex::new(RetentionState::default()),
            stall_ticks: settings.stall_ticks,
            staleness_bound: settings.staleness_bound(),
            probe_limit: i64::from(settings.probe_limit()),
        }
    }

    /// Record a completed pass and the bounded backlog measured beside it.
    ///
    /// # The rule, and the two ways an earlier version of it was wrong
    ///
    /// The obvious rule is `pruned > 0 || backlog is empty`. It is wrong twice over, and both ways
    /// report green over exactly the unbounded growth this facet exists to catch. A cold review
    /// found them before this shipped; the reasoning is kept here because the corrected rule looks
    /// arbitrary without it.
    ///
    /// **`pruned > 0` must not short-circuit.** On any cell whose terminal requests arrive faster
    /// than `batch` per `interval`, every pass removes a full batch and the table still grows. The
    /// first form reported that as healthy forever, and worse, a permanently blocked row was
    /// invisible underneath it: `blocked > 0` was never even read on a cell with traffic, so the
    /// one condition that orphans a spool file with no other red gate had no red gate.
    ///
    /// So progress requires all three of: nothing blocked, no saturated backlog, and either
    /// something actually removed or nothing left to remove. `blocked` is checked unconditionally
    /// because past the retention horizon it is never transient. Saturation is `prunable` or
    /// `grants` reaching the probe limit, which the caller sets one above its batch precisely so
    /// that "a full batch remains" and "more than a batch remains" are different observations.
    ///
    /// A burst legitimately saturates for a pass or two; `stall_ticks` is the tolerance for that,
    /// and a backlog that has not cleared in that many consecutive passes is a real capacity
    /// problem rather than a spike.
    pub fn record_pass(&self, report: &CellRetentionPruneReport, backlog: &CellRetentionBacklog) {
        let removed = report
            .pruned_requests
            .saturating_add(report.pruned_charge_grants);
        let stall_reason = if backlog.blocked > 0 {
            Some(REASON_BLOCKED_BACKLOG)
        } else if backlog.prunable >= self.probe_limit || backlog.grants >= self.probe_limit {
            Some(REASON_BACKLOG_SATURATED)
        } else if removed == 0 && (backlog.prunable > 0 || backlog.grants > 0) {
            Some(REASON_NOT_PROGRESSING)
        } else {
            None
        };
        self.record(
            RetentionObservation {
                at: Instant::now(),
                examined: report.examined,
                pruned: report.pruned_requests,
                prunable_backlog: backlog.prunable,
                blocked_backlog: backlog.blocked,
                grant_backlog: backlog.grants,
                stall_reason,
            },
            stall_reason.is_none(),
        );
    }

    /// Record a pass, or the probe beside it, that could not run.
    ///
    /// The observation timestamp still advances: the task is alive and looking, which is a
    /// different condition from the task having stopped, and the stall counter is what reports the
    /// failure. Leaving the timestamp behind would report both conditions as staleness and lose the
    /// distinction. The recorded backlogs are `-1` rather than `0`, so a reader cannot mistake "not
    /// measured" for "measured and empty".
    pub fn record_failure(&self) {
        self.record(
            RetentionObservation {
                at: Instant::now(),
                examined: 0,
                pruned: 0,
                prunable_backlog: -1,
                blocked_backlog: -1,
                grant_backlog: -1,
                stall_reason: Some(REASON_NOT_PROGRESSING),
            },
            false,
        );
    }

    fn record(&self, observation: RetentionObservation, progressed: bool) {
        let mut state = self.lock();
        state.last = Some(observation);
        state.consecutive_stalls = if progressed {
            0
        } else {
            state.consecutive_stalls.saturating_add(1)
        };
    }

    /// The facet plus its evidence.
    #[must_use]
    pub fn snapshot(&self) -> CellRetentionSnapshot {
        let (observation, consecutive_stalls) = {
            let state = self.lock();
            (state.last, state.consecutive_stalls)
        };
        let observation_age = observation.as_ref().map(|value| value.at.elapsed());
        let stale = observation_age.is_some_and(|age| age > self.staleness_bound);

        let retention_reason = match observation.as_ref() {
            None => Some(REASON_NO_OBSERVATION),
            Some(_) if stale => Some(REASON_STALE_OBSERVATION),
            // Fail closed on the condition CR-033 D5 refuses to activate on: evidence rows past
            // their retention horizon, not removed, tick after tick. The last pass's own cause is
            // reported rather than one generic string, because "held back by an orphaned spool
            // object" and "draining slower than arrivals" need different operator action.
            Some(value) if consecutive_stalls >= self.stall_ticks => {
                value.stall_reason.or(Some(REASON_NOT_PROGRESSING))
            }
            Some(_) => None,
        };

        CellRetentionSnapshot {
            retention_ready: retention_reason.is_none(),
            retention_reason,
            consecutive_stalls,
            last_pruned: observation.as_ref().map_or(0, |value| value.pruned),
            last_examined: observation.as_ref().map_or(0, |value| value.examined),
            last_prunable_backlog: observation
                .as_ref()
                .map_or(-1, |value| value.prunable_backlog),
            last_blocked_backlog: observation
                .as_ref()
                .map_or(-1, |value| value.blocked_backlog),
            last_grant_backlog: observation.as_ref().map_or(-1, |value| value.grant_backlog),
            observation_age,
        }
    }

    /// The facet alone.
    #[must_use]
    pub fn retention_ready(&self) -> bool {
        self.snapshot().retention_ready
    }

    /// A panic while holding this must not take readiness reporting down with it, and the guarded
    /// value is a plain observation with no invariant a panic could have broken halfway.
    fn lock(&self) -> MutexGuard<'_, RetentionState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// The periodic cell-retention task.
///
/// This is the entry point `lore-server` wires: build it, then `lore_spawn!` [`CellRetentionTask::run`]
/// into the endpoint `JoinSet`.
pub struct CellRetentionTask {
    client: CellRetentionClient,
    settings: CellRetentionSettings,
    readiness: Arc<CellRetentionReadiness>,
}

impl CellRetentionTask {
    /// Assemble the task. Nothing runs until [`CellRetentionTask::run`].
    #[must_use]
    pub fn new(
        client: CellRetentionClient,
        settings: CellRetentionSettings,
        readiness: Arc<CellRetentionReadiness>,
    ) -> Self {
        Self {
            client,
            settings,
            readiness,
        }
    }

    /// Run until `shutdown` goes true.
    ///
    /// Returns nothing and **never** fails: this is spawned into the server's endpoint `JoinSet`,
    /// where an error takes the process down, and a retention pass that cannot reach PostgreSQL is
    /// emphatically not that. It is logged, counted into the stall tolerance, and retried on the
    /// next tick. The caller wraps it in whatever result shape its `JoinSet` expects.
    ///
    /// Drain-aware in both directions. The shutdown branch is selected against the sleep, so a
    /// drain does not wait out a tick; and the check before each pass means a signal that arrived
    /// during the previous pass starts no new database work. A pass already in flight is allowed to
    /// finish -- it is one bounded, short serializable transaction, and abandoning it mid-batch
    /// would leave its locks to time out rather than be released.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            interval_seconds = self.settings.interval.as_secs(),
            batch = self.settings.batch,
            terminal_retention_seconds = self.settings.terminal_retention.as_secs(),
            stall_ticks = self.settings.stall_ticks,
            "Starting the WP-114 CD-8 cell-scale retention scheduler"
        );

        // The first pass runs immediately rather than one interval in. The facet fails closed on
        // having no observation, so deferring it would report a healthy cell as not ready for a
        // whole interval at every boot.
        loop {
            if *shutdown.borrow() {
                break;
            }
            self.prune_once().await;
            let stop = tokio::select! {
                () = tokio::time::sleep(self.settings.interval) => false,
                // Both outcomes of this arm mean stop: `Ok` is the predicate becoming true, `Err`
                // is every sender gone. Written as `wait_for` rather than `changed()` for that
                // second case -- a `changed()` returning `Err` completes instantly and forever,
                // turning a dropped sender into a tight loop running the prune with no interval.
                _ = shutdown.wait_for(|&stop| stop) => true,
            };
            if stop {
                break;
            }
        }

        info!("Cell-scale retention scheduler stopped");
    }

    /// One pass, recorded into the facet either way.
    ///
    /// Public so a component test can drive exactly one pass without racing the interval.
    pub async fn prune_once(&self) {
        let report = match self.client.prune_once(&self.settings).await {
            Ok(report) => report,
            Err(error) => {
                warn!(%error, "Cell-scale retention pass failed");
                self.readiness.record_failure();
                return;
            }
        };
        // Measured **after** the pass, so it reports what the pass left behind rather than what it
        // found. Taken every tick rather than only when nothing was pruned, because the counts are
        // the facet's evidence and an operator reading a green facet is entitled to see the numbers
        // it was green about.
        let backlog = match self.client.backlog(&self.settings).await {
            Ok(backlog) => backlog,
            Err(error) => {
                warn!(
                    %error,
                    pruned = report.pruned_requests,
                    "Cell-scale retention backlog probe failed; the pass cannot be called progress"
                );
                self.readiness.record_failure();
                return;
            }
        };
        self.readiness.record_pass(&report, &backlog);
    }
}

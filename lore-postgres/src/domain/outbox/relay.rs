// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The relay-side outbox store (CR-032; WP-119 Step A, `SCHEMA-119`).
//!
//! This is the Postgres half of CR-032's relay: claim, publication result,
//! dead letter, epoch-reset requeue, backlog readiness, and admission. **The
//! relay worker loop is not here** — it is Step B, in `lore-server`. Nothing in
//! this module publishes, retries, sleeps, or decides a backoff; it only makes
//! each of those a durable, fenced, compare-and-set fact.
//!
//! # Two rules the whole module is built around
//!
//! **No transaction spans anything but its own statements.** Every function
//! takes a caller-supplied client or transaction and returns before any network
//! publish happens. `claim_batch` opens one short transaction, stamps its
//! leases, and commits; the gateway call happens afterwards with nothing held.
//! CR-032 forbids a transaction, checked-out connection, row lock, or domain
//! claim spanning gateway, broker, DNS, TLS, auth, or object-store I/O, and the
//! shape of this API is what makes that unrepresentable rather than merely
//! discouraged.
//!
//! **The relay takes no domain row locks.** F-032-3 fixes the shared row-lock
//! order for domain transactions and puts the outbox insert last in it. Nothing
//! here touches `lore_domain_repositories`, `lore_domain_branches`, a lock
//! namespace, a fragment row, or an association, so the relay cannot appear in
//! that order at all and cannot deadlock against a mutation.
//!
//! # Fencing
//!
//! `claim_generation` is a per-row monotonic counter, incremented every time a
//! worker claims the row. Every state-advancing call carries the generation the
//! caller believes it holds and compares it in the `WHERE` clause, so a worker
//! that was declared dead and whose lease was reclaimed cannot acknowledge,
//! reschedule, or dead-letter the newer claim. Each such call returns a typed
//! [`CasOutcome`] rather than a row count, because "0 rows updated" conflates a
//! stale claim, an already-accepted row, and a row that no longer exists, and
//! those need different handling.
//!
//! # Partial indexes and SQL literals
//!
//! Every scan predicate here spells its state as a **SQL literal**
//! (`state = 'pending'`, `state = 'broker_accepted'`), matching the partial
//! index definitions in [`super::schema`] exactly. A bound parameter returns
//! the same rows and passes every test, but the planner can only use a partial
//! index when it can prove the query predicate implies the index predicate, and
//! under a generic plan it cannot prove that from a parameter. There is no
//! non-partial index leading with `available_at` or `stream_identity`, so the
//! fallback is a sequential scan of the whole table. Do not "parameterise" one
//! of these.

use std::time::Duration;
use std::time::SystemTime;

use tokio_postgres::GenericClient;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::domain::errors::DomainError;
use crate::domain::fragments::failpoint;
use crate::domain::outbox::schema::DEAD_LETTER_OBSOLETE;
use crate::domain::outbox::schema::DEAD_LETTER_PARKED;
use crate::domain::outbox::schema::DEAD_LETTER_REQUEUED;
use crate::domain::outbox::schema::MAX_CLAIM_OWNER_BYTES;
use crate::domain::outbox::schema::MAX_DISPOSITION_ACTOR_BYTES;
use crate::domain::outbox::schema::MAX_DISPOSITION_REASON_BYTES;
use crate::domain::outbox::schema::MAX_ERROR_CLASS_BYTES;
use crate::domain::outbox::schema::MAX_GATEWAY_RESPONSE_ID_BYTES;
use crate::domain::outbox::schema::MAX_STREAM_IDENTITY_BYTES;
use crate::domain::outbox::schema::MAX_TERMINAL_CLASS_BYTES;
use crate::domain::outbox::schema::OUTBOX_STATE_PENDING;
use crate::domain::outbox::schema::relay_is_compatible;
use crate::domain::retry::classify_commit;

/// CR-032's claim bound: at most 100 rows per `FOR UPDATE SKIP LOCKED`
/// transaction.
pub const MAX_CLAIM_BATCH: usize = 100;
/// CR-032's lease: 30 seconds.
pub const DEFAULT_CLAIM_LEASE: Duration = Duration::from_secs(30);
/// CR-032's prune/replay bound, reused for the epoch-reset requeue: at most
/// 1,000 rows in one transaction.
///
/// Declared as the `i64` the `LIMIT` placeholder actually binds, with the
/// `usize` view derived from it, rather than the other way round. A `usize`
/// constant needs a fallible conversion at the call site, and the only honest
/// fallback for one — `unwrap_or(i64::MAX)` — turns an impossible failure into
/// an unbounded batch, which is the opposite of what the bound is for.
pub const EPOCH_RESET_BATCH_ROWS: i64 = 1_000;
/// [`EPOCH_RESET_BATCH_ROWS`] as a count.
pub const MAX_EPOCH_RESET_BATCH: usize = EPOCH_RESET_BATCH_ROWS as usize;
/// Hard cap on how many bounded batches one `requeue_unsafe_for_epoch_reset`
/// call will drive before returning. Ten million rows is far above any cell's
/// unpublished backlog (admission closes at one million), so reaching this is a
/// symptom, not a workload — it fails loudly instead of looping forever.
pub const MAX_EPOCH_RESET_BATCHES: usize = 10_000;

/// How many rows the bounded backlog probes will count before reporting
/// saturation.
///
/// One above CR-032's one-million-row admission limit, so a saturated probe is
/// always already over that limit and no verdict depends on the exact value
/// beyond it.
pub const BACKLOG_PROBE_CEILING: i64 = 1_000_001;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// The immutable identity and payload of one outbox row, without any relay
/// state. Shared by [`ClaimedEvent`] and [`OutboxRow`] so the two cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEventRecord {
    /// Stable event ID, created once in the mutation transaction.
    pub event_id: Uuid,
    /// Cell identity from trusted server configuration.
    pub cell_id: String,
    /// The deterministic BLAKE3 key over F-032-2's canonical tuple.
    pub idempotency_key: [u8; 32],
    /// Repository partition.
    pub repository_id: Vec<u8>,
    /// Repository generation committed by the causing mutation.
    pub repository_generation: i64,
    /// Classified event kind.
    pub event_kind: String,
    /// Aggregate kind.
    pub aggregate_kind: String,
    /// Aggregate identity within that kind.
    pub aggregate_id: Vec<u8>,
    /// Committed aggregate version, in the v1 encoding
    /// ([`crate::domain::outbox::version`]).
    pub aggregate_version: Vec<u8>,
    /// Schema version of `payload`.
    pub payload_schema_version: i32,
    /// Bounded identity/version projection.
    pub payload: Vec<u8>,
    /// Diagnostics only; never an ordering authority.
    pub created_at: SystemTime,
}

/// One row a worker now holds a lease on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedEvent {
    /// The event itself.
    pub event: OutboxEventRecord,
    /// The generation this claim stamped. Every later call about this row must
    /// carry it, and a call carrying an older one is refused.
    pub claim_generation: i64,
    /// When the lease expires, by the **database** clock.
    pub claim_expires_at: SystemTime,
    /// Attempts made before this one.
    pub attempt_count: i32,
    /// How the **immediately preceding** attempt on this row failed, or `None`
    /// when this is the first attempt or the row has only ever been claimed.
    ///
    /// Carried so a worker can tell a first failure of some kind from a
    /// repeated one without a second query. CR-032 makes a *repeated*
    /// event-specific 4xx terminal while a single one is not, and
    /// `attempt_count` cannot answer that: it counts every release, including
    /// timeouts and 5xx, so a row that survived a broker outage would arrive at
    /// its first genuine rejection already looking like a repeat offender.
    pub last_error_class: Option<String>,
}

/// A versioned gateway acknowledgement, as recorded on the row.
///
/// This is proof of **broker acceptance only**. It never means any consumer is
/// safe: `consumer_safe` is advanced independently by the checkpoint evaluator
/// (Step C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerAcceptanceRecord {
    /// Stream the gateway accepted onto.
    pub stream_identity: String,
    /// Stream epoch at acceptance. A later epoch reset requeues by this pair.
    pub stream_epoch: i64,
    /// Broker sequence the checkpoint evaluator compares against a receiver's
    /// contiguous acknowledgement frontier.
    pub broker_sequence: i64,
    /// Gateway response identity, for reconciliation and diagnostics.
    pub gateway_response_id: String,
    /// Publisher contract version the acknowledgement was issued under.
    pub publisher_contract_version: i32,
}

/// The outcome of one fenced compare-and-set against an outbox row.
///
/// Deliberately not a `bool` or a row count: "nothing was updated" has three
/// distinct causes here and they need different handling by the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome {
    /// The row matched the expected claim generation and state, and moved.
    Applied,
    /// The row exists but a newer claim owns it. This worker is fenced out and
    /// must drop the row without republishing or rescheduling it.
    StaleClaim {
        /// The generation currently on the row.
        current_claim_generation: i64,
    },
    /// The row is already past `pending`. A duplicate acknowledgement of an
    /// event another attempt already published; not an error.
    AlreadyAccepted,
    /// No such row. It was dead-lettered or pruned while this worker held it.
    Vanished,
}

/// One outbox row with its full relay state, as returned by
/// [`lookup_by_idempotency_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// The event itself.
    pub event: OutboxEventRecord,
    /// `pending`, `broker_accepted`, or `consumer_safe`.
    pub state: String,
    /// When the row next becomes eligible for a claim.
    pub available_at: SystemTime,
    /// Current claim generation.
    pub claim_generation: i64,
    /// Current lease owner, if any.
    pub claim_owner: Option<String>,
    /// Current lease expiry, if any.
    pub claim_expires_at: Option<SystemTime>,
    /// Attempts made so far.
    pub attempt_count: i32,
    /// Last bounded error classification, if any.
    pub last_error_class: Option<String>,
    /// The publication result, present exactly when `state` is past `pending`.
    pub acceptance: Option<BrokerAcceptanceRecord>,
    /// When the broker accepted, present exactly when `acceptance` is.
    pub broker_accepted_at: Option<SystemTime>,
    /// How many operator replays this row has been through (WP-119 Phase 8).
    ///
    /// Zero on a row no operator has ever replayed, which is every row the
    /// relay produced on its own.
    pub replay_count: i32,
    /// The audit trail CR-032 requires on a replay, present exactly when
    /// `replay_count` is non-zero. `lore_outbox_events_replay_shape` makes the
    /// three all-set or all-null together.
    pub replay: Option<ReplayAudit>,
}

/// The operator/reason audit CR-032 requires a replay to write to the row.
///
/// Only the **most recent** replay is retained. A row replayed twice records
/// the second decision and a count of two; the first decision's own record is
/// the operator's incident reference, which CR-032 already requires to be
/// exported. Keeping a full history here would put an unbounded array on the
/// hottest table in the relay's scan path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayAudit {
    /// Who ordered the replay.
    pub actor: String,
    /// Why.
    pub reason: String,
    /// When, by the database clock.
    pub at: SystemTime,
}

/// Bounded backlog facts, from one query.
///
/// The three counts are **bounded probes**: each stops at
/// [`BACKLOG_PROBE_CEILING`] rows, so a value equal to the ceiling means "at
/// least this many" rather than an exact total. That is deliberate — an exact
/// count of an unbounded backlog is an unbounded scan, and every decision these
/// feed is a threshold comparison well below the ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxBacklog {
    /// Every **unpublished** row, capped at the probe ceiling.
    ///
    /// A claimed row is still `pending` — a lease is not a publication — so
    /// this **includes** the rows counted by `claimed_count` rather than
    /// excluding them. That is the semantics admission needs: CR-032's limits
    /// are on unpublished rows, and a row a worker is mid-publish on is
    /// unpublished. `pending_count - claimed_count` is the unleased remainder.
    pub pending_count: i64,
    /// Sum of payload lengths over the same unpublished set and bounded window.
    pub pending_bytes: i64,
    /// How long the oldest unpublished row has been unpublished **in its
    /// current publication cycle**, by the database clock. `None` when there
    /// are no pending rows.
    ///
    /// Measured from `unpublished_since`, not `created_at`. The two are the
    /// same for every row the producer wrote and never differ until something
    /// returns a published row to `pending` — a replay or a broker epoch reset.
    /// A row created a week ago and replayed a second ago is one second behind,
    /// and measuring it as a week would close the cell's admission gate on the
    /// strength of the recovery that fixed it.
    pub oldest_pending_age: Option<Duration>,
    /// The leased subset of `pending_count`: rows carrying a claim owner and
    /// expiry, expired or not. Capped at the ceiling.
    pub claimed_count: i64,
    /// Dead letters still awaiting an operator disposition, capped.
    pub dead_letter_count: i64,
}

impl OutboxBacklog {
    /// Whether any count reached the probe ceiling, so the exact totals are
    /// larger than reported.
    pub fn saturated(&self) -> bool {
        self.pending_count >= BACKLOG_PROBE_CEILING
            || self.claimed_count >= BACKLOG_PROBE_CEILING
            || self.dead_letter_count >= BACKLOG_PROBE_CEILING
    }
}

/// CR-032's initial required-event admission limits.
///
/// "Configurable only within reviewed bounds" — the defaults here are the
/// reviewed values, and CR-032 requires WP-119 to load-test and revise them
/// before production activation rather than silently widening them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Oldest-unpublished age above which admission closes.
    pub max_oldest_pending_age: Duration,
    /// Unpublished row count above which admission closes.
    pub max_pending_rows: i64,
    /// Unpublished payload byte budget above which admission closes.
    pub max_pending_bytes: i64,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_oldest_pending_age: Duration::from_secs(5 * 60),
            max_pending_rows: 1_000_000,
            max_pending_bytes: 5 * 1024 * 1024 * 1024,
        }
    }
}

/// Why admission closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRejection {
    /// The oldest unpublished row is older than the limit.
    OldestPendingAge {
        /// Observed age.
        observed: Duration,
        /// Configured limit.
        limit: Duration,
    },
    /// Too many unpublished rows.
    PendingRows {
        /// Observed count, possibly saturated at the probe ceiling.
        observed: i64,
        /// Configured limit.
        limit: i64,
    },
    /// Too many unpublished payload bytes.
    PendingBytes {
        /// Observed sum over the bounded window.
        observed: i64,
        /// Configured limit.
        limit: i64,
    },
}

/// The admission verdict for one required-event mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// Local Postgres facts are inside every limit.
    Admit,
    /// Closed. The caller rejects **before** opening the mutation transaction,
    /// with `RESOURCE_EXHAUSTED` and bounded `RetryInfo`.
    Reject(AdmissionRejection),
}

/// The outcome of an operator disposition on a dead letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadLetterOutcome {
    /// The disposition was recorded.
    Applied,
    /// No dead letter with that event ID.
    NotFound,
    /// The compare-and-set failed: the row already carries a disposition.
    NotParked {
        /// The disposition currently on the row.
        disposition: String,
    },
    /// A live outbox row with the same stable keys already exists, so the
    /// requeue would duplicate it. Nothing was changed.
    EventStillPresent,
    /// This build's relay contract version is below the cell's
    /// `relay_compat_floor`, so it may not requeue work it cannot publish.
    RelayIncompatible {
        /// The cell's floor.
        relay_compat_floor: i32,
    },
}

// ---------------------------------------------------------------------------
// Row decoding
// ---------------------------------------------------------------------------

/// The identity/payload columns, in one place so every `SELECT` that decodes an
/// [`OutboxEventRecord`] lists exactly these and cannot drift from the decoder.
pub(super) const EVENT_COLUMNS: &str = "event_id, cell_id, idempotency_key, \
     repository_id, repository_generation, \
     event_kind, aggregate_kind, aggregate_id, aggregate_version, \
     payload_schema_version, payload, created_at";

fn idempotency_key_from(row: &Row) -> Result<[u8; 32], DomainError> {
    let raw: Vec<u8> = row.try_get("idempotency_key").map_err(|e| {
        DomainError::Internal(format!("outbox row is missing idempotency_key: {e}"))
    })?;
    raw.try_into().map_err(|raw: Vec<u8>| {
        // The column carries `CHECK (octet_length(idempotency_key) = 32)`, so
        // this is unreachable while the schema holds. It is still an explicit
        // error rather than an `expect`, because the alternative is a panic in
        // a relay worker on a schema drift no test would have caught.
        DomainError::Internal(format!(
            "outbox idempotency_key must be 32 bytes, got {}; the column CHECK has drifted",
            raw.len()
        ))
    })
}

pub(super) fn event_from(row: &Row) -> Result<OutboxEventRecord, DomainError> {
    Ok(OutboxEventRecord {
        event_id: row.get("event_id"),
        cell_id: row.get("cell_id"),
        idempotency_key: idempotency_key_from(row)?,
        repository_id: row.get("repository_id"),
        repository_generation: row.get("repository_generation"),
        event_kind: row.get("event_kind"),
        aggregate_kind: row.get("aggregate_kind"),
        aggregate_id: row.get("aggregate_id"),
        aggregate_version: row.get("aggregate_version"),
        payload_schema_version: row.get("payload_schema_version"),
        payload: row.get("payload"),
        created_at: row.get("created_at"),
    })
}

// ---------------------------------------------------------------------------
// Bounded input validation
// ---------------------------------------------------------------------------

pub(super) fn bounded(label: &str, value: &str, max: usize) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::InvalidInput(format!(
            "outbox {label} is empty"
        )));
    }
    if value.len() > max {
        return Err(DomainError::InvalidInput(format!(
            "outbox {label} exceeds {max} bytes: {}",
            value.len()
        )));
    }
    Ok(())
}

fn validate_acceptance(record: &BrokerAcceptanceRecord) -> Result<(), DomainError> {
    bounded(
        "stream_identity",
        &record.stream_identity,
        MAX_STREAM_IDENTITY_BYTES,
    )?;
    bounded(
        "gateway_response_id",
        &record.gateway_response_id,
        MAX_GATEWAY_RESPONSE_ID_BYTES,
    )?;
    if record.stream_epoch < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox stream_epoch must be >= 1, got {}",
            record.stream_epoch
        )));
    }
    if record.broker_sequence < 0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox broker_sequence must be >= 0, got {}",
            record.broker_sequence
        )));
    }
    if record.publisher_contract_version < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox publisher_contract_version must be >= 1, got {}",
            record.publisher_contract_version
        )));
    }
    Ok(())
}

/// Turn a lease into the `double precision` seconds the SQL multiplies by
/// `interval '1 second'`, rejecting a lease that cannot be represented.
fn lease_seconds(lease: Duration) -> Result<f64, DomainError> {
    let secs = lease.as_secs_f64();
    if !secs.is_finite() || secs <= 0.0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox claim lease must be a positive finite duration, got {secs}s"
        )));
    }
    Ok(secs)
}

// ---------------------------------------------------------------------------
// Claiming
// ---------------------------------------------------------------------------

/// Claim up to `limit` eligible rows for `owner`, stamping a fresh generation
/// and a `lease`-long expiry on each.
///
/// One short transaction: a `FOR UPDATE SKIP LOCKED` select ordered by
/// `available_at, event_id`, then one update over exactly those IDs, then
/// commit. `SKIP LOCKED` is what lets several workers claim disjoint batches
/// without an elected leader and without blocking on each other.
///
/// **Expired-claim reclaim is part of this eligibility rather than a separate
/// sweep.** A row whose lease has passed is selected again by the same query,
/// so a worker that died before publishing needs no sweeper to recover it and
/// there is no window in which a row is expired but not yet reclaimable. The
/// increment fences the dead worker out: its `claim_generation` is now stale,
/// so its acknowledgement, reschedule, or dead-letter is refused.
///
/// Ordering is a scan preference only. CR-032 is explicit that consumers must
/// not treat claim order as mutation ordering authority.
pub async fn claim_batch(
    client: &mut deadpool_postgres::Client,
    owner: &str,
    limit: usize,
    lease: Duration,
) -> Result<Vec<ClaimedEvent>, DomainError> {
    bounded("claim_owner", owner, MAX_CLAIM_OWNER_BYTES)?;
    if limit == 0 {
        return Ok(Vec::new());
    }
    if limit > MAX_CLAIM_BATCH {
        return Err(DomainError::InvalidInput(format!(
            "outbox claim limit exceeds the CR-032 bound of {MAX_CLAIM_BATCH}: {limit}"
        )));
    }
    let lease_secs = lease_seconds(lease)?;
    let limit_i64 = i64::try_from(limit).map_err(|_| {
        DomainError::InvalidInput(format!("outbox claim limit does not fit in i64: {limit}"))
    })?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox claim transaction begin", e))?;

    // `state = 'pending'` is a literal so the planner can prove it implies
    // `lore_outbox_events_pending_available`'s partial predicate. The lease
    // test cannot live in the index (it depends on the current clock), so it
    // filters the index's own rows rather than the table's.
    let selected = tx
        .query(
            "SELECT event_id FROM lore_outbox_events \
             WHERE state = 'pending' \
               AND available_at <= clock_timestamp() \
               AND (claim_expires_at IS NULL OR claim_expires_at <= clock_timestamp()) \
             ORDER BY available_at, event_id \
             LIMIT $1 \
             FOR UPDATE SKIP LOCKED",
            &[&limit_i64],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox claim select", e))?;

    failpoint!("outbox.claim.after_select")?;

    if selected.is_empty() {
        // Nothing was locked or written, so rolling back is the honest close.
        drop(tx);
        return Ok(Vec::new());
    }
    let ids: Vec<Uuid> = selected.iter().map(|r| r.get("event_id")).collect();

    let claimed = tx
        .query(
            &format!(
                "UPDATE lore_outbox_events SET \
                     claim_generation = claim_generation + 1, \
                     claim_owner = $1, \
                     claim_expires_at = clock_timestamp() + ($2::double precision \
                                        * interval '1 second') \
                 WHERE event_id = ANY($3) \
                 RETURNING {EVENT_COLUMNS}, claim_generation, claim_expires_at, \
                           attempt_count, last_error_class"
            ),
            &[&owner, &lease_secs, &ids],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox claim update", e))?;

    failpoint!("outbox.claim.before_commit")?;

    classify_commit(tx.commit().await, "outbox claim commit")?;

    claimed
        .iter()
        .map(|row| {
            Ok(ClaimedEvent {
                event: event_from(row)?,
                claim_generation: row.get("claim_generation"),
                claim_expires_at: row.get("claim_expires_at"),
                attempt_count: row.get("attempt_count"),
                last_error_class: row.get("last_error_class"),
            })
        })
        .collect()
}

/// Extend an existing lease, refusing if a newer claim has taken the row.
///
/// The owner is compared as well as the generation. A generation match with a
/// different owner would mean two workers believe they hold the same claim,
/// which is a bug rather than a race, and renewing it would hide that.
pub async fn renew_claim(
    client: &impl GenericClient,
    event_id: Uuid,
    claim_generation: i64,
    owner: &str,
    lease: Duration,
) -> Result<CasOutcome, DomainError> {
    bounded("claim_owner", owner, MAX_CLAIM_OWNER_BYTES)?;
    let lease_secs = lease_seconds(lease)?;
    let updated = client
        .execute(
            "UPDATE lore_outbox_events SET \
                 claim_expires_at = clock_timestamp() + ($1::double precision \
                                    * interval '1 second') \
             WHERE event_id = $2 AND claim_generation = $3 AND claim_owner = $4 \
               AND state = 'pending'",
            &[&lease_secs, &event_id, &claim_generation, &owner],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox claim renew", e))?;
    if updated == 1 {
        return Ok(CasOutcome::Applied);
    }
    classify_miss(client, event_id, claim_generation).await
}

/// Explain a zero-row compare-and-set by reading the row's current state.
///
/// This is a second statement, so the row may have moved again between the
/// update and this read. That is acceptable and cannot cause a wrong action:
/// the caller has already failed to apply its change, and every outcome this
/// can return leads the worker to drop the row rather than to write.
async fn classify_miss(
    client: &impl GenericClient,
    event_id: Uuid,
    expected_generation: i64,
) -> Result<CasOutcome, DomainError> {
    let row = client
        .query_opt(
            "SELECT state, claim_generation FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox claim classification", e))?;
    let Some(row) = row else {
        return Ok(CasOutcome::Vanished);
    };
    let current: i64 = row.get("claim_generation");
    if current != expected_generation {
        return Ok(CasOutcome::StaleClaim {
            current_claim_generation: current,
        });
    }
    let state: String = row.get("state");
    if state != OUTBOX_STATE_PENDING {
        return Ok(CasOutcome::AlreadyAccepted);
    }
    // Same generation, still pending, yet the update matched nothing. For
    // `renew_claim` that is an owner mismatch: another worker holds the same
    // generation, which the schema cannot prevent and which must not be
    // reported as a successful renewal.
    Ok(CasOutcome::StaleClaim {
        current_claim_generation: current,
    })
}

// ---------------------------------------------------------------------------
// Publication outcomes
// ---------------------------------------------------------------------------

/// Record a versioned gateway acknowledgement, advancing the row to
/// `broker_accepted` only if this worker still holds the claim.
///
/// This never means a consumer is safe. `consumer_safe` is advanced separately
/// by the bounded checkpoint evaluator (Step C), against a required-receiver
/// membership snapshot this module does not read.
///
/// The lease is cleared on success: the publication is done, and leaving an
/// owner on a row that no longer needs one would make it look claimed to every
/// backlog probe.
pub async fn record_broker_accepted(
    client: &impl GenericClient,
    event_id: Uuid,
    claim_generation: i64,
    acceptance: &BrokerAcceptanceRecord,
) -> Result<CasOutcome, DomainError> {
    validate_acceptance(acceptance)?;

    failpoint!("outbox.accept.before_update")?;

    let updated = client
        .execute(
            "UPDATE lore_outbox_events SET \
                 state = 'broker_accepted', \
                 stream_identity = $3, \
                 stream_epoch = $4, \
                 broker_sequence = $5, \
                 gateway_response_id = $6, \
                 publisher_contract_version = $7, \
                 broker_accepted_at = clock_timestamp(), \
                 claim_owner = NULL, \
                 claim_expires_at = NULL, \
                 last_error_class = NULL \
             WHERE event_id = $1 AND claim_generation = $2 AND state = 'pending'",
            &[
                &event_id,
                &claim_generation,
                &acceptance.stream_identity,
                &acceptance.stream_epoch,
                &acceptance.broker_sequence,
                &acceptance.gateway_response_id,
                &acceptance.publisher_contract_version,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox record broker acceptance", e))?;

    failpoint!("outbox.accept.after_update")?;

    if updated == 1 {
        return Ok(CasOutcome::Applied);
    }
    classify_miss(client, event_id, claim_generation).await
}

/// Release the claim for a later attempt after a transient failure.
///
/// Increments `attempt_count`, records the bounded error class, and sets
/// `available_at` to the caller's next attempt time. The backoff and jitter
/// themselves are the worker's (Step B); this only makes the decision durable.
///
/// The row stays `pending`, which is what keeps a transient failure — transport
/// error, timeout, 429, 5xx, broker unavailability — out of the poison path.
pub async fn release_for_retry(
    client: &impl GenericClient,
    event_id: Uuid,
    claim_generation: i64,
    error_class: &str,
    next_attempt_at: SystemTime,
) -> Result<CasOutcome, DomainError> {
    bounded("last_error_class", error_class, MAX_ERROR_CLASS_BYTES)?;
    let updated = client
        .execute(
            "UPDATE lore_outbox_events SET \
                 attempt_count = attempt_count + 1, \
                 last_error_class = $3, \
                 available_at = $4, \
                 claim_owner = NULL, \
                 claim_expires_at = NULL \
             WHERE event_id = $1 AND claim_generation = $2 AND state = 'pending'",
            &[&event_id, &claim_generation, &error_class, &next_attempt_at],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox release for retry", e))?;
    if updated == 1 {
        return Ok(CasOutcome::Applied);
    }
    classify_miss(client, event_id, claim_generation).await
}

// ---------------------------------------------------------------------------
// Dead letters
// ---------------------------------------------------------------------------

/// Move a terminally failed row to the dead-letter table.
///
/// # Copy then delete, not copy then mark
///
/// The row is **removed** from `lore_outbox_events`, not left behind under a
/// fourth state. Three reasons, in order of weight:
///
/// 1. Requeue has to work. CR-032 requires a requeued dead letter to be
///    republished under its **original stable keys**, and those keys include
///    the `(cell_id, idempotency_key)` unique constraint. Leaving the original
///    row in place would make the requeue insert collide with the very row it
///    is reinstating.
/// 2. A fourth state would be a `CHECK` change on the state enum CR-032 froze
///    at three values, and every partial index predicate here would have to
///    widen with it.
/// 3. No evidence is lost: every identity and payload column is copied
///    verbatim, and an operator disposition never deletes the copy.
///
/// The copy and the delete are one transaction, so a crash between them cannot
/// lose the row or leave it in both places.
///
/// A repeat dead-letter of the same event (requeued, failed again) updates the
/// existing evidence row and preserves its `first_failed_at`.
pub async fn dead_letter(
    client: &mut deadpool_postgres::Client,
    event_id: Uuid,
    claim_generation: i64,
    terminal_class: &str,
) -> Result<CasOutcome, DomainError> {
    bounded("terminal_class", terminal_class, MAX_TERMINAL_CLASS_BYTES)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox dead letter transaction begin", e))?;

    let row = tx
        .query_opt(
            "SELECT state, claim_generation, attempt_count \
             FROM lore_outbox_events WHERE event_id = $1 FOR UPDATE",
            &[&event_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox dead letter row lock", e))?;

    let Some(row) = row else {
        drop(tx);
        return Ok(CasOutcome::Vanished);
    };
    let current_generation: i64 = row.get("claim_generation");
    if current_generation != claim_generation {
        drop(tx);
        return Ok(CasOutcome::StaleClaim {
            current_claim_generation: current_generation,
        });
    }
    let state: String = row.get("state");
    if state != OUTBOX_STATE_PENDING {
        drop(tx);
        return Ok(CasOutcome::AlreadyAccepted);
    }

    // The replay audit rides along, both on the insert and on the conflict
    // update (WP-119 Phase 8). Without it, the one path an incident review
    // actually asks about — a row an operator replayed, which then failed
    // terminally — reached the operator queue with no record that it had ever
    // been replayed, and a later requeue reinstated it at `replay_count = 0`
    // with a null actor. The evidence copy is immutable, so these are carried
    // verbatim rather than recomputed.
    //
    // A repeat dead-letter (requeued, then terminally failed again) must return
    // the row to `parked` or it would never reach the operator queue a second
    // time -- but overwriting the disposition in place would delete the record
    // of the decision that put it back in flight. The prior decision moves into
    // the `previous_disposition_*` columns and `dead_letter_count` counts the
    // cycles. `first_failed_at` is deliberately not in the update list, so the
    // original failure time survives every cycle.
    tx.execute(
        "INSERT INTO lore_outbox_dead_letters ( \
             event_id, cell_id, idempotency_key, \
             repository_id, repository_generation, \
             event_kind, aggregate_kind, aggregate_id, aggregate_version, \
             payload_schema_version, payload, created_at, attempt_count, \
             claim_generation, \
             replay_count, replayed_at, replay_actor, replay_reason, \
             terminal_class, first_failed_at, last_failed_at, disposition \
         ) \
         SELECT event_id, cell_id, idempotency_key, \
                repository_id, repository_generation, \
                event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                payload_schema_version, payload, created_at, attempt_count, \
                claim_generation, \
                replay_count, replayed_at, replay_actor, replay_reason, \
                $2, clock_timestamp(), clock_timestamp(), $3 \
         FROM lore_outbox_events WHERE event_id = $1 \
         ON CONFLICT (event_id) DO UPDATE SET \
             terminal_class = EXCLUDED.terminal_class, \
             attempt_count = EXCLUDED.attempt_count, \
             replay_count = EXCLUDED.replay_count, \
             replayed_at = EXCLUDED.replayed_at, \
             replay_actor = EXCLUDED.replay_actor, \
             replay_reason = EXCLUDED.replay_reason, \
             claim_generation = GREATEST(lore_outbox_dead_letters.claim_generation, \
                                         EXCLUDED.claim_generation), \
             last_failed_at = EXCLUDED.last_failed_at, \
             dead_letter_count = lore_outbox_dead_letters.dead_letter_count + 1, \
             previous_disposition = lore_outbox_dead_letters.disposition, \
             previous_disposition_reason = lore_outbox_dead_letters.disposition_reason, \
             previous_disposition_at = lore_outbox_dead_letters.disposition_at, \
             previous_disposition_actor = lore_outbox_dead_letters.disposition_actor, \
             disposition = EXCLUDED.disposition, \
             disposition_reason = NULL, \
             disposition_at = NULL, \
             disposition_actor = NULL",
        &[&event_id, &terminal_class, &DEAD_LETTER_PARKED],
    )
    .await
    .map_err(|e| DomainError::from_pg("outbox dead letter copy", e))?;

    failpoint!("outbox.dead_letter.between_copy_and_delete")?;

    tx.execute(
        "DELETE FROM lore_outbox_events WHERE event_id = $1",
        &[&event_id],
    )
    .await
    .map_err(|e| DomainError::from_pg("outbox dead letter delete", e))?;

    classify_commit(tx.commit().await, "outbox dead letter commit")?;
    Ok(CasOutcome::Applied)
}

/// Return a parked dead letter to `pending` with its original stable keys.
///
/// CR-032 requires a compare-and-set on the disposition **and** a currently
/// compatible relay version, so both are checked inside the one transaction
/// that performs the reinstatement.
///
/// The reinstated row keeps its `event_id`, `idempotency_key`, and every
/// identity field, **including any replay audit** the row carried when it went
/// terminal. `attempt_count` resets to 0, the lease is empty, and there is no
/// publication result. The evidence row is kept and marked `requeued` rather
/// than deleted.
///
/// `unpublished_since` is set to now rather than carried: the row is entering a
/// fresh publication cycle, and dating it from the original append would make a
/// requeued dead letter report its whole terminal lifetime as relay lag and
/// close the cell's admission gate.
///
/// **`claim_generation` does NOT reset.** It is reinstated at the dead letter's
/// stored generation **plus one**, which is strictly above every generation any
/// worker can still be holding for this event. Resetting it to 0 would make the
/// fence reusable: a worker that held generation 1 when the row was
/// dead-lettered would compare equal against a requeued row a second worker had
/// just claimed at generation 1, and its acknowledgement would apply. That is
/// not hypothetical — it was reproduced on PostgreSQL 16.15 against the reset-
/// to-zero version of this function, where the fenced-out worker's
/// `record_broker_accepted` updated one row and returned `Applied`.
pub async fn requeue_dead_letter(
    client: &mut deadpool_postgres::Client,
    event_id: Uuid,
    reason: &str,
    actor: &str,
) -> Result<DeadLetterOutcome, DomainError> {
    // Both operator dispositions require a reason, so both validate it the same
    // way. CR-032 requires a reason on an obsolete marking; a requeue is the
    // decision that puts an event back in flight and is no less worth
    // recording.
    bounded("disposition_actor", actor, MAX_DISPOSITION_ACTOR_BYTES)?;
    bounded("disposition_reason", reason, MAX_DISPOSITION_REASON_BYTES)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox requeue transaction begin", e))?;

    let floor: i32 = tx
        .query_one(
            "SELECT relay_compat_floor FROM lore_outbox_schema_state WHERE id = 1",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox requeue compatibility read", e))?
        .get("relay_compat_floor");
    if !relay_is_compatible(floor) {
        drop(tx);
        return Ok(DeadLetterOutcome::RelayIncompatible {
            relay_compat_floor: floor,
        });
    }

    let row = tx
        .query_opt(
            "SELECT disposition FROM lore_outbox_dead_letters WHERE event_id = $1 FOR UPDATE",
            &[&event_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox requeue row lock", e))?;
    let Some(row) = row else {
        drop(tx);
        return Ok(DeadLetterOutcome::NotFound);
    };
    let disposition: String = row.get("disposition");
    if disposition != DEAD_LETTER_PARKED {
        drop(tx);
        return Ok(DeadLetterOutcome::NotParked { disposition });
    }

    // Two different unique constraints can reject this insert — the primary key
    // and `(cell_id, idempotency_key)` — and `ON CONFLICT` can name only one
    // target, so the violation is classified from its SQLSTATE instead.
    let reinstated = tx
        .execute(
            "INSERT INTO lore_outbox_events ( \
                 event_id, cell_id, idempotency_key, \
                 repository_id, repository_generation, \
                 event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                 payload_schema_version, payload, \
                 state, created_at, available_at, unpublished_since, \
                 claim_generation, attempt_count, \
                 replay_count, replayed_at, replay_actor, replay_reason \
             ) \
             SELECT event_id, cell_id, idempotency_key, \
                    repository_id, repository_generation, \
                    event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                    payload_schema_version, payload, \
                    $2, created_at, clock_timestamp(), clock_timestamp(), \
                    claim_generation + 1, 0, \
                    replay_count, replayed_at, replay_actor, replay_reason \
             FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id, &OUTBOX_STATE_PENDING],
        )
        .await;
    match reinstated {
        Ok(_) => {}
        Err(e) => {
            let unique_violation = e
                .code()
                .is_some_and(|c| *c == tokio_postgres::error::SqlState::UNIQUE_VIOLATION);
            drop(tx);
            if unique_violation {
                return Ok(DeadLetterOutcome::EventStillPresent);
            }
            return Err(DomainError::from_pg("outbox requeue reinstate", e));
        }
    }

    let dispositioned = tx
        .execute(
            "UPDATE lore_outbox_dead_letters SET \
                 disposition = $2, \
                 disposition_reason = $3, \
                 disposition_at = clock_timestamp(), \
                 disposition_actor = $4 \
             WHERE event_id = $1 AND disposition = $5",
            &[
                &event_id,
                &DEAD_LETTER_REQUEUED,
                &reason,
                &actor,
                &DEAD_LETTER_PARKED,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox requeue disposition", e))?;
    // Unreachable while the `FOR UPDATE` above holds the row and reported it
    // `parked`. Checked anyway rather than discarded, because the alternative
    // to noticing here is committing a reinstated event whose dead letter still
    // reads `parked` — an operator queue entry for work already back in flight.
    if dispositioned != 1 {
        return Err(DomainError::Internal(format!(
            "outbox requeue updated {dispositioned} dead-letter rows for {event_id} while \
             holding its row lock; the disposition CAS and the locked read disagree"
        )));
    }

    classify_commit(tx.commit().await, "outbox requeue commit")?;
    Ok(DeadLetterOutcome::Applied)
}

/// Mark a parked dead letter obsolete, with a reason and an operator identity.
///
/// CR-032: marking obsolete requires authoritative state validation and a
/// reason, and **does not delete the original evidence** — only the disposition
/// changes. The authoritative validation is the operator's, performed before
/// this call; this records the decision and who made it.
pub async fn mark_obsolete(
    client: &impl GenericClient,
    event_id: Uuid,
    reason: &str,
    actor: &str,
) -> Result<DeadLetterOutcome, DomainError> {
    bounded("disposition_actor", actor, MAX_DISPOSITION_ACTOR_BYTES)?;
    bounded("disposition_reason", reason, MAX_DISPOSITION_REASON_BYTES)?;

    let updated = client
        .execute(
            "UPDATE lore_outbox_dead_letters SET \
                 disposition = $2, \
                 disposition_reason = $3, \
                 disposition_at = clock_timestamp(), \
                 disposition_actor = $4 \
             WHERE event_id = $1 AND disposition = $5",
            &[
                &event_id,
                &DEAD_LETTER_OBSOLETE,
                &reason,
                &actor,
                &DEAD_LETTER_PARKED,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox mark obsolete", e))?;
    if updated == 1 {
        return Ok(DeadLetterOutcome::Applied);
    }
    let row = client
        .query_opt(
            "SELECT disposition FROM lore_outbox_dead_letters WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox mark obsolete classification", e))?;
    match row {
        None => Ok(DeadLetterOutcome::NotFound),
        Some(row) => Ok(DeadLetterOutcome::NotParked {
            disposition: row.get("disposition"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Broker epoch reset
// ---------------------------------------------------------------------------

/// Return every `broker_accepted` row published to one stream identity and
/// epoch to `pending`, clearing its publication result.
///
/// This is the Postgres half of CR-032's broker epoch reset: when a broker
/// epoch resets or its sequence rolls back, the publication mapping for that
/// epoch is void, and every retained not-yet-`consumer_safe` row must be
/// republished **with its original stable keys** under the new epoch. Nothing
/// is re-created and no key is re-derived; the same rows go back to `pending`.
///
/// Bounded to [`MAX_EPOCH_RESET_BATCH`] rows per transaction, driven by an
/// `event_id` cursor so each batch is one short transaction rather than one
/// long one over the whole epoch. Returns the total requeued.
///
/// **The generation is bumped, and that closes less than it looks like.** An
/// acceptance recorded under the reset epoch is void, so a worker still holding
/// a claim on a row this requeued must not be able to re-record it. Without the
/// bump, a *retried* `record_broker_accepted` carrying the old epoch's
/// acceptance applies to the requeued row and puts it back to
/// `broker_accepted` under a void epoch, behind this scan's cursor and
/// therefore unreachable by this reset and by any later one. Measured on
/// PostgreSQL 16.15 both ways: without the bump that retry updates one row,
/// with it zero.
///
/// **The remaining hole is not closeable here, and this function must not be
/// read as closing it.** A worker whose row is still `pending` because its
/// gateway call has not returned is invisible to this scan — the scan selects
/// `broker_accepted` — so its generation is not bumped, and its later
/// acknowledgement under the old epoch applies. Demonstrated by the same probe.
/// CR-032 puts the fence for that case before the requeue, not in it: the reset
/// service installs `reset_in_progress` and compare-and-sets readiness false in
/// the transaction that allocates the new reset generation, and only then does
/// every retained unsafe row return to `pending`.
///
/// TODO(WP-119 Step C): `ReportStreamReset` owns that fence. This function is
/// its bounded requeue step and is not safe to call outside it.
///
/// **Termination is decided by the SELECT, not by the UPDATE.** The two are
/// separate statements because plain `FOR UPDATE` re-evaluates a concurrently
/// updated row (EvalPlanQual) and can drop it from the update's result set. A
/// loop that stopped when the *update* returned nothing would therefore end
/// early — with rows past the cursor still published under the void epoch —
/// the first time a whole batch was concurrently touched. The cursor advances
/// past every row the SELECT saw, whether or not the UPDATE moved it, which is
/// also what keeps the loop making forward progress rather than re-reading a
/// row it cannot change.
///
/// `consumer_safe` rows are deliberately **not** touched: CR-032 recovers those
/// through the receiver's authoritative baseline rather than fabricated replay.
/// A row that a concurrent Step C evaluator advances to `consumer_safe` mid-
/// reset is likewise left alone, and is exactly such a dropped row.
pub async fn requeue_unsafe_for_epoch_reset(
    client: &mut deadpool_postgres::Client,
    stream_identity: &str,
    old_epoch: i64,
) -> Result<u64, DomainError> {
    bounded(
        "stream_identity",
        stream_identity,
        MAX_STREAM_IDENTITY_BYTES,
    )?;
    if old_epoch < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox stream_epoch must be >= 1, got {old_epoch}"
        )));
    }
    let mut total: u64 = 0;
    let mut cursor = Uuid::nil();
    for _ in 0..MAX_EPOCH_RESET_BATCHES {
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("outbox epoch reset transaction begin", e))?;

        // `state = 'broker_accepted'` is a literal so the planner can prove it
        // implies `lore_outbox_events_accepted_stream`'s partial predicate.
        // Plain `FOR UPDATE`, not `SKIP LOCKED`: a reset must reach every row,
        // and skipping a locked one would silently leave it published under a
        // void epoch.
        let selected = tx
            .query(
                "SELECT event_id FROM lore_outbox_events \
                 WHERE state = 'broker_accepted' \
                   AND stream_identity = $1 \
                   AND stream_epoch = $2 \
                   AND event_id > $3 \
                 ORDER BY event_id \
                 LIMIT $4 \
                 FOR UPDATE",
                &[
                    &stream_identity,
                    &old_epoch,
                    &cursor,
                    &EPOCH_RESET_BATCH_ROWS,
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("outbox epoch reset select", e))?;

        if selected.is_empty() {
            // Nothing was written, so rolling back is the honest close, and
            // the SELECT finding no further candidate is the only termination
            // condition.
            drop(tx);
            return Ok(total);
        }
        let ids: Vec<Uuid> = selected.iter().map(|r| r.get("event_id")).collect();
        // Ordered by `event_id`, so the last is the maximum; taken from the
        // SELECT rather than from the UPDATE's `RETURNING`, which promises no
        // order and may omit a concurrently-changed row.
        let Some(highest) = ids.last().copied() else {
            drop(tx);
            return Ok(total);
        };

        let requeued = tx
            .execute(
                // `unpublished_since` restarts here for the same reason the
                // operator replay restarts it (WP-119 Phase 8): these rows were
                // published and are being returned to `pending` by a broker
                // epoch reset, so their unpublished clock begins now. Leaving
                // it at `created_at` would make an epoch reset on a
                // week-old-but-published backlog report a week-old backlog and
                // close the cell's admission gate, on rows the relay is not
                // actually behind on.
                "UPDATE lore_outbox_events SET \
                     state = 'pending', \
                     available_at = clock_timestamp(), \
                     unpublished_since = clock_timestamp(), \
                     claim_generation = claim_generation + 1, \
                     stream_identity = NULL, \
                     stream_epoch = NULL, \
                     broker_sequence = NULL, \
                     gateway_response_id = NULL, \
                     publisher_contract_version = NULL, \
                     broker_accepted_at = NULL, \
                     claim_owner = NULL, \
                     claim_expires_at = NULL \
                 WHERE event_id = ANY($1) AND state = 'broker_accepted' \
                   AND stream_identity = $2 AND stream_epoch = $3",
                &[&ids, &stream_identity, &old_epoch],
            )
            .await
            .map_err(|e| DomainError::from_pg("outbox epoch reset requeue", e))?;

        classify_commit(tx.commit().await, "outbox epoch reset commit")?;

        total = total.saturating_add(requeued);
        cursor = highest;
    }

    Err(DomainError::Internal(format!(
        "outbox epoch reset for stream {stream_identity} epoch {old_epoch} did not converge \
         within {MAX_EPOCH_RESET_BATCHES} batches of {MAX_EPOCH_RESET_BATCH} rows after \
         requeueing {total}; this is far above the one-million-row admission limit and \
         indicates a stuck cursor rather than a workload"
    )))
}

// ---------------------------------------------------------------------------
// Lookup and readiness
// ---------------------------------------------------------------------------

/// Read one row by its stable `(cell_id, idempotency_key)` pair.
///
/// INV-FL R-SHOULD-1: CR-032 requires the transaction-local API to support
/// lookup by idempotency key for outcome reconciliation, and the published
/// `OUTBOX-BASE-API-READY` handoff had none. This closes it. It is the read
/// behind CR-032's outcome-unknown path — a producer whose commit
/// acknowledgement was lost resolves what actually happened by looking up the
/// key it would have written, rather than by inferring it from later domain
/// state.
///
/// Answered from the `lore_outbox_events_cell_idempotency` unique index, so it
/// is a single index lookup regardless of backlog size.
pub async fn lookup_by_idempotency_key(
    client: &impl GenericClient,
    cell_id: &str,
    idempotency_key: &[u8; 32],
) -> Result<Option<OutboxRow>, DomainError> {
    let key = idempotency_key.as_slice();
    let row = client
        .query_opt(
            &format!(
                "SELECT {EVENT_COLUMNS}, {ROW_STATE_COLUMNS} \
                 FROM lore_outbox_events WHERE cell_id = $1 AND idempotency_key = $2"
            ),
            &[&cell_id, &key],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox lookup by idempotency key", e))?;

    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(row_from(&row)?))
}

/// The columns every `SELECT` decoding a full [`OutboxRow`] must list, beyond
/// [`EVENT_COLUMNS`].
///
/// Same reason as `EVENT_COLUMNS`: the list and the decoder are one fact, and
/// an operator listing that spelled its own subset would decode a row the
/// lookup path could not, or silently drop a column added to one and not the
/// other.
pub(super) const ROW_STATE_COLUMNS: &str = "state, available_at, \
     claim_generation, claim_owner, claim_expires_at, \
     attempt_count, last_error_class, \
     stream_identity, stream_epoch, broker_sequence, \
     gateway_response_id, publisher_contract_version, broker_accepted_at, \
     replay_count, replayed_at, replay_actor, replay_reason";

/// Decode one row selected with `{EVENT_COLUMNS}, {ROW_STATE_COLUMNS}`.
pub(super) fn row_from(row: &Row) -> Result<OutboxRow, DomainError> {
    // The `lore_outbox_events_publication_shape` CHECK makes these six columns
    // all-set or all-null together, so reading one of them decides whether the
    // record is present; the others are read unconditionally and would be
    // caught by that CHECK if the schema ever drifted.
    let stream_identity: Option<String> = row.get("stream_identity");
    let acceptance = stream_identity.map(|stream_identity| BrokerAcceptanceRecord {
        stream_identity,
        stream_epoch: row.get("stream_epoch"),
        broker_sequence: row.get("broker_sequence"),
        gateway_response_id: row.get("gateway_response_id"),
        publisher_contract_version: row.get("publisher_contract_version"),
    });

    // Same shape argument, against `lore_outbox_events_replay_shape`.
    let replayed_at: Option<SystemTime> = row.get("replayed_at");
    let replay = replayed_at.map(|at| ReplayAudit {
        actor: row.get("replay_actor"),
        reason: row.get("replay_reason"),
        at,
    });

    Ok(OutboxRow {
        event: event_from(row)?,
        state: row.get("state"),
        available_at: row.get("available_at"),
        claim_generation: row.get("claim_generation"),
        claim_owner: row.get("claim_owner"),
        claim_expires_at: row.get("claim_expires_at"),
        attempt_count: row.get("attempt_count"),
        last_error_class: row.get("last_error_class"),
        acceptance,
        broker_accepted_at: row.get("broker_accepted_at"),
        replay_count: row.get("replay_count"),
        replay,
    })
}

/// Read the bounded backlog facts in one query.
///
/// Every sub-query is index-backed, and each is named here because "it uses an
/// index" is the load-bearing claim rather than an aside:
///
/// * `pending_count` is an **index-only** scan over
///   `lore_outbox_events_dispatch`, whose leading column is the equality
///   predicate. Measured: 17 shared buffers for 18,000 pending rows, 0 heap
///   fetches. That index is **not** partial, so this one sub-query is the
///   exception to the literal rule — it plans the same way with the state
///   bound as a parameter.
/// * `pending_bytes` reads each pending row's main heap tuple and is **not**
///   index-only; an expression index on `octet_length(payload)` does not make
///   it so, and see the comment in [`super::schema`] for the measurement that
///   ruled that index out. Its plan is payload-size-dependent, which is the
///   part worth knowing: with 8 KiB payloads the table is wide enough that an
///   index scan wins (600 shared buffers, 4.9 ms for 18,000 rows), and with
///   64-byte payloads the planner takes a sequential scan (581 buffers) because
///   the whole table is smaller than the index walk. Either way the cost tracks
///   the pending ROW count rather than the payload bytes, because
///   `octet_length` reads the length from the TOAST pointer without detoasting.
///   All figures PostgreSQL 16.15.
/// * `oldest_pending_age` is a `min()` over the leading column of
///   `lore_outbox_events_pending_unpublished`, answered from the first live index
///   entry rather than by scanning — an `Index Only Scan` under a `Limit`.
/// * `claimed_count` counts over `lore_outbox_events_claim_expiry`, partial on
///   `claim_expires_at IS NOT NULL`, so it holds only rows a worker currently
///   owns — bounded by batch size times live workers, not by the table.
/// * `dead_letter_count` counts over `lore_outbox_dead_letters_operations`,
///   whose leading column is the equality predicate.
///
/// Of the four sub-queries with a value predicate, `pending_count` and
/// `pending_bytes` test `state = 'pending'` and `dead_letter_count` tests
/// `disposition = 'parked'`; all three are written as SQL literals for
/// uniformity with the module's rule, though only a **partial** index makes a
/// literal load-bearing — and of these three only the `state` pair sits on one.
/// `claimed_count` has no value predicate at all: its index is partial on
/// `claim_expires_at IS NOT NULL`.
pub async fn backlog(client: &impl GenericClient) -> Result<OutboxBacklog, DomainError> {
    let ceiling = BACKLOG_PROBE_CEILING;
    let row = client
        .query_one(
            "SELECT \
               (SELECT count(*) FROM ( \
                    SELECT 1 FROM lore_outbox_events \
                    WHERE state = 'pending' LIMIT $1) AS p)::bigint AS pending_count, \
               (SELECT coalesce(sum(len), 0) FROM ( \
                    SELECT octet_length(payload) AS len FROM lore_outbox_events \
                    WHERE state = 'pending' LIMIT $1) AS b)::bigint AS pending_bytes, \
               (SELECT extract(epoch FROM (clock_timestamp() - min(unpublished_since))) \
                  FROM lore_outbox_events \
                 WHERE state = 'pending')::double precision AS oldest_pending_age_secs, \
               (SELECT count(*) FROM ( \
                    SELECT 1 FROM lore_outbox_events \
                    WHERE claim_expires_at IS NOT NULL LIMIT $1) AS c)::bigint AS claimed_count, \
               (SELECT count(*) FROM ( \
                    SELECT 1 FROM lore_outbox_dead_letters \
                    WHERE disposition = 'parked' LIMIT $1) AS d)::bigint AS dead_letter_count",
            &[&ceiling],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox backlog", e))?;

    let age_secs: Option<f64> = row.get("oldest_pending_age_secs");
    Ok(OutboxBacklog {
        pending_count: row.get("pending_count"),
        pending_bytes: row.get("pending_bytes"),
        // A negative age would mean the oldest pending row was created in the
        // database's own future, which `clock_timestamp()` cannot produce;
        // clamping rather than erroring keeps a readiness probe answerable.
        oldest_pending_age: age_secs.map(|s| Duration::from_secs_f64(s.max(0.0))),
        claimed_count: row.get("claimed_count"),
        dead_letter_count: row.get("dead_letter_count"),
    })
}

/// Decide required-event mutation admission from **local Postgres facts only**.
///
/// CR-032 is explicit that this gate may read unpublished row/byte/age limits
/// and a bounded-staleness Postgres projection, and must not query live broker
/// lag, gateway health, or a receiver over the network. Nothing here leaves the
/// database.
///
/// The caller runs this **before** opening the mutation transaction. A mutation
/// that already committed stays successful; only a pre-commit rejection is
/// possible, and it maps outward to `RESOURCE_EXHAUSTED` with bounded
/// `RetryInfo`.
///
/// Age is checked first, deliberately. It is the cheapest probe (a single
/// index `min()`) and, in every failure mode CR-032 describes, the one that
/// trips first: a stalled relay passes five minutes of oldest-unpublished age
/// long before a cell accumulates a million rows. So the common rejection costs
/// one index lookup, and the two counting probes run only when the age is fine.
///
/// TODO(WP-119 Step B): CR-032 requires this to be load-tested and the initial
/// limits revised before production activation. The row and byte probes are
/// bounded but still O(pending): measured at 19 and 600 shared buffers
/// respectively for 18,000 pending rows on PostgreSQL 16.15, so a backlog near
/// the one-million-row limit puts the byte probe in the tens of thousands of
/// buffers. If a load test shows the per-mutation cost matters, cache the
/// verdict with an explicit bounded staleness rather than widening the limits.
pub async fn admission_check(
    client: &impl GenericClient,
    limits: &AdmissionLimits,
) -> Result<AdmissionVerdict, DomainError> {
    let age_secs: Option<f64> = client
        .query_one(
            "SELECT extract(epoch FROM (clock_timestamp() - min(unpublished_since)))::double \
               precision \
               AS oldest_pending_age_secs \
               FROM lore_outbox_events WHERE state = 'pending'",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox admission age probe", e))?
        .get("oldest_pending_age_secs");

    if let Some(secs) = age_secs {
        let observed = Duration::from_secs_f64(secs.max(0.0));
        if observed > limits.max_oldest_pending_age {
            return Ok(AdmissionVerdict::Reject(
                AdmissionRejection::OldestPendingAge {
                    observed,
                    limit: limits.max_oldest_pending_age,
                },
            ));
        }
    } else {
        // No pending rows at all: no row or byte probe can reject.
        return Ok(AdmissionVerdict::Admit);
    }

    // One row past each limit is enough to decide, so the probes stop there
    // instead of counting the whole backlog.
    let row_probe = limits.max_pending_rows.saturating_add(1);
    let row = client
        .query_one(
            "SELECT \
               (SELECT count(*) FROM ( \
                    SELECT 1 FROM lore_outbox_events \
                    WHERE state = 'pending' LIMIT $1) AS p)::bigint AS pending_count, \
               (SELECT coalesce(sum(len), 0) FROM ( \
                    SELECT octet_length(payload) AS len FROM lore_outbox_events \
                    WHERE state = 'pending' LIMIT $1) AS b)::bigint AS pending_bytes",
            &[&row_probe],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox admission backlog probe", e))?;

    let pending_count: i64 = row.get("pending_count");
    if pending_count > limits.max_pending_rows {
        return Ok(AdmissionVerdict::Reject(AdmissionRejection::PendingRows {
            observed: pending_count,
            limit: limits.max_pending_rows,
        }));
    }
    // The byte sum is taken over the same bounded window, which is sound
    // because the window covers every pending row whenever the row limit was
    // not already exceeded -- and if it were exceeded, the check above already
    // rejected.
    let pending_bytes: i64 = row.get("pending_bytes");
    if pending_bytes > limits.max_pending_bytes {
        return Ok(AdmissionVerdict::Reject(AdmissionRejection::PendingBytes {
            observed: pending_bytes,
            limit: limits.max_pending_bytes,
        }));
    }

    Ok(AdmissionVerdict::Admit)
}

// ---------------------------------------------------------------------------
// Startup enforcement
// ---------------------------------------------------------------------------

/// The `lore_outbox_schema_state` singleton, as the relay's startup gate reads
/// it (WP-119 Step B).
///
/// CR-032 requires a loreserver in required-event mode to refuse to boot
/// against a cell whose outbox is absent, whose relay compatibility floor is
/// above what the binary speaks, or whose cutover marker is incomplete. Those
/// are three facts on this one row, so the gate needs one read rather than
/// three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxSchemaState {
    /// Version of the DDL the row was last written by.
    pub migration_version: i64,
    /// Backfill algorithm version.
    pub backfill_version: i64,
    /// Lowest producer contract version this cell accepts.
    pub producer_compat_floor: i32,
    /// Lowest relay contract version this cell accepts. Compare with
    /// [`relay_is_compatible`].
    pub relay_compat_floor: i32,
    /// Lowest consumer contract version this cell accepts.
    pub consumer_compat_floor: i32,
    /// Set exactly when the cell's outbox cutover completed. `None` means the
    /// marker is incomplete and required-event mode must not run.
    pub cutover_at: Option<SystemTime>,
    /// Inert until Step C defines retention.
    pub retention_policy_version: Option<i32>,
    /// Last write to this row.
    pub updated_at: SystemTime,
}

/// Read the singleton outbox schema state, or `None` when this database has no
/// outbox at all.
///
/// The two ways the state can be absent are deliberately collapsed into one
/// `None`: the table may not exist (the connection addresses a database that
/// never ran `OUTBOX_SCHEMA`), or the table may exist with no singleton row
/// (bootstrap did not finish). The startup gate's answer is the same refusal
/// for both, and distinguishing them would put a SQLSTATE comparison in every
/// caller for no decision it can act on differently. The refusal message names
/// which one it was.
pub async fn schema_state(
    client: &impl GenericClient,
) -> Result<Option<OutboxSchemaState>, DomainError> {
    let row = match client
        .query_opt(
            "SELECT migration_version, backfill_version, \
                    producer_compat_floor, relay_compat_floor, consumer_compat_floor, \
                    cutover_at, retention_policy_version, updated_at \
             FROM lore_outbox_schema_state WHERE id = 1",
            &[],
        )
        .await
    {
        Ok(row) => row,
        Err(e) if is_undefined_table(&e) => return Ok(None),
        Err(e) => return Err(DomainError::from_pg("outbox schema state select", e)),
    };
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(OutboxSchemaState {
        migration_version: row.get("migration_version"),
        backfill_version: row.get("backfill_version"),
        producer_compat_floor: row.get("producer_compat_floor"),
        relay_compat_floor: row.get("relay_compat_floor"),
        consumer_compat_floor: row.get("consumer_compat_floor"),
        cutover_at: row.get("cutover_at"),
        retention_policy_version: row.get("retention_policy_version"),
        updated_at: row.get("updated_at"),
    }))
}

/// Whether a query failed because the relation does not exist (SQLSTATE 42P01).
fn is_undefined_table(error: &tokio_postgres::Error) -> bool {
    error
        .code()
        .is_some_and(|code| *code == tokio_postgres::error::SqlState::UNDEFINED_TABLE)
}

// TODO(WP-119 Step C): the receiver membership/checkpoint projection, the
// bounded `consumer_safe` evaluator, and retention pruning live here. Pruning
// depends on the checkpoint vector -- a row is reapable only when the minimum
// retention age has elapsed AND the consistent vector proves every required
// current receiver generation safe -- so it cannot be written before Step C.
// TODO(WP-119 Step C): the stream-reset service (`ReportStreamReset`), which
// owns the fence and drives `requeue_unsafe_for_epoch_reset` above.

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state predicate in this module is a SQL **literal**, because a
    /// bound parameter would make the partial indexes unprovable (see the
    /// module docs). The constants and the SQL can therefore drift apart
    /// silently, so the constants are pinned to the literals here.
    #[test]
    fn the_state_constants_match_the_sql_literals_this_module_writes() {
        use crate::domain::outbox::schema::OUTBOX_STATE_BROKER_ACCEPTED;
        use crate::domain::outbox::schema::OUTBOX_STATE_CONSUMER_SAFE;

        assert_eq!(OUTBOX_STATE_PENDING, "pending");
        assert_eq!(OUTBOX_STATE_BROKER_ACCEPTED, "broker_accepted");
        assert_eq!(OUTBOX_STATE_CONSUMER_SAFE, "consumer_safe");
        assert_eq!(DEAD_LETTER_PARKED, "parked");
        assert_eq!(DEAD_LETTER_REQUEUED, "requeued");
        assert_eq!(DEAD_LETTER_OBSOLETE, "obsolete");
    }

    #[test]
    fn the_claim_bound_matches_cr_032() {
        assert_eq!(MAX_CLAIM_BATCH, 100);
        assert_eq!(DEFAULT_CLAIM_LEASE, Duration::from_secs(30));
        assert_eq!(MAX_EPOCH_RESET_BATCH, 1_000);
    }

    /// The reviewed initial limits, restated so a silent widening is a test
    /// failure rather than a diff nobody reads. CR-032 requires a load test
    /// before these move.
    #[test]
    fn the_default_admission_limits_are_the_reviewed_ones() {
        let limits = AdmissionLimits::default();
        assert_eq!(limits.max_oldest_pending_age, Duration::from_secs(300));
        assert_eq!(limits.max_pending_rows, 1_000_000);
        assert_eq!(limits.max_pending_bytes, 5 * 1024 * 1024 * 1024);
    }

    /// The probe ceiling has to sit above the row limit, or a saturated probe
    /// could not distinguish "at the limit" from "past it".
    #[test]
    fn the_probe_ceiling_is_above_the_row_limit() {
        assert!(BACKLOG_PROBE_CEILING > AdmissionLimits::default().max_pending_rows);
    }

    #[test]
    fn a_zero_or_negative_lease_is_rejected() {
        assert!(lease_seconds(Duration::ZERO).is_err());
        assert!(lease_seconds(DEFAULT_CLAIM_LEASE).is_ok());
    }

    #[test]
    fn bounded_rejects_empty_and_over_wide_values() {
        assert!(bounded("x", "", 8).is_err());
        assert!(bounded("x", "abc", 8).is_ok());
        assert!(bounded("x", "aaaaaaaaa", 8).is_err());
    }

    #[test]
    fn acceptance_validation_rejects_an_unset_epoch_or_version() {
        let good = BrokerAcceptanceRecord {
            stream_identity: "cell-a.repo".to_owned(),
            stream_epoch: 1,
            broker_sequence: 0,
            gateway_response_id: "resp-1".to_owned(),
            publisher_contract_version: 1,
        };
        assert!(validate_acceptance(&good).is_ok());

        let mut bad = good.clone();
        bad.stream_epoch = 0;
        assert!(validate_acceptance(&bad).is_err());

        let mut bad = good.clone();
        bad.publisher_contract_version = 0;
        assert!(validate_acceptance(&bad).is_err());

        let mut bad = good.clone();
        bad.broker_sequence = -1;
        assert!(validate_acceptance(&bad).is_err());

        let mut bad = good.clone();
        bad.stream_identity = String::new();
        assert!(validate_acceptance(&bad).is_err());
    }

    /// `saturated()` must key on the ceiling the probes actually stop at, not
    /// on any single limit.
    #[test]
    fn a_backlog_reports_saturation_from_any_capped_count() {
        let base = OutboxBacklog {
            pending_count: 0,
            pending_bytes: 0,
            oldest_pending_age: None,
            claimed_count: 0,
            dead_letter_count: 0,
        };
        assert!(!base.saturated());
        for capped in [
            OutboxBacklog {
                pending_count: BACKLOG_PROBE_CEILING,
                ..base.clone()
            },
            OutboxBacklog {
                claimed_count: BACKLOG_PROBE_CEILING,
                ..base.clone()
            },
            OutboxBacklog {
                dead_letter_count: BACKLOG_PROBE_CEILING,
                ..base.clone()
            },
        ] {
            assert!(capped.saturated());
        }
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's bounded operator recovery surface (WP-119 Phase 8).
//!
//! CR-032's operator procedure is: identify the terminal class, verify gateway
//! and consumer compatibility, inspect authoritative aggregate state, choose
//! requeue or obsolete-with-proof, monitor the original stable key through
//! acknowledgement and consumer catch-up, then clear the event-readiness
//! incident. This module is the durable half of every step of that: the reads
//! it answers from and the two writes it is allowed to make.
//!
//! # Every function here is bounded and cell-scoped
//!
//! CR-032: "Replay and recovery are scoped to the configured cell and
//! repository range. No command accepts an arbitrary subject or cross-cell
//! destination." So `cell_id` is a required first argument on every function in
//! this module, and there is no variant that omits it. A caller cannot express
//! a cross-cell operation, which is stronger than a caller being asked not to.
//!
//! The bounds are refused rather than clamped. A caller asking for a 48-hour
//! replay window or 5,000 rows is asking to violate a limit CR-032 fixes, and
//! silently doing half of it would leave an operator believing they had
//! replayed a range they had not. This is the same rule
//! [`super::prune`]`::validate_age` applies to the retention floor, for the same
//! reason, and the opposite of the evaluator's batch clamp — that one clamps
//! because a caller asking for a *larger* batch is asking for something the
//! transaction bound simply will not do, with no range left unaccounted for.
//!
//! # This module decides no policy
//!
//! [`status`] returns facts: the backlog probe, the schema state, the membership
//! snapshot, and what the required checkpoint vector currently proves. It does
//! **not** decide whether the relay is "ready" — that comparison needs the
//! cell's configured thresholds, which live in `lore-server`'s
//! `event_relay::config`, and duplicating them here would put two answers to one
//! question in two crates. Same split as everywhere else in `domain::outbox`:
//! this side makes facts, the relay side decides.

use std::time::Duration;
use std::time::SystemTime;

// `tokio_postgres::GenericClient`, deliberately: `deadpool_postgres` has a
// sealed trait of the same name, and the two are not interchangeable. Every
// function in `super::relay` this module delegates to is bound on this one, so
// importing the other compiles the signatures here and fails at every call.
use tokio_postgres::GenericClient;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::domain::errors::DomainError;
use crate::domain::outbox::evaluator::EvaluationBlock;
use crate::domain::outbox::evaluator::SafeVector;
use crate::domain::outbox::evaluator::lock_membership_for_read;
use crate::domain::outbox::evaluator::prove_safe_vector;
use crate::domain::outbox::membership::MembershipSnapshot;
use crate::domain::outbox::membership::read_membership_snapshot;
use crate::domain::outbox::membership::validate_cell_id;
use crate::domain::outbox::relay;
use crate::domain::outbox::relay::DeadLetterOutcome;
use crate::domain::outbox::relay::EVENT_COLUMNS;
use crate::domain::outbox::relay::OutboxBacklog;
use crate::domain::outbox::relay::OutboxEventRecord;
use crate::domain::outbox::relay::OutboxRow;
use crate::domain::outbox::relay::OutboxSchemaState;
use crate::domain::outbox::relay::ROW_STATE_COLUMNS;
use crate::domain::outbox::relay::bounded;
use crate::domain::outbox::relay::event_from;
use crate::domain::outbox::relay::row_from;
use crate::domain::outbox::schema::DEAD_LETTER_PARKED;
use crate::domain::outbox::schema::MAX_DISPOSITION_ACTOR_BYTES;
use crate::domain::outbox::schema::MAX_DISPOSITION_REASON_BYTES;
use crate::domain::retry::classify_commit;

/// The client every **public** function in this module takes.
///
/// A concrete pooled client rather than `impl GenericClient`, because the only
/// caller — `lore-server`'s `event_relay::operator` — does not depend on
/// `tokio-postgres` and therefore cannot name that trait, nor the
/// `tokio_postgres::Client` two `Deref` hops beneath this type. Making the
/// public surface concrete puts that coercion here, once, instead of making it
/// unspellable at the call site.
///
/// The private helpers below stay generic, so [`status`] can run them on its
/// own transaction.
pub type PooledClient = deadpool_postgres::Client;

/// Coerce a pooled client to the client the generic helpers are bound on.
///
/// Two `Deref` hops (`Client` → `ClientWrapper` → `tokio_postgres::Client`), and
/// inference walks neither of them to satisfy a trait bound. Spelled as one
/// annotated binding rather than `&**client`, which compiles to the same thing
/// and reads like a pointer trick.
fn pooled(client: &PooledClient) -> &tokio_postgres::Client {
    client
}

/// CR-032's inspection bound: one command lists at most a thousand rows.
pub const MAX_INSPECT_ROWS: i64 = 1_000;

/// CR-032's replay row bound: "One replay command covers at most 1,000 rows or
/// 24 hours. Larger replays paginate explicitly."
pub const MAX_REPLAY_ROWS: i64 = 1_000;

/// The other half of that bound.
pub const MAX_REPLAY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// How the obsolete-with-proof disposition records the authoritative state the
/// operator checked, inside the reason column CR-032 already requires.
///
/// A separate column was the alternative and is deliberately not taken: the
/// proof is free text an operator writes once and an incident review reads
/// once, and a second `text` column beside `disposition_reason` would be a
/// second place for the same kind of value to go missing. The marker makes the
/// two halves separable by a reader without making them separable by a writer
/// who forgot one — [`mark_obsolete`] requires both arguments.
pub const OBSOLETE_PROOF_MARKER: &str = " | authoritative-state-proof: ";

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// One required receiver generation, as an operator needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredMember {
    /// Stable configured receiver identity.
    pub receiver_identity: String,
    /// Its current lifecycle generation.
    pub membership_generation: i64,
    /// `joining`, `ready`, `draining`, or `required_placeholder`. A retired
    /// generation is not required and never appears here.
    pub state: String,
    /// When the readiness compare-and-set succeeded, if it has.
    pub ready_at: Option<SystemTime>,
    /// When the authoritative baseline was taken, if it has been.
    pub baseline_at: Option<SystemTime>,
}

/// The membership facts behind a status report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipSummary {
    /// The compare-and-set anchor every membership write moves.
    pub membership_version: i64,
    /// Whether a reset fence stands. While it does, nothing advances to
    /// `consumer_safe` and nothing is pruned.
    pub reset_in_progress: bool,
    /// The cell's authoritative current stream identity.
    pub current_stream_identity: Option<String>,
    /// Its epoch, present exactly when the identity is.
    pub current_stream_epoch: Option<i64>,
    /// The highest reset generation this cell has accepted.
    pub reset_generation: i64,
    /// The required set, which is what a safety verdict is taken over.
    pub required_members: Vec<RequiredMember>,
}

impl MembershipSummary {
    fn from_snapshot(snapshot: &MembershipSnapshot) -> Self {
        Self {
            membership_version: snapshot.state.membership_version,
            reset_in_progress: snapshot.reset_in_progress,
            current_stream_identity: snapshot.state.current_stream_identity.clone(),
            current_stream_epoch: snapshot.state.current_stream_epoch,
            reset_generation: snapshot.state.reset_generation,
            required_members: snapshot
                .required_members()
                .into_iter()
                .map(|member| RequiredMember {
                    receiver_identity: member.receiver_identity.clone(),
                    membership_generation: member.membership_generation,
                    state: member.state.clone(),
                    ready_at: member.ready_at,
                    baseline_at: member.baseline_at,
                })
                .collect(),
        }
    }
}

/// Everything `outbox status` reports for one cell, as facts rather than
/// verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorStatus {
    /// The configured cell every fact below is scoped to.
    pub cell_id: String,
    /// The singleton schema state, or `None` on a database with no outbox at
    /// all. `None` is also what a cell that never finished bootstrap reports.
    pub schema_state: Option<OutboxSchemaState>,
    /// The bounded backlog probe: unpublished rows and bytes, oldest pending
    /// age, leased subset, and parked dead letters.
    ///
    /// Cell-wide rather than cell-scoped, and that is not an oversight: the
    /// relay's own backlog probe is the same query, and reporting a different
    /// number here than the number admission and readiness act on would make
    /// this command useless for diagnosing either. A cell database holding two
    /// cells' rows is not a deployment this fork produces.
    pub backlog: OutboxBacklog,
    /// Parked dead letters for **this** cell, exactly. Unlike
    /// [`OperatorStatus::backlog`]'s own count this one is cell-scoped, because
    /// it is the queue the operator is about to act on rather than the number
    /// readiness reports.
    pub parked_dead_letters: i64,
    /// What the required checkpoint vector proves right now, if anything.
    pub safe_vector: Option<SafeVector>,
    /// Why it proves nothing, if it does not.
    pub evaluation_block: Option<EvaluationBlock>,
    /// The membership behind that verdict, or `None` on a cell that has never
    /// been through cutover.
    pub membership: Option<MembershipSummary>,
}

/// Read every status fact for one cell in one consistent transaction.
///
/// The transaction is not incidental. The membership snapshot and the
/// checkpoint vector must be read under one [`lock_membership_for_read`], or
/// the reported required set and the reported safe sequence can straddle a
/// membership change and describe a state that never existed at one moment —
/// the same rule [`super::evaluator`] and [`super::prune`] follow, and a status
/// report is exactly where an inconsistent pair would be believed.
///
/// Read-only: it takes a share lock, writes nothing, and commits.
pub async fn status(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
) -> Result<OperatorStatus, DomainError> {
    validate_cell_id(cell_id)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox operator status begin", e))?;

    // The schema probe runs FIRST and gates every probe after it.
    //
    // `relay::schema_state` is the one read here that tolerates the tables not
    // existing; `backlog` and the membership reads all fail with a raw
    // SQLSTATE 42P01. On a database with no outbox at all — which is every
    // database before cutover, and the first thing an operator points this
    // command at when they are not sure — running them anyway turns "this cell
    // has no outbox" into "db error", which is the least useful answer this
    // command could give. Found by running the command against a fresh
    // database rather than by reading this function.
    let schema_state = relay::schema_state(&*tx).await?;
    if schema_state.is_none() {
        classify_commit(tx.commit().await, "outbox operator status commit")?;
        return Ok(OperatorStatus {
            cell_id: cell_id.to_owned(),
            schema_state: None,
            backlog: OutboxBacklog {
                pending_count: 0,
                pending_bytes: 0,
                oldest_pending_age: None,
                claimed_count: 0,
                dead_letter_count: 0,
            },
            parked_dead_letters: 0,
            safe_vector: None,
            evaluation_block: Some(EvaluationBlock::CellUnknown),
            membership: None,
        });
    }

    let backlog = relay::backlog(&*tx).await?;
    let parked_dead_letters = parked_dead_letter_count(&*tx, cell_id).await?;

    // A cell with no membership state row has never been through cutover.
    // `lock_membership_for_read` reports that as `false` rather than as an
    // error, and the vector below is then skipped rather than guessed at.
    let (membership, safe_vector, evaluation_block) =
        if lock_membership_for_read(&*tx, cell_id).await? {
            let snapshot = read_membership_snapshot(&*tx, cell_id).await?;
            match prove_safe_vector(&*tx, cell_id).await? {
                Ok(proven) => (
                    snapshot.as_ref().map(MembershipSummary::from_snapshot),
                    Some(proven),
                    None,
                ),
                Err(block) => (
                    snapshot.as_ref().map(MembershipSummary::from_snapshot),
                    None,
                    Some(block),
                ),
            }
        } else {
            (None, None, Some(EvaluationBlock::CellUnknown))
        };

    classify_commit(tx.commit().await, "outbox operator status commit")?;

    Ok(OperatorStatus {
        cell_id: cell_id.to_owned(),
        schema_state,
        backlog,
        parked_dead_letters,
        safe_vector,
        evaluation_block,
        membership,
    })
}

/// Count this cell's un-dispositioned dead letters, bounded by the same probe
/// ceiling the backlog uses.
async fn parked_dead_letter_count(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<i64, DomainError> {
    let ceiling = relay::BACKLOG_PROBE_CEILING;
    // `disposition = 'parked'` as a literal, so the planner can use
    // `lore_outbox_dead_letters_operations`, whose leading column is this
    // equality.
    let row = client
        .query_one(
            "SELECT count(*)::bigint AS parked FROM ( \
                 SELECT 1 FROM lore_outbox_dead_letters \
                  WHERE cell_id = $1 AND disposition = 'parked' \
                  LIMIT $2) AS d",
            &[&cell_id, &ceiling],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox operator parked dead letter probe", e))?;
    Ok(row.get("parked"))
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

/// One terminal row, as the operator procedure's first step needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterRecord {
    /// The event, carried verbatim out of `lore_outbox_events`.
    pub event: OutboxEventRecord,
    /// Attempts made before the row went terminal.
    pub attempt_count: i32,
    /// CR-032's terminal class — the first thing the operator procedure asks
    /// for.
    pub terminal_class: String,
    /// When the failing run began.
    pub first_failed_at: SystemTime,
    /// When it ended.
    pub last_failed_at: SystemTime,
    /// `parked`, `requeued`, or `obsolete`.
    pub disposition: String,
    /// The operator's reason, present exactly when the disposition is not
    /// `parked`.
    pub disposition_reason: Option<String>,
    /// When that decision was made.
    pub disposition_at: Option<SystemTime>,
    /// Who made it.
    pub disposition_actor: Option<String>,
}

fn dead_letter_from(row: &Row) -> Result<DeadLetterRecord, DomainError> {
    Ok(DeadLetterRecord {
        event: event_from(row)?,
        attempt_count: row.get("attempt_count"),
        terminal_class: row.get("terminal_class"),
        first_failed_at: row.get("first_failed_at"),
        last_failed_at: row.get("last_failed_at"),
        disposition: row.get("disposition"),
        disposition_reason: row.get("disposition_reason"),
        disposition_at: row.get("disposition_at"),
        disposition_actor: row.get("disposition_actor"),
    })
}

/// The dead-letter columns beyond [`EVENT_COLUMNS`], in one place for the same
/// reason as [`ROW_STATE_COLUMNS`].
const DEAD_LETTER_COLUMNS: &str = "attempt_count, terminal_class, \
     first_failed_at, last_failed_at, \
     disposition, disposition_reason, disposition_at, disposition_actor";

/// What one event ID resolves to.
///
/// Both halves can be present at once and that is a real, informative state: a
/// dead letter that was requeued has an evidence row **and** a live row, which
/// is exactly what an operator monitoring a requeue through to acknowledgement
/// needs to see. Collapsing them into an either/or would hide it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedEvent {
    /// The live outbox row, if the event is still in flight.
    pub live: Option<OutboxRow>,
    /// The terminal evidence row, if the event ever went terminal.
    pub dead_letter: Option<DeadLetterRecord>,
}

impl InspectedEvent {
    /// Whether the cell knows this event at all.
    pub fn is_empty(&self) -> bool {
        self.live.is_none() && self.dead_letter.is_none()
    }
}

/// Resolve one event ID within the configured cell.
///
/// The `cell_id` predicate is what makes a probe for an event ID in another
/// cell indistinguishable from a probe for an ID that does not exist: both
/// return an empty result, on both halves.
pub async fn inspect_event(
    client: &PooledClient,
    cell_id: &str,
    event_id: Uuid,
) -> Result<InspectedEvent, DomainError> {
    validate_cell_id(cell_id)?;
    let client = pooled(client);

    let live = client
        .query_opt(
            &format!(
                "SELECT {EVENT_COLUMNS}, {ROW_STATE_COLUMNS} \
                 FROM lore_outbox_events WHERE event_id = $1 AND cell_id = $2"
            ),
            &[&event_id, &cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox operator inspect event", e))?;

    let dead_letter = client
        .query_opt(
            &format!(
                "SELECT {EVENT_COLUMNS}, {DEAD_LETTER_COLUMNS} \
                 FROM lore_outbox_dead_letters WHERE event_id = $1 AND cell_id = $2"
            ),
            &[&event_id, &cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox operator inspect dead letter", e))?;

    Ok(InspectedEvent {
        live: live.as_ref().map(row_from).transpose()?,
        dead_letter: dead_letter.as_ref().map(dead_letter_from).transpose()?,
    })
}

/// List up to `limit` of one repository's live outbox rows in the configured
/// cell, oldest first.
///
/// Oldest first because that is the order an operator reads a backlog in: the
/// row holding the oldest-unpublished age is the one closing admission, and it
/// is the first row of this listing.
///
/// # Errors
/// `InvalidInput` when `limit` is outside `1..=`[`MAX_INSPECT_ROWS`], or when
/// `repository_id` is not the 16 bytes the column's own CHECK requires.
pub async fn inspect_repository(
    client: &PooledClient,
    cell_id: &str,
    repository_id: &[u8],
    limit: i64,
) -> Result<Vec<OutboxRow>, DomainError> {
    let client = pooled(client);
    validate_cell_id(cell_id)?;
    validate_repository_id(repository_id)?;
    let limit = validate_limit("inspect", limit, MAX_INSPECT_ROWS)?;

    let rows = client
        .query(
            &format!(
                "SELECT {EVENT_COLUMNS}, {ROW_STATE_COLUMNS} \
                 FROM lore_outbox_events \
                  WHERE cell_id = $1 AND repository_id = $2 \
                  ORDER BY created_at, event_id \
                  LIMIT $3"
            ),
            &[&cell_id, &repository_id, &limit],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox operator inspect repository", e))?;

    rows.iter().map(row_from).collect()
}

/// List up to `limit` of this cell's parked dead letters, oldest failure first.
///
/// This is the queue CR-032's operator procedure works through, and the only
/// way to learn the event IDs [`requeue_dead_letter`] and [`mark_obsolete`]
/// take. Parked only: a disposed row is a closed decision, and listing it here
/// would put resolved incidents back in front of the operator every time.
pub async fn inspect_dead_letters(
    client: &PooledClient,
    cell_id: &str,
    limit: i64,
) -> Result<Vec<DeadLetterRecord>, DomainError> {
    let client = pooled(client);
    validate_cell_id(cell_id)?;
    let limit = validate_limit("inspect", limit, MAX_INSPECT_ROWS)?;

    // `disposition = 'parked'` as a literal: `lore_outbox_dead_letters_operations`
    // leads with it.
    let rows = client
        .query(
            &format!(
                "SELECT {EVENT_COLUMNS}, {DEAD_LETTER_COLUMNS} \
                 FROM lore_outbox_dead_letters \
                  WHERE cell_id = $1 AND disposition = 'parked' \
                  ORDER BY last_failed_at, event_id \
                  LIMIT $2"
            ),
            &[&cell_id, &limit],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox operator inspect dead letters", e))?;

    rows.iter().map(dead_letter_from).collect()
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// What one bounded replay did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Rows returned to `pending` by this command.
    pub replayed: u64,
    /// The window the command covered.
    pub window: Duration,
    /// The row bound it ran under.
    pub limit: i64,
    /// Whether it was narrowed to one repository.
    pub repository_id: Option<Vec<u8>>,
}

/// The `SET` clause every replay applies, in one place so the two window
/// variants below cannot drift.
///
/// It clears the whole publication result. That is required rather than tidy:
/// `lore_outbox_events_publication_shape` forbids a `pending` row from carrying
/// any of the six publication columns, so a replay that returned the state and
/// left the acceptance would be rejected by the database — and if the CHECK
/// were ever relaxed, a leftover stream identity on a pending row reads to a
/// later reader as proof of an acceptance that was withdrawn.
///
/// `claim_generation + 1`, never a reset to zero, for the reason
/// [`relay::requeue_dead_letter`]'s documentation records at length: the
/// generation is the only relay fence, and a reused value lets a worker that
/// held the old one act on a claim it has lost.
///
/// `unpublished_since = clock_timestamp()` is the fix for the defect a review
/// of this function found and reproduced: the row is entering a fresh
/// publication cycle, and leaving its unpublished clock at `created_at` made a
/// successful replay of a week-old row report a week of relay lag — above both
/// the 30-second readiness threshold and the five-minute admission limit, so
/// the recovery command closed the cell's own write admission the moment it
/// worked. See the column's own comment in [`super::schema`].
const REPLAY_SET_CLAUSE: &str = "SET state = 'pending', \
     available_at = clock_timestamp(), \
     unpublished_since = clock_timestamp(), \
     claim_generation = event.claim_generation + 1, \
     claim_owner = NULL, \
     claim_expires_at = NULL, \
     attempt_count = 0, \
     last_error_class = NULL, \
     stream_identity = NULL, \
     stream_epoch = NULL, \
     broker_sequence = NULL, \
     gateway_response_id = NULL, \
     publisher_contract_version = NULL, \
     broker_accepted_at = NULL, \
     replay_count = event.replay_count + 1, \
     replayed_at = clock_timestamp(), \
     replay_actor = $4, \
     replay_reason = $5";

/// Return up to `limit` broker-accepted rows inside `window` to `pending`,
/// keeping every original key and recording who ordered it and why.
///
/// CR-032: "One replay command covers at most 1,000 rows or 24 hours. Larger
/// replays paginate explicitly. Replay reuses the original event and
/// idempotency keys and records an operator/reason audit field." Nothing here
/// creates a row, derives a key, or changes an identity column — the same rows
/// go back to `pending` and the relay republishes them under the same
/// `(cell_id, idempotency_key)` the gateway already deduplicates on.
///
/// # What it deliberately cannot reach
///
/// * **`consumer_safe` rows.** They are proven delivered. Republishing one
///   would put a duplicate through a consumer that already handled it, on the
///   strength of an operator's guess rather than any evidence. The predicate is
///   the literal `state = 'broker_accepted'`, so no spelling of this statement
///   can match one.
/// * **`pending` rows.** They are already queued; "replaying" one would only
///   reset its attempt count and erase the error class that says why it is
///   still there.
/// * **Another cell.** `cell_id` is an equality on the configured cell.
/// * **Rows outside the window.** `broker_accepted_at` is the anchor rather
///   than `created_at`: the operator is replaying a *publication*, and the
///   publication's own time is what a gateway or consumer incident is bounded
///   by. A row created a week ago and published an hour ago is inside a
///   one-hour window, which is the reading that matches the incident.
///
/// # Errors
/// `InvalidInput` when the window or the row bound is outside CR-032's limits,
/// when the actor or reason is empty or over-wide, or when a supplied
/// repository ID is not 16 bytes.
pub async fn replay(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    repository_id: Option<&[u8]>,
    window: Duration,
    limit: i64,
    actor: &str,
    reason: &str,
) -> Result<ReplayOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    bounded("replay_actor", actor, MAX_DISPOSITION_ACTOR_BYTES)?;
    bounded("replay_reason", reason, MAX_DISPOSITION_REASON_BYTES)?;
    if let Some(repository_id) = repository_id {
        validate_repository_id(repository_id)?;
    }
    let limit = validate_limit("replay", limit, MAX_REPLAY_ROWS)?;
    let window_seconds = validate_window(window)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox replay begin", e))?;

    // Two statements rather than one with `($n IS NULL OR repository_id = $n)`.
    // That disjunction returns the same rows and plans differently: the planner
    // cannot use an index for a predicate it may have to ignore, so the narrowed
    // case would degrade to the unnarrowed scan plus a filter. The duplication
    // is confined to the `WHERE` clause; the `SET` is shared above.
    //
    // `state = 'broker_accepted'` is a SQL **literal** in both halves of both
    // statements, so the planner can prove the predicate implies
    // `lore_outbox_events_replay_window`'s partial predicate. A bound-parameter
    // spelling of the *state* returns the same rows and cannot use that index.
    //
    // `FOR UPDATE SKIP LOCKED`: a row a relay worker is mid-settle on is left
    // for the next command rather than waited on, so a replay can never block
    // the publish loop it exists to help.
    //
    // The window cutoff is the opposite rule, and the two are easy to conflate.
    // The *timestamp* must be a bound parameter: written inline as
    // `clock_timestamp() - ($n * interval '1 second')` it is VOLATILE, so the
    // planner cannot use it as an index bound and demotes it to a `Filter` over
    // the whole cell's accepted set. So the cutoff is resolved to a value in
    // this same transaction and then bound. The clock is read from the
    // **database**, not from this process, which is what keeps the window on
    // the same clock every other timestamp in this table is written by.
    //
    // The scan is `ORDER BY broker_accepted_at` ascending, matching the index's
    // own order, so there is no sort at all. Descending is an Incremental Sort
    // over a backward scan for no benefit: a replayed row leaves the
    // `broker_accepted` set, so repeated commands paginate either way.
    //
    // Measured on PostgreSQL 16, 50,000 accepted rows in one cell, a 60-second
    // window matching 58 of them, `force_generic_plan`:
    //
    // | spelling | plan | buffers | time |
    // | --- | --- | --- | --- |
    // | bound cutoff, ASC | `Index Cond` on both columns | 10 | 0.095 ms |
    // | inline volatile, DESC | `Index Cond` on `cell_id` only, window in `Filter`, 49,942 rows removed | 4,220 | 18.7 ms |
    //
    // The cost of the inline form scales with the cell's whole accepted set
    // rather than with the window, so a one-minute replay on a busy cell costs
    // what a 24-hour one does.
    let cutoff: SystemTime = tx
        .query_one(
            "SELECT clock_timestamp() - ($1 * interval '1 second') AS cutoff",
            &[&window_seconds],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox replay window cutoff", e))?
        .get("cutoff");

    let replayed = match repository_id {
        None => {
            tx.execute(
                &format!(
                    "WITH candidate AS ( \
                         SELECT event_id FROM lore_outbox_events \
                          WHERE state = 'broker_accepted' \
                            AND cell_id = $1 \
                            AND broker_accepted_at >= $2 \
                          ORDER BY broker_accepted_at, event_id \
                          LIMIT $3 \
                          FOR UPDATE SKIP LOCKED \
                     ) \
                     UPDATE lore_outbox_events AS event {REPLAY_SET_CLAUSE} \
                       FROM candidate \
                      WHERE event.event_id = candidate.event_id \
                        AND event.state = 'broker_accepted'"
                ),
                &[&cell_id, &cutoff, &limit, &actor, &reason],
            )
            .await
        }
        Some(repository_id) => {
            tx.execute(
                &format!(
                    "WITH candidate AS ( \
                         SELECT event_id FROM lore_outbox_events \
                          WHERE state = 'broker_accepted' \
                            AND cell_id = $1 \
                            AND broker_accepted_at >= $2 \
                            AND repository_id = $6 \
                          ORDER BY broker_accepted_at, event_id \
                          LIMIT $3 \
                          FOR UPDATE SKIP LOCKED \
                     ) \
                     UPDATE lore_outbox_events AS event {REPLAY_SET_CLAUSE} \
                       FROM candidate \
                      WHERE event.event_id = candidate.event_id \
                        AND event.state = 'broker_accepted'"
                ),
                &[&cell_id, &cutoff, &limit, &actor, &reason, &repository_id],
            )
            .await
        }
    }
    .map_err(|e| DomainError::from_pg("outbox replay update", e))?;

    classify_commit(tx.commit().await, "outbox replay commit")?;

    Ok(ReplayOutcome {
        replayed,
        window,
        limit,
        repository_id: repository_id.map(<[u8]>::to_vec),
    })
}

// ---------------------------------------------------------------------------
// Dead-letter dispositions
// ---------------------------------------------------------------------------

/// Requeue one parked dead letter, scoped to the configured cell.
///
/// The fenced compare-and-set, the relay-compatibility check, and the
/// reinstatement are [`relay::requeue_dead_letter`]'s; this adds the cell scope
/// CR-032 requires of every operator command.
///
/// # Why the cell check can be a separate statement
///
/// `cell_id` is written once, by the mutation transaction that created the
/// event, and no statement in this crate ever updates it — the dead letter
/// copies it verbatim and the requeue copies it back. So there is no
/// interleaving in which the row belongs to this cell when checked and another
/// cell when acted on, and the two-step needs no shared transaction to be
/// sound. A row in another cell reports [`DeadLetterOutcome::NotFound`], the
/// same answer as an ID that does not exist, so an operator on one cell cannot
/// probe another's event IDs.
pub async fn requeue_dead_letter(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    event_id: Uuid,
    actor: &str,
    reason: &str,
) -> Result<DeadLetterOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    // `deadpool_postgres::Client` reaches `tokio_postgres::Client` through two
    // `Deref` hops, and inference will not walk both to satisfy a trait bound.
    // Coerced explicitly, and in its own binding so the shared borrow ends
    // before `relay::requeue_dead_letter` takes the exclusive one.
    let scoped: &tokio_postgres::Client = client;
    if !dead_letter_is_in_cell(scoped, cell_id, event_id).await? {
        return Ok(DeadLetterOutcome::NotFound);
    }
    relay::requeue_dead_letter(client, event_id, reason, actor).await
}

/// Mark one parked dead letter obsolete, with the authoritative-state proof
/// CR-032 requires alongside the reason.
///
/// CR-032: "Marking it obsolete requires authoritative state validation and a
/// reason; it does not delete the original evidence." The validation is the
/// operator's — this crate cannot re-derive whether a repository still exists
/// or a branch still points where the event said — so what is enforceable here
/// is that the operator recorded *what* they checked. `proof` is therefore a
/// required argument, not an option, and it is stored beside the reason under
/// [`OBSOLETE_PROOF_MARKER`].
///
/// The evidence row is never deleted: only its disposition columns change.
///
/// # Errors
/// `InvalidInput` when the actor, reason, or proof is empty, or when the
/// composed reason exceeds the column's own bound.
pub async fn mark_obsolete(
    client: &PooledClient,
    cell_id: &str,
    event_id: Uuid,
    actor: &str,
    reason: &str,
    proof: &str,
) -> Result<DeadLetterOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    // Each half is checked for emptiness on its own first, so an operator who
    // supplied a reason and an empty proof is told which one is missing rather
    // than being told the composed string is empty — which it would not be.
    bounded("obsolete_reason", reason, MAX_DISPOSITION_REASON_BYTES)?;
    bounded("obsolete_proof", proof, MAX_DISPOSITION_REASON_BYTES)?;
    let composed = format!("{reason}{OBSOLETE_PROOF_MARKER}{proof}");
    bounded(
        "obsolete_reason_with_proof",
        &composed,
        MAX_DISPOSITION_REASON_BYTES,
    )?;

    let client = pooled(client);
    if !dead_letter_is_in_cell(client, cell_id, event_id).await? {
        return Ok(DeadLetterOutcome::NotFound);
    }
    relay::mark_obsolete(client, event_id, &composed, actor).await
}

/// Whether a dead letter with this ID exists **and** belongs to this cell.
///
/// One predicate rather than a lookup plus a comparison, so there is no shape
/// of this function that can return the other cell's identity to a caller.
async fn dead_letter_is_in_cell(
    client: &impl GenericClient,
    cell_id: &str,
    event_id: Uuid,
) -> Result<bool, DomainError> {
    let row = client
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lore_outbox_dead_letters \
                  WHERE event_id = $1 AND cell_id = $2 \
             ) AS present",
            &[&event_id, &cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox operator dead letter cell scope", e))?;
    Ok(row.get("present"))
}

// ---------------------------------------------------------------------------
// Bounded input validation
// ---------------------------------------------------------------------------

/// Refuse a row bound outside `1..=max` rather than clamping it.
///
/// See the module documentation: a caller asking for more than CR-032's bound
/// is asking to violate it, and a clamp would leave the unrequested remainder
/// silently unreplayed while reporting success.
fn validate_limit(label: &str, limit: i64, max: i64) -> Result<i64, DomainError> {
    if limit < 1 || limit > max {
        return Err(DomainError::InvalidInput(format!(
            "outbox operator {label} row bound must be 1..={max}, got {limit}; CR-032 requires a \
             larger range to paginate explicitly"
        )));
    }
    Ok(limit)
}

/// Refuse a replay window outside `(0, 24 hours]`, and convert it to the
/// `double precision` seconds the SQL multiplies by `interval '1 second'`.
fn validate_window(window: Duration) -> Result<f64, DomainError> {
    let seconds = window.as_secs_f64();
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox replay window must be a positive finite duration, got {seconds}s"
        )));
    }
    if window > MAX_REPLAY_WINDOW {
        return Err(DomainError::InvalidInput(format!(
            "outbox replay window {window:?} exceeds CR-032's bound of {MAX_REPLAY_WINDOW:?}; a \
             larger range paginates explicitly"
        )));
    }
    Ok(seconds)
}

/// Refuse a repository ID that is not the 16 bytes the column's CHECK requires.
///
/// Checked here rather than left to the database so a mistyped ID is an
/// `InvalidInput` naming the width, not a constraint violation from a statement
/// that could never have matched anything.
fn validate_repository_id(repository_id: &[u8]) -> Result<(), DomainError> {
    if repository_id.len() != 16 {
        return Err(DomainError::InvalidInput(format!(
            "outbox operator repository_id must be 16 bytes, got {}",
            repository_id.len()
        )));
    }
    Ok(())
}

/// The parked disposition, re-exported through this module's own vocabulary so
/// an operator surface never spells the literal.
pub const PARKED: &str = DEAD_LETTER_PARKED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bounds_are_cr_032s() {
        assert_eq!(MAX_REPLAY_ROWS, 1_000);
        assert_eq!(MAX_INSPECT_ROWS, 1_000);
        assert_eq!(MAX_REPLAY_WINDOW, Duration::from_secs(24 * 60 * 60));
    }

    /// Refused, not clamped. A clamp would report success over a range it did
    /// not cover.
    #[test]
    fn a_row_bound_outside_the_range_is_refused() {
        assert!(validate_limit("replay", 0, MAX_REPLAY_ROWS).is_err());
        assert!(validate_limit("replay", -1, MAX_REPLAY_ROWS).is_err());
        assert!(validate_limit("replay", MAX_REPLAY_ROWS + 1, MAX_REPLAY_ROWS).is_err());
        assert_eq!(
            validate_limit("replay", MAX_REPLAY_ROWS, MAX_REPLAY_ROWS)
                .expect("the bound itself is inside the range"),
            MAX_REPLAY_ROWS
        );
        assert_eq!(
            validate_limit("replay", 1, MAX_REPLAY_ROWS).expect("one row is inside the range"),
            1
        );
    }

    #[test]
    fn a_replay_window_outside_the_range_is_refused() {
        assert!(validate_window(Duration::ZERO).is_err());
        assert!(validate_window(MAX_REPLAY_WINDOW + Duration::from_secs(1)).is_err());
        assert_eq!(
            validate_window(MAX_REPLAY_WINDOW).expect("24 hours is the bound, not past it"),
            86_400.0
        );
    }

    #[test]
    fn a_repository_id_must_be_sixteen_bytes() {
        assert!(validate_repository_id(&[0_u8; 16]).is_ok());
        assert!(validate_repository_id(&[0_u8; 15]).is_err());
        assert!(validate_repository_id(&[0_u8; 17]).is_err());
        assert!(validate_repository_id(&[]).is_err());
    }

    /// The replay `SET` clause must clear every publication column, or the
    /// `lore_outbox_events_publication_shape` CHECK rejects the statement at
    /// runtime — on a real cell, during an incident, which is the worst place
    /// to discover it. Pinned against the column list rather than against a
    /// copy of the clause, so adding a publication column to the schema without
    /// clearing it here fails here.
    #[test]
    fn the_replay_clause_clears_every_publication_column() {
        for column in [
            "stream_identity",
            "stream_epoch",
            "broker_sequence",
            "gateway_response_id",
            "publisher_contract_version",
            "broker_accepted_at",
        ] {
            assert!(
                REPLAY_SET_CLAUSE.contains(&format!("{column} = NULL")),
                "replay must clear {column}; a pending row carrying it violates \
                 lore_outbox_events_publication_shape"
            );
        }
    }

    /// The lease must be cleared too, and the fence must advance rather than
    /// reset. Both are the difference between a replay and a way for a fenced
    /// worker to reacquire a row it lost.
    #[test]
    fn the_replay_clause_clears_the_lease_and_advances_the_fence() {
        assert!(REPLAY_SET_CLAUSE.contains("claim_owner = NULL"));
        assert!(REPLAY_SET_CLAUSE.contains("claim_expires_at = NULL"));
        assert!(REPLAY_SET_CLAUSE.contains("claim_generation = event.claim_generation + 1"));
        assert!(
            !REPLAY_SET_CLAUSE.contains("claim_generation = 0"),
            "resetting the fence makes an old generation comparable again"
        );
    }

    /// The audit CR-032 requires is written by the same statement that moves
    /// the state, so there is no interleaving in which a row is pending again
    /// with no record of who ordered it.
    #[test]
    fn the_replay_clause_writes_the_audit() {
        assert!(REPLAY_SET_CLAUSE.contains("replay_actor = $4"));
        assert!(REPLAY_SET_CLAUSE.contains("replay_reason = $5"));
        assert!(REPLAY_SET_CLAUSE.contains("replayed_at = clock_timestamp()"));
        assert!(REPLAY_SET_CLAUSE.contains("replay_count = event.replay_count + 1"));
    }

    /// `now()` is the transaction start time. Every timestamp a replay writes
    /// and every window it measures must come from `clock_timestamp()`, the
    /// same rule `prune_consumer_safe` follows.
    #[test]
    fn the_replay_clause_uses_the_statement_clock() {
        assert!(!REPLAY_SET_CLAUSE.contains("now()"));
        assert!(REPLAY_SET_CLAUSE.contains("clock_timestamp()"));
    }

    #[test]
    fn the_composed_obsolete_reason_carries_both_halves() {
        let composed = format!("stale repository{OBSOLETE_PROOF_MARKER}repo 0x0a.. is deleted");
        assert!(composed.starts_with("stale repository"));
        assert!(composed.contains("repo 0x0a.. is deleted"));
        assert!(composed.contains(OBSOLETE_PROOF_MARKER));
    }

    #[test]
    fn an_empty_inspection_knows_it_is_empty() {
        let empty = InspectedEvent {
            live: None,
            dead_letter: None,
        };
        assert!(empty.is_empty());
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's receiver membership projection (WP-119 Step C).
//!
//! Every required receiver has an explicit identity and a monotonic lifecycle
//! **generation**, and this module owns both. It is deliberately not a
//! "receiver table": the row is per generation, so a replacement at a greater
//! generation is a different row that starts with no frontier of its own. Name
//! reuse therefore cannot inherit a checkpoint, and a retired generation cannot
//! satisfy its successor's requirement — both by construction rather than by a
//! rule a query has to remember.
//!
//! # The ordered bootstrap
//!
//! The notification-plane contract fixes the order and forbids every shortcut:
//!
//! 1. [`join_receiver`] allocates the next generation under a compare-and-set
//!    on `membership_version`;
//! 2. [`record_capture`] pins the durable consumer's stream identity, epoch,
//!    and start position — **before** the authoritative baseline, never after;
//! 3. [`record_baseline`] records that the baseline was taken;
//! 4. the receiver drains from the captured position and persists its frontier
//!    through [`super::checkpoint::report_checkpoint`];
//! 5. [`readiness_cas`] rereads the cell's **authoritative current** stream
//!    identity and epoch and succeeds only when both still equal the captured
//!    values.
//!
//! Step 5 is the one that carries the weight. Neither a baseline alone nor a
//! newly sampled live edge can mark a receiver caught up, and a reset anywhere
//! in 2..5 moves the authoritative placement, so the CAS fails and
//! [`readiness_cas`] retires that generation rather than letting it resume an
//! epoch that no longer exists.
//!
//! # Two versions that are not the same number
//!
//! `lore_outbox_membership_state.membership_version` is the cell's snapshot
//! version: the compare-and-set anchor a safety evaluation reads once and
//! writes back against. `lore_outbox_receiver_membership.membership_version` is
//! the snapshot version at which **that row** last changed, carried so an
//! operator can see when a generation moved without replaying the whole
//! history. Only the first is ever compared.
//!
//! A join, a readiness transition, a retirement, and an accepted reset bump the
//! cell version, because each changes the required set. A capture, a baseline,
//! and a checkpoint report do not: they change nothing a safety evaluation
//! reads about *which* members are required, and bumping on a checkpoint would
//! make the evaluator's own compare-and-set livelock against the reports it
//! exists to consume.

use std::collections::BTreeMap;
use std::time::SystemTime;

use tokio_postgres::GenericClient;
use tokio_postgres::Row;

use crate::domain::errors::DomainError;
use crate::domain::outbox::schema::MAX_RECEIVER_IDENTITY_BYTES;
use crate::domain::outbox::schema::MAX_STREAM_IDENTITY_BYTES;
use crate::domain::outbox::schema::MEMBERSHIP_STATE_DRAINING;
use crate::domain::outbox::schema::MEMBERSHIP_STATE_READY;
use crate::domain::outbox::schema::MEMBERSHIP_STATE_RETIRED;
use crate::domain::outbox::schema::PLACEHOLDER_GENERATION;
use crate::domain::outbox::schema::REQUIRED_REPLACEMENT_PLACEHOLDER;
use crate::domain::outbox::schema::RESET_STATE_CLEARED;
use crate::domain::outbox::schema::is_valid_cell_id;
use crate::domain::retry::classify_commit;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// The durable consumer position a receiver generation pinned before taking its
/// authoritative baseline.
///
/// All three fields are one fact. A half-captured position would let a baseline
/// be taken against an epoch nothing recorded, which is exactly the bootstrap
/// the contract forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPosition {
    /// Stream identity at capture.
    pub stream_identity: String,
    /// Stream epoch at capture.
    pub stream_epoch: i64,
    /// Broker sequence the drain starts from.
    pub start_sequence: i64,
}

/// One receiver generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipMember {
    /// Stable configured receiver identity.
    pub receiver_identity: String,
    /// Monotonic lifecycle generation. `0` is the reset fence's placeholder.
    pub membership_generation: i64,
    /// `joining`, `ready`, `draining`, `retired`, or `required_placeholder`.
    pub state: String,
    /// Snapshot version at which this row last changed. Never compared.
    pub membership_version: i64,
    /// The position captured before the baseline, once step 2 has run.
    pub captured: Option<CapturedPosition>,
    /// When the authoritative baseline was taken.
    pub baseline_at: Option<SystemTime>,
    /// When the readiness compare-and-set succeeded.
    pub ready_at: Option<SystemTime>,
}

impl MembershipMember {
    /// Whether this generation still participates at all.
    pub fn is_retired(&self) -> bool {
        self.state == MEMBERSHIP_STATE_RETIRED
    }

    /// Whether this generation's frontier is what a safety evaluation reads.
    ///
    /// `draining` counts: a member shutting down is still consuming and still
    /// retires only after its final checkpoint, so crediting safety without it
    /// would release rows it has not acknowledged.
    pub fn counts_toward_safety(&self) -> bool {
        self.state == MEMBERSHIP_STATE_READY || self.state == MEMBERSHIP_STATE_DRAINING
    }
}

/// The cell's per-cell counters and authoritative placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipState {
    /// Cell identity.
    pub cell_id: String,
    /// The compare-and-set anchor.
    pub membership_version: i64,
    /// The generation [`join_receiver`] will allocate next.
    pub next_membership_generation: i64,
    /// The highest reset generation this cell has accepted. `0` before any.
    pub reset_generation: i64,
    /// Authoritative current stream identity, or `None` before the cell's first
    /// placement is recorded.
    pub current_stream_identity: Option<String>,
    /// Authoritative current stream epoch, present exactly when the identity is.
    pub current_stream_epoch: Option<i64>,
    /// Authoritative current placement revision.
    pub current_placement_revision: i64,
    /// Last write to this row.
    pub updated_at: SystemTime,
}

/// One consistent read of a cell's membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipSnapshot {
    /// The counters and authoritative placement.
    pub state: MembershipState,
    /// Whether a reset fence stands. While true, `consumer_safe` advancement
    /// and pruning fail for this cell even if membership is otherwise empty.
    pub reset_in_progress: bool,
    /// Every generation this cell has, retired ones included. The required set
    /// is [`MembershipSnapshot::required_members`], not this.
    pub members: Vec<MembershipMember>,
}

/// Why a snapshot cannot prove any event consumer-safe.
///
/// Deliberately a reason rather than a `bool`. Every one of these is an
/// operator-visible condition with a different resolution, and "not safe" alone
/// would collapse "a member is behind" into "this cell has no receivers at
/// all".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyBlock {
    /// A reset fence stands. The contract makes this block evaluation and
    /// pruning independently of membership, so it is checked first.
    ResetInProgress,
    /// The cell has no authoritative current placement, so there is no stream
    /// and epoch to key a checkpoint vector by.
    NoCurrentPlacement,
    /// Zero required members. **Never** safety: zero members is not everyone
    /// caught up, and reading it that way would release every retained row.
    EmptyRequiredMembership,
    /// A current member is not ready, so its frontier proves nothing.
    MemberNotReady {
        /// Which receiver.
        receiver_identity: String,
        /// Which generation.
        membership_generation: i64,
        /// The state it is actually in.
        state: String,
    },
}

impl MembershipSnapshot {
    /// The current generation of every receiver that still participates.
    ///
    /// One row per receiver identity — the greatest generation it has — and
    /// only when that generation is not retired. That is what makes a safely
    /// retired generation stop blocking: its successor outranks it here, and a
    /// receiver whose only generation is retired drops out of the required set
    /// entirely rather than blocking forever with a frontier no one will
    /// advance.
    pub fn required_members(&self) -> Vec<&MembershipMember> {
        let mut current: BTreeMap<&str, &MembershipMember> = BTreeMap::new();
        for member in &self.members {
            current
                .entry(member.receiver_identity.as_str())
                .and_modify(|held| {
                    if member.membership_generation > held.membership_generation {
                        *held = member;
                    }
                })
                .or_insert(member);
        }
        current
            .into_values()
            .filter(|member| !member.is_retired())
            .collect()
    }

    /// Why this snapshot cannot prove safety, or `None` when it can.
    ///
    /// Order is not arbitrary. The fence is checked before membership because
    /// the contract makes it an *additional* block rather than the only one:
    /// checking membership first would let an empty-but-fenced cell report the
    /// membership reason and hide the fence from an operator reading the
    /// readiness detail.
    pub fn safety_block(&self) -> Option<SafetyBlock> {
        if self.reset_in_progress {
            return Some(SafetyBlock::ResetInProgress);
        }
        if self.state.current_stream_identity.is_none() || self.state.current_stream_epoch.is_none()
        {
            return Some(SafetyBlock::NoCurrentPlacement);
        }
        let required = self.required_members();
        if required.is_empty() {
            return Some(SafetyBlock::EmptyRequiredMembership);
        }
        required
            .into_iter()
            .find(|member| !member.counts_toward_safety())
            .map(|member| SafetyBlock::MemberNotReady {
                receiver_identity: member.receiver_identity.clone(),
                membership_generation: member.membership_generation,
                state: member.state.clone(),
            })
    }
}

/// The outcome of one fenced membership write.
///
/// Not a `bool` and not a row count, for the reason [`super::CasOutcome`]
/// records on the relay side: "nothing was updated" has several distinct causes
/// here and a caller handles them differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipCas {
    /// The write applied.
    Applied {
        /// The cell's snapshot version after the write. Unchanged for writes
        /// that do not alter the required set.
        membership_version: i64,
        /// The generation the write concerns.
        membership_generation: i64,
    },
    /// The cell's snapshot version moved under this caller. Reread and retry;
    /// never proceed against the version that was read.
    VersionConflict {
        /// The version now on the row.
        current_membership_version: i64,
    },
    /// No `lore_outbox_membership_state` row for this cell.
    CellUnknown,
    /// No such receiver generation.
    GenerationNotFound,
    /// The generation exists but is in a state this transition cannot leave.
    WrongState {
        /// The state it is in.
        state: String,
    },
    /// The transition had already been recorded. Idempotent, not an error.
    AlreadyRecorded,
    /// The readiness compare-and-set failed because the cell's authoritative
    /// placement no longer equals what this generation captured. The generation
    /// has been **retired**; start a new one with a fresh capture, baseline,
    /// and drain.
    PlacementMoved {
        /// Authoritative identity now.
        current_stream_identity: Option<String>,
        /// Authoritative epoch now.
        current_stream_epoch: Option<i64>,
    },
    /// The readiness compare-and-set was refused because this generation has no
    /// persisted checkpoint at the cell's current placement. A baseline alone
    /// never marks a receiver caught up.
    NoCheckpointAtCurrentPlacement,
    /// The retirement was refused because neither of the contract's two
    /// preconditions holds: this generation has no persisted checkpoint at the
    /// current placement (graceful drain), and no strictly greater generation
    /// for the same receiver is ready (hard-dead replacement).
    ///
    /// Retiring anyway would drop the receiver out of the required set and
    /// release every row above its frontier, so this is a refusal rather than a
    /// warning.
    RetirementUnproven,
}

// ---------------------------------------------------------------------------
// Bounded input validation
// ---------------------------------------------------------------------------

fn bounded(label: &str, value: &str, max: usize) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::InvalidInput(format!(
            "outbox membership {label} is empty"
        )));
    }
    if value.len() > max {
        return Err(DomainError::InvalidInput(format!(
            "outbox membership {label} exceeds {max} bytes: {}",
            value.len()
        )));
    }
    Ok(())
}

pub(super) fn validate_cell_id(cell_id: &str) -> Result<(), DomainError> {
    if !is_valid_cell_id(cell_id) {
        return Err(DomainError::InvalidInput(format!(
            "outbox cell_id must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ and fit 63 bytes, got \
             {cell_id:?}"
        )));
    }
    Ok(())
}

pub(super) fn validate_receiver_identity(receiver_identity: &str) -> Result<(), DomainError> {
    bounded(
        "receiver_identity",
        receiver_identity,
        MAX_RECEIVER_IDENTITY_BYTES,
    )
}

pub(super) fn validate_stream(identity: &str, epoch: i64) -> Result<(), DomainError> {
    bounded("stream_identity", identity, MAX_STREAM_IDENTITY_BYTES)?;
    if epoch < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox stream_epoch must be >= 1, got {epoch}"
        )));
    }
    Ok(())
}

fn validate_generation(membership_generation: i64) -> Result<(), DomainError> {
    if membership_generation < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox membership_generation must be >= 1 (0 is the reset placeholder), got \
             {membership_generation}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Row decoding
// ---------------------------------------------------------------------------

/// The membership-state columns, in one place so every `SELECT` lists exactly
/// these and cannot drift from the decoder.
const STATE_COLUMNS: &str = "cell_id, membership_version, next_membership_generation, \
     reset_generation, current_stream_identity, current_stream_epoch, \
     current_placement_revision, updated_at";

/// The receiver-generation columns, same reason.
const MEMBER_COLUMNS: &str = "receiver_identity, membership_generation, state, \
     membership_version, captured_stream_identity, captured_stream_epoch, \
     captured_start_sequence, baseline_at, ready_at";

fn state_from(row: &Row) -> MembershipState {
    MembershipState {
        cell_id: row.get("cell_id"),
        membership_version: row.get("membership_version"),
        next_membership_generation: row.get("next_membership_generation"),
        reset_generation: row.get("reset_generation"),
        current_stream_identity: row.get("current_stream_identity"),
        current_stream_epoch: row.get("current_stream_epoch"),
        current_placement_revision: row.get("current_placement_revision"),
        updated_at: row.get("updated_at"),
    }
}

fn member_from(row: &Row) -> MembershipMember {
    let identity: Option<String> = row.get("captured_stream_identity");
    let epoch: Option<i64> = row.get("captured_stream_epoch");
    let start: Option<i64> = row.get("captured_start_sequence");
    // The `capture_shape` CHECK makes these three all-or-none, so a partial
    // tuple here means the constraint has drifted. Treating it as absent is the
    // fail-closed reading: a generation with no captured position can never
    // pass the readiness CAS.
    let captured = match (identity, epoch, start) {
        (Some(stream_identity), Some(stream_epoch), Some(start_sequence)) => {
            Some(CapturedPosition {
                stream_identity,
                stream_epoch,
                start_sequence,
            })
        }
        _ => None,
    };
    MembershipMember {
        receiver_identity: row.get("receiver_identity"),
        membership_generation: row.get("membership_generation"),
        state: row.get("state"),
        membership_version: row.get("membership_version"),
        captured,
        baseline_at: row.get("baseline_at"),
        ready_at: row.get("ready_at"),
    }
}

// ---------------------------------------------------------------------------
// Cell state
// ---------------------------------------------------------------------------

/// Create this cell's membership-state row if it has none, and return it.
///
/// Idempotent, and safe to call from every replica at boot: the insert is
/// `ON CONFLICT DO NOTHING`, so a concurrent caller neither fails nor resets a
/// live counter.
pub async fn ensure_membership_state(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<MembershipState, DomainError> {
    validate_cell_id(cell_id)?;
    client
        .execute(
            "INSERT INTO lore_outbox_membership_state \
                 (cell_id, membership_version, next_membership_generation, reset_generation, \
                  current_placement_revision, updated_at) \
             VALUES ($1, 1, 1, 0, 0, clock_timestamp()) \
             ON CONFLICT (cell_id) DO NOTHING",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership state insert", e))?;
    read_membership_state(client, cell_id)
        .await?
        .ok_or_else(|| {
            DomainError::Internal(format!(
                "outbox membership state for cell {cell_id} is absent immediately after an \
             ON CONFLICT DO NOTHING insert; the row was deleted concurrently"
            ))
        })
}

/// Read this cell's membership-state row.
pub async fn read_membership_state(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<Option<MembershipState>, DomainError> {
    validate_cell_id(cell_id)?;
    let row = client
        .query_opt(
            &format!("SELECT {STATE_COLUMNS} FROM lore_outbox_membership_state WHERE cell_id = $1"),
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership state select", e))?;
    Ok(row.as_ref().map(state_from))
}

/// Record the cell's authoritative current placement.
///
/// This is the value [`readiness_cas`] rereads and the reset service validates a
/// report's old tuple against — the cell's own fact, never a receiver's view of
/// it. It is set at cutover and moved only by an accepted reset.
///
/// Bumps the snapshot version, because moving the placement invalidates every
/// captured position and therefore changes what the required set can prove.
pub async fn set_current_placement(
    client: &impl GenericClient,
    cell_id: &str,
    stream_identity: &str,
    stream_epoch: i64,
    placement_revision: i64,
    expected_membership_version: i64,
) -> Result<MembershipCas, DomainError> {
    validate_cell_id(cell_id)?;
    validate_stream(stream_identity, stream_epoch)?;
    if placement_revision < 0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox placement_revision must be >= 0, got {placement_revision}"
        )));
    }
    let updated = client
        .query_opt(
            "UPDATE lore_outbox_membership_state SET \
                 current_stream_identity = $2, \
                 current_stream_epoch = $3, \
                 current_placement_revision = $4, \
                 membership_version = membership_version + 1, \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 AND membership_version = $5 \
             RETURNING membership_version",
            &[
                &cell_id,
                &stream_identity,
                &stream_epoch,
                &placement_revision,
                &expected_membership_version,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership placement update", e))?;
    match updated {
        Some(row) => Ok(MembershipCas::Applied {
            membership_version: row.get("membership_version"),
            membership_generation: PLACEHOLDER_GENERATION,
        }),
        None => Ok(classify_state_miss(client, cell_id).await?),
    }
}

/// Distinguish "no such cell" from "the version moved" after a CAS that matched
/// nothing. Only reached on the failure path, so it costs one extra read on a
/// path that is already retrying.
async fn classify_state_miss(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<MembershipCas, DomainError> {
    match read_membership_state(client, cell_id).await? {
        Some(state) => Ok(MembershipCas::VersionConflict {
            current_membership_version: state.membership_version,
        }),
        None => Ok(MembershipCas::CellUnknown),
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// Read one cell's whole membership: counters, fence, and every generation.
///
/// **Two statements, so the caller owns the consistency.** Pass a
/// `tokio_postgres::Transaction` when the answer has to be a single point in
/// time — which every safety evaluation does, and which
/// [`super::evaluator::evaluate_consumer_safe`] arranges. Outside a
/// transaction this is a diagnostic read, and the snapshot version it returns
/// is what makes a torn read detectable rather than silently acted on: any
/// write built on it compare-and-sets that version.
pub async fn read_membership_snapshot(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<Option<MembershipSnapshot>, DomainError> {
    let Some(state) = read_membership_state(client, cell_id).await? else {
        return Ok(None);
    };
    // `state = 'reset_in_progress'` as a SQL literal, so the planner can prove
    // the predicate implies `lore_outbox_reset_generations_fence`'s partial
    // predicate. A bound parameter returns the same rows under a generic plan
    // by scanning the table instead.
    let fenced: bool = client
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lore_outbox_reset_generations \
                 WHERE cell_id = $1 AND state = 'reset_in_progress' \
             ) AS fenced",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset fence probe", e))?
        .get("fenced");
    let rows = client
        .query(
            &format!(
                "SELECT {MEMBER_COLUMNS} FROM lore_outbox_receiver_membership \
                 WHERE cell_id = $1 \
                 ORDER BY receiver_identity, membership_generation"
            ),
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership select", e))?;
    Ok(Some(MembershipSnapshot {
        state,
        reset_in_progress: fenced,
        members: rows.iter().map(member_from).collect(),
    }))
}

// ---------------------------------------------------------------------------
// Lifecycle transitions
// ---------------------------------------------------------------------------

/// Allocate the next generation for `receiver_identity` and create its row.
///
/// The allocation and the row creation are one transaction, so a crash between
/// them cannot burn a generation number that no row ever claims. The
/// compare-and-set on `membership_version` is what makes two replicas racing to
/// join the same receiver produce two generations rather than one shared row:
/// the loser sees [`MembershipCas::VersionConflict`], rereads, and allocates its
/// own.
///
/// The new row is `joining` with no captured position. It is not required and
/// cannot be credited for safety until [`readiness_cas`] moves it to `ready`.
pub async fn join_receiver(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    expected_membership_version: i64,
) -> Result<MembershipCas, DomainError> {
    validate_cell_id(cell_id)?;
    validate_receiver_identity(receiver_identity)?;
    if receiver_identity == REQUIRED_REPLACEMENT_PLACEHOLDER {
        return Err(DomainError::InvalidInput(format!(
            "outbox receiver_identity {REQUIRED_REPLACEMENT_PLACEHOLDER:?} is reserved for the \
             reset fence's placeholder and cannot be joined"
        )));
    }

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox membership join begin", e))?;

    let allocated = tx
        .query_opt(
            "UPDATE lore_outbox_membership_state SET \
                 next_membership_generation = next_membership_generation + 1, \
                 membership_version = membership_version + 1, \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 AND membership_version = $2 \
             RETURNING next_membership_generation - 1 AS membership_generation, \
                       membership_version",
            &[&cell_id, &expected_membership_version],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership generation allocate", e))?;

    let Some(row) = allocated else {
        drop(tx);
        // `deadpool_postgres::Client` reaches `tokio_postgres::Client` through
        // two `Deref` hops; the annotation lets coercion do it rather than
        // spelling the hops.
        let client: &tokio_postgres::Client = client;
        return classify_state_miss(client, cell_id).await;
    };
    let membership_generation: i64 = row.get("membership_generation");
    let membership_version: i64 = row.get("membership_version");

    tx.execute(
        "INSERT INTO lore_outbox_receiver_membership \
             (cell_id, receiver_identity, membership_generation, membership_version, state, \
              created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'joining', clock_timestamp(), clock_timestamp())",
        &[
            &cell_id,
            &receiver_identity,
            &membership_generation,
            &membership_version,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("outbox membership join insert", e))?;

    classify_commit(tx.commit().await, "outbox membership join commit")?;
    Ok(MembershipCas::Applied {
        membership_version,
        membership_generation,
    })
}

/// Pin the durable consumer position this generation will baseline and drain
/// from.
///
/// Accepted only on a `joining` row that has not captured yet, which is what
/// makes the contract's ordering a shape rather than a convention: a second
/// capture on the same generation is refused rather than silently moving the
/// position a baseline was already taken against.
pub async fn record_capture(
    client: &impl GenericClient,
    cell_id: &str,
    receiver_identity: &str,
    membership_generation: i64,
    captured: &CapturedPosition,
) -> Result<MembershipCas, DomainError> {
    validate_cell_id(cell_id)?;
    validate_receiver_identity(receiver_identity)?;
    validate_generation(membership_generation)?;
    validate_stream(&captured.stream_identity, captured.stream_epoch)?;
    if captured.start_sequence < 0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox captured start_sequence must be >= 0, got {}",
            captured.start_sequence
        )));
    }
    let updated = client
        .query_opt(
            "UPDATE lore_outbox_receiver_membership SET \
                 captured_stream_identity = $4, \
                 captured_stream_epoch = $5, \
                 captured_start_sequence = $6, \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3 \
               AND state = 'joining' AND captured_stream_identity IS NULL \
             RETURNING membership_version",
            &[
                &cell_id,
                &receiver_identity,
                &membership_generation,
                &captured.stream_identity,
                &captured.stream_epoch,
                &captured.start_sequence,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership capture", e))?;
    match updated {
        Some(row) => Ok(MembershipCas::Applied {
            membership_version: row.get("membership_version"),
            membership_generation,
        }),
        None => {
            classify_member_miss(
                client,
                cell_id,
                receiver_identity,
                membership_generation,
                |member| member.captured.is_some(),
            )
            .await
        }
    }
}

/// Record that this generation took its authoritative baseline.
///
/// Requires a captured position and refuses a second baseline. Ordering again
/// as a shape: baseline-first is the bootstrap the contract names as invalid,
/// and the `WHERE` clause is what makes it unreachable rather than merely
/// discouraged.
pub async fn record_baseline(
    client: &impl GenericClient,
    cell_id: &str,
    receiver_identity: &str,
    membership_generation: i64,
) -> Result<MembershipCas, DomainError> {
    validate_cell_id(cell_id)?;
    validate_receiver_identity(receiver_identity)?;
    validate_generation(membership_generation)?;
    let updated = client
        .query_opt(
            "UPDATE lore_outbox_receiver_membership SET \
                 baseline_at = clock_timestamp(), \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3 \
               AND state = 'joining' \
               AND captured_stream_identity IS NOT NULL \
               AND baseline_at IS NULL \
             RETURNING membership_version",
            &[&cell_id, &receiver_identity, &membership_generation],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership baseline", e))?;
    match updated {
        Some(row) => Ok(MembershipCas::Applied {
            membership_version: row.get("membership_version"),
            membership_generation,
        }),
        None => {
            classify_member_miss(
                client,
                cell_id,
                receiver_identity,
                membership_generation,
                |member| member.baseline_at.is_some(),
            )
            .await
        }
    }
}

/// The readiness compare-and-set.
///
/// Rereads the cell's authoritative current stream identity and epoch and
/// succeeds only when both still equal what this generation captured. That
/// reread is the whole point: a reset anywhere between capture and here moved
/// the placement, and a generation that resumed against the old one would be
/// declaring itself caught up on an epoch that no longer exists.
///
/// On mismatch the generation is **retired** in the same transaction and
/// [`MembershipCas::PlacementMoved`] is returned. That is a mutation on a
/// failure path, and it is the specified behaviour: the contract requires a
/// reset or mismatch at any bootstrap boundary to fail readiness *and* retire
/// that generation, so the replacement starts from a new capture rather than
/// retrying into the same dead end.
///
/// A persisted checkpoint at the current placement is also required. A baseline
/// alone never marks a receiver caught up, and this is where that rule is
/// enforced rather than trusted.
///
/// # Clearing the reset fence
///
/// When this CAS succeeds and a reset fence stands, it may also clear the fence
/// and remove the required-replacement placeholder — but only here, only for a
/// generation that has just proved a fresh checkpoint at the new epoch, and
/// only when **no receiver in the cell is still stranded on a retired
/// generation**.
///
/// That last condition is not belt and braces. CR-032 makes durable receivers
/// **per replica**, and an accepted reset retires every generation in the cell.
/// A three-replica cell therefore has three receivers to rebuild, and clearing
/// the fence when the first one goes ready would be actively wrong:
/// [`MembershipSnapshot::required_members`] drops a receiver whose greatest
/// generation is retired, so the other two would simply be absent from the
/// required set, the safe sequence would be the minimum over one member, and
/// the evaluator would release rows the other two never acknowledged. The fence
/// is what holds the cell while they rebuild, so it must outlast all of them.
///
/// A receiver that is genuinely gone forever blocks the fence until an operator
/// removes its rows. That direction is deliberate: the failure is availability
/// of the event plane for that cell, never a released row.
pub async fn readiness_cas(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    membership_generation: i64,
) -> Result<MembershipCas, DomainError> {
    validate_cell_id(cell_id)?;
    validate_receiver_identity(receiver_identity)?;
    validate_generation(membership_generation)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox readiness cas begin", e))?;

    // `FOR UPDATE` on the counters row serialises this CAS against a concurrent
    // join, retirement, or accepted reset for the same cell. Taking it first,
    // before the member row, fixes one lock order for every writer here and in
    // `super::reset`, so two of them cannot deadlock by approaching the same
    // pair from opposite ends.
    let Some(state_row) = tx
        .query_opt(
            &format!(
                "SELECT {STATE_COLUMNS} FROM lore_outbox_membership_state \
                 WHERE cell_id = $1 FOR UPDATE"
            ),
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox readiness cas state select", e))?
    else {
        drop(tx);
        return Ok(MembershipCas::CellUnknown);
    };
    let state = state_from(&state_row);

    let Some(member_row) = tx
        .query_opt(
            &format!(
                "SELECT {MEMBER_COLUMNS} FROM lore_outbox_receiver_membership \
                 WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3 \
                 FOR UPDATE"
            ),
            &[&cell_id, &receiver_identity, &membership_generation],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox readiness cas member select", e))?
    else {
        drop(tx);
        return Ok(MembershipCas::GenerationNotFound);
    };
    let member = member_from(&member_row);

    if member.state == MEMBERSHIP_STATE_READY {
        drop(tx);
        return Ok(MembershipCas::AlreadyRecorded);
    }
    if member.state != "joining" {
        drop(tx);
        return Ok(MembershipCas::WrongState {
            state: member.state,
        });
    }
    let Some(captured) = member.captured.clone() else {
        drop(tx);
        return Ok(MembershipCas::WrongState {
            state: "joining (no captured position)".to_string(),
        });
    };
    if member.baseline_at.is_none() {
        drop(tx);
        return Ok(MembershipCas::WrongState {
            state: "joining (no authoritative baseline)".to_string(),
        });
    }

    let placement_matches = state.current_stream_identity.as_deref()
        == Some(captured.stream_identity.as_str())
        && state.current_stream_epoch == Some(captured.stream_epoch);
    if !placement_matches {
        tx.execute(
            "UPDATE lore_outbox_receiver_membership SET \
                 state = 'retired', \
                 membership_version = $4, \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3",
            &[
                &cell_id,
                &receiver_identity,
                &membership_generation,
                &(state.membership_version + 1),
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox readiness cas retire", e))?;
        bump_membership_version(&*tx, cell_id).await?;
        classify_commit(tx.commit().await, "outbox readiness cas retire commit")?;
        return Ok(MembershipCas::PlacementMoved {
            current_stream_identity: state.current_stream_identity,
            current_stream_epoch: state.current_stream_epoch,
        });
    }

    let checkpointed: bool = tx
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lore_outbox_checkpoints \
                 WHERE stream_identity = $1 AND stream_epoch = $2 \
                   AND receiver_identity = $3 AND membership_generation = $4 \
             ) AS checkpointed",
            &[
                &captured.stream_identity,
                &captured.stream_epoch,
                &receiver_identity,
                &membership_generation,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox readiness cas checkpoint probe", e))?
        .get("checkpointed");
    if !checkpointed {
        drop(tx);
        return Ok(MembershipCas::NoCheckpointAtCurrentPlacement);
    }

    let membership_version = state.membership_version + 1;
    tx.execute(
        "UPDATE lore_outbox_receiver_membership SET \
             state = 'ready', \
             ready_at = clock_timestamp(), \
             membership_version = $4, \
             updated_at = clock_timestamp() \
         WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3",
        &[
            &cell_id,
            &receiver_identity,
            &membership_generation,
            &membership_version,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("outbox readiness cas ready", e))?;

    // The fence exit. Every statement is a no-op when no reset is standing, so
    // the ordinary join path pays one cheap indexed read and nothing else.
    //
    // `receiver_identity <> $2` excludes the placeholder itself, which is not a
    // real receiver and is about to be deleted.
    let stranded: bool = tx
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lore_outbox_receiver_membership AS retired \
                  WHERE retired.cell_id = $1 \
                    AND retired.receiver_identity <> $2 \
                    AND retired.state = 'retired' \
                    AND NOT EXISTS ( \
                        SELECT 1 FROM lore_outbox_receiver_membership AS successor \
                         WHERE successor.cell_id = retired.cell_id \
                           AND successor.receiver_identity = retired.receiver_identity \
                           AND successor.membership_generation \
                               > retired.membership_generation \
                           AND successor.state <> 'retired' \
                    ) \
             ) AS stranded",
            &[&cell_id, &REQUIRED_REPLACEMENT_PLACEHOLDER],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset stranded receiver probe", e))?
        .get("stranded");
    if !stranded {
        tx.execute(
            "DELETE FROM lore_outbox_receiver_membership \
             WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3 \
               AND state = 'required_placeholder'",
            &[
                &cell_id,
                &REQUIRED_REPLACEMENT_PLACEHOLDER,
                &PLACEHOLDER_GENERATION,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset placeholder clear", e))?;
        tx.execute(
            "UPDATE lore_outbox_reset_generations SET \
                 state = $2, cleared_at = clock_timestamp() \
             WHERE cell_id = $1 AND state = 'reset_in_progress'",
            &[&cell_id, &RESET_STATE_CLEARED],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset fence clear", e))?;
    }

    bump_membership_version(&*tx, cell_id).await?;
    classify_commit(tx.commit().await, "outbox readiness cas commit")?;
    Ok(MembershipCas::Applied {
        membership_version,
        membership_generation,
    })
}

/// Retire one generation.
///
/// The contract gives exactly two ways a generation may leave, and this
/// **enforces both** rather than documenting them as a caller obligation:
///
/// * **graceful drain** — the generation has persisted a checkpoint at the
///   cell's current placement, so its work is accounted for; or
/// * **hard-dead replacement** — a strictly greater generation for the same
///   receiver is already `ready`, which by [`readiness_cas`] means it captured,
///   baselined, drained, and checkpointed at the current placement.
///
/// Neither holding is [`MembershipCas::RetirementUnproven`]. The alternative —
/// retiring on request — is not a smaller version of this: retiring a lagging
/// current generation drops it out of
/// [`MembershipSnapshot::required_members`], and the very next evaluation takes
/// the minimum over the remaining members and releases every row that
/// generation had not acknowledged. There is no error at that point and nothing
/// to notice; the rows are simply gone at day seven.
///
/// A generation that has never been ready and never checkpointed is refused
/// too. That is the honest reading: it has no proof of anything, so there is
/// nothing to retire it *against*. Deleting such a row is an operator action,
/// not a lifecycle transition.
pub async fn retire_generation(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    receiver_identity: &str,
    membership_generation: i64,
) -> Result<MembershipCas, DomainError> {
    validate_cell_id(cell_id)?;
    validate_receiver_identity(receiver_identity)?;
    if membership_generation < 0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox membership_generation must be >= 0, got {membership_generation}"
        )));
    }

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox retire begin", e))?;
    let Some(state_row) = tx
        .query_opt(
            &format!(
                "SELECT {STATE_COLUMNS} FROM lore_outbox_membership_state \
                 WHERE cell_id = $1 FOR UPDATE"
            ),
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox retire state select", e))?
    else {
        drop(tx);
        return Ok(MembershipCas::CellUnknown);
    };
    let state = state_from(&state_row);
    let membership_version: i64 = state.membership_version + 1;

    // The two contract preconditions, in one query so a retirement cannot slip
    // between two reads. The placeholder is exempt: it is not a receiver, it
    // has no work to account for, and only an accepted reset installs or
    // removes it.
    if membership_generation != PLACEHOLDER_GENERATION {
        let (Some(current_identity), Some(current_epoch)) = (
            state.current_stream_identity.as_deref(),
            state.current_stream_epoch,
        ) else {
            drop(tx);
            // With no authoritative placement there is no checkpoint key to
            // prove a graceful drain against, so neither precondition can hold.
            return Ok(MembershipCas::RetirementUnproven);
        };
        let proven: bool = tx
            .query_one(
                "SELECT ( \
                     EXISTS ( \
                         SELECT 1 FROM lore_outbox_checkpoints \
                          WHERE stream_identity = $4 AND stream_epoch = $5 \
                            AND receiver_identity = $2 AND membership_generation = $3 \
                     ) \
                     OR EXISTS ( \
                         SELECT 1 FROM lore_outbox_receiver_membership \
                          WHERE cell_id = $1 AND receiver_identity = $2 \
                            AND membership_generation > $3 \
                            AND state = 'ready' \
                     ) \
                 ) AS proven",
                &[
                    &cell_id,
                    &receiver_identity,
                    &membership_generation,
                    &current_identity,
                    &current_epoch,
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("outbox retire precondition probe", e))?
            .get("proven");
        if !proven {
            drop(tx);
            return Ok(MembershipCas::RetirementUnproven);
        }
    }

    let updated = tx
        .execute(
            "UPDATE lore_outbox_receiver_membership SET \
                 state = 'retired', \
                 membership_version = $4, \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3 \
               AND state <> 'retired'",
            &[
                &cell_id,
                &receiver_identity,
                &membership_generation,
                &membership_version,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox retire", e))?;
    if updated == 0 {
        drop(tx);
        let client: &tokio_postgres::Client = client;
        return classify_member_miss(
            client,
            cell_id,
            receiver_identity,
            membership_generation,
            MembershipMember::is_retired,
        )
        .await;
    }
    bump_membership_version(&*tx, cell_id).await?;
    classify_commit(tx.commit().await, "outbox retire commit")?;
    Ok(MembershipCas::Applied {
        membership_version,
        membership_generation,
    })
}

/// Install the reset fence's required-replacement placeholder.
///
/// Called only from [`super::reset`], inside its receipt transaction, which is
/// why it takes a plain client rather than opening one of its own.
pub(super) async fn install_required_placeholder(
    client: &impl GenericClient,
    cell_id: &str,
    membership_version: i64,
) -> Result<(), DomainError> {
    client
        .execute(
            "INSERT INTO lore_outbox_receiver_membership \
                 (cell_id, receiver_identity, membership_generation, membership_version, state, \
                  created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'required_placeholder', clock_timestamp(), \
                     clock_timestamp()) \
             ON CONFLICT (cell_id, receiver_identity, membership_generation) DO UPDATE SET \
                 state = 'required_placeholder', \
                 membership_version = EXCLUDED.membership_version, \
                 updated_at = clock_timestamp()",
            &[
                &cell_id,
                &REQUIRED_REPLACEMENT_PLACEHOLDER,
                &PLACEHOLDER_GENERATION,
                &membership_version,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset placeholder install", e))?;
    Ok(())
}

/// Retire every generation of this cell that is not already retired, except the
/// reset placeholder.
///
/// Called only from [`super::reset`]'s receipt transaction. The placeholder is
/// excluded because retiring it would empty the required set and hand the
/// evaluator a vacuously safe snapshot the instant the fence cleared.
pub(super) async fn retire_all_for_reset(
    client: &impl GenericClient,
    cell_id: &str,
    membership_version: i64,
) -> Result<u64, DomainError> {
    client
        .execute(
            "UPDATE lore_outbox_receiver_membership SET \
                 state = 'retired', \
                 membership_version = $2, \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 AND state <> 'retired' AND state <> 'required_placeholder'",
            &[&cell_id, &membership_version],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset retire all", e))
}

/// Bump the cell's snapshot version by one, inside a caller's transaction.
pub(super) async fn bump_membership_version(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<i64, DomainError> {
    let row = client
        .query_one(
            "UPDATE lore_outbox_membership_state SET \
                 membership_version = membership_version + 1, \
                 updated_at = clock_timestamp() \
             WHERE cell_id = $1 \
             RETURNING membership_version",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership version bump", e))?;
    Ok(row.get("membership_version"))
}

/// Classify a member-scoped update that matched nothing.
///
/// `already` decides whether the transition had simply been made before, which
/// is idempotent rather than an error. Only reached on a failure path.
async fn classify_member_miss(
    client: &impl GenericClient,
    cell_id: &str,
    receiver_identity: &str,
    membership_generation: i64,
    already: impl Fn(&MembershipMember) -> bool,
) -> Result<MembershipCas, DomainError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {MEMBER_COLUMNS} FROM lore_outbox_receiver_membership \
                 WHERE cell_id = $1 AND receiver_identity = $2 AND membership_generation = $3"
            ),
            &[&cell_id, &receiver_identity, &membership_generation],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership miss classify", e))?;
    let Some(row) = row else {
        return Ok(MembershipCas::GenerationNotFound);
    };
    let member = member_from(&row);
    if already(&member) {
        return Ok(MembershipCas::AlreadyRecorded);
    }
    Ok(MembershipCas::WrongState {
        state: member.state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::outbox::schema::MEMBERSHIP_STATE_REQUIRED_PLACEHOLDER;

    fn member(identity: &str, generation: i64, state: &str) -> MembershipMember {
        MembershipMember {
            receiver_identity: identity.to_string(),
            membership_generation: generation,
            state: state.to_string(),
            membership_version: 1,
            captured: None,
            baseline_at: None,
            ready_at: None,
        }
    }

    fn snapshot(reset_in_progress: bool, members: Vec<MembershipMember>) -> MembershipSnapshot {
        MembershipSnapshot {
            state: MembershipState {
                cell_id: "sfo3-cell-a".to_string(),
                membership_version: 31,
                next_membership_generation: 6,
                reset_generation: 0,
                current_stream_identity: Some("DURABLE-sfo3-cell-a".to_string()),
                current_stream_epoch: Some(8),
                current_placement_revision: 4,
                updated_at: SystemTime::UNIX_EPOCH,
            },
            reset_in_progress,
            members,
        }
    }

    #[test]
    fn two_ready_members_are_both_required() {
        let snapshot = snapshot(
            false,
            vec![
                member("loreserver-sfo3-cell-a-1", 4, MEMBERSHIP_STATE_READY),
                member("loreserver-sfo3-cell-a-2", 2, MEMBERSHIP_STATE_READY),
            ],
        );
        assert_eq!(snapshot.required_members().len(), 2);
        assert_eq!(snapshot.safety_block(), None);
    }

    /// The contract's "safely retired generations do not block reaping
    /// forever": generation 4 retired, generation 5 ready, and only 5 is
    /// required.
    #[test]
    fn a_retired_generation_is_outranked_by_its_successor() {
        let snapshot = snapshot(
            false,
            vec![
                member("loreserver-sfo3-cell-a-1", 4, MEMBERSHIP_STATE_RETIRED),
                member("loreserver-sfo3-cell-a-1", 5, MEMBERSHIP_STATE_READY),
                member("loreserver-sfo3-cell-a-2", 2, MEMBERSHIP_STATE_READY),
            ],
        );
        let required = snapshot.required_members();
        assert_eq!(required.len(), 2);
        assert!(
            required
                .iter()
                .all(|m| m.membership_generation == 5 || m.membership_generation == 2)
        );
        assert_eq!(snapshot.safety_block(), None);
    }

    /// A receiver whose only generation is retired leaves the required set
    /// entirely rather than blocking forever with a frontier no one advances.
    #[test]
    fn a_receiver_whose_only_generation_is_retired_drops_out() {
        let snapshot = snapshot(
            false,
            vec![
                member("loreserver-sfo3-cell-a-1", 4, MEMBERSHIP_STATE_RETIRED),
                member("loreserver-sfo3-cell-a-2", 2, MEMBERSHIP_STATE_READY),
            ],
        );
        assert_eq!(snapshot.required_members().len(), 1);
        assert_eq!(snapshot.safety_block(), None);
    }

    /// The single most dangerous failure mode: zero required members must never
    /// read as everyone caught up.
    #[test]
    fn empty_membership_is_never_vacuously_safe() {
        assert_eq!(
            snapshot(false, vec![]).safety_block(),
            Some(SafetyBlock::EmptyRequiredMembership)
        );
        assert_eq!(
            snapshot(
                false,
                vec![member(
                    "loreserver-sfo3-cell-a-1",
                    4,
                    MEMBERSHIP_STATE_RETIRED
                )]
            )
            .safety_block(),
            Some(SafetyBlock::EmptyRequiredMembership)
        );
    }

    #[test]
    fn the_reset_fence_blocks_a_snapshot_that_would_otherwise_be_safe() {
        let snapshot = snapshot(
            true,
            vec![
                member("loreserver-sfo3-cell-a-1", 4, MEMBERSHIP_STATE_READY),
                member("loreserver-sfo3-cell-a-2", 2, MEMBERSHIP_STATE_READY),
            ],
        );
        assert_eq!(snapshot.safety_block(), Some(SafetyBlock::ResetInProgress));
    }

    /// The fence is an ADDITIONAL block, not the only one, and it is reported
    /// ahead of the membership reason so an operator sees the real condition.
    #[test]
    fn the_reset_fence_blocks_empty_membership_and_is_the_reported_reason() {
        assert_eq!(
            snapshot(true, vec![]).safety_block(),
            Some(SafetyBlock::ResetInProgress)
        );
    }

    #[test]
    fn the_required_replacement_placeholder_can_never_be_ready() {
        let snapshot = snapshot(
            false,
            vec![member(
                REQUIRED_REPLACEMENT_PLACEHOLDER,
                PLACEHOLDER_GENERATION,
                MEMBERSHIP_STATE_REQUIRED_PLACEHOLDER,
            )],
        );
        assert_eq!(
            snapshot.safety_block(),
            Some(SafetyBlock::MemberNotReady {
                receiver_identity: REQUIRED_REPLACEMENT_PLACEHOLDER.to_string(),
                membership_generation: PLACEHOLDER_GENERATION,
                state: MEMBERSHIP_STATE_REQUIRED_PLACEHOLDER.to_string(),
            })
        );
    }

    #[test]
    fn a_joining_member_is_required_but_not_ready() {
        let snapshot = snapshot(
            false,
            vec![
                member("loreserver-sfo3-cell-a-1", 4, MEMBERSHIP_STATE_READY),
                member("loreserver-sfo3-cell-a-2", 3, "joining"),
            ],
        );
        assert!(matches!(
            snapshot.safety_block(),
            Some(SafetyBlock::MemberNotReady { .. })
        ));
    }

    /// A draining member is still consuming, so it still counts. Crediting
    /// safety without it would release rows it has not acknowledged.
    #[test]
    fn a_draining_member_still_counts_toward_safety() {
        let snapshot = snapshot(
            false,
            vec![member(
                "loreserver-sfo3-cell-a-1",
                4,
                MEMBERSHIP_STATE_DRAINING,
            )],
        );
        assert_eq!(snapshot.safety_block(), None);
    }

    #[test]
    fn a_cell_with_no_placement_cannot_prove_safety() {
        let mut snapshot = snapshot(
            false,
            vec![member(
                "loreserver-sfo3-cell-a-1",
                4,
                MEMBERSHIP_STATE_READY,
            )],
        );
        snapshot.state.current_stream_identity = None;
        snapshot.state.current_stream_epoch = None;
        assert_eq!(
            snapshot.safety_block(),
            Some(SafetyBlock::NoCurrentPlacement)
        );
    }

    #[test]
    fn the_placeholder_identity_cannot_be_joined() {
        // Validation only; no database contact. `join_receiver` rejects the
        // reserved identity before it opens a transaction.
        assert!(validate_receiver_identity(REQUIRED_REPLACEMENT_PLACEHOLDER).is_ok());
        assert!(validate_receiver_identity("").is_err());
        assert!(validate_receiver_identity(&"x".repeat(129)).is_err());
    }

    /// The placeholder is exempt from the retirement preconditions, and every
    /// real generation is not. Provable here because the exemption is a pure
    /// comparison against the reserved generation.
    #[test]
    fn only_the_placeholder_generation_is_exempt_from_the_retirement_guard() {
        assert_eq!(PLACEHOLDER_GENERATION, 0);
        for generation in [1_i64, 2, 5] {
            assert_ne!(generation, PLACEHOLDER_GENERATION);
        }
    }

    /// A receiver stranded on a retired generation is one whose GREATEST
    /// generation is retired. The fence-exit query expresses exactly that, and
    /// this pins the reading the query encodes: generation 4 retired with a
    /// ready 5 is not stranded, and 4 retired alone is.
    #[test]
    fn a_stranded_receiver_is_one_whose_greatest_generation_is_retired() {
        let rebuilt = snapshot(
            false,
            vec![
                member("loreserver-sfo3-cell-a-1", 4, MEMBERSHIP_STATE_RETIRED),
                member("loreserver-sfo3-cell-a-1", 5, MEMBERSHIP_STATE_READY),
            ],
        );
        assert_eq!(rebuilt.required_members().len(), 1);

        let stranded = snapshot(
            false,
            vec![
                member("loreserver-sfo3-cell-a-1", 4, MEMBERSHIP_STATE_RETIRED),
                member("loreserver-sfo3-cell-a-1", 5, MEMBERSHIP_STATE_READY),
                member("loreserver-sfo3-cell-a-2", 2, MEMBERSHIP_STATE_RETIRED),
            ],
        );
        // The stranded receiver silently LEAVES the required set, which is the
        // whole reason the fence must not clear while it is in that state: the
        // safe sequence would be the minimum over one member instead of two.
        assert_eq!(stranded.required_members().len(), 1);
        assert_eq!(stranded.safety_block(), None);
    }

    #[test]
    fn generation_zero_is_reserved() {
        assert!(validate_generation(0).is_err());
        assert!(validate_generation(-1).is_err());
        assert!(validate_generation(1).is_ok());
    }

    #[test]
    fn a_stream_epoch_below_one_is_refused() {
        assert!(validate_stream("DURABLE-sfo3-cell-a", 0).is_err());
        assert!(validate_stream("DURABLE-sfo3-cell-a", 1).is_ok());
        assert!(validate_stream("", 1).is_err());
    }
}

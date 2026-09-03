// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's bounded `consumer_safe` evaluator (WP-119 Step C).
//!
//! `pending`, `broker_accepted`, and `consumer_safe` are three separate durable
//! facts, and this module owns the third. A gateway acknowledgement advances a
//! row only to `broker_accepted`; nothing here infers consumer safety from it.
//! An event becomes `consumer_safe` only when its broker sequence is at or
//! below **every** required current receiver generation's contiguous
//! acknowledgement frontier, read under **one** membership snapshot version.
//!
//! # The three ways this must not be wrong
//!
//! * **Empty is never safe.** Zero required members is not everyone caught up.
//!   [`super::membership::MembershipSnapshot::safety_block`] refuses it, and
//!   the reset fence's required-replacement placeholder exists so that a cell
//!   mid-reset cannot reach the empty case at all.
//! * **The minimum, not the maximum.** The safe sequence is the *lowest*
//!   frontier across the required set. One lagging member holds every row.
//! * **One snapshot, not several.** The whole evaluation runs under a share
//!   lock on the cell's counters row, so a concurrent join, retirement,
//!   replacement, or accepted reset serialises against it rather than landing
//!   halfway through and mixing two memberships into one verdict.
//!
//! # Why a share lock rather than a version write-back
//!
//! Compare-and-setting the snapshot version by writing it back would work, but
//! it would also make every evaluator tick a write to the one row every
//! membership transition contends on — on a five-second probe interval, for a
//! decision that usually changes nothing. `SELECT ... FOR SHARE` gives the same
//! guarantee for a read: it blocks until this bounded transaction commits, and
//! a change that committed *before* this transaction started is simply the
//! snapshot this evaluation reads.
//!
//! **Which writers that actually covers**, because "every writer" would be too
//! strong and the distinction is the whole argument. Every transition that
//! changes the required set takes `FOR UPDATE` on that row first —
//! `join_receiver`, `readiness_cas`, `retire_generation`, `set_current_placement`,
//! and `accept_reset` — so the share lock serialises against all of them, in a
//! consistent order with no cycle. `report_checkpoint` takes the same share
//! lock, so it neither blocks nor is blocked by an evaluation. `record_capture`
//! and `record_baseline` take no lock at all, and deliberately: they write only
//! to a `joining` row, which is never in the required set and never carries a
//! frontier this evaluation reads.

use tokio_postgres::GenericClient;

use crate::domain::errors::DomainError;
use crate::domain::outbox::checkpoint::read_checkpoint;
use crate::domain::outbox::membership::SafetyBlock;
use crate::domain::outbox::membership::read_membership_snapshot;
use crate::domain::outbox::membership::validate_cell_id;
use crate::domain::retry::classify_commit;

/// CR-032's bound on one evaluation transaction. "Prune transactions contain at
/// most 1,000 rows"; the same bound applies to the transition that makes a row
/// prunable, for the same reason — a long transaction on this table blocks the
/// relay's own claim path.
pub const MAX_EVALUATION_BATCH: i64 = 1_000;

/// What the required checkpoint vector proves, when it proves anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeVector {
    /// The snapshot version this verdict was read under.
    pub membership_version: i64,
    /// The cell's authoritative current stream.
    pub stream_identity: String,
    /// The cell's authoritative current epoch.
    pub stream_epoch: i64,
    /// The lowest contiguous frontier across the required set. Every accepted
    /// row at or below this sequence is safe.
    pub safe_sequence: i64,
    /// How many receiver generations that minimum was taken over. Never zero.
    pub required_members: usize,
}

/// Why an evaluation could prove nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationBlock {
    /// The cell has no membership state row at all, so it has never been
    /// through cutover.
    CellUnknown,
    /// The membership snapshot itself forbids a verdict.
    Membership(SafetyBlock),
    /// A required member has no checkpoint at the current placement. It has
    /// joined but not yet drained, or its generation was replaced without one.
    /// Either way its frontier is unknown, which is not the same as zero.
    MissingCheckpoint {
        /// Which receiver.
        receiver_identity: String,
        /// Which generation.
        membership_generation: i64,
    },
}

/// The result of one bounded evaluation tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationOutcome {
    /// Rows advanced to `consumer_safe` by this tick.
    pub advanced: u64,
    /// What the vector proved, when it proved anything.
    pub proven: Option<SafeVector>,
    /// Why it proved nothing.
    pub block: Option<EvaluationBlock>,
}

impl EvaluationOutcome {
    /// A tick that proved nothing and moved nothing.
    fn blocked(block: EvaluationBlock) -> Self {
        Self {
            advanced: 0,
            proven: None,
            block: Some(block),
        }
    }
}

/// Prove what the required checkpoint vector currently supports.
///
/// **Must be called inside a transaction that already holds
/// [`lock_membership_for_read`] on this cell.** Without it the two reads below
/// can straddle a membership change and the minimum would be taken over a set
/// that never existed at one moment.
pub(super) async fn prove_safe_vector(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<Result<SafeVector, EvaluationBlock>, DomainError> {
    let Some(snapshot) = read_membership_snapshot(client, cell_id).await? else {
        return Ok(Err(EvaluationBlock::CellUnknown));
    };
    if let Some(block) = snapshot.safety_block() {
        return Ok(Err(EvaluationBlock::Membership(block)));
    }
    // `safety_block` returned `None`, which it can only do when both are set.
    let (Some(stream_identity), Some(stream_epoch)) = (
        snapshot.state.current_stream_identity.clone(),
        snapshot.state.current_stream_epoch,
    ) else {
        return Ok(Err(EvaluationBlock::Membership(
            SafetyBlock::NoCurrentPlacement,
        )));
    };

    let required = snapshot.required_members();
    let mut safe_sequence: Option<i64> = None;
    for member in &required {
        let Some(record) = read_checkpoint(
            client,
            &stream_identity,
            stream_epoch,
            &member.receiver_identity,
            member.membership_generation,
        )
        .await?
        else {
            return Ok(Err(EvaluationBlock::MissingCheckpoint {
                receiver_identity: member.receiver_identity.clone(),
                membership_generation: member.membership_generation,
            }));
        };
        // The minimum, not the maximum. One lagging member holds every row, and
        // a blocker has already been reflected in that member's frontier by
        // `report_checkpoint`, which refuses a frontier that passed one.
        safe_sequence = Some(match safe_sequence {
            Some(held) => held.min(record.contiguous_frontier),
            None => record.contiguous_frontier,
        });
    }

    let Some(safe_sequence) = safe_sequence else {
        // Unreachable while `safety_block` refuses an empty required set. Kept
        // as an explicit block rather than a `0` default, because a zero safe
        // sequence would silently mean "sequence 0 is safe" on a store whose
        // sequences start at 0.
        return Ok(Err(EvaluationBlock::Membership(
            SafetyBlock::EmptyRequiredMembership,
        )));
    };

    Ok(Ok(SafeVector {
        membership_version: snapshot.state.membership_version,
        stream_identity,
        stream_epoch,
        safe_sequence,
        required_members: required.len(),
    }))
}

/// Take the share lock every safety evaluation runs under.
///
/// Returns `false` when the cell has no membership state row.
pub(super) async fn lock_membership_for_read(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<bool, DomainError> {
    let row = client
        .query_opt(
            "SELECT cell_id FROM lore_outbox_membership_state WHERE cell_id = $1 FOR SHARE",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox membership share lock", e))?;
    Ok(row.is_some())
}

/// Advance up to `batch` accepted rows to `consumer_safe`.
///
/// One bounded transaction: take the share lock, prove the vector, move at most
/// `batch` rows at or below the proven safe sequence, commit. A tick that proves
/// nothing writes nothing and reports why.
///
/// `batch` is clamped to [`MAX_EVALUATION_BATCH`] rather than rejected: the
/// bound is a property of the transaction this function owns, and a caller
/// asking for more is asking for something this function is not allowed to do,
/// not making an error.
pub async fn evaluate_consumer_safe(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    batch: i64,
) -> Result<EvaluationOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    if batch < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox evaluation batch must be >= 1, got {batch}"
        )));
    }
    let batch = batch.min(MAX_EVALUATION_BATCH);

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox evaluation begin", e))?;

    if !lock_membership_for_read(&*tx, cell_id).await? {
        drop(tx);
        return Ok(EvaluationOutcome::blocked(EvaluationBlock::CellUnknown));
    }

    let proven = match prove_safe_vector(&*tx, cell_id).await? {
        Ok(proven) => proven,
        Err(block) => {
            drop(tx);
            return Ok(EvaluationOutcome::blocked(block));
        }
    };

    // `state = 'broker_accepted'` written as a SQL literal in both halves, so
    // the planner can prove the predicate implies
    // `lore_outbox_events_accepted_sequence`'s partial predicate. A bound
    // parameter returns the same rows and degrades to a sequential scan of the
    // whole table under a generic plan.
    //
    // `SKIP LOCKED` because a row another transaction holds is one this tick
    // must not decide about: the epoch-reset requeue takes a plain `FOR UPDATE`
    // on exactly the rows it is voiding, and waiting for it would mean either
    // blocking the evaluator behind a multi-batch sweep or marking safe a row
    // that sweep is about to return to `pending`. Skipped rows are simply
    // evaluated on the next tick.
    let advanced = tx
        .execute(
            "WITH candidate AS ( \
                 SELECT event_id FROM lore_outbox_events \
                  WHERE state = 'broker_accepted' \
                    AND cell_id = $1 \
                    AND stream_identity = $2 \
                    AND stream_epoch = $3 \
                    AND broker_sequence <= $4 \
                  ORDER BY broker_sequence \
                  LIMIT $5 \
                  FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE lore_outbox_events AS event SET state = 'consumer_safe' \
               FROM candidate \
              WHERE event.event_id = candidate.event_id \
                AND event.state = 'broker_accepted'",
            &[
                &cell_id,
                &proven.stream_identity,
                &proven.stream_epoch,
                &proven.safe_sequence,
                &batch,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox consumer safe advance", e))?;

    classify_commit(tx.commit().await, "outbox evaluation commit")?;
    Ok(EvaluationOutcome {
        advanced,
        proven: Some(proven),
        block: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blocked_tick_moves_nothing_and_names_the_reason() {
        let outcome = EvaluationOutcome::blocked(EvaluationBlock::Membership(
            SafetyBlock::EmptyRequiredMembership,
        ));
        assert_eq!(outcome.advanced, 0);
        assert!(outcome.proven.is_none());
        assert_eq!(
            outcome.block,
            Some(EvaluationBlock::Membership(
                SafetyBlock::EmptyRequiredMembership
            ))
        );
    }

    /// The batch bound is a property of the transaction, so a caller asking for
    /// more gets the bound rather than an error.
    #[test]
    fn the_batch_is_clamped_not_rejected() {
        assert_eq!(10_000_i64.min(MAX_EVALUATION_BATCH), MAX_EVALUATION_BATCH);
        assert_eq!(50_i64.min(MAX_EVALUATION_BATCH), 50);
    }

    #[test]
    fn the_evaluation_bound_is_cr_032s_thousand_rows() {
        assert_eq!(MAX_EVALUATION_BATCH, 1_000);
    }
}

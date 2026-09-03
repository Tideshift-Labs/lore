// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's bounded retention pruning (WP-119 Step C, Phase 8's retention half).
//!
//! Reapability needs **two** independent proofs, and this module refuses to
//! delete a row that has only one:
//!
//! 1. the minimum retention age has elapsed ([`MIN_RETENTION_AGE`]), and
//! 2. a consistent checkpoint vector proves every required *current* receiver
//!    generation safe at the cell's *current* placement.
//!
//! `consumer_safe` is correctness history, not a deletion trigger. A row that
//! was safe under a membership that has since changed is not reapable, so this
//! re-proves the vector at prune time through
//! [`super::evaluator::prove_safe_vector`] rather than trusting the state
//! column the evaluator wrote earlier.
//!
//! Every block CR-032 names therefore falls out of that one re-proof: a lagging
//! member holds the minimum down, a dead-but-not-safely-retired member is still
//! in the required set, a replacement without a baseline has no checkpoint at
//! the current placement, a gap or poison disposition has already held its own
//! reporter's frontier back, and a reset fence blocks the snapshot outright.
//! None of them is a separate condition this file has to remember.
//!
//! **Pending rows are never age-pruned.** They are unpublished work, and age is
//! evidence the relay is behind rather than evidence the row is finished.
//! Nothing here can match one: every statement spells `state = 'consumer_safe'`
//! literally.

use std::time::Duration;

use crate::domain::errors::DomainError;
use crate::domain::outbox::evaluator::EvaluationBlock;
use crate::domain::outbox::evaluator::SafeVector;
use crate::domain::outbox::evaluator::lock_membership_for_read;
use crate::domain::outbox::evaluator::prove_safe_vector;
use crate::domain::outbox::membership::validate_cell_id;
use crate::domain::retry::classify_commit;

/// CR-032's replay window: broker-accepted and consumer-safe rows stay
/// replayable for at least seven days.
pub const MIN_RETENTION_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// CR-032's dead-letter floor: at least thirty days, and never deleted without
/// an operator disposition and an exported incident reference.
pub const MIN_DEAD_LETTER_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// CR-032's bound: "Prune transactions contain at most 1,000 rows."
pub const MAX_PRUNE_BATCH: i64 = 1_000;

/// The result of one bounded prune transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneOutcome {
    /// Rows deleted by this transaction.
    pub deleted: u64,
    /// What the vector proved, when it proved anything.
    pub proven: Option<SafeVector>,
    /// Why nothing was deleted.
    pub block: Option<EvaluationBlock>,
}

impl PruneOutcome {
    fn blocked(block: EvaluationBlock) -> Self {
        Self {
            deleted: 0,
            proven: None,
            block: Some(block),
        }
    }
}

/// Reject a retention age below the floor CR-032 fixes.
///
/// A caller asking for a shorter window is asking to violate the replay
/// guarantee, which is not something a parameter may quietly do — unlike the
/// evaluator's batch size, which is clamped because a caller asking for a
/// larger one is asking for something the transaction bound simply will not do.
fn validate_age(label: &str, requested: Duration, floor: Duration) -> Result<(), DomainError> {
    if requested < floor {
        return Err(DomainError::InvalidInput(format!(
            "outbox {label} retention age {requested:?} is below CR-032's floor of {floor:?}; \
             widening the window is a reviewed change, not a parameter"
        )));
    }
    Ok(())
}

/// Delete up to `batch` reapable `consumer_safe` rows for one cell.
///
/// One bounded transaction, and a caller that wants more calls again: that is
/// what keeps the transaction inside CR-032's thousand-row bound and keeps a
/// long delete from blocking the relay's own claim path on the same table.
///
/// The safe sequence is re-proved here rather than assumed. A row is deleted
/// only when it is at or below every required current receiver generation's
/// frontier **at the cell's current placement**, so a membership change since
/// the row was marked safe holds it rather than releasing it.
///
/// # Rows published under a superseded epoch
///
/// A `consumer_safe` row whose stream identity or epoch is not the cell's
/// current one is deliberately **not** matched. After an accepted reset the
/// current receivers took a fresh authoritative baseline, so those rows are very
/// probably reapable — but "very probably" is the wrong standard for a delete,
/// and proving it needs the accepted-transition chain in
/// `lore_outbox_reset_generations` rather than an epoch comparison. Until that
/// lands the rows are retained, which fails toward keeping evidence rather than
/// toward losing it.
///
/// TODO(WP-119 Phase 8): reap superseded-epoch rows by walking the accepted
/// reset chain for the cell, requiring each transition to be `cleared` and its
/// replacement generation to carry a checkpoint at the successor placement.
pub async fn prune_consumer_safe(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    min_age: Duration,
    batch: i64,
) -> Result<PruneOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    validate_age("consumer-safe", min_age, MIN_RETENTION_AGE)?;
    if batch < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox prune batch must be >= 1, got {batch}"
        )));
    }
    let batch = batch.min(MAX_PRUNE_BATCH);
    let age_seconds = age_seconds(min_age)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox prune begin", e))?;

    if !lock_membership_for_read(&*tx, cell_id).await? {
        drop(tx);
        return Ok(PruneOutcome::blocked(EvaluationBlock::CellUnknown));
    }
    let proven = match prove_safe_vector(&*tx, cell_id).await? {
        Ok(proven) => proven,
        Err(block) => {
            drop(tx);
            return Ok(PruneOutcome::blocked(block));
        }
    };

    // `state = 'consumer_safe'` as a SQL literal in both halves, so the planner
    // can prove the predicate implies `lore_outbox_events_safe_retention`'s
    // partial predicate — and so no spelling of this statement can ever reach a
    // `pending` row.
    //
    // `clock_timestamp()`, not `now()`: `now()` is the transaction start time,
    // and a prune loop calling this repeatedly inside one long-lived session
    // would compare every batch against the same instant.
    let deleted = tx
        .execute(
            "WITH candidate AS ( \
                 SELECT event_id FROM lore_outbox_events \
                  WHERE state = 'consumer_safe' \
                    AND cell_id = $1 \
                    AND stream_identity = $2 \
                    AND stream_epoch = $3 \
                    AND broker_sequence <= $4 \
                    AND created_at < clock_timestamp() - ($5 * interval '1 second') \
                  ORDER BY created_at, event_id \
                  LIMIT $6 \
                  FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM lore_outbox_events AS event \
              USING candidate \
              WHERE event.event_id = candidate.event_id \
                AND event.state = 'consumer_safe'",
            &[
                &cell_id,
                &proven.stream_identity,
                &proven.stream_epoch,
                &proven.safe_sequence,
                &age_seconds,
                &batch,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox prune delete", e))?;

    classify_commit(tx.commit().await, "outbox prune commit")?;
    Ok(PruneOutcome {
        deleted,
        proven: Some(proven),
        block: None,
    })
}

/// Delete up to `batch` dead letters that an operator has already disposed of
/// and that are past the thirty-day floor.
///
/// A `parked` row is never matched: CR-032 is explicit that a dead letter is
/// never deleted without an operator disposition and an exported incident
/// reference. Age alone does not dispose of one, and this function cannot be
/// asked to pretend otherwise — the disposition predicate is a literal.
///
/// The age is measured from `disposition_at`, not from `last_failed_at`: the
/// thirty days are recovery time after the decision, and measuring from the
/// failure would let a row disposed of on day twenty-nine leave the next day.
pub async fn prune_dead_letters(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    min_age: Duration,
    batch: i64,
) -> Result<u64, DomainError> {
    validate_cell_id(cell_id)?;
    validate_age("dead-letter", min_age, MIN_DEAD_LETTER_RETENTION)?;
    if batch < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox dead-letter prune batch must be >= 1, got {batch}"
        )));
    }
    let batch = batch.min(MAX_PRUNE_BATCH);
    let age_seconds = age_seconds(min_age)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox dead letter prune begin", e))?;
    let deleted = tx
        .execute(
            "WITH candidate AS ( \
                 SELECT event_id FROM lore_outbox_dead_letters \
                  WHERE cell_id = $1 \
                    AND disposition <> 'parked' \
                    AND disposition_at IS NOT NULL \
                    AND disposition_at < clock_timestamp() - ($2 * interval '1 second') \
                  ORDER BY disposition_at, event_id \
                  LIMIT $3 \
                  FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM lore_outbox_dead_letters AS dead \
              USING candidate \
              WHERE dead.event_id = candidate.event_id \
                AND dead.disposition <> 'parked'",
            &[&cell_id, &age_seconds, &batch],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox dead letter prune delete", e))?;
    classify_commit(tx.commit().await, "outbox dead letter prune commit")?;
    Ok(deleted)
}

/// Turn a retention window into the `double precision` seconds the SQL
/// multiplies by `interval '1 second'`, refusing one that cannot be
/// represented.
fn age_seconds(age: Duration) -> Result<f64, DomainError> {
    let seconds = age.as_secs_f64();
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox retention age must be a positive finite duration, got {seconds}s"
        )));
    }
    Ok(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_floors_are_cr_032s() {
        assert_eq!(MIN_RETENTION_AGE, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(
            MIN_DEAD_LETTER_RETENTION,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
        assert_eq!(MAX_PRUNE_BATCH, 1_000);
    }

    /// A shorter window is refused rather than clamped. Silently widening the
    /// reap window is exactly the failure CR-032 names.
    #[test]
    fn a_window_below_the_floor_is_refused() {
        assert!(validate_age("consumer-safe", MIN_RETENTION_AGE, MIN_RETENTION_AGE).is_ok());
        assert!(
            validate_age(
                "consumer-safe",
                MIN_RETENTION_AGE - Duration::from_secs(1),
                MIN_RETENTION_AGE,
            )
            .is_err()
        );
        assert!(
            validate_age("dead-letter", MIN_RETENTION_AGE, MIN_DEAD_LETTER_RETENTION).is_err(),
            "seven days must not satisfy the thirty-day dead-letter floor"
        );
    }

    /// A longer window is always allowed: retaining more is never the unsafe
    /// direction.
    #[test]
    fn a_longer_window_is_allowed() {
        assert!(validate_age("consumer-safe", MIN_RETENTION_AGE * 4, MIN_RETENTION_AGE,).is_ok());
    }

    #[test]
    fn a_retention_window_converts_to_finite_seconds() {
        assert_eq!(
            age_seconds(MIN_RETENTION_AGE).expect("seven days is representable"),
            604_800.0
        );
        assert!(age_seconds(Duration::ZERO).is_err());
    }

    #[test]
    fn a_blocked_prune_deletes_nothing_and_names_the_reason() {
        let outcome = PruneOutcome::blocked(EvaluationBlock::CellUnknown);
        assert_eq!(outcome.deleted, 0);
        assert!(outcome.proven.is_none());
        assert_eq!(outcome.block, Some(EvaluationBlock::CellUnknown));
    }
}

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
//!
//! # Two reapers, one proof each
//!
//! [`prune_consumer_safe`] reaps rows at the cell's **current** placement, and
//! its proof is the required set's contiguous frontier.
//! [`prune_superseded_epochs`] reaps rows at a placement the cell has **left**,
//! and its proof is an unbroken chain of `cleared` reset transitions leading
//! from that placement to the current one. Neither proof works on the other's
//! rows, which is why this is two functions and not one predicate: a superseded
//! placement's broker sequences are not comparable to the current placement's,
//! and the current placement has no completed transition away from it to walk.

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

/// How far back [`prune_superseded_epochs`] walks the accepted reset chain.
///
/// A bound rather than a guard against a specific shape. Nothing in the schema
/// forbids a cycle across a whole chain — the per-row successor check only
/// refuses a successor equal to its own predecessor — so an unbounded recursive
/// walk is a statement that runs until the statement timeout. Sixty-four is far
/// beyond any plausible reset history for one cell: a cell that has reset its
/// broker sixty-four times has an operational problem this reaper is not the
/// place to discover. Reaching the bound reaps less, never more, so the failure
/// direction is retention.
pub const MAX_RESET_CHAIN_DEPTH: i32 = 64;

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

/// The result of one bounded superseded-epoch prune transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupersededPruneOutcome {
    /// Rows deleted by this transaction.
    pub deleted: u64,
    /// The cell's current authoritative placement, when one was proven. This is
    /// the walk's starting point, not a frontier the delete used.
    pub current: Option<SafeVector>,
    /// How many superseded placements the cleared-transition chain admitted.
    /// Zero means the cell has no finished reset behind it, which is the
    /// ordinary case and is not a block.
    pub superseded_placements: u64,
    /// Why nothing could be proven. Distinct from `superseded_placements == 0`,
    /// which is a proven answer that admitted nothing.
    pub block: Option<EvaluationBlock>,
}

impl SupersededPruneOutcome {
    fn blocked(block: EvaluationBlock) -> Self {
        Self {
            deleted: 0,
            current: None,
            superseded_placements: 0,
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
/// current one is deliberately **not** matched here, because this function's
/// proof is a frontier comparison and a superseded epoch's sequences are a
/// different sequence space: `broker_sequence <= safe_sequence` would be
/// comparing two unrelated numbers. Those rows are reaped by
/// [`prune_superseded_epochs`], which proves them a different way.
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

/// Delete up to `batch` `consumer_safe` rows that were published under a
/// placement the cell has since left, for one cell.
///
/// # Why this cannot be an epoch comparison
///
/// "Not the current epoch" is not evidence of anything. A row could carry a
/// foreign epoch because the cell reset past it, or because it was written by a
/// defective producer, or because a stream identity was reused. Only the first
/// is reapable, and the difference is not visible in the row.
///
/// So the proof is the accepted-transition chain in
/// `lore_outbox_reset_generations`, walked **backwards from the cell's current
/// authoritative placement**. A placement is admitted only when an unbroken run
/// of `cleared` transitions leads from it to the placement
/// [`prove_safe_vector`] just proved. Walking backwards rather than forwards is
/// what makes that an admission rather than an inference: the walk starts at
/// authoritative current state, and a tuple nothing leads from is never reached,
/// so a stray or forged epoch on a row can never be admitted by it.
///
/// `cleared` is the load-bearing word, and it is worth being exact about what
/// the write actually proves rather than about what the contract's prose
/// promises. The only writer is [`super::membership::readiness_cas`], which
/// clears the fence when a generation proves a fresh checkpoint at the new
/// epoch and no receiver in the cell is still stranded on a retired generation.
/// That stranded probe accepts a successor row in any non-`retired` state, so a
/// `cleared` hop proves that one replacement generation passed readiness
/// CAS at the new epoch and that no retired receiver was left without a
/// successor **row**. It does not by itself prove every current member has a
/// baseline: a `joining` member with no capture satisfies that probe.
///
/// The missing half is carried by the vector proof that runs before the walk,
/// rather than restated here. Such a
/// member is in `required_members`, so [`prove_safe_vector`] blocks with
/// `MemberNotReady` and this function deletes nothing. The two together are the
/// proof; neither is it alone, and reading the chain walk as though `cleared`
/// carried all of it would be believing something the write does not say.
///
/// In practice an in-progress hop never gets as far as the walk, and it is worth
/// being exact about why rather than leaving it to look like a chain property.
/// The fence `prove_safe_vector` reads is **cell-wide**: any
/// `reset_in_progress` row for the cell blocks the whole evaluation in step 2
/// above, so nothing is reaped anywhere, not merely behind that hop. And
/// `lore_outbox_reset_generations_fence` — the partial unique index on
/// `(cell_id) WHERE state = 'reset_in_progress'` — allows at most one such row
/// per cell, which can only be the most recent transition. So the walk's
/// `state = 'cleared'` predicate is not what handles an unfinished reset; it
/// handles a *missing* transition, which is the case that makes the walk an
/// admission: a tuple no cleared chain reaches is never reapable, and there is
/// no fence anywhere to notice it. Both behaviours are pinned separately in
/// `lore-postgres/tests/domain_outbox_prune.rs`.
///
/// # What still holds a row
///
/// Everything that holds [`prune_consumer_safe`] holds this too, because it runs
/// the same [`prove_safe_vector`] first: an in-progress reset fence, an empty or
/// lagging required membership, a missing checkpoint, an unknown cell. The
/// seven-day retention floor applies unchanged and is measured the same way. The
/// only thing that differs is which rows the proof then releases.
///
/// Note that no frontier bound appears in the delete. That is deliberate and is
/// the one real asymmetry with [`prune_consumer_safe`]: a superseded placement's
/// `broker_sequence` values are not comparable to the current placement's, and
/// the replacement generation's authoritative baseline — not a sequence — is
/// what makes the old rows redundant. Restricting by the current frontier here
/// would look like extra safety and would in fact be an arbitrary filter over an
/// unrelated number.
///
/// The positive argument matters more than that negative one: the `consumer_safe`
/// stamp already **is** the old placement's frontier proof. Only the evaluator
/// writes that state, and only for rows at the placement that was current when
/// it ran, so a row carrying it was proven safe against the required set at the
/// placement it names. No later evaluator run can re-stamp a row at a placement
/// the cell has left. Re-applying the current placement's frontier to it would
/// not re-prove anything; it would discard a proof already made.
pub async fn prune_superseded_epochs(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    min_age: Duration,
    batch: i64,
) -> Result<SupersededPruneOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    validate_age("superseded-epoch", min_age, MIN_RETENTION_AGE)?;
    if batch < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox superseded-epoch prune batch must be >= 1, got {batch}"
        )));
    }
    let batch = batch.min(MAX_PRUNE_BATCH);
    let age_seconds = age_seconds(min_age)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox superseded prune begin", e))?;

    if !lock_membership_for_read(&*tx, cell_id).await? {
        drop(tx);
        return Ok(SupersededPruneOutcome::blocked(
            EvaluationBlock::CellUnknown,
        ));
    }
    let current = match prove_safe_vector(&*tx, cell_id).await? {
        Ok(proven) => proven,
        Err(block) => {
            drop(tx);
            return Ok(SupersededPruneOutcome::blocked(block));
        }
    };

    // The backward walk. `UNION` rather than `UNION ALL` so a repeated tuple at
    // one depth is not re-expanded, and `depth < $4` so a cycle -- which the
    // per-row successor check cannot rule out across a whole chain -- terminates
    // at a bound instead of running until the statement timeout. The final
    // `DISTINCT` collapses a tuple reachable at two depths, and the
    // `IS DISTINCT FROM` drops the current placement if a cycle reintroduced it:
    // current-placement rows belong to `prune_consumer_safe`'s frontier proof,
    // not to this one.
    let chain = tx
        .query(
            "WITH RECURSIVE chain(identity, epoch, depth) AS ( \
                     SELECT $2::text, $3::bigint, 0 \
                   UNION \
                     SELECT reset.old_stream_identity, reset.old_stream_epoch, chain.depth + 1 \
                       FROM lore_outbox_reset_generations AS reset \
                       JOIN chain ON reset.new_stream_identity = chain.identity \
                                 AND reset.new_stream_epoch = chain.epoch \
                      WHERE reset.cell_id = $1 \
                        AND reset.state = 'cleared' \
                        AND chain.depth < $4 \
             ) \
             SELECT DISTINCT identity, epoch FROM chain \
              WHERE depth > 0 \
                AND (identity, epoch) IS DISTINCT FROM ($2::text, $3::bigint)",
            &[
                &cell_id,
                &current.stream_identity,
                &current.stream_epoch,
                &MAX_RESET_CHAIN_DEPTH,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox superseded chain walk", e))?;

    let identities: Vec<String> = chain.iter().map(|row| row.get("identity")).collect();
    let epochs: Vec<i64> = chain.iter().map(|row| row.get("epoch")).collect();
    let superseded_placements = u64::try_from(identities.len()).unwrap_or(u64::MAX);
    if identities.is_empty() {
        // No accepted, cleared transition leads to the current placement, so
        // this cell has never reset or its reset is not finished. Commit rather
        // than roll back: the membership read took a lock the evaluator also
        // wants, and holding it for an aborted transaction buys nothing.
        classify_commit(tx.commit().await, "outbox superseded prune commit")?;
        return Ok(SupersededPruneOutcome {
            deleted: 0,
            current: Some(current),
            superseded_placements: 0,
            block: None,
        });
    }

    // `state = 'consumer_safe'` as a literal in both halves, exactly as in
    // `prune_consumer_safe`, so `lore_outbox_events_safe_retention` is usable
    // and so no spelling of this statement can reach a `pending` row. The
    // ordering matches that index's `(created_at, event_id)` for the same
    // reason. `clock_timestamp()`, not `now()`, so a loop calling this
    // repeatedly in one session does not compare every batch against the
    // transaction's start instant.
    let deleted = tx
        .execute(
            "WITH candidate AS ( \
                 SELECT event_id FROM lore_outbox_events \
                  WHERE state = 'consumer_safe' \
                    AND cell_id = $1 \
                    AND (stream_identity, stream_epoch) IN ( \
                          SELECT identity, epoch \
                            FROM unnest($2::text[], $3::bigint[]) AS t(identity, epoch) \
                        ) \
                    AND created_at < clock_timestamp() - ($4 * interval '1 second') \
                  ORDER BY created_at, event_id \
                  LIMIT $5 \
                  FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM lore_outbox_events AS event \
              USING candidate \
              WHERE event.event_id = candidate.event_id \
                AND event.state = 'consumer_safe'",
            &[&cell_id, &identities, &epochs, &age_seconds, &batch],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox superseded prune delete", e))?;

    classify_commit(tx.commit().await, "outbox superseded prune commit")?;
    Ok(SupersededPruneOutcome {
        deleted,
        current: Some(current),
        superseded_placements,
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

    /// A blocked superseded-epoch prune carries no proven current placement and
    /// no admitted count -- distinct from a proven answer that happens to admit
    /// zero placements, which carries `Some(current)` and `block: None`. See
    /// [`SupersededPruneOutcome::block`]'s doc comment.
    #[test]
    fn a_blocked_superseded_prune_deletes_nothing_names_the_reason_and_proves_no_placement() {
        let outcome = SupersededPruneOutcome::blocked(EvaluationBlock::CellUnknown);
        assert_eq!(outcome.deleted, 0);
        assert!(outcome.current.is_none());
        assert_eq!(outcome.superseded_placements, 0);
        assert_eq!(outcome.block, Some(EvaluationBlock::CellUnknown));
    }

    #[test]
    fn the_reset_chain_walk_is_bounded_at_sixty_four() {
        assert_eq!(MAX_RESET_CHAIN_DEPTH, 64);
    }
}

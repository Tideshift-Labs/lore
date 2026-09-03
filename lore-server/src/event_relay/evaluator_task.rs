// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The bounded `consumer_safe` evaluator loop and its retention sweep
//! (WP-119 Step C).
//!
//! One task per Postgres-mode loreserver, running beside the relay worker on the
//! same readiness probe interval. Each tick does at most two bounded
//! transactions: advance accepted rows the checkpoint vector proves safe, then
//! reap rows that are both past the retention floor and still proven safe.
//!
//! # Why it is a separate task from the worker
//!
//! The relay worker's tick is dominated by one network publish with its own
//! deadline. Folding the evaluation into it would make the safety verdict wait
//! on the broker — the exact coupling CR-032 separates `broker_accepted` from
//! `consumer_safe` to avoid. Two tasks on one pool cost one more connection and
//! keep the two facts independent.
//!
//! # Nothing here decides safety
//!
//! Every verdict comes from `lore_postgres`'s evaluator, under a share lock on
//! the cell's membership counters. This task chooses *when* to ask and what to
//! log; it cannot make a row safe, and it cannot make one reapable.

use std::sync::Arc;
use std::time::Duration;

use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::SafetyBlock;
use lore_postgres::domain::outbox::evaluate_consumer_safe;
use lore_postgres::domain::outbox::evaluator::MAX_EVALUATION_BATCH;
use lore_postgres::domain::outbox::prune::MAX_PRUNE_BATCH;
use lore_postgres::domain::outbox::prune::MIN_DEAD_LETTER_RETENTION;
use lore_postgres::domain::outbox::prune::MIN_RETENTION_AGE;
use lore_postgres::domain::outbox::prune_consumer_safe;
use lore_postgres::domain::outbox::prune_dead_letters;
use lore_postgres::pool::Pool;
use tokio::sync::watch;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::event_relay::metrics;
use crate::event_relay::readiness::EventRelayReadiness;

/// How many prune transactions one tick may run.
///
/// Retention is a background sweep, not a deadline: a cell with a large reapable
/// backlog drains over several ticks rather than holding one long transaction.
/// Four batches is 4,000 rows a tick, which clears a day of a busy cell's
/// backlog well inside an hour at the shipped probe interval.
const PRUNE_BATCHES_PER_TICK: usize = 4;

/// How often the retention sweep runs relative to the evaluation.
///
/// Retention has a seven-day floor, so running it on every five-second tick
/// would be four orders of magnitude more often than it can possibly matter.
/// Once a minute at the shipped interval.
const PRUNE_EVERY_N_TICKS: u64 = 12;

/// The evaluator and retention loop.
pub struct ConsumerSafetyTask {
    pool: Pool,
    cell_id: String,
    interval: Duration,
    readiness: Arc<EventRelayReadiness>,
}

impl std::fmt::Debug for ConsumerSafetyTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsumerSafetyTask")
            .field("cell_id", &self.cell_id)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl ConsumerSafetyTask {
    /// Build the loop for one cell.
    pub fn new(
        pool: Pool,
        cell_id: String,
        interval: Duration,
        readiness: Arc<EventRelayReadiness>,
    ) -> Self {
        Self {
            pool,
            cell_id,
            interval,
            readiness,
        }
    }

    /// Run until shutdown.
    ///
    /// Never returns an error: a database failure is a transient condition this
    /// loop retries on the next tick, and returning would take the whole
    /// endpoint `JoinSet` down with it. What a failure does do is stop
    /// refreshing the receiver facet, which then goes stale and reports not
    /// ready — the same fail-closed-on-silence rule the relay facet uses.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        info!(
            cell_id = %self.cell_id,
            interval_ms = self.interval.as_millis(),
            "CR-032 consumer-safety evaluator started"
        );
        let mut ticks: u64 = 0;
        loop {
            tokio::select! {
                _ = shutdown.wait_for(|stop| *stop) => break,
                () = tokio::time::sleep(self.interval) => {}
            }
            ticks = ticks.wrapping_add(1);
            self.tick(ticks).await;
        }
        info!(cell_id = %self.cell_id, "CR-032 consumer-safety evaluator stopped");
        Ok(())
    }

    async fn tick(&self, ticks: u64) {
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(error) => {
                warn!(
                    %error,
                    cell_id = %self.cell_id,
                    "the consumer-safety evaluator could not take a connection this tick"
                );
                return;
            }
        };

        match evaluate_consumer_safe(&mut client, &self.cell_id, MAX_EVALUATION_BATCH).await {
            Ok(outcome) => {
                if let Some(block) = outcome.block.as_ref() {
                    metrics::record_evaluation_block(block_label(block));
                    self.readiness.record_receiver_block(block_label(block));
                    debug!(
                        cell_id = %self.cell_id,
                        reason = block_label(block),
                        "the consumer-safety evaluator proved nothing this tick"
                    );
                } else if let Some(proven) = outcome.proven.as_ref() {
                    metrics::record_consumer_safe_rows(outcome.advanced);
                    self.readiness
                        .record_receiver_proof(proven.required_members);
                    if outcome.advanced > 0 {
                        info!(
                            cell_id = %self.cell_id,
                            advanced = outcome.advanced,
                            safe_sequence = proven.safe_sequence,
                            required_members = proven.required_members,
                            "advanced outbox rows to consumer_safe"
                        );
                    }
                }
            }
            Err(error) => {
                warn!(
                    %error,
                    cell_id = %self.cell_id,
                    "the consumer-safety evaluation failed this tick"
                );
                return;
            }
        }

        if !ticks.is_multiple_of(PRUNE_EVERY_N_TICKS) {
            return;
        }
        // TODO(WP-119 Phase 8): this is the whole scheduler. An operator command
        // calls the same `prune_consumer_safe` directly, and a cell needing a
        // faster drain than four batches a minute needs a real schedule rather
        // than a larger constant here.
        let mut reaped = 0_u64;
        for _ in 0..PRUNE_BATCHES_PER_TICK {
            match prune_consumer_safe(
                &mut client,
                &self.cell_id,
                MIN_RETENTION_AGE,
                MAX_PRUNE_BATCH,
            )
            .await
            {
                Ok(outcome) => {
                    reaped = reaped.saturating_add(outcome.deleted);
                    // A blocked or empty batch means there is nothing more to do
                    // this tick, and continuing would re-prove the same vector
                    // three more times for nothing.
                    if outcome.deleted == 0 {
                        break;
                    }
                }
                Err(error) => {
                    warn!(
                        %error,
                        cell_id = %self.cell_id,
                        "retention pruning failed this tick"
                    );
                    break;
                }
            }
        }
        if reaped > 0 {
            metrics::record_pruned_rows(metrics::PRUNED_EVENTS, reaped);
            info!(
                cell_id = %self.cell_id,
                reaped,
                "reaped consumer-safe outbox rows past the retention floor"
            );
        }

        // Dead letters are swept on the same cadence but under their own rule:
        // only rows an operator has already disposed of, and only past the
        // thirty-day floor. A parked row is never matched, so this can never
        // clear an incident nobody decided on.
        //
        // One batch a sweep rather than four. The disposed set is bounded by how
        // often an operator acts, which is orders of magnitude below the event
        // volume the consumer-safe sweep drains.
        match prune_dead_letters(
            &mut client,
            &self.cell_id,
            MIN_DEAD_LETTER_RETENTION,
            MAX_PRUNE_BATCH,
        )
        .await
        {
            Ok(0) => {}
            Ok(deleted) => {
                metrics::record_pruned_rows(metrics::PRUNED_DEAD_LETTERS, deleted);
                info!(
                    cell_id = %self.cell_id,
                    deleted,
                    "reaped dispositioned dead letters past the thirty-day floor"
                );
            }
            Err(error) => {
                warn!(
                    %error,
                    cell_id = %self.cell_id,
                    "dead-letter pruning failed this tick"
                );
            }
        }
    }
}

/// The bounded metric label for one evaluation block.
///
/// The only place `EvaluationBlock` and the metric label set are related, so a
/// new variant is a compile error here rather than a silently unlabelled
/// increment. That is why the match is exhaustive with no wildcard arm.
pub(crate) fn block_label(block: &EvaluationBlock) -> &'static str {
    match block {
        EvaluationBlock::CellUnknown => metrics::BLOCK_CELL_UNKNOWN,
        EvaluationBlock::MissingCheckpoint { .. } => metrics::BLOCK_MISSING_CHECKPOINT,
        EvaluationBlock::Membership(membership) => match membership {
            SafetyBlock::ResetInProgress => metrics::BLOCK_RESET_IN_PROGRESS,
            SafetyBlock::NoCurrentPlacement => metrics::BLOCK_NO_PLACEMENT,
            SafetyBlock::EmptyRequiredMembership => metrics::BLOCK_EMPTY_MEMBERSHIP,
            SafetyBlock::MemberNotReady { .. } => metrics::BLOCK_MEMBER_NOT_READY,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_evaluation_block_has_its_own_label() {
        let blocks = [
            EvaluationBlock::CellUnknown,
            EvaluationBlock::MissingCheckpoint {
                receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
                membership_generation: 4,
            },
            EvaluationBlock::Membership(SafetyBlock::ResetInProgress),
            EvaluationBlock::Membership(SafetyBlock::NoCurrentPlacement),
            EvaluationBlock::Membership(SafetyBlock::EmptyRequiredMembership),
            EvaluationBlock::Membership(SafetyBlock::MemberNotReady {
                receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
                membership_generation: 4,
                state: "joining".to_string(),
            }),
        ];
        let mut labels: Vec<&'static str> = blocks.iter().map(block_label).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            total,
            "two blocks share a label, so two different operator signals merge"
        );
    }

    /// A label never carries a receiver identity or a generation. Those are the
    /// unbounded values CR-032 prohibits, and both blocked variants carry them.
    #[test]
    fn no_label_carries_an_identity() {
        let block = EvaluationBlock::MissingCheckpoint {
            receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
            membership_generation: 4,
        };
        let label = block_label(&block);
        assert!(!label.contains("loreserver"));
        assert!(!label.contains('4'));
        assert_eq!(label, metrics::BLOCK_MISSING_CHECKPOINT);
    }

    #[test]
    fn the_prune_cadence_is_far_below_the_retention_floor() {
        // Sanity on the two constants together: pruning once every twelve
        // five-second ticks is a minute, against a seven-day floor.
        let cadence = Duration::from_secs(5) * PRUNE_EVERY_N_TICKS as u32;
        assert!(cadence < MIN_RETENTION_AGE);
        assert!(cadence < MIN_DEAD_LETTER_RETENTION);
        assert_eq!(cadence, Duration::from_secs(60));
        assert_eq!(PRUNE_BATCHES_PER_TICK * MAX_PRUNE_BATCH as usize, 4_000);
    }
}

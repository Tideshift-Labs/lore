// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The bounded `consumer_safe` evaluator loop (WP-119 Step C).
//!
//! One task per Postgres-mode loreserver, running beside the relay worker on the
//! same readiness probe interval. Each tick is one bounded transaction that
//! advances accepted rows the checkpoint vector proves safe.
//!
//! Retention used to run here too, on a fixed divisor of this tick. WP-119
//! Phase 8 moved it to [`super::prune_task`] so the two cadences are
//! independent and so a drain is not made to wait on a sweep — see that
//! module's own documentation for both reasons.
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
use lore_postgres::pool::Pool;
use tokio::sync::watch;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::event_relay::metrics;
use crate::event_relay::readiness::EventRelayReadiness;

/// The evaluator loop.
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
        loop {
            tokio::select! {
                _ = shutdown.wait_for(|stop| *stop) => break,
                () = tokio::time::sleep(self.interval) => {}
            }
            self.tick().await;
        }
        info!(cell_id = %self.cell_id, "CR-032 consumer-safety evaluator stopped");
        Ok(())
    }

    async fn tick(&self) {
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
                // Nothing follows: the retention sweep this used to fall
                // through to is `super::prune_task`'s since Phase 8. The facet
                // is deliberately left unrefreshed, so a run of failed ticks
                // ages it past the staleness bound and the receiver facet goes
                // false on its own.
                warn!(
                    %error,
                    cell_id = %self.cell_id,
                    "the consumer-safety evaluation failed this tick"
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
}

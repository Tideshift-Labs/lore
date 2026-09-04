// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's retention schedule (WP-119 Phase 8).
//!
//! One task per Postgres-mode loreserver, running beside
//! [`super::evaluator_task`] rather than inside it. Each sweep runs a bounded
//! number of `consumer_safe` prune transactions, then one dead-letter prune
//! transaction, and stops.
//!
//! # Why it is its own task now
//!
//! Step C folded the sweep into the evaluator's tick, on a fixed twelve-tick
//! divisor of the readiness probe interval. That coupled three unrelated
//! cadences: how often safety is evaluated, how often readiness is refreshed,
//! and how often retention runs. A cell that wanted a slower readiness probe got
//! a slower reap for free, and a cell needing a faster drain could only get one
//! by evaluating safety more often. Splitting them makes the retention cadence a
//! reviewed configuration value in its own right, which is what CR-032's
//! "configurable only within reviewed bounds" asks for.
//!
//! It also fixes a real drain defect. The folded sweep ran up to four prune
//! transactions with no shutdown check between them, so a drain arriving mid-
//! sweep waited for the remaining batches. This loop checks the shutdown watch
//! between every transaction and abandons the sweep the moment it is set: a
//! half-finished reap is exactly as correct as a finished one, because every
//! batch commits on its own and nothing here is a multi-step invariant.
//!
//! # Nothing here decides what is reapable
//!
//! [`prune_consumer_safe`] re-proves the checkpoint vector inside its own
//! transaction and deletes only what that proof supports. This task chooses
//! *when* to ask and how many times; it cannot make a row reapable, and it
//! cannot shorten the retention floor — the store refuses a window below
//! CR-032's rather than clamping it.

use std::sync::Arc;

use lore_postgres::domain::outbox::prune_consumer_safe;
use lore_postgres::domain::outbox::prune_dead_letters;
use lore_postgres::pool::Pool;
use tokio::sync::watch;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::event_relay::config::RetentionConfig;
use crate::event_relay::evaluator_task::block_label;
use crate::event_relay::metrics;
use crate::event_relay::readiness::EventRelayReadiness;

/// The retention loop for one cell.
pub struct RetentionTask {
    pool: Pool,
    cell_id: String,
    retention: RetentionConfig,
    readiness: Arc<EventRelayReadiness>,
}

impl std::fmt::Debug for RetentionTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetentionTask")
            .field("cell_id", &self.cell_id)
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

impl RetentionTask {
    /// Build the loop for one cell.
    pub fn new(
        pool: Pool,
        cell_id: String,
        retention: RetentionConfig,
        readiness: Arc<EventRelayReadiness>,
    ) -> Self {
        Self {
            pool,
            cell_id,
            retention,
            readiness,
        }
    }

    /// Run until shutdown.
    ///
    /// Never returns an error, for the same reason the evaluator does not: a
    /// database failure is a transient condition the next sweep retries, and
    /// returning would take the whole endpoint `JoinSet` down with it. A failed
    /// sweep is recorded and reported rather than fatal — retention falling
    /// behind costs disk, and disk is recoverable in a way an endpoint outage
    /// is not.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        info!(
            cell_id = %self.cell_id,
            interval_secs = self.retention.sweep_interval.as_secs(),
            consumer_safe_age_secs = self.retention.consumer_safe_age.as_secs(),
            dead_letter_age_secs = self.retention.dead_letter_age.as_secs(),
            batches_per_sweep = self.retention.batches_per_sweep,
            "CR-032 retention schedule started"
        );
        loop {
            tokio::select! {
                _ = shutdown.wait_for(|stop| *stop) => break,
                () = tokio::time::sleep(self.retention.sweep_interval) => {}
            }
            self.sweep(&mut shutdown).await;
        }
        info!(cell_id = %self.cell_id, "CR-032 retention schedule stopped");
        Ok(())
    }

    /// One bounded sweep: up to `batches_per_sweep` consumer-safe prune
    /// transactions, then one dead-letter transaction.
    ///
    /// `shutdown` is checked before every transaction rather than only between
    /// sweeps. `borrow()` rather than an `await`: this is a non-blocking read of
    /// the current value, so it costs nothing on the common path and cannot
    /// itself delay the drain.
    async fn sweep(&self, shutdown: &mut watch::Receiver<bool>) {
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(error) => {
                warn!(
                    %error,
                    cell_id = %self.cell_id,
                    "the retention sweep could not take a connection"
                );
                metrics::record_prune_sweep(metrics::SWEEP_UNAVAILABLE);
                self.readiness.record_retention_failure();
                return;
            }
        };

        let mut reaped = 0_u64;
        let mut blocked: Option<&'static str> = None;
        let mut drained = false;
        for batch in 0..self.retention.batches_per_sweep {
            if *shutdown.borrow() {
                debug!(
                    cell_id = %self.cell_id,
                    completed_batches = batch,
                    "the retention sweep stopped early for a drain"
                );
                drained = true;
                break;
            }
            match prune_consumer_safe(
                &mut client,
                &self.cell_id,
                self.retention.consumer_safe_age,
                self.retention.batch_rows,
            )
            .await
            {
                Ok(outcome) => {
                    reaped = reaped.saturating_add(outcome.deleted);
                    if let Some(block) = outcome.block.as_ref() {
                        blocked = Some(block_label(block));
                    }
                    // A blocked or empty batch means there is nothing more to do
                    // this sweep, and continuing would re-prove the same vector
                    // for nothing.
                    if outcome.deleted == 0 {
                        break;
                    }
                }
                Err(error) => {
                    warn!(
                        %error,
                        cell_id = %self.cell_id,
                        "retention pruning failed this sweep"
                    );
                    metrics::record_prune_sweep(metrics::SWEEP_FAILED);
                    self.readiness.record_retention_failure();
                    return;
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
        // One transaction a sweep rather than several. The disposed set is
        // bounded by how often an operator acts, which is orders of magnitude
        // below the event volume the consumer-safe sweep drains.
        let mut dead_letters = 0_u64;
        if !*shutdown.borrow() {
            match prune_dead_letters(
                &mut client,
                &self.cell_id,
                self.retention.dead_letter_age,
                self.retention.batch_rows,
            )
            .await
            {
                Ok(0) => {}
                Ok(deleted) => {
                    dead_letters = deleted;
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
                        "dead-letter pruning failed this sweep"
                    );
                    metrics::record_prune_sweep(metrics::SWEEP_FAILED);
                    self.readiness.record_retention_failure();
                    return;
                }
            }
        }

        // A drain-abandoned sweep is reported as such rather than as a
        // completed one: during a rolling restart every sweep is cut short, and
        // labelling those `completed` would read as a run of full sweeps that
        // happened to reap nothing.
        metrics::record_prune_sweep(match (drained, blocked) {
            (true, _) => metrics::SWEEP_DRAINED,
            (false, Some(_)) => metrics::SWEEP_BLOCKED,
            (false, None) => metrics::SWEEP_COMPLETED,
        });
        self.readiness
            .record_retention_sweep(reaped, dead_letters, blocked);
    }
}

#[cfg(test)]
mod tests {
    use lore_postgres::domain::outbox::prune::MAX_PRUNE_BATCH;
    use lore_postgres::domain::outbox::prune::MIN_DEAD_LETTER_RETENTION;
    use lore_postgres::domain::outbox::prune::MIN_RETENTION_AGE;

    use super::*;

    /// The shipped cadence must stay orders of magnitude below the floor it
    /// sweeps against. A sweep interval anywhere near seven days would mean a
    /// reapable row waits most of a second retention window to be reaped.
    #[test]
    fn the_default_cadence_is_far_below_the_retention_floor() {
        let retention = RetentionConfig::default();
        assert!(retention.sweep_interval < MIN_RETENTION_AGE);
        assert!(retention.sweep_interval < MIN_DEAD_LETTER_RETENTION);
        assert_eq!(retention.consumer_safe_age, MIN_RETENTION_AGE);
        assert_eq!(retention.dead_letter_age, MIN_DEAD_LETTER_RETENTION);
        assert_eq!(retention.batch_rows, MAX_PRUNE_BATCH);
    }
}

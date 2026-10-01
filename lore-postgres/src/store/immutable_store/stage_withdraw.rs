// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Withdrawing a staged put's own preparation after a failure or a
//! cancellation before its rename. The boundary itself is
//! [`StageAttempt`]; this module owns the database half and its bounds.
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use tokio::sync::Semaphore;

use crate::domain::DomainError;
use crate::domain::fragments::FragmentIntent;
use crate::domain::fragments::PostgresFragmentCoordinator;
use crate::store::write_behind::StageAttempt;

/// Detached withdrawals one store runs at once for cancelled puts.
///
/// A cancellation burst must not take the domain pool from live traffic. A
/// cancellation over this bound skips its database withdrawal, and its
/// preparation expires at its prepare deadline, which is the behavior
/// without withdrawal.
pub(super) const CANCEL_WITHDRAW_PERMITS: usize = 4;

/// The bound on detached withdrawals, shared by every clone of one store.
#[derive(Clone)]
pub(super) struct CancelWithdrawals {
    permits: Arc<Semaphore>,
    skipped: Arc<AtomicU64>,
}

impl CancelWithdrawals {
    pub(super) fn new(permits: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits)),
            skipped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Cancellations whose database withdrawal was skipped for want of a
    /// permit.
    #[cfg(test)]
    pub(super) fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    /// Take every free permit, so the next cancellation must skip.
    #[cfg(all(test, unix))]
    pub(super) fn exhaust(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let free = u32::try_from(self.permits.available_permits()).ok()?;
        Arc::clone(&self.permits).try_acquire_many_owned(free).ok()
    }

    /// Run `withdraw` on a detached task when a permit is free, and hold the
    /// permit until it finishes. Otherwise count a skip. `true` when spawned.
    fn spawn_or_skip(
        &self,
        epoch: i64,
        withdraw: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            let skipped = self.skipped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(
                epoch,
                skipped,
                "cancelled staged put skipped its withdrawal at the bound; it expires at its prepare deadline"
            );
            return false;
        };
        drop(lore_base::lore_spawn!("stage-withdraw", async move {
            let _permit = permit;
            withdraw.await;
        }));
        true
    }
}

/// How one withdrawal outcome is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WithdrawLog {
    /// Withdrawn; nothing to say.
    Quiet,
    /// The database refused: the head or the row moved, or a conflict. Normal
    /// under concurrency, so `debug`.
    Refused,
    /// The database could not answer: a pool, connection, or unexpected
    /// failure. An operator should see these, so `warn`.
    Failed,
}

fn classify(result: &Result<bool, DomainError>) -> WithdrawLog {
    match result {
        Ok(true) => WithdrawLog::Quiet,
        Ok(false)
        | Err(
            DomainError::Contention(_)
            | DomainError::PreconditionRejected { .. }
            | DomainError::InvalidInput(_)
            | DomainError::NotReady(_)
            | DomainError::DomainKeyBypass(_),
        ) => WithdrawLog::Refused,
        Err(
            DomainError::Transient(_) | DomainError::OutcomeUnknown(_) | DomainError::Internal(_),
        ) => WithdrawLog::Failed,
    }
}

/// Run the database withdrawal and log its outcome. Never returns an error:
/// a failed withdrawal leaves the preparation to its prepare deadline.
async fn withdraw_logged(
    coordinator: &PostgresFragmentCoordinator,
    intent: &FragmentIntent,
    cancelled: bool,
) {
    let result = coordinator.withdraw_stage(intent).await;
    let epoch = intent.epoch;
    match (classify(&result), &result) {
        (WithdrawLog::Failed, Err(error)) => tracing::warn!(
            epoch,
            cancelled,
            %error,
            "staged put could not withdraw its preparation; it expires at its prepare deadline"
        ),
        (WithdrawLog::Refused, Err(error)) => tracing::debug!(
            epoch,
            cancelled,
            %error,
            "staged put could not withdraw its preparation; it expires at its prepare deadline"
        ),
        (WithdrawLog::Refused, Ok(_)) => tracing::debug!(
            epoch,
            cancelled,
            "staged put's preparation moved before its withdrawal; nothing was withdrawn"
        ),
        _ => {}
    }
}

/// Withdraw a staged put's own preparation, when the attempt has not claimed
/// its rename. Best effort: a failed withdrawal leaves the preparation to its
/// prepare deadline, which is the behavior without withdrawal, and never
/// replaces the caller's own error.
pub(super) async fn withdraw_preparation(
    coordinator: &PostgresFragmentCoordinator,
    attempt: &StageAttempt,
    intent: &FragmentIntent,
) {
    if attempt.withdraw() {
        withdraw_logged(coordinator, intent, false).await;
    }
}

/// The cancellation arm of [`withdraw_preparation`]. `Drop` cannot wait, so
/// the database half runs on a detached task, bounded by
/// [`CancelWithdrawals`]. The attempt is marked withdrawn synchronously here,
/// whether or not a permit is free, which is what stops a still-running
/// finalizer from renaming afterwards.
pub(super) struct WithdrawOnDrop {
    pub(super) attempt: StageAttempt,
    pub(super) coordinator: PostgresFragmentCoordinator,
    pub(super) intent: FragmentIntent,
    pub(super) bound: CancelWithdrawals,
}

impl Drop for WithdrawOnDrop {
    fn drop(&mut self) {
        if !self.attempt.withdraw() {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let coordinator = self.coordinator.clone();
        let intent = self.intent.clone();
        self.bound.spawn_or_skip(intent.epoch, async move {
            withdraw_logged(&coordinator, &intent, true).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn refusals_log_at_debug_and_database_failures_at_warn() {
        let cases = [
            (Ok(true), WithdrawLog::Quiet),
            (Ok(false), WithdrawLog::Refused),
            (
                Err(DomainError::Contention("serialization".into())),
                WithdrawLog::Refused,
            ),
            (
                Err(DomainError::Transient("pool timed out".into())),
                WithdrawLog::Failed,
            ),
            (
                Err(DomainError::OutcomeUnknown("connection closed".into())),
                WithdrawLog::Failed,
            ),
            (
                Err(DomainError::Internal("pool closed".into())),
                WithdrawLog::Failed,
            ),
        ];
        for (result, expected) in cases {
            assert_eq!(classify(&result), expected, "{result:?}");
        }
    }

    /// More cancellations than permits: the excess skip and are counted, and
    /// a finished withdrawal frees its permit for the next one.
    #[tokio::test]
    async fn a_cancellation_burst_over_the_bound_skips_and_counts() {
        let bound = CancelWithdrawals::new(2);
        // Closed until released, so the permitted withdrawals stay in flight.
        let gate = Arc::new(Semaphore::new(0));
        let finished = Arc::new(AtomicU64::new(0));
        let spawn = |bound: &CancelWithdrawals| {
            let gate = Arc::clone(&gate);
            let finished = Arc::clone(&finished);
            bound.spawn_or_skip(7, async move {
                drop(gate.acquire().await);
                finished.fetch_add(1, Ordering::Relaxed);
            })
        };
        let spawned = (0..5).filter(|_| spawn(&bound)).count();
        assert_eq!(spawned, 2, "only the permitted withdrawals run");
        assert_eq!(bound.skipped(), 3, "every excess cancellation is counted");
        assert_eq!(finished.load(Ordering::Relaxed), 0);

        gate.add_permits(Semaphore::MAX_PERMITS / 2);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while finished.load(Ordering::Relaxed) < 2 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "withdrawals finished"
            );
            tokio::task::yield_now().await;
        }
        while bound.permits.available_permits() < 2 {
            assert!(tokio::time::Instant::now() < deadline, "permits returned");
            tokio::task::yield_now().await;
        }
        assert!(spawn(&bound), "a freed permit admits the next withdrawal");
        assert_eq!(bound.skipped(), 3);
    }
}

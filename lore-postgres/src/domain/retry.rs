// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Bounded serialization/deadlock retry, and outcome classification (CR-029).
//!
//! **`OutcomeUnknown` is never retried.** That is the whole reason this module
//! exists as a shared helper rather than a loop written per handler. A commit
//! whose acknowledgement was lost may or may not have applied; re-driving it
//! can apply it a second time. Only `Contention` — SQLSTATE 40001 serialization
//! failure and 40P01 deadlock detected — and `Transient` pool/connection
//! failures are safe to re-drive, because in both cases the transaction
//! provably did not commit.
//!
//! The retry is bounded and small. An unbounded server-side loop is what the
//! v0/v1 `BranchPush` handlers do today (worklog 254 §A.4: `branch_push.rs:375`
//! and `:527`, neither with an attempt cap), and it converts sustained
//! contention into an unbounded latency tail rather than an honest error.

use std::time::Duration;

use crate::domain::errors::DomainError;

/// Attempts, including the first. Four total means at most three re-drives.
pub const MAX_ATTEMPTS: u32 = 4;

/// Base backoff. Doubled per attempt, so 5ms, 10ms, 20ms.
pub const BASE_BACKOFF: Duration = Duration::from_millis(5);

/// Run `op` with bounded retry on contention and transient failure.
///
/// `op` must be a closure returning a fresh future each call: a retried
/// transaction is a *new* transaction, never a resumed one.
///
/// Exhausting the attempts returns the last error unchanged rather than a
/// synthetic "retries exhausted" error, so the caller still sees the real
/// SQLSTATE classification and can map it once.
pub async fn with_retry<F, Fut, T>(mut op: F) -> Result<T, DomainError>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, DomainError>>,
{
    let mut attempt = 0;
    loop {
        match op(attempt).await {
            Ok(value) => return Ok(value),
            Err(e) => {
                attempt += 1;
                if attempt >= MAX_ATTEMPTS || !e.is_retryable() {
                    return Err(e);
                }
                let backoff = BASE_BACKOFF * 2u32.saturating_pow(attempt - 1);
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Classify the result of committing a domain transaction.
///
/// A commit that returns an error is not automatically a failed mutation: the
/// database may have committed and lost the acknowledgement. Anything that is
/// not a clean success or a clean pre-commit rejection becomes
/// [`DomainError::OutcomeUnknown`], which the caller must never retry and must
/// never resolve by inspecting later repository, branch, or tombstone state.
///
/// Per CR-029's R-BLOCK-1 correction, that maps outward to gRPC `ABORTED`, whose
/// `From<tonic::Status>` arm is *not* `ProtocolError::Disconnected`.
/// `lore-transport/src/error.rs:22` folds `Unavailable` **and** `Unknown` into
/// `Disconnected`, and `grpc/mod.rs:1177` reissues on exactly that variant — so
/// the codes that read as "outcome unknown" are precisely the two that cause the
/// client to replay.
pub fn classify_commit(
    result: Result<(), tokio_postgres::Error>,
    context: &str,
) -> Result<(), DomainError> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            // A serialization failure or deadlock is detected *before* commit,
            // so the transaction definitively did not apply and re-driving is
            // safe. Everything else at commit time is indeterminate.
            let classified = DomainError::from_pg(context, e);
            match classified {
                DomainError::Contention(msg) => Err(DomainError::Contention(msg)),
                other => Err(DomainError::OutcomeUnknown(format!(
                    "{other}; the commit acknowledgement was not received, so this operation \
                     must not be retried and its outcome must be resolved by receipt lookup"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;

    use super::*;

    #[tokio::test]
    async fn a_successful_first_attempt_does_not_retry() {
        let calls = AtomicU32::new(0);
        let out: Result<u32, DomainError> = with_retry(|_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(7) }
        })
        .await;
        assert_eq!(out.expect("ok"), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn contention_is_retried_up_to_the_bound() {
        let calls = AtomicU32::new(0);
        let out: Result<u32, DomainError> = with_retry(|_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(DomainError::Contention("40001".into())) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn outcome_unknown_is_never_retried() {
        // The load-bearing case: re-driving an indeterminate commit can apply
        // the same mutation twice.
        let calls = AtomicU32::new(0);
        let out: Result<u32, DomainError> = with_retry(|_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(DomainError::OutcomeUnknown("lost ack".into())) }
        })
        .await;
        assert!(matches!(out, Err(DomainError::OutcomeUnknown(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_precondition_rejection_is_never_retried() {
        let calls = AtomicU32::new(0);
        let out: Result<u32, DomainError> = with_retry(|_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err(DomainError::PreconditionRejected {
                    reason: "GENERATION_MISMATCH".into(),
                    reason_version: 1,
                })
            }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_retry_that_eventually_succeeds_returns_the_value() {
        let calls = AtomicU32::new(0);
        let out: Result<u32, DomainError> = with_retry(|attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err(DomainError::Transient("pool".into()))
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(out.expect("ok"), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn the_error_kinds_agree_with_is_retryable() {
        assert!(DomainError::Contention("x".into()).is_retryable());
        assert!(DomainError::Transient("x".into()).is_retryable());
        assert!(!DomainError::OutcomeUnknown("x".into()).is_retryable());
        assert!(!DomainError::NotReady("x".into()).is_retryable());
        assert!(!DomainError::InvalidInput("x".into()).is_retryable());
        assert!(
            !DomainError::PreconditionRejected {
                reason: "x".into(),
                reason_version: 1
            }
            .is_retryable()
        );
    }
}

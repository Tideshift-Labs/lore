// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Dark PostgreSQL implementation of the shared cell-local provider limiter.
//!
//! The authority leases from the same dispatch-runtime pool as the typed authority client. It does
//! not install schema,
//! publish a budget, choose a concrete pin, open a provider route, or become the shipped default.
//! Each call uses one serializable transaction. The database function resolves and validates the
//! current publication, takes the one grant CAS, and debits the shared bucket plus every applicable
//! subordinate cap before this client commits.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio_postgres::IsolationLevel;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use crate::BudgetPin;
use crate::ProviderAttemptClass;
use crate::ProviderCapClass;
use crate::ProviderChargeAuthority;
use crate::ProviderChargeError;
use crate::ProviderChargeGrant;
use crate::ProviderChargeRequest;
use crate::ProviderTrafficClass;
use crate::dispatch_pool::DispatchLease;
use crate::dispatch_pool::DispatchPoolRole;
use crate::dispatch_pool::DispatchRuntimePool;

pub const PROVIDER_CHARGE_API_REVISION_V1: &str = "object-store-dispatch-budget-limiter-v1";

const CHARGE_SQL: &str = "SELECT
  (r).result_code,
  (r).allocation_revision,
  ((r).allocation_fence)::text,
  (r).grant_id,
  (r).traffic_class,
  (r).attempt_class,
  ((r).charged_units)::text,
  (r).logical_request_id,
  (r).attempt_id,
  (r).attempt_ordinal,
  (r).database_now_unix_ms
FROM (SELECT object_store_retention.object_store_dispatch_charge_provider_attempt_v1(
  $1, $2, $3, $4, $5::text::object_store_retention.uint64, $6,
  $7::text::object_store_retention.uint64, $8, $9, $10, $11, $12
) AS r) q";

// Three attempts total: retry after the first two, never after the last.
const MUTATION_RETRY_SCHEDULE: [Option<Duration>; 3] = [
    Some(Duration::from_millis(25)),
    Some(Duration::from_millis(100)),
    None,
];

/// The CD-4 authority over one cell's shared dispatch-runtime pool.
///
/// `UnwiredChargeAuthority` remains the shipped default. Constructing this value is explicit and
/// still does not publish a budget configuration.
pub struct PostgresProviderChargeAuthority {
    pool: Arc<DispatchRuntimePool>,
}

impl PostgresProviderChargeAuthority {
    /// Share the typed client's runtime pool. A maintenance credential fails closed.
    pub fn new(pool: Arc<DispatchRuntimePool>) -> Result<Self, ProviderChargeError> {
        if pool.role() != DispatchPoolRole::Runtime {
            return Err(ProviderChargeError::ConfigurationUnresolved);
        }
        Ok(Self { pool })
    }

    async fn charge_once(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ChargeAttempt, ChargeExecutionError> {
        let mut lease =
            self.pool.acquire().await.map_err(|_| {
                ChargeExecutionError::Public(ProviderChargeError::AuthorityUnavailable)
            })?;
        // Match the typed dispatch client's commit-phase tracking: a timeout before COMMIT is a
        // known no-commit authority failure, while a timeout after COMMIT entered the wire path is
        // ambiguous. In both cases the timed-out transaction leaves the session unsuitable for
        // reuse, so the lease is retired rather than returned to the shared pool.
        let commit_started = AtomicBool::new(false);
        let outcome = match tokio::time::timeout(
            self.pool.operation_timeout(),
            charge_on_lease(&self.pool, &mut lease, request, &commit_started),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(classify_charge_timeout(
                commit_started.load(Ordering::SeqCst),
            )),
        };
        match outcome {
            Err(ChargeExecutionError::SessionUnusable(_)) => lease.poison(),
            _ => lease.release().await,
        }
        outcome
    }
}

async fn charge_on_lease(
    pool: &DispatchRuntimePool,
    lease: &mut DispatchLease<'_>,
    request: &ProviderChargeRequest,
    commit_started: &AtomicBool,
) -> Result<ChargeAttempt, ChargeExecutionError> {
    let logical_request_id =
        parse_uuid(request.logical_request_id()).map_err(ChargeExecutionError::Public)?;
    let attempt_id = parse_uuid(request.attempt_id()).map_err(ChargeExecutionError::Public)?;
    let attempt_ordinal = i32::try_from(request.attempt_ordinal())
        .map_err(|_| ChargeExecutionError::Public(ProviderChargeError::ConfigurationUnresolved))?;
    let cap_classes: Vec<i16> = request
        .cap_classes()
        .into_iter()
        .map(cap_class_code)
        .collect();
    let preamble = pool.bounded_execution_preamble();
    let client = lease.client().map_err(|_| {
        ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
            ProviderChargeError::AuthorityUnavailable,
        ))
    })?;
    let transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await
        .map_err(classify_precommit_error)?;
    if let Err(error) = transaction.batch_execute(&preamble).await {
        let failure = classify_precommit_error(error);
        return Err(rollback_after_failure(transaction, failure).await);
    }
    let row = match transaction
        .query_one(
            CHARGE_SQL,
            &[
                &PROVIDER_CHARGE_API_REVISION_V1,
                &request.provider_boundary_id(),
                &traffic_class_code(request.traffic_class()),
                &attempt_class_code(request.attempt_class()),
                &request.attempt_units().to_string(),
                &request.budget_pin().revision,
                &request.budget_pin().fence.to_string(),
                &logical_request_id,
                &attempt_id,
                &attempt_ordinal,
                &request.deadline_unix_ms(),
                &cap_classes,
            ],
        )
        .await
    {
        Ok(row) => row,
        Err(error) => {
            let failure = classify_precommit_error(error);
            return Err(rollback_after_failure(transaction, failure).await);
        }
    };
    let outcome = match decode_charge_row(&row, request) {
        Ok(outcome) => outcome,
        Err(error) => {
            let failure = ChargeExecutionError::Public(error);
            return Err(rollback_after_failure(transaction, failure).await);
        }
    };
    match outcome {
        ChargeAttempt::Granted(grant) => {
            commit_started.store(true, Ordering::SeqCst);
            transaction
                .commit()
                .await
                .map_err(|error| classify_commit_sqlstate(error.code()))?;
            Ok(ChargeAttempt::Granted(grant))
        }
        ChargeAttempt::Refused(error) => {
            // Every refusal result is emitted before this invocation's grant CAS and bucket
            // updates. No COMMIT is sent. A lost ROLLBACK cannot make the transaction commit.
            match transaction.rollback().await {
                Ok(()) => Ok(ChargeAttempt::Refused(error)),
                Err(_) => Err(ChargeExecutionError::SessionUnusable(
                    SessionUnusableChargeError::Public(error),
                )),
            }
        }
    }
}

impl fmt::Debug for PostgresProviderChargeAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresProviderChargeAuthority")
            .finish_non_exhaustive()
    }
}

impl ProviderChargeAuthority for PostgresProviderChargeAuthority {
    async fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        for retry_delay in MUTATION_RETRY_SCHEDULE {
            match self.charge_once(request).await {
                Ok(ChargeAttempt::Granted(grant)) => return Ok(grant),
                Ok(ChargeAttempt::Refused(error)) => return Err(error),
                Err(ChargeExecutionError::Retryable) => match retry_delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => return Err(ProviderChargeError::AuthorityUnavailable),
                },
                Err(ChargeExecutionError::SessionUnusable(
                    SessionUnusableChargeError::Retryable,
                )) => match retry_delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => return Err(ProviderChargeError::AuthorityUnavailable),
                },
                Err(ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
                    error,
                ))) => return Err(error),
                Err(ChargeExecutionError::Public(error)) => return Err(error),
            }
        }
        Err(ProviderChargeError::AuthorityUnavailable)
    }
}

enum ChargeAttempt {
    Granted(ProviderChargeGrant),
    Refused(ProviderChargeError),
}

#[derive(Debug, PartialEq, Eq)]
enum ChargeExecutionError {
    Retryable,
    SessionUnusable(SessionUnusableChargeError),
    Public(ProviderChargeError),
}

#[derive(Debug, PartialEq, Eq)]
enum SessionUnusableChargeError {
    Retryable,
    Public(ProviderChargeError),
}

impl ChargeExecutionError {
    fn on_unusable_session(self) -> Self {
        match self {
            Self::Retryable => Self::SessionUnusable(SessionUnusableChargeError::Retryable),
            Self::Public(error) => Self::SessionUnusable(SessionUnusableChargeError::Public(error)),
            Self::SessionUnusable(error) => Self::SessionUnusable(error),
        }
    }
}

fn decode_charge_row(
    row: &tokio_postgres::Row,
    request: &ProviderChargeRequest,
) -> Result<ChargeAttempt, ProviderChargeError> {
    let result_code: &str = row
        .try_get(0)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let refusal = match result_code {
        "BUDGET_PIN_REJECTED" => Some(ProviderChargeError::BudgetPinRejected),
        "BUDGET_EXHAUSTED" => Some(ProviderChargeError::BudgetExhausted),
        "CLASS_CAP_EXHAUSTED" => Some(ProviderChargeError::ClassCapExhausted),
        "CONFIGURATION_UNRESOLVED" => Some(ProviderChargeError::ConfigurationUnresolved),
        // The durable CAS proves one earlier charge. This call did not create another one, so the
        // current ledger must not increment again. Fresh-ledger recovery is a separate caller and
        // uses ProviderChargeError::RecoveredCommittedCharge rather than this result.
        "ATTEMPT_ALREADY_CHARGED" => Some(ProviderChargeError::AttemptAlreadyCharged),
        "DEADLINE_EXCEEDED" => Some(ProviderChargeError::DeadlineExceeded),
        "GRANTED" => None,
        _ => return Err(ProviderChargeError::ConfigurationUnresolved),
    };
    if let Some(error) = refusal {
        return Ok(ChargeAttempt::Refused(error));
    }
    let revision: String = row
        .try_get(1)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let fence = parse_u64_text(row, 2)?;
    let grant_id: Uuid = row
        .try_get(3)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let traffic: i16 = row
        .try_get(4)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let attempt: i16 = row
        .try_get(5)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let charged_units = parse_u64_text(row, 6)?;
    let logical_request_id: Uuid = row
        .try_get(7)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let attempt_id: Uuid = row
        .try_get(8)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let attempt_ordinal: i32 = row
        .try_get(9)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let granted_at_database_unix_ms: i64 = row
        .try_get(10)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    if traffic != traffic_class_code(request.traffic_class())
        || attempt != attempt_class_code(request.attempt_class())
        || attempt_ordinal <= 0
    {
        return Err(ProviderChargeError::ConfigurationUnresolved);
    }
    Ok(ChargeAttempt::Granted(ProviderChargeGrant {
        grant_id: grant_id.to_string(),
        traffic_class: request.traffic_class(),
        attempt_class: request.attempt_class(),
        charged_units,
        budget_pin: BudgetPin { revision, fence },
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        attempt_ordinal: u32::try_from(attempt_ordinal)
            .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?,
        granted_at_database_unix_ms,
    }))
}

/// A commit outcome with no PostgreSQL SQLSTATE remains ambiguous because durability cannot be
/// proved. This helper preserves the public seam used by source-dark tests.
#[doc(hidden)]
pub fn classify_provider_charge_commit<T, E>(
    result: Result<T, E>,
) -> Result<T, ProviderChargeError> {
    result.map_err(|_| ProviderChargeError::AmbiguousCommit)
}

fn classify_charge_timeout(commit_started: bool) -> ChargeExecutionError {
    let error = if commit_started {
        ProviderChargeError::AmbiguousCommit
    } else {
        ProviderChargeError::AuthorityUnavailable
    };
    ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(error))
}

/// Classify a SQLSTATE raised by `COMMIT` without discarding the proof that PostgreSQL aborted the
/// transaction. Every unrecognized or absent SQLSTATE stays ambiguous.
fn classify_commit_sqlstate(code: Option<&SqlState>) -> ChargeExecutionError {
    match code {
        Some(code)
            if code == &SqlState::T_R_SERIALIZATION_FAILURE
                || code == &SqlState::T_R_DEADLOCK_DETECTED =>
        {
            ChargeExecutionError::Retryable
        }
        _ => ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
            ProviderChargeError::AmbiguousCommit,
        )),
    }
}

fn classify_precommit_error(error: tokio_postgres::Error) -> ChargeExecutionError {
    match error.code() {
        Some(code) if code == &SqlState::T_R_SERIALIZATION_FAILURE => {
            ChargeExecutionError::Retryable
        }
        Some(code) if code == &SqlState::T_R_DEADLOCK_DETECTED => ChargeExecutionError::Retryable,
        Some(code) if code == &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE => {
            ChargeExecutionError::Public(ProviderChargeError::ConfigurationUnresolved)
        }
        Some(code) if code == &SqlState::INVALID_PARAMETER_VALUE => {
            ChargeExecutionError::Public(ProviderChargeError::ConfigurationUnresolved)
        }
        // A SQLSTATE is a server refusal on a functioning protocol session. An unknown one still
        // fails closed, but the session itself may be reused after the transaction rolls back.
        Some(_) => ChargeExecutionError::Public(ProviderChargeError::AuthorityUnavailable),
        // With no SQLSTATE, the failure is at the connection/protocol layer. Returning that session
        // to the idle pool would let the next charge inherit state this call could not prove sound.
        None => ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
            ProviderChargeError::AuthorityUnavailable,
        )),
    }
}

/// End an open transaction before making its session reusable. A failed rollback preserves the
/// semantic failure but independently marks the session unusable, so the caller can poison it.
async fn rollback_after_failure(
    transaction: tokio_postgres::Transaction<'_>,
    failure: ChargeExecutionError,
) -> ChargeExecutionError {
    match transaction.rollback().await {
        Ok(()) => failure,
        Err(_) => failure.on_unusable_session(),
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, ProviderChargeError> {
    Uuid::parse_str(value).map_err(|_| ProviderChargeError::ConfigurationUnresolved)
}

fn parse_u64_text(row: &tokio_postgres::Row, index: usize) -> Result<u64, ProviderChargeError> {
    let value: &str = row
        .try_get(index)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    value
        .parse()
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)
}

const fn traffic_class_code(value: ProviderTrafficClass) -> i16 {
    match value {
        ProviderTrafficClass::Drain => 1,
        ProviderTrafficClass::DirectFallback => 2,
        ProviderTrafficClass::Read => 3,
        ProviderTrafficClass::Repair => 4,
        ProviderTrafficClass::Operator => 5,
    }
}

const fn attempt_class_code(value: ProviderAttemptClass) -> i16 {
    match value {
        ProviderAttemptClass::Readiness => 1,
        ProviderAttemptClass::HeadObject => 2,
        ProviderAttemptClass::GetObject => 3,
        ProviderAttemptClass::PutObject => 4,
        ProviderAttemptClass::CreateMultipartUpload => 5,
        ProviderAttemptClass::UploadPart => 6,
        ProviderAttemptClass::CompleteMultipartUpload => 7,
        ProviderAttemptClass::AbortMultipartUpload => 8,
        ProviderAttemptClass::ListObjectsV2 => 9,
        ProviderAttemptClass::ListObjectVersions => 10,
        ProviderAttemptClass::DeleteObject => 11,
    }
}

const fn cap_class_code(value: ProviderCapClass) -> i16 {
    match value {
        ProviderCapClass::SharedPhysicalBudget => 1,
        ProviderCapClass::TrafficDrain => 2,
        ProviderCapClass::TrafficDirectFallback => 3,
        ProviderCapClass::TrafficRead => 4,
        ProviderCapClass::TrafficRepair => 5,
        ProviderCapClass::TrafficOperator => 6,
        ProviderCapClass::List => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_provably_aborted_commit_sqlstates_are_retryable() {
        assert_eq!(
            classify_commit_sqlstate(Some(&SqlState::T_R_SERIALIZATION_FAILURE)),
            ChargeExecutionError::Retryable
        );
        assert_eq!(
            classify_commit_sqlstate(Some(&SqlState::T_R_DEADLOCK_DETECTED)),
            ChargeExecutionError::Retryable
        );
        assert_eq!(
            classify_commit_sqlstate(Some(&SqlState::CONNECTION_FAILURE)),
            ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
                ProviderChargeError::AmbiguousCommit
            ))
        );
        assert_eq!(
            classify_commit_sqlstate(None),
            ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
                ProviderChargeError::AmbiguousCommit
            ))
        );
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Dark PostgreSQL implementation of the shared cell-local provider limiter.
//!
//! The authority accepts a preconnected dispatch-runtime client. It does not install schema,
//! publish a budget, choose a concrete pin, open a provider route, or become the shipped default.
//! Each call uses one serializable transaction. The database function resolves and validates the
//! current publication, takes the one grant CAS, and debits the shared bucket plus every applicable
//! subordinate cap before this client commits.

use std::fmt;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio_postgres::Client;
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

/// Bounded transaction settings for one PostgreSQL charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostgresProviderChargeConfig {
    pub statement_timeout: Duration,
    pub lock_timeout: Duration,
}

impl PostgresProviderChargeConfig {
    pub fn validate(self) -> Result<Self, ProviderChargeError> {
        let statement = duration_millis(self.statement_timeout)?;
        let lock = duration_millis(self.lock_timeout)?;
        statement
            .checked_add(lock)
            .ok_or(ProviderChargeError::ConfigurationUnresolved)?;
        Ok(self)
    }
}

/// The CD-4 authority over one cell's dispatch-runtime database connection.
///
/// `UnwiredChargeAuthority` remains the shipped default. Constructing this value is explicit and
/// still does not publish a budget configuration.
pub struct PostgresProviderChargeAuthority {
    client: Mutex<Client>,
    statement_timeout_ms: u64,
    lock_timeout_ms: u64,
}

impl PostgresProviderChargeAuthority {
    pub fn new(
        client: Client,
        config: PostgresProviderChargeConfig,
    ) -> Result<Self, ProviderChargeError> {
        let config = config.validate()?;
        Ok(Self {
            client: Mutex::new(client),
            statement_timeout_ms: duration_millis(config.statement_timeout)?,
            lock_timeout_ms: duration_millis(config.lock_timeout)?,
        })
    }

    async fn charge_once(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ChargeAttempt, ChargeExecutionError> {
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(classify_precommit_error)?;
        transaction
            .batch_execute(&format!(
                "SET LOCAL statement_timeout = '{}ms'; SET LOCAL lock_timeout = '{}ms';",
                self.statement_timeout_ms, self.lock_timeout_ms
            ))
            .await
            .map_err(classify_precommit_error)?;
        let logical_request_id =
            parse_uuid(request.logical_request_id()).map_err(ChargeExecutionError::Public)?;
        let attempt_id = parse_uuid(request.attempt_id()).map_err(ChargeExecutionError::Public)?;
        let cap_classes: Vec<i16> = request
            .cap_classes()
            .into_iter()
            .map(cap_class_code)
            .collect();
        let row = transaction
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
                    &i32::try_from(request.attempt_ordinal()).map_err(|_| {
                        ChargeExecutionError::Public(ProviderChargeError::ConfigurationUnresolved)
                    })?,
                    &request.deadline_unix_ms(),
                    &cap_classes,
                ],
            )
            .await
            .map_err(classify_precommit_error)?;
        let outcome = decode_charge_row(&row, request).map_err(ChargeExecutionError::Public)?;
        match outcome {
            ChargeAttempt::Granted(grant) => {
                transaction.commit().await.map_err(classify_commit_error)?;
                Ok(ChargeAttempt::Granted(grant))
            }
            ChargeAttempt::Refused(error) => {
                // Every refusal result is emitted before this invocation's grant CAS and bucket
                // updates. No COMMIT is sent. A lost ROLLBACK cannot make the transaction commit.
                let _ = transaction.rollback().await;
                Ok(ChargeAttempt::Refused(error))
            }
        }
    }
}

impl fmt::Debug for PostgresProviderChargeAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresProviderChargeAuthority")
            .field("statement_timeout_ms", &self.statement_timeout_ms)
            .field("lock_timeout_ms", &self.lock_timeout_ms)
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

enum ChargeExecutionError {
    Retryable,
    Public(ProviderChargeError),
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

/// The only two safe classifications for an error returned by PostgreSQL `COMMIT`.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderChargeCommitDisposition {
    /// PostgreSQL proves the transaction aborted, so the same attempt may be retried.
    Retryable,
    /// Durability cannot be proved, so the caller must conservatively count a grant.
    Ambiguous,
}

/// Classify a SQLSTATE raised by `COMMIT` without discarding the proof that PostgreSQL aborted the
/// transaction. Every unrecognized or absent SQLSTATE stays ambiguous.
#[doc(hidden)]
#[must_use]
pub fn classify_provider_charge_commit_sqlstate(
    code: Option<&SqlState>,
) -> ProviderChargeCommitDisposition {
    match code {
        Some(code)
            if code == &SqlState::T_R_SERIALIZATION_FAILURE
                || code == &SqlState::T_R_DEADLOCK_DETECTED =>
        {
            ProviderChargeCommitDisposition::Retryable
        }
        _ => ProviderChargeCommitDisposition::Ambiguous,
    }
}

fn classify_commit_error(error: tokio_postgres::Error) -> ChargeExecutionError {
    match classify_provider_charge_commit_sqlstate(error.code()) {
        ProviderChargeCommitDisposition::Retryable => ChargeExecutionError::Retryable,
        ProviderChargeCommitDisposition::Ambiguous => {
            ChargeExecutionError::Public(ProviderChargeError::AmbiguousCommit)
        }
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
        _ => ChargeExecutionError::Public(ProviderChargeError::AuthorityUnavailable),
    }
}

fn duration_millis(duration: Duration) -> Result<u64, ProviderChargeError> {
    if duration.is_zero()
        || duration.as_millis() == 0
        || !duration.subsec_nanos().is_multiple_of(1_000_000)
    {
        return Err(ProviderChargeError::ConfigurationUnresolved);
    }
    let value = u64::try_from(duration.as_millis())
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    Ok(value)
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

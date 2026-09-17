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

// CR-034's head read. Two columns of one row of one table, through the only function the runtime
// role may execute against the head. The `::text` cast on the uint64 domain mirrors CHARGE_SQL.
const HEAD_READ_SQL: &str = "SELECT
  (r).result_code,
  (r).allocation_revision,
  ((r).allocation_fence)::text
FROM (SELECT object_store_retention.object_store_dispatch_read_current_budget_pin_v1(
  $1, $2
) AS r) q";

// Three attempts total: retry after the first two, never after the last.
const MUTATION_RETRY_SCHEDULE: [Option<Duration>; 3] = [
    Some(Duration::from_millis(25)),
    Some(Duration::from_millis(100)),
    None,
];

// Match the charge/configuration functions' transaction advisory lock. Taking the same key on
// this session before BEGIN prevents a waiter from retaining a snapshot older than the preceding
// bucket debit. The function's transaction lock remains in place for all other callers.
const CHARGE_BOUNDARY_LOCK_SQL: &str =
    "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1, 1144))";
const CHARGE_BOUNDARY_UNLOCK_SQL: &str =
    "SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1, 1144))";

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
        let mut lease = self.pool.acquire().await.map_err(|error| {
            // DispatchPoolError carries only closed, redaction-safe diagnostics.
            tracing::warn!(
                stage = "charge_pool_acquire",
                reason = ?error,
                "Provider charge admission refused"
            );
            ChargeExecutionError::Public(ProviderChargeError::AuthorityUnavailable)
        })?;
        let deadline = tokio::time::Instant::now() + self.pool.operation_timeout();
        // Until acquisition is acknowledged the session may already own the lock. An error,
        // timeout, or cancellation must close it, never return it to the pool or guess ownership.
        let acquired = tokio::time::timeout_at(deadline, async {
            let client = lease.client().map_err(|_| ())?;
            // Bound the wait on the server as well: a backend blocked on an advisory lock may
            // not notice a disconnected client until the lock holder exits. A short setup
            // transaction provides SET LOCAL timeouts without leaking session configuration.
            // Its session lock survives COMMIT; the charge's Serializable snapshot starts later.
            let setup = client
                .build_transaction()
                .isolation_level(IsolationLevel::ReadCommitted)
                .start()
                .await
                .map_err(|_| ())?;
            setup
                .batch_execute(&self.pool.bounded_execution_preamble())
                .await
                .map_err(|_| ())?;
            setup
                .query_one(CHARGE_BOUNDARY_LOCK_SQL, &[&request.provider_boundary_id()])
                .await
                .map_err(|_| ())?;
            setup.commit().await.map_err(|_| ())?;
            Ok::<(), ()>(())
        })
        .await;
        if !matches!(acquired, Ok(Ok(()))) {
            tracing::warn!(
                stage = "charge_lock_setup",
                timed_out = acquired.is_err(),
                "Provider charge admission refused"
            );
            lease.poison();
            return Err(ChargeExecutionError::SessionUnusable(
                SessionUnusableChargeError::Public(ProviderChargeError::AuthorityUnavailable),
            ));
        }
        // Match the typed dispatch client's commit-phase tracking: a timeout before COMMIT is a
        // known no-commit authority failure, while a timeout after COMMIT entered the wire path is
        // ambiguous. In both cases the timed-out transaction leaves the session unsuitable for
        // reuse, so the lease is retired rather than returned to the shared pool.
        let commit_started = AtomicBool::new(false);
        let outcome = match tokio::time::timeout_at(
            deadline,
            charge_on_lease(&self.pool, &mut lease, request, &commit_started),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                let started = commit_started.load(Ordering::SeqCst);
                tracing::warn!(
                    stage = "charge_transaction_timeout",
                    commit_started = started,
                    "Provider charge admission refused"
                );
                Err(classify_charge_timeout(started))
            }
        };
        if matches!(outcome, Err(ChargeExecutionError::SessionUnusable(_))) {
            lease.poison();
        } else {
            // COMMIT/ROLLBACK (or a known pre-transaction rejection) has completed. Only an
            // acknowledged unlock permits reuse. Cleanup shares the original deadline; failure
            // retires the connection without changing the already known accounting outcome.
            let unlocked = tokio::time::timeout_at(deadline, async {
                let client = lease.client().map_err(|_| ())?;
                let row = client
                    .query_one(
                        CHARGE_BOUNDARY_UNLOCK_SQL,
                        &[&request.provider_boundary_id()],
                    )
                    .await
                    .map_err(|_| ())?;
                row.try_get::<_, bool>(0).map_err(|_| ())
            })
            .await;
            if matches!(unlocked, Ok(Ok(true))) {
                lease.release().await;
            } else {
                lease.poison();
            }
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
                    None => {
                        tracing::warn!(
                            stage = "contention_exhausted",
                            "Provider charge admission refused"
                        );
                        return Err(ProviderChargeError::AuthorityUnavailable);
                    }
                },
                Err(ChargeExecutionError::SessionUnusable(
                    SessionUnusableChargeError::Retryable,
                )) => match retry_delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => {
                        tracing::warn!(
                            stage = "contention_exhausted",
                            "Provider charge admission refused"
                        );
                        return Err(ProviderChargeError::AuthorityUnavailable);
                    }
                },
                Err(ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
                    error,
                ))) => return Err(error),
                Err(ChargeExecutionError::Public(error)) => return Err(error),
            }
        }
        Err(ProviderChargeError::AuthorityUnavailable)
    }

    async fn refresh_budget_pin(
        &self,
        provider_boundary_id: &str,
    ) -> Result<BudgetPin, ProviderChargeError> {
        self.read_current_pin(provider_boundary_id).await
    }
}

/// CR-034's head read.
///
/// **This block is placed after `charge_once` and after `charge_on_lease` deliberately.**
/// `tests/shared_dispatch_pool.rs` proves the charge path's session disposition by mutating the
/// *first* textual occurrence of `tokio::time::timeout_at(` and of `lease.poison();` in this file
/// and requiring the proof to fail. A leased, timed-out helper placed above `charge_once` silently
/// absorbs those mutations and turns those negative controls green against an unchanged charge
/// path. Keep any future leased helper below the charge path for the same reason.
impl PostgresProviderChargeAuthority {
    /// Read the cell's currently published budget pin for one provider boundary.
    ///
    /// This exists so a writer fenced by a renewal can learn what the head became without a
    /// restart. It commits nothing, so it never returns `AmbiguousCommit` or
    /// `AttemptAlreadyCharged`: every failure -- pool, timeout, decode, or a non-`HEAD` result
    /// code -- is `ConfigurationUnresolved`, a typed decisive refusal.
    ///
    /// It takes no boundary advisory lock. The database function is `STABLE`; taking
    /// `CHARGE_BOUNDARY_LOCK_SQL` here would serialize head reads behind in-flight charges for no
    /// benefit. It borrows the same runtime pool the charge uses and is serial with the charge it
    /// retries, so it adds no concurrent lease demand.
    async fn read_current_pin(
        &self,
        provider_boundary_id: &str,
    ) -> Result<BudgetPin, ProviderChargeError> {
        let mut lease = self.pool.acquire().await.map_err(|error| {
            // DispatchPoolError carries only closed, redaction-safe diagnostics.
            tracing::warn!(
                stage = "head_read_pool_acquire",
                reason = ?error,
                "Provider budget head read refused"
            );
            ProviderChargeError::ConfigurationUnresolved
        })?;
        let head_read_deadline = tokio::time::Instant::now() + self.pool.operation_timeout();
        let preamble = self.pool.bounded_execution_preamble();
        // The preamble is SET LOCAL, so it needs a transaction to scope it. ReadCommitted is
        // sufficient for a single STABLE read and, unlike the charge, needs no serializable
        // snapshot: nothing is debited and no CAS is taken.
        let read = tokio::time::timeout_at(head_read_deadline, async {
            let client = lease.client().map_err(|_| ())?;
            let transaction = client
                .build_transaction()
                .isolation_level(IsolationLevel::ReadCommitted)
                .start()
                .await
                .map_err(|_| ())?;
            transaction.batch_execute(&preamble).await.map_err(|_| ())?;
            let row = transaction
                .query_one(
                    HEAD_READ_SQL,
                    &[&PROVIDER_CHARGE_API_REVISION_V1, &provider_boundary_id],
                )
                .await
                .map_err(|_| ())?;
            let decoded = decode_head_read_row(&row);
            transaction.commit().await.map_err(|_| ())?;
            Ok::<_, ()>(decoded)
        })
        .await;
        let timed_out = read.is_err();
        match read {
            Ok(Ok(decoded)) => {
                lease.release().await;
                decoded
            }
            // A timed-out or failed read leaves the session's transaction state unproven, so the
            // connection is retired rather than returned to the shared pool.
            Ok(Err(())) | Err(_) => {
                tracing::warn!(
                    stage = "head_read",
                    timed_out,
                    "Provider budget head read refused"
                );
                lease.poison();
                Err(ProviderChargeError::ConfigurationUnresolved)
            }
        }
    }
}

/// `HEAD` yields the published pin; every other result code, and every decode or grammar failure,
/// is `ConfigurationUnresolved`. A read commits nothing, so no arm here may be ambiguous.
fn decode_head_read_row(row: &tokio_postgres::Row) -> Result<BudgetPin, ProviderChargeError> {
    let result_code: &str = row
        .try_get(0)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    if result_code != "HEAD" {
        return Err(ProviderChargeError::ConfigurationUnresolved);
    }
    let revision: String = row
        .try_get(1)
        .map_err(|_| ProviderChargeError::ConfigurationUnresolved)?;
    let fence = parse_u64_text(row, 2)?;
    // BudgetPin::new re-runs the same pin grammar every governed charge checks, so a head the cell
    // somehow published outside that grammar is refused here rather than carried into a charge.
    BudgetPin::new(&revision, fence).map_err(|_| ProviderChargeError::ConfigurationUnresolved)
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
        Some(code) => {
            let reason = if code == &SqlState::QUERY_CANCELED {
                "query_canceled"
            } else if code == &SqlState::LOCK_NOT_AVAILABLE {
                "lock_not_available"
            } else {
                "database_refused"
            };
            tracing::warn!(
                stage = "charge_precommit",
                reason,
                "Provider charge admission refused"
            );
            ChargeExecutionError::Public(ProviderChargeError::AuthorityUnavailable)
        }
        // With no SQLSTATE, the failure is at the connection/protocol layer. Returning that session
        // to the idle pool would let the next charge inherit state this call could not prove sound.
        None => {
            tracing::warn!(
                stage = "charge_precommit",
                reason = "connection_or_protocol",
                "Provider charge admission refused"
            );
            ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(
                ProviderChargeError::AuthorityUnavailable,
            ))
        }
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

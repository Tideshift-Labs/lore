// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Validate the cell's `NOT VALID` constraints, one at a time, out of band.
//!
//! The boot path adds every constraint on a table that may already hold rows
//! as `NOT VALID`, because `ensure_schema_online` runs under a 250 ms statement
//! timeout and a validating `ADD CONSTRAINT` scans the whole table under
//! ACCESS EXCLUSIVE. PostgreSQL still enforces a `NOT VALID` constraint on every
//! insert and update. It skips only the proof over rows that already existed,
//! and `pg_constraint.convalidated` stays false until something runs
//! `ALTER TABLE ... VALIDATE CONSTRAINT`. Nothing on the boot path does.
//!
//! [`validate_not_valid_constraints`] is that step. It is idempotent by
//! construction: it finds its work in the catalog (`convalidated = false`) on
//! every run, so a rerun after a full success finds nothing, and a rerun after
//! a partial one retries only what is left.
//!
//! # Why this is safe against a serving cell
//!
//! `VALIDATE CONSTRAINT` takes SHARE UPDATE EXCLUSIVE on the table for a CHECK,
//! which does not block reads or writes; a foreign key also takes ROW SHARE on
//! the referenced table. Each statement runs in its own implicit transaction
//! under a session `lock_timeout` and `statement_timeout`, so one slow or
//! contended table fails on its own and the rest still run.
//!
//! # Scope
//!
//! Only CHECK and foreign-key constraints on `lore_`-prefixed tables in the
//! connection's `search_path` schemas. Another application's objects in the
//! same database are not this command's to change.

use std::time::Duration;

use tokio_postgres::GenericClient;
use tokio_postgres::error::SqlState;

use crate::domain::errors::DomainError;

/// What happened to one `NOT VALID` constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// PostgreSQL scanned the table and marked the constraint validated.
    Validated,
    /// An existing row breaks the constraint. It stays `NOT VALID`, and still
    /// binds every new write; the row needs an operator's repair first.
    Violated(String),
    /// The table lock was not granted within the lock timeout.
    LockTimeout,
    /// PostgreSQL reported `QUERY_CANCELED`. Usually the scan ran past the
    /// statement timeout, but the same SQLSTATE also covers an operator's
    /// manual `pg_cancel_backend`, so this outcome does not claim which one
    /// happened.
    StatementTimeout,
    /// Any other failure, with PostgreSQL's message.
    Failed(String),
}

impl ValidationOutcome {
    /// Stable label for reports.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Violated(_) => "violated",
            Self::LockTimeout => "lock_timeout",
            Self::StatementTimeout => "canceled (statement_timeout or manual cancel)",
            Self::Failed(_) => "failed",
        }
    }

    /// PostgreSQL's message, when the outcome carries one.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Violated(message) | Self::Failed(message) => Some(message),
            _ => None,
        }
    }
}

/// One constraint's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintValidation {
    /// The table, as `regclass` text.
    pub relation: String,
    /// The constraint name.
    pub constraint: String,
    /// What happened.
    pub outcome: ValidationOutcome,
    /// How long the statement ran.
    pub elapsed: Duration,
}

/// The two timeouts each `VALIDATE CONSTRAINT` runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationTimeouts {
    /// How long to wait for the table lock.
    pub lock_timeout: Duration,
    /// How long one validation scan may run.
    pub statement_timeout: Duration,
}

/// List the `NOT VALID` constraints this command would validate, in order.
///
/// # Errors
/// A database failure reading the catalog.
pub async fn list_not_valid_constraints(
    client: &impl GenericClient,
) -> Result<Vec<(String, String)>, DomainError> {
    Ok(not_valid_constraints(client)
        .await?
        .into_iter()
        .map(|pending| (pending.relation, pending.constraint))
        .collect())
}

/// Failure of [`validate_not_valid_constraints`].
///
/// Split from a plain [`DomainError`] so a failure in the final session-reset
/// step does not discard the constraint results the run already produced:
/// those results are real work, proved against the database, and a caller
/// should see them even when the cleanup step afterward fails.
#[derive(Debug, thiserror::Error)]
pub enum ConstraintValidationError {
    /// Failed before any constraint was attempted: a zero timeout, a catalog
    /// read failure, or a failure to set the session's validation timeouts.
    /// No constraint was touched.
    #[error("{0}")]
    Setup(#[source] DomainError),
    /// Every constraint in `results` was attempted and the outcomes are
    /// final, but resetting the session's `lock_timeout`/`statement_timeout`
    /// afterward failed.
    #[error(
        "constraint validation ran to completion, but resetting the session's \
         timeouts afterward failed: {error}"
    )]
    ResetFailed {
        /// The results from every constraint this run attempted. Complete and
        /// trustworthy; only the post-scan cleanup failed.
        results: Vec<ConstraintValidation>,
        /// Why the reset failed.
        #[source]
        error: DomainError,
    },
}

/// Validate every `NOT VALID` constraint in scope, one statement each.
///
/// Returns one entry per constraint attempted, in catalog order. A failure on
/// one constraint is recorded and the next one still runs; only a failure to
/// read the catalog or to set the timeouts is an [`ConstraintValidationError::Setup`].
/// The session timeouts are reset before returning; if that reset fails, the
/// results are not lost — they come back in
/// [`ConstraintValidationError::ResetFailed`] alongside the reset error.
///
/// # Errors
/// [`ConstraintValidationError::Setup`] for a zero timeout or a database
/// failure reading the catalog or setting the session timeouts;
/// [`ConstraintValidationError::ResetFailed`] when every constraint ran but
/// the final timeout reset failed.
pub async fn validate_not_valid_constraints(
    client: &impl GenericClient,
    timeouts: ValidationTimeouts,
) -> Result<Vec<ConstraintValidation>, ConstraintValidationError> {
    if timeouts.lock_timeout.is_zero() || timeouts.statement_timeout.is_zero() {
        // Zero means "no timeout" to PostgreSQL, which is the opposite of what
        // an operator passing a bound asked for.
        return Err(ConstraintValidationError::Setup(DomainError::InvalidInput(
            "constraint validation timeouts must be greater than zero".to_owned(),
        )));
    }
    let pending = not_valid_constraints(client)
        .await
        .map_err(ConstraintValidationError::Setup)?;
    if pending.is_empty() {
        return Ok(Vec::new());
    }

    set_session_timeouts(client, timeouts)
        .await
        .map_err(ConstraintValidationError::Setup)?;
    let mut results = Vec::with_capacity(pending.len());
    for constraint in pending {
        let started = std::time::Instant::now();
        let outcome = match client.batch_execute(&constraint.statement).await {
            Ok(()) => ValidationOutcome::Validated,
            Err(error) => classify(&error),
        };
        results.push(ConstraintValidation {
            relation: constraint.relation,
            constraint: constraint.constraint,
            outcome,
            elapsed: started.elapsed(),
        });
    }
    if let Err(error) = reset_session_timeouts(client).await {
        return Err(ConstraintValidationError::ResetFailed { results, error });
    }
    Ok(results)
}

/// One catalog row, with the statement PostgreSQL quoted for it.
struct PendingConstraint {
    relation: String,
    constraint: String,
    statement: String,
}

async fn not_valid_constraints(
    client: &impl GenericClient,
) -> Result<Vec<PendingConstraint>, DomainError> {
    // `format('%I')` quotes on the server, so no identifier is ever spliced
    // into SQL by this crate. `LIKE 'lore\_%'` escapes the underscore, which is
    // otherwise a single-character wildcard.
    let rows = client
        .query(
            "SELECT c.conrelid::regclass::text AS relation, c.conname::text AS constraint_name, \
                    format('ALTER TABLE %I.%I VALIDATE CONSTRAINT %I', \
                           n.nspname, r.relname, c.conname) AS statement \
               FROM pg_constraint AS c \
               JOIN pg_class AS r ON r.oid = c.conrelid \
               JOIN pg_namespace AS n ON n.oid = r.relnamespace \
              WHERE NOT c.convalidated \
                AND c.contype IN ('c', 'f') \
                AND n.nspname = ANY(current_schemas(false)) \
                AND r.relname LIKE 'lore\\_%' \
              ORDER BY r.relname, c.conname",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("list NOT VALID constraints", e))?;
    Ok(rows
        .iter()
        .map(|row| PendingConstraint {
            relation: row.get("relation"),
            constraint: row.get("constraint_name"),
            statement: row.get("statement"),
        })
        .collect())
}

async fn set_session_timeouts(
    client: &impl GenericClient,
    timeouts: ValidationTimeouts,
) -> Result<(), DomainError> {
    let lock = format!("{}ms", timeouts.lock_timeout.as_millis());
    let statement = format!("{}ms", timeouts.statement_timeout.as_millis());
    client
        .execute(
            "SELECT set_config('lock_timeout', $1, false), \
                    set_config('statement_timeout', $2, false)",
            &[&lock, &statement],
        )
        .await
        .map_err(|e| DomainError::from_pg("set constraint validation timeouts", e))?;
    Ok(())
}

async fn reset_session_timeouts(client: &impl GenericClient) -> Result<(), DomainError> {
    client
        .batch_execute("RESET lock_timeout; RESET statement_timeout")
        .await
        .map_err(|e| DomainError::from_pg("reset constraint validation timeouts", e))
}

fn classify(error: &tokio_postgres::Error) -> ValidationOutcome {
    let Some(db_error) = error.as_db_error() else {
        return ValidationOutcome::Failed(error.to_string());
    };
    classify_code(db_error.code(), db_error.message())
}

/// The SQLSTATE-to-outcome mapping itself, split out from [`classify`] so it
/// can be unit-tested directly: `tokio_postgres::Error`/`DbError` have no
/// public constructor, so a test cannot build one to drive `classify` without
/// a live database round trip.
fn classify_code(code: &SqlState, message: &str) -> ValidationOutcome {
    if *code == SqlState::CHECK_VIOLATION || *code == SqlState::FOREIGN_KEY_VIOLATION {
        ValidationOutcome::Violated(message.to_owned())
    } else if *code == SqlState::LOCK_NOT_AVAILABLE {
        ValidationOutcome::LockTimeout
    } else if *code == SqlState::QUERY_CANCELED {
        // QUERY_CANCELED also fires for an operator's manual
        // `pg_cancel_backend`, not only a statement-timeout abort; the label
        // says so rather than assuming the timeout.
        ValidationOutcome::StatementTimeout
    } else {
        ValidationOutcome::Failed(message.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_outcome_has_a_distinct_label() {
        let outcomes = [
            ValidationOutcome::Validated,
            ValidationOutcome::Violated(String::new()),
            ValidationOutcome::LockTimeout,
            ValidationOutcome::StatementTimeout,
            ValidationOutcome::Failed(String::new()),
        ];
        let labels: std::collections::BTreeSet<&str> =
            outcomes.iter().map(ValidationOutcome::label).collect();
        assert_eq!(labels.len(), outcomes.len());
    }

    /// A SQLSTATE this run has no other classification for — e.g. the
    /// table-owner-role gap the runbook now documents (INSUFFICIENT_PRIVILEGE,
    /// `42501`) — falls through to `Failed` with PostgreSQL's own message
    /// preserved, rather than being silently dropped or misclassified as one
    /// of the named outcomes.
    #[test]
    fn classify_code_maps_insufficient_privilege_to_failed() {
        let outcome = classify_code(
            &SqlState::INSUFFICIENT_PRIVILEGE,
            "permission denied for table lore_fragment_state",
        );
        assert_eq!(
            outcome,
            ValidationOutcome::Failed("permission denied for table lore_fragment_state".to_owned())
        );
    }
}

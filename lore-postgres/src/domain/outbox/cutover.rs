// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The outbox cutover marker (WP-119 Step C).
//!
//! Step B's startup gate refuses to boot a relay against a cell whose
//! `lore_outbox_schema_state.cutover_at` is unset, and until now **nothing in
//! this tree wrote it** — deliberately, because CR-032 puts the cutover
//! procedure in Step C and a fail-closed gate with no key is the correct state
//! for a default-off feature. This module is the key.
//!
//! Stamping the marker asserts three things about the cell, and the caller is
//! the one that has to have proved them:
//!
//! * the outbox exists and every producer writes to this same database;
//! * relay and required-consumer compatibility floors are satisfied; and
//! * each required receiver has captured a position, taken an authoritative
//!   baseline, drained, and persisted a checkpoint.
//!
//! None of that is checked here, because none of it is a fact this transaction
//! can read: the first is a co-location proof the startup gate already makes,
//! the second is a version comparison the relay makes at boot, and the third is
//! a live receiver's own bootstrap. What this module guarantees instead is that
//! the marker is written **once**, idempotently, alongside the retention policy
//! version and the cell's membership counters — so a restarted cutover resumes
//! rather than restarting a counter some generation already claimed.

use std::time::SystemTime;

use tokio_postgres::GenericClient;

use crate::domain::errors::DomainError;
use crate::domain::outbox::membership::ensure_membership_state;
use crate::domain::outbox::membership::validate_cell_id;
use crate::domain::outbox::schema::RETENTION_POLICY_VERSION;

/// What stamping the marker did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutoverOutcome {
    /// The marker was unset and is now stamped.
    Stamped {
        /// When it was stamped, by the database clock.
        cutover_at: SystemTime,
    },
    /// The marker was already set. Idempotent: the original timestamp stands,
    /// because it is the one an operator correlates an incident against.
    AlreadyStamped {
        /// The original timestamp.
        cutover_at: SystemTime,
    },
    /// There is no `lore_outbox_schema_state` singleton, so this database has
    /// no outbox at all.
    SchemaStateAbsent,
}

/// Complete the cutover for one cell.
///
/// Creates the cell's membership counters if it has none, then stamps the
/// singleton's `cutover_at` and `retention_policy_version`.
///
/// The stamp is guarded by `cutover_at IS NULL` rather than written
/// unconditionally, so a second call cannot move a marker an operator has
/// already correlated an incident against, and two concurrent operators produce
/// one timestamp rather than a last-writer-wins race.
pub async fn stamp_cutover(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<CutoverOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    ensure_membership_state(client, cell_id).await?;

    let stamped = client
        .query_opt(
            "UPDATE lore_outbox_schema_state SET \
                 cutover_at = clock_timestamp(), \
                 retention_policy_version = $1, \
                 updated_at = clock_timestamp() \
             WHERE id = 1 AND cutover_at IS NULL \
             RETURNING cutover_at",
            &[&RETENTION_POLICY_VERSION],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox cutover stamp", e))?;
    if let Some(row) = stamped {
        let cutover_at: Option<SystemTime> = row.get("cutover_at");
        return match cutover_at {
            Some(cutover_at) => Ok(CutoverOutcome::Stamped { cutover_at }),
            // The `RETURNING` came from the row this statement just set, so a
            // null here means the column was cleared concurrently. An explicit
            // error rather than a silent success: the startup gate is about to
            // read this value.
            None => Err(DomainError::Internal(
                "outbox cutover_at is null immediately after being stamped; it was cleared \
                 concurrently"
                    .to_string(),
            )),
        };
    }

    let existing = client
        .query_opt(
            "SELECT cutover_at FROM lore_outbox_schema_state WHERE id = 1",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox cutover read", e))?;
    match existing {
        Some(row) => match row.get::<_, Option<SystemTime>>("cutover_at") {
            Some(cutover_at) => Ok(CutoverOutcome::AlreadyStamped { cutover_at }),
            // The guarded update matched nothing and the column is still null,
            // which one concurrent transaction holding the row can produce.
            // Reported rather than retried here: the caller is an operator
            // command, and a retry loop belongs to it.
            None => Err(DomainError::Contention(
                "outbox cutover marker is still unset after a guarded stamp; another transaction \
                 holds the schema-state row"
                    .to_string(),
            )),
        },
        None => Ok(CutoverOutcome::SchemaStateAbsent),
    }
}

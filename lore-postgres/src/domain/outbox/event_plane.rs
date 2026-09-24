// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The event plane marker and the offline switch between planes.
//!
//! Notification-plane contract amendment A-32 ("Event plane modes") gives a
//! cell exactly one of two planes:
//!
//! * `durable` — CR-032 in full: producers append outbox rows, the relay
//!   publishes them, receivers checkpoint them. Every cell that existed before
//!   this module is in this plane.
//! * `live_only` — producers append **nothing**. There is no relay, no
//!   receiver, and no outbox admission gate. Desktops recover through live hints
//!   and authoritative refetch alone.
//!
//! The authority is a row in cell Postgres, not configuration: the latest row of
//! `lore_outbox_event_plane_transitions` for the cell. A cell with no row is
//! `durable`. `lore-server` refuses to boot when its configured plane differs
//! from this marker, so two replicas of one cell cannot run different planes.
//!
//! # The switch is offline
//!
//! [`set_event_plane`] refuses while any other backend is connected to the cell
//! database, using the same `pg_stat_database.numbackends` count as CR-039's
//! fragment schema upgrade, with `ACCESS EXCLUSIVE NOWAIT` on the outbox table
//! as the backstop. Stop every replica of the cell first.
//!
//! # Retained rows are moved, never discarded
//!
//! Switching to `live_only`:
//!
//! 1. refuses while any `pending` row exists, because a pending row is work
//!    that was never published. The operator drains it in `durable` mode first;
//! 2. moves every `broker_accepted` and `consumer_safe` row into
//!    `lore_outbox_retired_events`, verbatim, with disposition
//!    `retired_live_only`;
//! 3. writes the transition row that names who ordered it, why, and how many
//!    rows it retired.
//!
//! All three happen in one transaction. Nothing is deleted without its evidence
//! copy and its audit row.
//!
//! Switching back to `durable` writes only the transition row. A `live_only`
//! cell has no outbox rows (boot refuses one that does), and the retired
//! evidence stays where it is. Receivers join under new membership generations
//! by the ordinary CR-032 rules.

use std::time::Duration;
use std::time::SystemTime;

use tokio_postgres::GenericClient;
use tokio_postgres::Transaction;
use tokio_postgres::error::SqlState;

use crate::domain::errors::DomainError;
use crate::domain::outbox::membership::validate_cell_id;
use crate::domain::outbox::relay::bounded;
use crate::domain::outbox::schema::MAX_DISPOSITION_ACTOR_BYTES;
use crate::domain::outbox::schema::MAX_DISPOSITION_REASON_BYTES;

/// The boot-time DDL for the marker and the evidence table.
///
/// An `include_str!` of the migration file rather than a copy of it, so the
/// out-of-band provisioning path and the boot path are one declaration.
pub const EVENT_PLANE_SCHEMA: &str =
    include_str!("../../../migrations/0005_outbox_event_plane.sql");

/// The disposition every retired row carries.
pub const RETIRED_LIVE_ONLY: &str = "retired_live_only";

/// Bounded wait for a just-closed backend to leave `numbackends` before the
/// switch refuses. The same bound CR-039's schema upgrade uses.
const BACKEND_SETTLE_ATTEMPTS: u32 = 10;
const BACKEND_SETTLE_INTERVAL: Duration = Duration::from_millis(200);

/// A cell's event plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPlane {
    /// Live hints only. No outbox row is produced.
    LiveOnly,
    /// CR-032's durable plane.
    Durable,
}

impl EventPlane {
    /// The stored and configured spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiveOnly => "live_only",
            Self::Durable => "durable",
        }
    }

    /// Parse the stored and configured spelling. Nothing else is accepted.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "live_only" => Some(Self::LiveOnly),
            "durable" => Some(Self::Durable),
            _ => None,
        }
    }
}

impl std::fmt::Display for EventPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The cell's current marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPlaneMarker {
    /// The plane in force.
    pub plane: EventPlane,
    /// The latest transition's sequence, or 0 when none was ever written.
    pub transition_seq: i64,
    /// When that transition was written. `None` for a cell with no transition.
    pub transitioned_at: Option<SystemTime>,
}

impl EventPlaneMarker {
    /// The marker of a cell that never switched: `durable`, as every cell was
    /// before the marker existed.
    const fn never_switched() -> Self {
        Self {
            plane: EventPlane::Durable,
            transition_seq: 0,
            transitioned_at: None,
        }
    }
}

/// What boot needs to decide whether a configured plane may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPlaneBootFacts {
    /// The marker in force.
    pub marker: EventPlaneMarker,
    /// Whether `lore_outbox_events` holds any row for the cell, in any state.
    pub has_outbox_rows: bool,
}

/// The outcome of [`set_event_plane`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetEventPlaneOutcome {
    /// The switch committed.
    Applied {
        /// The plane before.
        from: EventPlane,
        /// The plane now.
        to: EventPlane,
        /// The transition row's sequence.
        transition_seq: i64,
        /// How many outbox rows moved to the evidence table.
        retired_rows: i64,
    },
    /// The cell was already in the requested plane. Nothing was written.
    AlreadyCurrent {
        /// The plane in force.
        plane: EventPlane,
    },
}

/// Read the cell's marker. A cell with no transition row is `durable`.
///
/// # Errors
/// `InvalidInput` for a malformed `cell_id`; a database failure otherwise, and
/// `Internal` for a stored plane this build cannot parse.
pub async fn read_event_plane(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<EventPlaneMarker, DomainError> {
    validate_cell_id(cell_id)?;
    let row = client
        .query_opt(
            "SELECT to_plane, transition_seq, transitioned_at \
               FROM lore_outbox_event_plane_transitions \
              WHERE cell_id = $1 \
              ORDER BY transition_seq DESC \
              LIMIT 1",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("event plane marker read", e))?;
    let Some(row) = row else {
        return Ok(EventPlaneMarker::never_switched());
    };
    let stored: String = row.get("to_plane");
    let plane = EventPlane::parse(&stored).ok_or_else(|| {
        DomainError::Internal(format!(
            "event plane marker for cell {cell_id} holds an unknown plane {stored:?}"
        ))
    })?;
    Ok(EventPlaneMarker {
        plane,
        transition_seq: row.get("transition_seq"),
        transitioned_at: Some(row.get("transitioned_at")),
    })
}

/// Read the marker and whether the cell has any outbox row, for the boot gate.
///
/// # Errors
/// As [`read_event_plane`].
pub async fn read_boot_facts(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<EventPlaneBootFacts, DomainError> {
    let marker = read_event_plane(client, cell_id).await?;
    let has_outbox_rows = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM lore_outbox_events WHERE cell_id = $1) AS present",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("event plane outbox row probe", e))?
        .get("present");
    Ok(EventPlaneBootFacts {
        marker,
        has_outbox_rows,
    })
}

/// Switch the cell's event plane, offline, in one transaction.
///
/// `own_backends` is how many connections the caller's own pool holds to this
/// database. They are subtracted from `numbackends`; every other backend
/// refuses the switch.
///
/// Rerunning after a lost commit reply is safe: a switch that committed
/// reports [`SetEventPlaneOutcome::AlreadyCurrent`] on the rerun.
///
/// # Errors
/// * `InvalidInput` — malformed `cell_id`, or an empty or over-wide actor or
///   reason.
/// * `Contention` — another backend is connected, or holds the outbox table.
/// * `NotReady` — a switch to `live_only` while `pending` rows exist, or a
///   switch to `durable` while outbox rows exist.
/// * `OutcomeUnknown` — the commit reply was lost; rerun to reconcile.
pub async fn set_event_plane(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    target: EventPlane,
    actor: &str,
    reason: &str,
    own_backends: i64,
) -> Result<SetEventPlaneOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    bounded("event_plane_actor", actor, MAX_DISPOSITION_ACTOR_BYTES)?;
    bounded("event_plane_reason", reason, MAX_DISPOSITION_REASON_BYTES)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("event plane switch begin", e))?;
    tx.batch_execute("SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '120s'")
        .await
        .map_err(|e| DomainError::from_pg("event plane switch bounds", e))?;
    // The schema advisory lock: no installer runs DDL under the switch.
    tx.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&crate::pool::SCHEMA_LOCK_KEY],
    )
    .await
    .map_err(|e| DomainError::from_pg("event plane switch schema lock", e))?;
    refuse_other_backends(&tx, own_backends).await?;
    if let Err(error) = tx
        .batch_execute(
            "LOCK TABLE lore_outbox_events, lore_outbox_event_plane_transitions, \
             lore_outbox_retired_events IN ACCESS EXCLUSIVE MODE NOWAIT",
        )
        .await
    {
        if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) {
            return Err(DomainError::Contention(
                "event plane switch refused: a live session holds an outbox table; stop every \
                 loreserver replica of this cell first"
                    .into(),
            ));
        }
        return Err(DomainError::from_pg("event plane switch table lock", error));
    }

    // `deadpool_postgres::Transaction` derefs to the `tokio_postgres` one, which
    // is the type the generic reader is bound on.
    let current = read_event_plane(&*tx, cell_id).await?;
    if current.plane == target {
        // Read-only. The transaction rolls back on drop.
        return Ok(SetEventPlaneOutcome::AlreadyCurrent { plane: target });
    }

    let counts = tx
        .query_one(
            "SELECT count(*) FILTER (WHERE state = 'pending') AS pending, \
                    count(*) FILTER (WHERE state IN ('broker_accepted', 'consumer_safe')) \
                        AS published, \
                    count(*) AS total \
               FROM lore_outbox_events \
              WHERE cell_id = $1",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("event plane switch backlog count", e))?;
    let pending: i64 = counts.get("pending");
    let published: i64 = counts.get("published");
    let total: i64 = counts.get("total");

    let retired_rows = match target {
        EventPlane::LiveOnly => {
            if pending > 0 {
                return Err(DomainError::NotReady(format!(
                    "event plane switch to live_only refused: cell {cell_id} has {pending} \
                     pending outbox row(s) that were never published; drain them in durable mode \
                     first, then rerun"
                )));
            }
            published
        }
        EventPlane::Durable => {
            if total > 0 {
                return Err(DomainError::NotReady(format!(
                    "event plane switch to durable refused: cell {cell_id} is live_only but holds \
                     {total} outbox row(s); a live_only cell must hold none"
                )));
            }
            0
        }
    };

    let transition_seq = current.transition_seq + 1;
    tx.execute(
        "INSERT INTO lore_outbox_event_plane_transitions \
             (cell_id, transition_seq, from_plane, to_plane, actor, reason, retired_rows, \
              transitioned_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp())",
        &[
            &cell_id,
            &transition_seq,
            &current.plane.as_str(),
            &target.as_str(),
            &actor,
            &reason,
            &retired_rows,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("event plane transition insert", e))?;

    if target == EventPlane::LiveOnly && retired_rows > 0 {
        let moved = tx
            .execute(
                "WITH moved AS ( \
                     DELETE FROM lore_outbox_events \
                      WHERE cell_id = $1 \
                        AND state IN ('broker_accepted', 'consumer_safe') \
                     RETURNING * \
                 ) \
                 INSERT INTO lore_outbox_retired_events \
                     (event_id, cell_id, transition_seq, idempotency_key, repository_id, \
                      repository_generation, event_kind, aggregate_kind, aggregate_id, \
                      aggregate_version, payload_schema_version, payload, state_at_retirement, \
                      created_at, unpublished_since, claim_generation, attempt_count, \
                      stream_identity, stream_epoch, broker_sequence, gateway_response_id, \
                      publisher_contract_version, broker_accepted_at, replay_count, replayed_at, \
                      replay_actor, replay_reason, disposition, disposition_actor, \
                      disposition_reason, disposition_at) \
                 SELECT event_id, cell_id, $2, idempotency_key, repository_id, \
                        repository_generation, event_kind, aggregate_kind, aggregate_id, \
                        aggregate_version, payload_schema_version, payload, state, created_at, \
                        unpublished_since, claim_generation, attempt_count, stream_identity, \
                        stream_epoch, broker_sequence, gateway_response_id, \
                        publisher_contract_version, broker_accepted_at, replay_count, replayed_at, \
                        replay_actor, replay_reason, $3, $4, $5, clock_timestamp() \
                   FROM moved",
                &[
                    &cell_id,
                    &transition_seq,
                    &RETIRED_LIVE_ONLY,
                    &actor,
                    &reason,
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("event plane retire rows", e))?;
        if i64::try_from(moved).unwrap_or(i64::MAX) != retired_rows {
            return Err(DomainError::Internal(format!(
                "event plane switch counted {retired_rows} published row(s) but moved {moved}; \
                 nothing was committed"
            )));
        }
    }

    // A live_only cell holds no outbox row at all. Proven under the same lock
    // that made the counts above stable, before the commit.
    if target == EventPlane::LiveOnly {
        let remaining: i64 = tx
            .query_one(
                "SELECT count(*) FROM lore_outbox_events WHERE cell_id = $1",
                &[&cell_id],
            )
            .await
            .map_err(|e| DomainError::from_pg("event plane switch residue probe", e))?
            .get(0);
        if remaining != 0 {
            return Err(DomainError::Internal(format!(
                "event plane switch left {remaining} outbox row(s) for cell {cell_id}; nothing \
                 was committed"
            )));
        }
    }

    // A replica that connected during the switch is blocked on the table locks
    // now and would act on the old plane after commit.
    refuse_other_backends(&tx, own_backends).await?;
    // A lost commit reply is safe to rerun, unlike a governed mutation's: the
    // rerun reads the marker and reports `AlreadyCurrent` if this committed.
    tx.commit().await.map_err(|e| {
        DomainError::OutcomeUnknown(format!(
            "event plane switch commit: {e}; rerun the same command to reconcile"
        ))
    })?;
    Ok(SetEventPlaneOutcome::Applied {
        from: current.plane,
        to: target,
        transition_seq,
        retired_rows,
    })
}

/// Refuse while any backend outside the caller's pool is connected to the cell
/// database.
///
/// `numbackends` counts every backend whatever its role, where
/// `pg_stat_activity` hides other roles' sessions from an unprivileged caller
/// (CR-038 measured this on PostgreSQL 16). A backend that is still exiting gets
/// a short bounded wait.
async fn refuse_other_backends(tx: &Transaction<'_>, own_backends: i64) -> Result<(), DomainError> {
    let mut others = 0;
    for attempt in 0..BACKEND_SETTLE_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(BACKEND_SETTLE_INTERVAL).await;
        }
        // Statistics are snapshotted per transaction; take a fresh one.
        tx.batch_execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
            .await
            .map_err(|e| DomainError::from_pg("event plane switch statistics snapshot", e))?;
        let connected: i64 = tx
            .query_one(
                "SELECT numbackends::bigint FROM pg_catalog.pg_stat_database \
                  WHERE datname = pg_catalog.current_database()",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("event plane switch backend count", e))?
            .get(0);
        others = connected.saturating_sub(own_backends);
        if others <= 0 {
            return Ok(());
        }
    }
    Err(DomainError::Contention(format!(
        "event plane switch refused: {others} other backend(s) are connected to the cell \
         database; stop every loreserver replica and other client, then rerun"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plane_spellings_round_trip_and_nothing_else_parses() {
        for plane in [EventPlane::LiveOnly, EventPlane::Durable] {
            assert_eq!(EventPlane::parse(plane.as_str()), Some(plane));
        }
        for other in ["", "live-only", "LIVE_ONLY", "Durable", "remote", "local"] {
            assert_eq!(EventPlane::parse(other), None, "{other:?}");
        }
    }

    #[test]
    fn a_cell_that_never_switched_is_durable() {
        let marker = EventPlaneMarker::never_switched();
        assert_eq!(marker.plane, EventPlane::Durable);
        assert_eq!(marker.transition_seq, 0);
        assert_eq!(marker.transitioned_at, None);
    }

    #[test]
    fn the_boot_schema_is_the_migration_file() {
        assert!(EVENT_PLANE_SCHEMA.contains("lore_outbox_event_plane_transitions"));
        assert!(EVENT_PLANE_SCHEMA.contains("lore_outbox_retired_events"));
        assert!(EVENT_PLANE_SCHEMA.contains(RETIRED_LIVE_ONLY));
    }
}

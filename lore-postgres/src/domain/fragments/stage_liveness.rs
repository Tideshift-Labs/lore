// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-115 K11: per-replica stage liveness, exchanged through the cell's
//! Postgres so a stage replica can tell "my mount is stale" from "the stage is
//! stale for everyone".
//!
//! Each replica publishes a count of its own fully successful stage probes,
//! with a process incarnation id. A stale replica looks for a peer whose
//! count goes up after it went stale. Time is used only to stop old progress
//! from looking new:
//!
//! - The stored count never goes down for one incarnation.
//! - A higher count is accepted only if the success it reports was at most
//!   `fresh_within` old when the statement was sent, and the statement runs
//!   by a database-time deadline (the publisher's last view of the database
//!   clock, plus the local time since, plus `deadline`). A statement that a
//!   slow network or a stalled host delays past its sender's own timeout
//!   changes nothing.
//! - `progressed_at` is the database time at which the last increase ran. An
//!   observer counts an increase only if it ran after the observer's earlier
//!   view, so an increase that ran before that view but committed after it
//!   proves nothing.
//! - The fresh-and-on-time test is made once, in the inserted row's
//!   `progressed_at`: the statement time when it passes, else the Unix epoch,
//!   which no observer can count. A new incarnation's row (an insert, or a
//!   replacement of another incarnation's row) takes that stamp as is, so a
//!   row that goes X, Y, X with a stale X success comes back with X's higher
//!   count but an epoch stamp. An observer that missed Y then sees a higher
//!   count it cannot count. No path stamps a time without the test.

use super::*;

/// The boot-time declaration of the liveness table. An `include_str!` of the
/// migration, so the two cannot drift.
pub const STAGE_LIVENESS_SCHEMA: &str =
    include_str!("../../../migrations/0010_write_behind_stage_liveness.sql");

/// The longest `cell_id` or `replica_id` the table accepts, in bytes.
pub const MAX_STAGE_LIVENESS_ID_BYTES: usize = 128;
/// The longest `incarnation` the table accepts, in bytes.
pub const MAX_STAGE_LIVENESS_INCARNATION_BYTES: usize = 64;

/// One replica's progress row as an exchange read it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StageProgressRecord {
    pub incarnation: String,
    pub progress: i64,
    /// Database time of the last accepted increase, in microseconds since the
    /// Unix epoch. A row first written for this incarnation carries the
    /// statement time only if that write passed the fresh-and-on-time test,
    /// else 0 (the Unix epoch), which never counts as progress.
    pub progressed_micros: i64,
}

/// One peer's row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StagePeerProgress {
    pub replica_id: String,
    pub record: StageProgressRecord,
}

/// What one exchange learned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StagePeerLiveness {
    /// Every peer row of this cell (this replica's own row excluded), as the
    /// statement's snapshot saw it.
    pub peers: Vec<StagePeerProgress>,
    /// This replica's own row as the statement found it, before the upsert.
    /// `None` when there was no row.
    pub prior: Option<StageProgressRecord>,
    /// This replica's own row as the statement left it. If the next exchange
    /// finds a different prior row, another process publishes under the same
    /// `replica_id`.
    pub published: Option<StageProgressRecord>,
    /// `clock_timestamp()` during the statement, in microseconds since the
    /// Unix epoch. It is no earlier than the statement's snapshot and no
    /// later than the reply, so it is a safe "after this view" mark for an
    /// observer and a safe clock anchor for the next deadline.
    pub db_clock_micros: i64,
}

/// The publisher's last view of the database clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageLivenessClock {
    /// [`StagePeerLiveness::db_clock_micros`] of a successful exchange.
    pub db_micros: i64,
    /// When that exchange's reply arrived, on the publisher's clock. The
    /// database time it names is no later than this instant.
    pub received: Instant,
}

/// What a replica publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageLivenessPublication {
    /// Unique per process, so a restart starts a new sequence.
    pub incarnation: String,
    /// Fully successful probes so far in this incarnation.
    pub progress: u64,
    /// When the last of those succeeded, on the publisher's clock.
    pub last_good: Instant,
    /// `None` before the first successful exchange: then no increase is
    /// accepted (a first row for a new incarnation is still written).
    pub clock: Option<StageLivenessClock>,
}

/// The bounds of one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageLivenessLimits {
    /// The oldest success an increase may report.
    pub fresh_within: Duration,
    /// How long after it is sent an increase may still run.
    pub deadline: Duration,
    /// `statement_timeout` for this exchange's transaction only.
    pub statement_timeout: Duration,
    /// Rows not published for this long are deleted.
    pub retain: Duration,
}

fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

fn record(
    incarnation: Option<String>,
    progress: Option<i64>,
    progressed_micros: Option<i64>,
) -> Option<StageProgressRecord> {
    Some(StageProgressRecord {
        incarnation: incarnation?,
        progress: progress?,
        progressed_micros: progressed_micros?,
    })
}

impl PostgresFragmentCoordinator {
    /// Delete this replica's row, so its peers stop counting it.
    ///
    /// A replica calls this when it starts to drain (lame duck or SIGTERM).
    /// Returns whether a row was deleted.
    pub async fn withdraw_stage_liveness(
        &self,
        cell_id: &str,
        replica_id: &str,
    ) -> Result<bool, DomainError> {
        let client = self.checkout().await?;
        let deleted = client
            .execute(
                "DELETE FROM lore_domain_write_behind_stage_progress \
                 WHERE cell_id = $1 AND replica_id = $2",
                &[&cell_id, &replica_id],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage liveness withdraw", error))?;
        Ok(deleted > 0)
    }

    /// Publish this replica's probe progress and read its peers'.
    ///
    /// One transaction with its own `statement_timeout`, so a stuck statement
    /// cannot pile up on the shared pool; the setting ends with the
    /// transaction. One statement inside it: the upsert, the prune of rows not
    /// published for `retain`, and the read of every peer row of the cell.
    ///
    /// The success age and the deadline are measured after the checkout,
    /// right before the statement is sent.
    pub async fn exchange_stage_liveness(
        &self,
        cell_id: &str,
        replica_id: &str,
        publication: &StageLivenessPublication,
        limits: StageLivenessLimits,
    ) -> Result<StagePeerLiveness, DomainError> {
        for (field, value, max) in [
            ("cell_id", cell_id, MAX_STAGE_LIVENESS_ID_BYTES),
            ("replica_id", replica_id, MAX_STAGE_LIVENESS_ID_BYTES),
            (
                "incarnation",
                publication.incarnation.as_str(),
                MAX_STAGE_LIVENESS_INCARNATION_BYTES,
            ),
        ] {
            if value.is_empty() || value.len() > max {
                return Err(DomainError::Internal(format!(
                    "stage liveness {field} must be 1..={max} bytes"
                )));
            }
        }
        let progress = i64::try_from(publication.progress).map_err(|error| {
            DomainError::Internal(format!("stage liveness progress is out of range: {error}"))
        })?;
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage liveness transaction", error))?;
        let timeout = format!("{}ms", limits.statement_timeout.as_millis().max(1));
        tx.execute(
            "SELECT set_config('statement_timeout', $1, true)",
            &[&timeout],
        )
        .await
        .map_err(|error| {
            DomainError::from_pg_detailed("stage liveness statement timeout", error)
        })?;
        // Measured after the checkout: see the doc comment.
        let sent = Instant::now();
        let last_good_age = sent.saturating_duration_since(publication.last_good);
        let deadline_micros: Option<i64> = publication.clock.map(|clock| {
            clock
                .db_micros
                .saturating_add(micros(sent.saturating_duration_since(clock.received)))
                .saturating_add(micros(limits.deadline))
        });
        // Every CTE reads the snapshot from before the upsert, so `prior` is
        // this replica's row as another writer may have left it and `peers`
        // excludes this statement's own write.
        let row = tx
            .query_one(
                "WITH prior AS ( \
                   SELECT incarnation, progress, \
                     (extract(epoch FROM progressed_at) * 1000000)::bigint AS progressed_micros \
                   FROM lore_domain_write_behind_stage_progress \
                   WHERE cell_id = $1 AND replica_id = $2), \
                 published AS ( \
                   INSERT INTO lore_domain_write_behind_stage_progress AS stored \
                     (cell_id, replica_id, incarnation, progress, progressed_at, published_at) \
                   VALUES ($1, $2, $3, $4, \
                     CASE WHEN $5::double precision <= $6::double precision \
                       AND $7::bigint IS NOT NULL \
                       AND (extract(epoch FROM clock_timestamp()) * 1000000)::bigint <= $7::bigint \
                     THEN clock_timestamp() ELSE 'epoch'::timestamptz END, \
                     now()) \
                   ON CONFLICT (cell_id, replica_id) DO UPDATE SET \
                     incarnation = EXCLUDED.incarnation, \
                     (progress, progressed_at) = ( \
                       SELECT \
                         CASE WHEN take THEN EXCLUDED.progress ELSE stored.progress END, \
                         CASE WHEN take THEN EXCLUDED.progressed_at ELSE stored.progressed_at END \
                       FROM (SELECT stored.incarnation <> EXCLUDED.incarnation \
                         OR (EXCLUDED.progress > stored.progress \
                           AND EXCLUDED.progressed_at > 'epoch'::timestamptz) AS take) AS decision), \
                     published_at = EXCLUDED.published_at \
                   RETURNING incarnation, progress, \
                     (extract(epoch FROM progressed_at) * 1000000)::bigint AS progressed_micros), \
                 pruned AS ( \
                   DELETE FROM lore_domain_write_behind_stage_progress \
                   WHERE cell_id = $1 AND replica_id <> $2 \
                     AND published_at < now() - make_interval(secs => $8::double precision) \
                   RETURNING 1), \
                 peers AS ( \
                   SELECT replica_id, incarnation, progress, \
                     (extract(epoch FROM progressed_at) * 1000000)::bigint AS progressed_micros \
                   FROM lore_domain_write_behind_stage_progress \
                   WHERE cell_id = $1 AND replica_id <> $2) \
                 SELECT \
                   coalesce((SELECT array_agg(replica_id ORDER BY replica_id) FROM peers), \
                     '{}'::text[]) AS peer_ids, \
                   coalesce((SELECT array_agg(incarnation ORDER BY replica_id) FROM peers), \
                     '{}'::text[]) AS peer_incarnations, \
                   coalesce((SELECT array_agg(progress ORDER BY replica_id) FROM peers), \
                     '{}'::bigint[]) AS peer_progress, \
                   coalesce((SELECT array_agg(progressed_micros ORDER BY replica_id) FROM peers), \
                     '{}'::bigint[]) AS peer_progressed, \
                   (SELECT count(*) FROM published)::bigint AS published, \
                   (SELECT incarnation FROM published) AS published_incarnation, \
                   (SELECT progress FROM published) AS published_progress, \
                   (SELECT progressed_micros FROM published) AS published_progressed, \
                   (SELECT incarnation FROM prior) AS prior_incarnation, \
                   (SELECT progress FROM prior) AS prior_progress, \
                   (SELECT progressed_micros FROM prior) AS prior_progressed, \
                   (SELECT count(*) FROM pruned)::bigint AS pruned, \
                   (extract(epoch FROM clock_timestamp()) * 1000000)::bigint AS db_clock_micros",
                &[
                    &cell_id,
                    &replica_id,
                    &publication.incarnation,
                    &progress,
                    &last_good_age.as_secs_f64(),
                    &limits.fresh_within.as_secs_f64(),
                    &deadline_micros,
                    &limits.retain.as_secs_f64(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage liveness exchange", error))?;
        tx.commit()
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage liveness commit", error))?;
        if row.get::<_, i64>("published") != 1 {
            return Err(DomainError::Internal(
                "stage liveness exchange did not publish this replica".to_owned(),
            ));
        }
        let ids: Vec<String> = row.get("peer_ids");
        let incarnations: Vec<String> = row.get("peer_incarnations");
        let progress: Vec<i64> = row.get("peer_progress");
        let progressed: Vec<i64> = row.get("peer_progressed");
        if [incarnations.len(), progress.len(), progressed.len()] != [ids.len(); 3] {
            return Err(DomainError::Internal(
                "stage liveness exchange returned uneven peer columns".to_owned(),
            ));
        }
        let peers = ids
            .into_iter()
            .zip(incarnations)
            .zip(progress)
            .zip(progressed)
            .map(
                |(((replica_id, incarnation), progress), progressed_micros)| StagePeerProgress {
                    replica_id,
                    record: StageProgressRecord {
                        incarnation,
                        progress,
                        progressed_micros,
                    },
                },
            )
            .collect();
        Ok(StagePeerLiveness {
            peers,
            prior: record(
                row.get("prior_incarnation"),
                row.get("prior_progress"),
                row.get("prior_progressed"),
            ),
            published: record(
                row.get("published_incarnation"),
                row.get("published_progress"),
                row.get("published_progressed"),
            ),
            db_clock_micros: row.get("db_clock_micros"),
        })
    }
}

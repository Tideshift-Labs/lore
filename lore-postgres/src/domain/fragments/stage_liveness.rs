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

/// The boot-time declaration of the drain guard's one relation (WP-115 drain
/// guard): the stager of each staged representation. An `include_str!` of
/// the migration, so the two cannot drift.
pub const DRAIN_GUARD_SCHEMA: &str =
    include_str!("../../../migrations/0011_write_behind_drain_guard.sql");

/// The longest `cell_id` or `replica_id` the table accepts, in bytes.
pub const MAX_STAGE_LIVENESS_ID_BYTES: usize = 128;
/// The longest `incarnation` the table accepts, in bytes.
pub const MAX_STAGE_LIVENESS_INCARNATION_BYTES: usize = 64;

/// The web replica process that staged one representation: its liveness
/// replica id and incarnation. Recorded with the stage custody reservation
/// (WP-115 drain guard).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StagerIdentity {
    pub replica_id: String,
    pub incarnation: String,
}

impl StagerIdentity {
    /// A stager identity, or `None` when either part is empty or too long
    /// for the table.
    pub fn new(replica_id: &str, incarnation: &str) -> Option<Self> {
        let fits = |value: &str, max: usize| !value.is_empty() && value.len() <= max;
        (fits(replica_id, MAX_STAGE_LIVENESS_ID_BYTES)
            && fits(incarnation, MAX_STAGE_LIVENESS_INCARNATION_BYTES))
        .then(|| Self {
            replica_id: replica_id.to_owned(),
            incarnation: incarnation.to_owned(),
        })
    }
}

/// What the drain guard knows about one staged representation it cannot
/// find in its own stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagerAbsence {
    /// Its stager was confirmed in the reader's stage directory: the file is
    /// really gone, so it may read as absent.
    Confirmed,
    /// Its stager was confirmed, but the representation was published
    /// `Staged` less than the minimum staged age ago (database clock), or
    /// its epoch row is not found. A copy of the stage kept in step by a
    /// sync tool may not carry the file yet, so it is not read as absent
    /// yet (review B S1 of round 4).
    TooRecent,
    /// Its stager was not confirmed by this reader process. It may have
    /// staged the file into another directory.
    Unconfirmed,
    /// No stager is recorded (an older binary, stage liveness off, or a
    /// full-role replica). Never read as absent through the drain guard.
    NoStager,
}

/// What one drain guard prune deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainGuardPrune {
    /// Stager rows whose representation no longer has a live custody row.
    pub stagers: u64,
    /// Prune statements run. Each is its own transaction.
    pub passes: u32,
}

/// Record `stager` as the stager of `(hash, epoch)`, in the transaction that
/// reserves its stage custody. The epoch was just taken from the fence
/// sequence, so no other row can hold its key.
///
/// Call it BEFORE `stage_custody::reserve_stage_locked`: that statement
/// updates the cell-wide `lore_fragment_stage_usage` row, and every
/// `begin_stage` in the cell waits on that row lock until this transaction
/// ends. A round trip after it is paid by the whole cell (review S1).
pub(super) async fn record_stager_locked(
    tx: &Transaction<'_>,
    hash: &[u8],
    epoch: i64,
    stager: &StagerIdentity,
) -> Result<(), DomainError> {
    tx.execute_cached(
        "INSERT INTO lore_domain_write_behind_stagers (hash, epoch, replica_id, incarnation) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (hash, epoch) DO NOTHING",
        &[&hash, &epoch, &stager.replica_id, &stager.incarnation],
    )
    .await
    .map_err(|error| DomainError::from_pg("stage stager record", error))?;
    Ok(())
}

/// Run `pass` until one deletes fewer than `limit` rows, at most
/// `max_passes` times. A single bounded pass per tick is slower than a busy
/// drain creates rows (review S2), so the table would grow without bound.
/// Returns the rows deleted and the passes run. Stops at the first error.
pub async fn prune_in_passes<F, Fut, E>(
    limit: u64,
    max_passes: u32,
    mut pass: F,
) -> Result<DrainGuardPrune, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<u64, E>>,
{
    let mut total = DrainGuardPrune::default();
    while total.passes < max_passes.max(1) {
        let deleted = pass().await?;
        total.passes += 1;
        total.stagers = total.stagers.saturating_add(deleted);
        if deleted < limit {
            break;
        }
    }
    Ok(total)
}

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

/// Which kind of replica published a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StageLivenessRole {
    /// A `role = "stage"` web replica. Also every row an older binary wrote.
    #[default]
    Stage,
    /// The `role = "drain"` worker, while a read-back of its own stage marker
    /// shows its current incarnation. It anchors the K11 shared-stage check
    /// and is never a K11 eject peer.
    Drain,
    /// The drain worker while its own marker read-back fails or is too old.
    /// Not an anchor, and not a K11 eject peer either.
    DrainUnverified,
}

impl StageLivenessRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Drain => "drain",
            Self::DrainUnverified => "drain_unverified",
        }
    }

    /// Decode a stored value. Anything not named here (also NULL) is
    /// `Stage`.
    pub fn from_stored(value: Option<&str>) -> Self {
        match value {
            Some("drain") => Self::Drain,
            Some("drain_unverified") => Self::DrainUnverified,
            _ => Self::Stage,
        }
    }
}

/// One peer's row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StagePeerProgress {
    pub replica_id: String,
    pub record: StageProgressRecord,
    /// Database time of the peer's last publication, in microseconds since
    /// the Unix epoch.
    pub published_micros: i64,
    /// Who published the row.
    pub role: StageLivenessRole,
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
    /// Who publishes.
    pub role: StageLivenessRole,
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
        //
        // `stamp` reads `clock_timestamp()` once. The deadline test and the
        // stored `progressed_at` use that one value, so the stored time is
        // exactly the time that passed the test.
        //
        // The stamp is taken when the insert row is built, which is before
        // any wait for this row's lock in `ON CONFLICT`. That is safe: the
        // proof (`lore_server::stage_liveness`, steps 3 to 5) uses only the
        // stored stamp `p` (it must pass the deadline and be later than the
        // observer's baseline clock). A commit later than `p` can only hide
        // the increase from views taken between `p` and the commit, so they
        // err toward "no eject". The transaction's `statement_timeout` bounds
        // the wait. Only this process writes this row (assumption A3), so the
        // wait is normally zero.
        let row = tx
            .query_one(
                "WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS at), \
                 prior AS ( \
                   SELECT incarnation, progress, \
                     (extract(epoch FROM progressed_at) * 1000000)::bigint AS progressed_micros \
                   FROM lore_domain_write_behind_stage_progress \
                   WHERE cell_id = $1 AND replica_id = $2), \
                 published AS ( \
                   INSERT INTO lore_domain_write_behind_stage_progress AS stored \
                     (cell_id, replica_id, incarnation, progress, progressed_at, published_at, \
                      role) \
                   VALUES ($1, $2, $3, $4, \
                     (SELECT CASE WHEN $5::double precision <= $6::double precision \
                       AND $7::bigint IS NOT NULL \
                       AND (extract(epoch FROM stamp.at) * 1000000)::bigint <= $7::bigint \
                     THEN stamp.at ELSE 'epoch'::timestamptz END FROM stamp), \
                     now(), $9) \
                   ON CONFLICT (cell_id, replica_id) DO UPDATE SET \
                     incarnation = EXCLUDED.incarnation, \
                     (progress, progressed_at) = ( \
                       SELECT \
                         CASE WHEN take THEN EXCLUDED.progress ELSE stored.progress END, \
                         CASE WHEN take THEN EXCLUDED.progressed_at ELSE stored.progressed_at END \
                       FROM (SELECT stored.incarnation <> EXCLUDED.incarnation \
                         OR (EXCLUDED.progress > stored.progress \
                           AND EXCLUDED.progressed_at > 'epoch'::timestamptz) AS take) AS decision), \
                     published_at = EXCLUDED.published_at, \
                     role = EXCLUDED.role \
                   RETURNING incarnation, progress, \
                     (extract(epoch FROM progressed_at) * 1000000)::bigint AS progressed_micros), \
                 pruned AS ( \
                   DELETE FROM lore_domain_write_behind_stage_progress \
                   WHERE cell_id = $1 AND replica_id <> $2 \
                     AND published_at < now() - make_interval(secs => $8::double precision) \
                   RETURNING 1), \
                 peers AS ( \
                   SELECT replica_id, incarnation, progress, \
                     (extract(epoch FROM progressed_at) * 1000000)::bigint AS progressed_micros, \
                     (extract(epoch FROM published_at) * 1000000)::bigint AS published_micros, \
                     role \
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
                   coalesce((SELECT array_agg(published_micros ORDER BY replica_id) FROM peers), \
                     '{}'::bigint[]) AS peer_published, \
                   coalesce((SELECT array_agg(role ORDER BY replica_id) FROM peers), \
                     '{}'::text[]) AS peer_roles, \
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
                    &publication.role.as_str(),
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
        let published_at: Vec<i64> = row.get("peer_published");
        let roles: Vec<Option<String>> = row.get("peer_roles");
        if [
            incarnations.len(),
            progress.len(),
            progressed.len(),
            published_at.len(),
            roles.len(),
        ] != [ids.len(); 5]
        {
            return Err(DomainError::Internal(
                "stage liveness exchange returned uneven peer columns".to_owned(),
            ));
        }
        let peers = ids
            .into_iter()
            .zip(incarnations)
            .zip(progress)
            .zip(progressed)
            .zip(published_at)
            .zip(roles)
            .map(
                |(
                    ((((replica_id, incarnation), progress), progressed_micros), published_micros),
                    role,
                )| StagePeerProgress {
                    replica_id,
                    role: StageLivenessRole::from_stored(role.as_deref()),
                    record: StageProgressRecord {
                        incarnation,
                        progress,
                        progressed_micros,
                    },
                    published_micros,
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

    /// WP-115 drain guard: the web replica process recorded as the stager of
    /// `(hash, epoch)`, and whether that representation's epoch row was
    /// published at least `min_age` ago by the database clock (`false` when
    /// the epoch row is not found; always `true` for a zero `min_age`, which
    /// asks for no minimum), or `None` when no stager is recorded. One read.
    pub async fn stager_of(
        &self,
        hash: &[u8],
        epoch: i64,
        min_age: std::time::Duration,
    ) -> Result<Option<(StagerIdentity, bool)>, DomainError> {
        let min_age_ms = i64::try_from(min_age.as_millis()).unwrap_or(i64::MAX);
        let client = self.checkout().await?;
        let row = if min_age_ms <= 0 {
            client
                .query_opt(
                    "SELECT replica_id, incarnation, true AS settled \
                     FROM lore_domain_write_behind_stagers \
                     WHERE hash = $1 AND epoch = $2",
                    &[&hash, &epoch],
                )
                .await
        } else {
            // The epoch row of a `Staged` representation is inserted by
            // `commit_staged`, after the stager made its file durable, so its
            // `created_at` is the earliest time the file existed in the
            // stager's directory.
            client
                .query_opt(
                    "SELECT s.replica_id, s.incarnation, \
                            COALESCE((SELECT e.created_at <= clock_timestamp() \
                                             - ($3::bigint * interval '1 millisecond') \
                                      FROM lore_fragment_epochs e \
                                      WHERE e.hash = s.hash AND e.epoch = s.epoch), false) \
                            AS settled \
                     FROM lore_domain_write_behind_stagers s \
                     WHERE s.hash = $1 AND s.epoch = $2",
                    &[&hash, &epoch, &min_age_ms],
                )
                .await
        }
        .map_err(|error| DomainError::from_pg_detailed("drain guard stager read", error))?;
        Ok(row.map(|row| {
            (
                StagerIdentity {
                    replica_id: row.get("replica_id"),
                    incarnation: row.get("incarnation"),
                },
                row.get("settled"),
            )
        }))
    }

    /// WP-115 drain guard: whether the stager of `(hash, epoch)` is one the
    /// calling reader process confirmed in its own stage (`confirmed`), and
    /// whether the representation was published `Staged` at least `min_age`
    /// ago. The confirmations live in the reader's memory, for its current
    /// incarnation only; nothing about them is stored.
    pub async fn stager_absence(
        &self,
        hash: &[u8],
        epoch: i64,
        min_age: std::time::Duration,
        confirmed: &(dyn Fn(&StagerIdentity) -> bool + Send + Sync),
    ) -> Result<StagerAbsence, DomainError> {
        Ok(match self.stager_of(hash, epoch, min_age).await? {
            None => StagerAbsence::NoStager,
            Some((stager, _)) if !confirmed(&stager) => StagerAbsence::Unconfirmed,
            Some((_, false)) => StagerAbsence::TooRecent,
            Some((_, true)) => StagerAbsence::Confirmed,
        })
    }

    /// WP-115 drain guard: whether `hash`'s lifecycle head is still `Staged`
    /// at `epoch`. A staged read that found no file and could not prove it
    /// gone asks this: when the head moved (a promotion and purge, or an
    /// obliterate, won the race), the miss says nothing about the fragment,
    /// and the read must answer for the new head instead of `SlowDown`.
    pub async fn staged_head_current(&self, hash: &[u8], epoch: i64) -> Result<bool, DomainError> {
        let client = self.checkout().await?;
        let row = client
            .query_opt(
                "SELECT 1 FROM lore_fragment_lifecycle \
                 WHERE hash = $1 AND current_epoch = $2 AND state = $3",
                &[&hash, &epoch, &FragmentLifecycleState::Staged.bits()],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("staged head read", error))?;
        Ok(row.is_some())
    }

    /// WP-115 drain guard: delete stager rows whose representation has no
    /// live stage custody row (no row, or a released `state = 3` tombstone),
    /// at most `limit` per pass, in passes until one deletes fewer than
    /// `limit`, at most `max_passes` ([`prune_in_passes`]).
    ///
    /// Safe against a concurrent `begin_stage`: its stager row commits with
    /// its custody row, so a pass sees both or neither. Each pass is one
    /// transaction with its own `statement_timeout`, so a statement a caller
    /// stopped waiting for cannot run on.
    pub async fn prune_drain_guard(
        &self,
        limit: i64,
        max_passes: u32,
        statement_timeout: Duration,
    ) -> Result<DrainGuardPrune, DomainError> {
        let limit = limit.max(1);
        prune_in_passes(u64::try_from(limit).unwrap_or(1), max_passes, || {
            self.prune_drain_guard_pass(limit, statement_timeout)
        })
        .await
    }

    async fn prune_drain_guard_pass(
        &self,
        limit: i64,
        statement_timeout: Duration,
    ) -> Result<u64, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client.transaction().await.map_err(|error| {
            DomainError::from_pg_detailed("drain guard prune transaction", error)
        })?;
        let timeout = format!("{}ms", statement_timeout.as_millis().max(1));
        tx.execute(
            "SELECT set_config('statement_timeout', $1, true)",
            &[&timeout],
        )
        .await
        .map_err(|error| DomainError::from_pg_detailed("drain guard prune timeout", error))?;
        let deleted = tx
            .execute(
                "WITH gone AS ( \
                   SELECT s.hash, s.epoch FROM lore_domain_write_behind_stagers s \
                   WHERE NOT EXISTS ( \
                     SELECT 1 FROM lore_fragment_stage_custody c \
                     WHERE c.hash = s.hash AND c.epoch = s.epoch AND c.state <> 3) \
                   LIMIT $1) \
                 DELETE FROM lore_domain_write_behind_stagers s USING gone g \
                 WHERE s.hash = g.hash AND s.epoch = g.epoch",
                &[&limit],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("drain guard prune", error))?;
        tx.commit()
            .await
            .map_err(|error| DomainError::from_pg_detailed("drain guard prune commit", error))?;
        Ok(deleted)
    }
}

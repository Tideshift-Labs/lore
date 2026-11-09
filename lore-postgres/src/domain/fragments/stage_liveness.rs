// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-115 K11: per-replica stage liveness, exchanged through the cell's
//! Postgres so a stage replica can tell "my mount is stale" from "the stage is
//! stale for everyone".
//!
//! Every timestamp is the database clock (`now()`). A replica reports only how
//! long ago, on its own monotonic clock, its last good probe was; the database
//! turns that into a time. Freshness is decided in SQL against the same clock,
//! so host clock skew cannot make a peer look fresh or stale.

use super::*;

/// The boot-time declaration of the liveness table. An `include_str!` of the
/// migration, so the two cannot drift.
pub const STAGE_LIVENESS_SCHEMA: &str =
    include_str!("../../../migrations/0010_write_behind_stage_liveness.sql");

/// The longest `cell_id` or `replica_id` the table accepts, in bytes.
pub const MAX_STAGE_LIVENESS_ID_BYTES: usize = 128;

/// What one exchange learned about this replica's peers in the same cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StagePeerLiveness {
    /// Peers whose last good probe is within the freshness window.
    pub fresh_peers: u64,
    /// Fresh peers whose last good probe is more than the margin AFTER this
    /// replica's own. Only these prove that the stage was writable for a peer
    /// after this replica stopped writing. In a cell-wide hang every probe
    /// stops at about the same time, so no peer proves anything.
    pub proving_peers: u64,
    /// Every peer row of this cell, fresh or not.
    pub peers: u64,
    /// This replica's own `last_good_at` as the statement found it, before
    /// the upsert, in microseconds since the Unix epoch on the database clock.
    /// `None` when there was no row.
    pub prior_last_good_micros: Option<i64>,
    /// This replica's own `last_good_at` as the statement left it, in the same
    /// unit. If the next exchange finds a different prior value, another
    /// process publishes under the same `replica_id`.
    pub published_last_good_micros: Option<i64>,
}

impl PostgresFragmentCoordinator {
    /// Delete this replica's row, so its peers stop counting it as fresh.
    ///
    /// A replica calls this when it starts to drain (lame duck or SIGTERM).
    /// Without it, a draining peer still reads fresh for up to the freshness
    /// window, and a peer whose own mount is stale ejects itself while the
    /// draining one leaves: the cell goes dark. Returns whether a row was
    /// deleted.
    pub async fn withdraw_stage_liveness(
        &self,
        cell_id: &str,
        replica_id: &str,
    ) -> Result<bool, DomainError> {
        let client = self.checkout().await?;
        let deleted = client
            .execute(
                "DELETE FROM lore_domain_write_behind_liveness \
                 WHERE cell_id = $1 AND replica_id = $2",
                &[&cell_id, &replica_id],
            )
            .await
            .map_err(|error| DomainError::from_pg("stage liveness withdraw", error))?;
        Ok(deleted > 0)
    }

    /// Publish this replica's last good stage probe and count fresh peers.
    ///
    /// One statement: the upsert, the prune of rows not published for
    /// `retain`, and the count. The count excludes this replica's own row.
    ///
    /// `last_good` is when this replica's last good probe was, on its own
    /// monotonic clock. The age is measured only after the pool checkout, so
    /// a slow checkout does not make the published time look fresher than it
    /// is. What remains is the time from the measurement to the statement's
    /// `now()`, which the caller's exchange timeout bounds.
    ///
    /// `fresh_within` is the freshness window. `prove_margin` is how much
    /// later than this replica's own last good probe a peer's must be to count
    /// in [`StagePeerLiveness::proving_peers`]. Both timestamps compared are
    /// database time.
    pub async fn exchange_stage_liveness(
        &self,
        cell_id: &str,
        replica_id: &str,
        last_good: Instant,
        fresh_within: Duration,
        prove_margin: Duration,
        retain: Duration,
    ) -> Result<StagePeerLiveness, DomainError> {
        for (field, value) in [("cell_id", cell_id), ("replica_id", replica_id)] {
            if value.is_empty() || value.len() > MAX_STAGE_LIVENESS_ID_BYTES {
                return Err(DomainError::Internal(format!(
                    "stage liveness {field} must be 1..={MAX_STAGE_LIVENESS_ID_BYTES} bytes"
                )));
            }
        }
        let client = self.checkout().await?;
        // Measured after the checkout: see the doc comment.
        let last_good_age = Instant::now().saturating_duration_since(last_good);
        // Every CTE and the outer SELECT read the snapshot from before the
        // upsert, so `prior` is this replica's row as another writer may
        // have left it, and the outer count sees peers only.
        let row = client
            .query_one(
                "WITH prior AS ( \
                   SELECT (extract(epoch FROM last_good_at) * 1000000)::bigint AS micros \
                   FROM lore_domain_write_behind_liveness \
                   WHERE cell_id = $1 AND replica_id = $2), \
                 published AS ( \
                   INSERT INTO lore_domain_write_behind_liveness \
                     (cell_id, replica_id, last_good_at, published_at) \
                   VALUES ($1, $2, now() - make_interval(secs => $3::double precision), now()) \
                   ON CONFLICT (cell_id, replica_id) DO UPDATE \
                     SET last_good_at = EXCLUDED.last_good_at, \
                         published_at = EXCLUDED.published_at \
                   RETURNING last_good_at, \
                     (extract(epoch FROM last_good_at) * 1000000)::bigint AS micros), \
                 pruned AS ( \
                   DELETE FROM lore_domain_write_behind_liveness \
                   WHERE cell_id = $1 AND replica_id <> $2 \
                     AND published_at < now() - make_interval(secs => $5::double precision) \
                   RETURNING 1) \
                 SELECT \
                   count(*) FILTER ( \
                     WHERE now() - last_good_at < make_interval(secs => $4::double precision) \
                   )::bigint AS fresh_peers, \
                   count(*) FILTER ( \
                     WHERE now() - last_good_at < make_interval(secs => $4::double precision) \
                       AND last_good_at > (SELECT last_good_at FROM published) \
                         + make_interval(secs => $6::double precision) \
                   )::bigint AS proving_peers, \
                   count(*)::bigint AS peers, \
                   (SELECT count(*) FROM published)::bigint AS published, \
                   (SELECT micros FROM published) AS published_micros, \
                   (SELECT micros FROM prior) AS prior_micros, \
                   (SELECT count(*) FROM pruned)::bigint AS pruned \
                 FROM lore_domain_write_behind_liveness \
                 WHERE cell_id = $1 AND replica_id <> $2",
                &[
                    &cell_id,
                    &replica_id,
                    &last_good_age.as_secs_f64(),
                    &fresh_within.as_secs_f64(),
                    &retain.as_secs_f64(),
                    &prove_margin.as_secs_f64(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("stage liveness exchange", error))?;
        let count = |name: &str| -> u64 {
            let value: i64 = row.get(name);
            u64::try_from(value).unwrap_or(0)
        };
        if count("published") != 1 {
            return Err(DomainError::Internal(
                "stage liveness exchange did not publish this replica".to_owned(),
            ));
        }
        Ok(StagePeerLiveness {
            fresh_peers: count("fresh_peers"),
            proving_peers: count("proving_peers"),
            peers: count("peers"),
            prior_last_good_micros: row.get("prior_micros"),
            published_last_good_micros: row.get("published_micros"),
        })
    }
}

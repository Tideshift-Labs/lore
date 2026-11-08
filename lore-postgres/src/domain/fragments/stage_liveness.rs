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
    /// Every peer row of this cell, fresh or not.
    pub peers: u64,
}

impl PostgresFragmentCoordinator {
    /// Publish this replica's last good stage probe and count fresh peers.
    ///
    /// One statement: the upsert, the prune of rows not published for
    /// `retain`, and the count. The count excludes this replica's own row.
    ///
    /// `last_good_age` is how long ago this replica's last good probe was,
    /// measured on its own clock. `fresh_within` is the freshness window.
    pub async fn exchange_stage_liveness(
        &self,
        cell_id: &str,
        replica_id: &str,
        last_good_age: Duration,
        fresh_within: Duration,
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
        let row = client
            .query_one(
                "WITH published AS ( \
                   INSERT INTO lore_domain_write_behind_liveness \
                     (cell_id, replica_id, last_good_at, published_at) \
                   VALUES ($1, $2, now() - make_interval(secs => $3::double precision), now()) \
                   ON CONFLICT (cell_id, replica_id) DO UPDATE \
                     SET last_good_at = EXCLUDED.last_good_at, \
                         published_at = EXCLUDED.published_at \
                   RETURNING 1), \
                 pruned AS ( \
                   DELETE FROM lore_domain_write_behind_liveness \
                   WHERE cell_id = $1 AND replica_id <> $2 \
                     AND published_at < now() - make_interval(secs => $5::double precision) \
                   RETURNING 1) \
                 SELECT \
                   count(*) FILTER ( \
                     WHERE now() - last_good_at < make_interval(secs => $4::double precision) \
                   )::bigint AS fresh_peers, \
                   count(*)::bigint AS peers, \
                   (SELECT count(*) FROM published)::bigint AS published, \
                   (SELECT count(*) FROM pruned)::bigint AS pruned \
                 FROM lore_domain_write_behind_liveness \
                 WHERE cell_id = $1 AND replica_id <> $2",
                &[
                    &cell_id,
                    &replica_id,
                    &last_good_age.as_secs_f64(),
                    &fresh_within.as_secs_f64(),
                    &retain.as_secs_f64(),
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
            peers: count("peers"),
        })
    }
}

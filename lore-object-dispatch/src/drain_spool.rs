// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Exact expiry-based spool cleanup. This module has no provider capability.

use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::drain_policy::DrainClient;
use crate::drain_policy::DrainError;
use crate::spool::SpoolLayout;
use crate::spool::SpoolObjectKey;
use crate::spool::SpoolObjectKind;
use crate::spool_writer::LinuxSpoolWriter;
use crate::spool_writer::MAX_SPOOL_BODY_BYTES;
use crate::spool_writer::SpoolWriteError;

/// How far the retired floor trails the database clock (migration 0032's `900000`). It must cover
/// the time from minting a write claim's `UUIDv7` attempt id in a replica to reserving it, at most
/// the provider send timeout, plus clock skew between replicas and the database and an NTP step
/// allowance (CR-041). A replica whose clock lags by more than the rest of this window has its
/// reservations refused; the floor itself stays sound at any skew.
pub const RETIRED_FLOOR_WINDOW_MS: i64 = 900_000;

pub struct DrainCleanupIntent {
    spool: Uuid,
    fence: i64,
    key: SpoolObjectKey,
}

impl DrainCleanupIntent {
    /// Call on a bounded blocking lane, retain ownership until the syscall finishes.
    pub fn unlink(&self, layout: &SpoolLayout) -> Result<(), SpoolWriteError> {
        LinuxSpoolWriter::open(layout, MAX_SPOOL_BODY_BYTES)?
            .purge_put_body(layout, &self.key)
            .map(|_| ())
    }

    pub fn unlink_with_writer(
        &self,
        layout: &SpoolLayout,
        writer: &LinuxSpoolWriter,
    ) -> Result<bool, SpoolWriteError> {
        writer.purge_put_body(layout, &self.key)
    }
}

impl DrainClient {
    /// Lease up to `batch` due rows for this caller (migration 0029).
    ///
    /// This is the one drain call below `SERIALIZABLE`. It picks rows `FOR UPDATE SKIP LOCKED` and
    /// leases them for 30 s, so two replicas take disjoint rows. Under `SERIALIZABLE` two such
    /// scans of one index page read each other's leased rows and abort with 40001, which is the
    /// head contention the lease removes. `READ COMMITTED` is sound here because the lease is only
    /// a hint about who scans a row first. Claim, release and compaction stay `SERIALIZABLE` and
    /// keep every fence and state check, so a wrong or lost lease can only delay a row.
    pub async fn cleanup_candidates(
        &self,
        boundary: &str,
        cell: &str,
        batch: u16,
    ) -> Result<Vec<Uuid>, DrainError> {
        let rows = self
            .query_at(
                IsolationLevel::ReadCommitted,
                "SELECT spool FROM object_store_retention.drain_cleanup_candidates_v1($1,$2,$3)",
                &[&boundary, &cell, &i32::from(batch)],
            )
            .await?;
        rows.into_iter()
            .map(|r| r.try_get(0).map_err(|_error| DrainError::Invalid))
            .collect()
    }

    /// A row another replica already deleted reads as [`DrainError::Contended`]: that replica did
    /// this row's work.
    ///
    /// A contended claim also clears this caller's lease on the row, best effort, so the row is
    /// due again at once rather than after the lease. The claim rolled back, so this caller holds
    /// nothing; the lease only kept every other replica away for 30 s.
    pub async fn claim_cleanup(&self, spool: Uuid) -> Result<DrainCleanupIntent, DrainError> {
        let rows = match self
            .query(
                "SELECT * FROM object_store_retention.drain_cleanup_claim_v2($1)",
                &[&spool],
            )
            .await
        {
            Err(DrainError::Contended) => {
                self.unlease(spool).await;
                return Err(DrainError::Contended);
            }
            other => other?,
        };
        let r = rows.first().ok_or(DrainError::Contended)?;
        Ok(DrainCleanupIntent {
            spool,
            fence: r.try_get(3).map_err(|_error| DrainError::Invalid)?,
            key: SpoolObjectKey {
                provider_boundary_id: r.try_get(0).map_err(|_error| DrainError::Invalid)?,
                logical_request_id: r
                    .try_get::<_, Uuid>(1)
                    .map_err(|_error| DrainError::Invalid)?
                    .to_string(),
                attempt_id: r
                    .try_get::<_, Uuid>(2)
                    .map_err(|_error| DrainError::Invalid)?
                    .to_string(),
                kind: SpoolObjectKind::Put,
            },
        })
    }

    /// Clear a lease, best effort and below `SERIALIZABLE` like the lease itself. A row another
    /// session holds is skipped: that session is working on it. A failure only leaves the lease.
    async fn unlease(&self, spool: Uuid) {
        let _ = self
            .query_at(
                IsolationLevel::ReadCommitted,
                "SELECT object_store_retention.drain_cleanup_unlease_v1($1)",
                &[&spool],
            )
            .await;
    }

    /// Call only after this intent's unlink finished.
    pub async fn release_cleanup(&self, intent: &DrainCleanupIntent) -> Result<(), DrainError> {
        let result = self.release_and_compact(intent).await;
        if result == Err(DrainError::MetadataUnderflow) {
            tracing::warn!(
                spool = %intent.spool,
                "drain cleanup skipped a row: giving back its metadata charge would underflow the \
                 policy counters; the row is left for an operator"
            );
        }
        result
    }

    async fn release_and_compact(&self, intent: &DrainCleanupIntent) -> Result<(), DrainError> {
        self.query(
            "SELECT object_store_retention.drain_cleanup_release_v1($1,$2)",
            &[&intent.spool, &intent.fence],
        )
        .await?;
        // The release above has committed. Compaction deletes the released row (migration 0032);
        // one lost to another replica is redone on the row's next re-scan, so it must not read as
        // a release that committed nothing.
        match self
            .query(
                "SELECT object_store_retention.drain_cleanup_compact_v3($1)",
                &[&intent.spool],
            )
            .await
        {
            Ok(_) | Err(DrainError::Contended) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Raise the cell's retired floor and return it (migration 0032). No custody row of the cell
    /// is older than the floor and no first-seen reservation below it is accepted, so a spool body
    /// whose `UUIDv7` attempt is older than the returned value has no row and never will.
    pub async fn advance_retired_floor(
        &self,
        boundary: &str,
        cell: &str,
    ) -> Result<i64, DrainError> {
        let rows = self
            .query(
                "SELECT object_store_retention.drain_retired_floor_advance_v1($1,$2)",
                &[&boundary, &cell],
            )
            .await?;
        rows.first()
            .ok_or(DrainError::Invalid)?
            .try_get(0)
            .map_err(|_error| DrainError::Invalid)
    }
}

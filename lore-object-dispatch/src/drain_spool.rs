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

pub struct DrainCleanupIntent {
    spool: Uuid,
    fence: i64,
    /// Database time of this intent's own claim. Compaction deletes a superseded marker only when
    /// this claim, which precedes this intent's unlink, came after the marker's fence.
    scanned_ms: i64,
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
    pub async fn claim_cleanup(&self, spool: Uuid) -> Result<DrainCleanupIntent, DrainError> {
        let rows = self
            .query(
                "SELECT * FROM object_store_retention.drain_cleanup_claim_v2($1)",
                &[&spool],
            )
            .await?;
        let r = rows.first().ok_or(DrainError::Contended)?;
        Ok(DrainCleanupIntent {
            spool,
            fence: r.try_get(3).map_err(|_error| DrainError::Invalid)?,
            scanned_ms: r.try_get(4).map_err(|_error| DrainError::Invalid)?,
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

    /// Call only after this intent's unlink finished.
    pub async fn release_cleanup(&self, intent: &DrainCleanupIntent) -> Result<(), DrainError> {
        self.query(
            "SELECT object_store_retention.drain_cleanup_release_v1($1,$2)",
            &[&intent.spool, &intent.fence],
        )
        .await?;
        // The release above has committed. A compaction lost to another replica is redone on the
        // row's next re-scan, so it must not read as a release that committed nothing.
        match self
            .query(
                "SELECT object_store_retention.drain_cleanup_compact_v2($1,$2)",
                &[&intent.spool, &intent.scanned_ms],
            )
            .await
        {
            Ok(_) | Err(DrainError::Contended) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

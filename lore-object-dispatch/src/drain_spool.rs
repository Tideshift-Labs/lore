// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Exact expiry-based spool cleanup. This module has no provider capability.

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
    pub async fn cleanup_candidates(
        &self,
        boundary: &str,
        cell: &str,
        batch: u16,
    ) -> Result<Vec<Uuid>, DrainError> {
        let rows = self
            .query(
                "SELECT spool FROM object_store_retention.drain_cleanup_candidates_v1($1,$2,$3)",
                &[&boundary, &cell, &i32::from(batch)],
            )
            .await?;
        rows.into_iter()
            .map(|r| r.try_get(0).map_err(|_error| DrainError::Invalid))
            .collect()
    }

    pub async fn claim_cleanup(&self, spool: Uuid) -> Result<DrainCleanupIntent, DrainError> {
        let rows = self
            .query(
                "SELECT * FROM object_store_retention.drain_cleanup_claim_v1($1)",
                &[&spool],
            )
            .await?;
        let r = rows.first().ok_or(DrainError::Refused)?;
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

    pub async fn release_cleanup(&self, intent: &DrainCleanupIntent) -> Result<(), DrainError> {
        self.query(
            "SELECT object_store_retention.drain_cleanup_release_v1($1,$2)",
            &[&intent.spool, &intent.fence],
        )
        .await?;
        self.query(
            "SELECT object_store_retention.drain_cleanup_compact_v1($1)",
            &[&intent.spool],
        )
        .await?;
        Ok(())
    }
}

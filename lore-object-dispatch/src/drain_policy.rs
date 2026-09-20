// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Maintenance-owned drain policy and immutable reservation descriptors.

use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio_postgres::IsolationLevel;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::dispatch_pool::DispatchRuntimePool;

/// Values are local spool capacity, never customer billing limits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DrainPolicy {
    pub boundary: String,
    pub cell: String,
    pub service: String,
    pub revision: String,
    pub quota_revision: u64,
    /// Scope order: boundary, cell, internal service. Each scope is
    /// bytes/rows/concurrency/low-water-bytes/low-water-rows/low-water-concurrency.
    pub quotas: [[u64; 6]; 3],
    pub maximum_ttl_ms: u64,
    pub expires_at_ms: u64,
    pub metadata_max_rows: u64,
    pub metadata_max_bytes: u64,
    pub stage: DrainStagePolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DrainStagePolicy {
    pub max_bytes: u64,
    pub max_files: u64,
    pub max_metadata_bytes: u64,
    pub max_metadata_rows: u64,
    pub prepare_ttl_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DrainDescriptor {
    pub policy_revision: String,
    pub policy_digest: String,
    pub boundary: String,
    pub cell: String,
    pub service: String,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub upload_id: Uuid,
    pub spool_object_id: Uuid,
    pub upload_fence: u64,
    pub source_hash: String,
    pub source_epoch: u64,
    pub source_manifest: String,
    pub remote_epoch: u64,
    pub remote_fence: u64,
    pub object_key: String,
    pub body_digest: String,
    pub body_size: u64,
    pub send_not_after_ms: u64,
    pub hard_not_after_ms: u64,
    pub prepared_ttl_ms: u64,
    pub max_chunk_bytes: u64,
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub allocation_expiry_ms: u64,
    pub boundary_digest: String,
    pub boundary_token: String,
    pub observation_digest: String,
}

impl std::fmt::Debug for DrainDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DrainDescriptor([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DrainError {
    #[error("drain descriptor or policy is invalid")]
    Invalid,
    #[error("drain authority refused the operation")]
    Refused,
    #[error("drain authority is unavailable; the operation may have committed")]
    Unavailable,
}

fn framed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DrainError> {
    let len = u32::try_from(bytes.len()).map_err(|_error| DrainError::Invalid)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

pub fn decode_digest(value: &str) -> Result<[u8; 32], DrainError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(DrainError::Invalid);
    }
    let mut result = [0; 32];
    for (index, target) in result.iter_mut().enumerate() {
        *target = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_error| DrainError::Invalid)?;
    }
    Ok(result)
}

impl DrainPolicy {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DrainError> {
        let mut bytes = b"fragment-drain-policy-v1".to_vec();
        for value in [&self.boundary, &self.cell, &self.service, &self.revision] {
            if value.is_empty() || value.len() > 256 {
                return Err(DrainError::Invalid);
            }
            framed(&mut bytes, value.as_bytes())?;
        }
        if self.boundary == self.cell
            || self.boundary == self.service
            || self.cell == self.service
            || self.quota_revision == 0
            || self.maximum_ttl_ms == 0
            || self.expires_at_ms > i64::MAX as u64
            || self.maximum_ttl_ms > i64::MAX as u64
            || self.metadata_max_rows == 0
            || self.metadata_max_bytes < 16384
        {
            return Err(DrainError::Invalid);
        }
        bytes.extend_from_slice(&self.quota_revision.to_be_bytes());
        for scope in self.quotas {
            for index in 0..3 {
                if scope[index] == 0 || scope[index + 3] >= scope[index] {
                    return Err(DrainError::Invalid);
                }
            }
            for value in scope {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        for value in [
            self.maximum_ttl_ms,
            self.expires_at_ms,
            self.metadata_max_rows,
            self.metadata_max_bytes,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.stage.max_bytes,
            self.stage.max_files,
            self.stage.max_metadata_bytes,
            self.stage.max_metadata_rows,
            self.stage.prepare_ttl_ms,
        ] {
            if value == 0 || value > i64::MAX as u64 {
                return Err(DrainError::Invalid);
            }
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        if self.stage.max_metadata_bytes < 1024 || self.stage.prepare_ttl_ms > i32::MAX as u64 {
            return Err(DrainError::Invalid);
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<[u8; 32], DrainError> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }
}

impl DrainDescriptor {
    /// Allocation renewal pins are checked separately and deliberately excluded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DrainError> {
        let mut bytes = b"fragment-drain-reservation-v1".to_vec();
        for value in [
            &self.policy_revision,
            &self.policy_digest,
            &self.boundary,
            &self.cell,
            &self.service,
        ] {
            if value.is_empty() || value.len() > 256 {
                return Err(DrainError::Invalid);
            }
            framed(&mut bytes, value.as_bytes())?;
        }
        for id in [
            self.logical_request_id,
            self.attempt_id,
            self.upload_id,
            self.spool_object_id,
        ] {
            if id.get_version_num() != 7 {
                return Err(DrainError::Invalid);
            }
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes.extend_from_slice(&self.upload_fence.to_be_bytes());
        framed(&mut bytes, self.source_hash.as_bytes())?;
        bytes.extend_from_slice(&self.source_epoch.to_be_bytes());
        framed(&mut bytes, &decode_digest(&self.source_manifest)?)?;
        bytes.extend_from_slice(&self.remote_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.remote_fence.to_be_bytes());
        framed(&mut bytes, self.object_key.as_bytes())?;
        framed(&mut bytes, &decode_digest(&self.body_digest)?)?;
        for value in [
            self.body_size,
            self.send_not_after_ms,
            self.hard_not_after_ms,
            self.prepared_ttl_ms,
            self.max_chunk_bytes,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        if bytes.len() > 8192
            || self.body_size > 262144
            || self.upload_fence == 0
            || self.prepared_ttl_ms == 0
            || self.send_not_after_ms > self.hard_not_after_ms
            || self.hard_not_after_ms > i64::MAX as u64
            || self.max_chunk_bytes != 262144
        {
            return Err(DrainError::Invalid);
        }
        Ok(bytes)
    }
}

/// Owns only a reference to the existing dispatch pool.
#[derive(Clone)]
pub struct DrainClient {
    pool: Arc<DispatchRuntimePool>,
}

#[derive(Clone, Copy, Debug)]
pub struct DrainObservation {
    pub spool_bytes: u64,
    pub spool_files: u64,
    pub cleanup_backlog: u64,
    pub metadata_full: bool,
}

impl DrainClient {
    pub fn new(pool: Arc<DispatchRuntimePool>) -> Self {
        Self { pool }
    }

    pub async fn observe(
        &self,
        boundary: &str,
        cell: &str,
    ) -> Result<DrainObservation, DrainError> {
        let rows = self
            .query(
                "SELECT * FROM object_store_retention.drain_observe_v1($1,$2)",
                &[&boundary, &cell],
            )
            .await?;
        let r = rows.first().ok_or(DrainError::Refused)?;
        Ok(DrainObservation {
            spool_bytes: r
                .try_get::<_, &str>(0)
                .map_err(|_error| DrainError::Invalid)?
                .parse()
                .map_err(|_error| DrainError::Invalid)?,
            spool_files: r
                .try_get::<_, &str>(1)
                .map_err(|_error| DrainError::Invalid)?
                .parse()
                .map_err(|_error| DrainError::Invalid)?,
            cleanup_backlog: u64::try_from(
                r.try_get::<_, i64>(2)
                    .map_err(|_error| DrainError::Invalid)?,
            )
            .map_err(|_error| DrainError::Invalid)?,
            metadata_full: r.try_get(3).map_err(|_error| DrainError::Invalid)?,
        })
    }

    /// All SQL goes through bounded serializable transactions. An uncertain response
    /// preserves the caller's descriptor; no retry creates a replacement identity.
    pub(crate) async fn query(
        &self,
        sql: &str,
        values: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Row>, DrainError> {
        let mut lease = self
            .pool
            .acquire()
            .await
            .map_err(|_error| DrainError::Unavailable)?;
        let operation = tokio::time::timeout(self.pool.operation_timeout(), async {
            let client = lease.client().map_err(|_error| DrainError::Unavailable)?;
            let tx = client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
                .await
                .map_err(|_error| DrainError::Unavailable)?;
            tx.batch_execute(&self.pool.bounded_execution_preamble())
                .await
                .map_err(|_error| DrainError::Unavailable)?;
            let rows = tx.query(sql, values).await.map_err(|e| {
                if e.code().is_some() {
                    DrainError::Refused
                } else {
                    DrainError::Unavailable
                }
            })?;
            tx.commit()
                .await
                .map_err(|_error| DrainError::Unavailable)?;
            Ok(rows)
        })
        .await;
        match operation {
            Ok(Ok(rows)) => {
                lease.release().await;
                Ok(rows)
            }
            Ok(Err(error)) => {
                lease.poison();
                Err(error)
            }
            Err(_) => {
                lease.poison();
                Err(DrainError::Unavailable)
            }
        }
    }

    pub async fn publish(&self, policy: &DrainPolicy) -> Result<(), DrainError> {
        let json = serde_json::to_string(policy).map_err(|_error| DrainError::Invalid)?;
        self.query(
            "SELECT object_store_retention.drain_policy_publish_v1($1::text::jsonb,$2,$3)",
            &[&json, &policy.canonical_bytes()?, &&policy.digest()?[..]],
        )
        .await?;
        Ok(())
    }

    pub async fn configure(&self, policy: &DrainPolicy, publish: bool) -> Result<(), DrainError> {
        let json = serde_json::to_string(policy).map_err(|_error| DrainError::Invalid)?;
        let canonical = policy.canonical_bytes()?;
        let digest = policy.digest()?;
        if publish {
            self.query("SELECT object_store_retention.drain_policy_publish_v1($1::text::jsonb,$2,$3), public.stage_policy_publish_v1($4,$5,$3,$6,$7,$8,$9,$10,$11)",
                &[&json,&canonical,&&digest[..],&policy.cell,&policy.revision,
                &i64::try_from(policy.stage.max_bytes).map_err(|_error|DrainError::Invalid)?,
                &i64::try_from(policy.stage.max_files).map_err(|_error|DrainError::Invalid)?,
                &i64::try_from(policy.stage.max_metadata_bytes).map_err(|_error|DrainError::Invalid)?,
                &i64::try_from(policy.stage.max_metadata_rows).map_err(|_error|DrainError::Invalid)?,
                &i64::try_from(policy.stage.prepare_ttl_ms).map_err(|_error|DrainError::Invalid)?,
                &i64::try_from(policy.expires_at_ms).map_err(|_error|DrainError::Invalid)?]).await?;
        } else {
            self.query(
                "SELECT object_store_retention.drain_policy_verify_v1($1::text::jsonb,$2,$3)",
                &[&json, &canonical, &&digest[..]],
            )
            .await?;
            let rows = self
                .query(
                    "SELECT public.stage_policy_verify_v1($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                    &[
                        &policy.cell,
                        &policy.revision,
                        &&digest[..],
                        &i64::try_from(policy.stage.max_bytes)
                            .map_err(|_error| DrainError::Invalid)?,
                        &i64::try_from(policy.stage.max_files)
                            .map_err(|_error| DrainError::Invalid)?,
                        &i64::try_from(policy.stage.max_metadata_bytes)
                            .map_err(|_error| DrainError::Invalid)?,
                        &i64::try_from(policy.stage.max_metadata_rows)
                            .map_err(|_error| DrainError::Invalid)?,
                        &i64::try_from(policy.stage.prepare_ttl_ms)
                            .map_err(|_error| DrainError::Invalid)?,
                        &i64::try_from(policy.expires_at_ms)
                            .map_err(|_error| DrainError::Invalid)?,
                    ],
                )
                .await?;
            if rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()) != Some(true) {
                return Err(DrainError::Refused);
            }
        }
        Ok(())
    }

    /// Offline, atomic replacement of both policy stores. The operator must
    /// stop and exclude all replicas first. Revision strings strictly increase
    /// in `PostgreSQL` `C` byte order; retained custody and counters never reset.
    /// Retry a lost reply with the exact same new policy and predecessor pins.
    pub async fn rotate(
        &self,
        policy: &DrainPolicy,
        previous_revision: &str,
        previous_digest: &[u8; 32],
    ) -> Result<(), DrainError> {
        let json = serde_json::to_string(policy).map_err(|_error| DrainError::Invalid)?;
        self.query(
            "SELECT object_store_retention.drain_policy_rotate_v1($1::text::jsonb,$2,$3,$4,$5)",
            &[
                &json,
                &policy.canonical_bytes()?,
                &&policy.digest()?[..],
                &previous_revision,
                &&previous_digest[..],
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn read(
        &self,
        boundary: &str,
        cell: &str,
        revision: &str,
        digest: &[u8; 32],
    ) -> Result<(DrainPolicy, String, u64, u64), DrainError> {
        let (policy, revision, fence, expiry, _) =
            self.read_clocked(boundary, cell, revision, digest).await?;
        Ok((policy, revision, fence, expiry))
    }

    /// Check configured work bounds against trusted lifetimes before activation.
    /// Database time anchors expiry; round-trip time can only shorten its window.
    pub async fn verify_activation_window(
        &self,
        boundary: &str,
        cell: &str,
        revision: &str,
        digest: &[u8; 32],
        preparation: std::time::Duration,
        send: std::time::Duration,
    ) -> Result<(), DrainError> {
        let started = std::time::Instant::now();
        let (policy, _, _, allocation_expiry, observed_ms) =
            self.read_clocked(boundary, cell, revision, digest).await?;
        let required = preparation.checked_add(send).ok_or(DrainError::Invalid)?;
        let required_ms =
            u64::try_from(required.as_millis()).map_err(|_error| DrainError::Invalid)?;
        let preparation_ms =
            u64::try_from(preparation.as_millis()).map_err(|_error| DrainError::Invalid)?;
        let elapsed_ms =
            u64::try_from(started.elapsed().as_millis()).map_err(|_error| DrainError::Invalid)?;
        let end = observed_ms
            .checked_add(required_ms)
            .and_then(|at| at.checked_add(elapsed_ms))
            .ok_or(DrainError::Invalid)?;
        if preparation.is_zero()
            || send.is_zero()
            || policy.maximum_ttl_ms < required_ms
            || policy.stage.prepare_ttl_ms < preparation_ms
            || policy.expires_at_ms <= end
            || allocation_expiry <= end
        {
            return Err(DrainError::Refused);
        }
        Ok(())
    }

    async fn read_clocked(
        &self,
        boundary: &str,
        cell: &str,
        revision: &str,
        digest: &[u8; 32],
    ) -> Result<(DrainPolicy, String, u64, u64, u64), DrainError> {
        let rows = self.query("SELECT policy::text, allocation_revision, allocation_fence::text, allocation_expiry_ms, observed_at_ms FROM object_store_retention.drain_policy_read_v1($1,$2,$3,$4)", &[&boundary,&cell,&revision,&&digest[..]]).await?;
        let row = rows.first().ok_or(DrainError::Refused)?;
        let policy: DrainPolicy = serde_json::from_str(
            row.try_get::<_, &str>(0)
                .map_err(|_error| DrainError::Invalid)?,
        )
        .map_err(|_error| DrainError::Invalid)?;
        if policy.digest()? != *digest {
            return Err(DrainError::Invalid);
        }
        Ok((
            policy,
            row.try_get(1).map_err(|_error| DrainError::Invalid)?,
            row.try_get::<_, &str>(2)
                .map_err(|_error| DrainError::Invalid)?
                .parse()
                .map_err(|_error| DrainError::Invalid)?,
            u64::try_from(
                row.try_get::<_, i64>(3)
                    .map_err(|_error| DrainError::Invalid)?,
            )
            .map_err(|_error| DrainError::Invalid)?,
            u64::try_from(
                row.try_get::<_, i64>(4)
                    .map_err(|_error| DrainError::Invalid)?,
            )
            .map_err(|_error| DrainError::Invalid)?,
        ))
    }

    pub async fn reserve(&self, descriptor: &DrainDescriptor) -> Result<(), DrainError> {
        let json = serde_json::to_string(descriptor).map_err(|_error| DrainError::Invalid)?;
        let canonical = descriptor.canonical_bytes()?;
        self.query(
            "SELECT object_store_retention.drain_reserve_v1($1::text::jsonb,$2,$3)",
            &[&json, &canonical, &&blake3::hash(&canonical).as_bytes()[..]],
        )
        .await?;
        Ok(())
    }

    pub async fn check_ready(
        &self,
        spool: Uuid,
        attempt: Uuid,
        record: &[u8; 32],
        key: &str,
        deadline: i64,
    ) -> Result<(i64, u64), DrainError> {
        let rows = self
            .query(
                "SELECT * FROM object_store_retention.drain_check_ready_v1($1,$2,$3,$4,$5)",
                &[&spool, &attempt, &&record[..], &key, &deadline],
            )
            .await?;
        let row = rows.first().ok_or(DrainError::Refused)?;
        Ok((
            row.try_get(0).map_err(|_error| DrainError::Invalid)?,
            u64::try_from(
                row.try_get::<_, i64>(1)
                    .map_err(|_error| DrainError::Invalid)?,
            )
            .map_err(|_error| DrainError::Invalid)?,
        ))
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Maintenance-owned drain policy and immutable reservation descriptors.

use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio_postgres::IsolationLevel;
use tokio_postgres::Row;
use tokio_postgres::error::SqlState;
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

/// The cell schema revision this build ships (CR-038). Migration 0030's
/// `cell_schema_revision_v1()` returns it; write-behind refuses to start on any other value.
pub const CELL_SCHEMA_REVISION: i32 = 30;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DrainError {
    #[error("drain descriptor or policy is invalid")]
    Invalid,
    #[error("drain authority refused the operation")]
    Refused,
    #[error("drain authority is unavailable; the operation may have committed")]
    Unavailable,
    /// Another session held or had just changed the same row. Nothing committed. Two replicas
    /// scanning one cell meet this routinely, so it is not a refusal of the operation itself.
    #[error("drain authority lost a race for the same row to another session; nothing committed")]
    Contended,
    #[error(
        "the cell schema is older than this build: stop every replica and run `cell-schema-install upgrade`"
    )]
    SchemaUpgradeRequired,
    #[error("the cell schema revision is not one this build knows; refusing write-behind")]
    SchemaUnknown,
    /// `DRAIN_METADATA_UNDERFLOW`: giving back this row's metadata charge would take the policy's
    /// counters below zero. Nothing committed. That is a bookkeeping fault on one row, so cleanup
    /// skips the row and leaves it for an operator rather than failing its whole pass.
    #[error("the drain metadata counters would underflow; this row is left for an operator")]
    MetadataUnderflow,
}

/// Serialization failure, lock timeout and deadlock each roll the transaction back. They report
/// a race with another session, not a verdict on the operation.
fn is_contention(code: &SqlState) -> bool {
    *code == SqlState::T_R_SERIALIZATION_FAILURE
        || *code == SqlState::LOCK_NOT_AVAILABLE
        || *code == SqlState::T_R_DEADLOCK_DETECTED
}

/// A statement error with a SQLSTATE is the authority's answer; without one the outcome is unknown.
fn statement_error(code: Option<&SqlState>) -> DrainError {
    match code {
        Some(code) if is_contention(code) => DrainError::Contended,
        Some(_) => DrainError::Refused,
        None => DrainError::Unavailable,
    }
}

/// [`statement_error`], except that the one authority refusal a caller acts on by name is kept.
fn statement_error_of(error: &tokio_postgres::Error) -> DrainError {
    match error.as_db_error() {
        Some(db) if db.message() == "DRAIN_METADATA_UNDERFLOW" => DrainError::MetadataUnderflow,
        _ => statement_error(error.code()),
    }
}

/// A commit that reports contention rolled back. Any other commit failure may have committed.
fn commit_error(code: Option<&SqlState>) -> DrainError {
    match code {
        Some(code) if is_contention(code) => DrainError::Contended,
        _ => DrainError::Unavailable,
    }
}

/// Why one drain authority call failed, finer than [`DrainError`].
///
/// Observation only. [`DrainError`] stays the contract every caller matches on; this closed set is
/// recorded on `lore.object_dispatch.drain_authority_failures{procedure, cause}` at the one place
/// the SQLSTATE, the raised message and the failing step are still known
/// ([`DrainClient::query_at`]). Every label is a static string from this enum, never SQL text,
/// a message, or an identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainFailureCause {
    /// The dispatch pool gave no connection. Reaches the caller as `Unavailable`.
    PoolAcquire,
    /// The leased session failed before the statement: client, `BEGIN`, or the timeout preamble.
    /// Reaches the caller as `Unavailable`.
    Session,
    /// The whole bounded operation outlived the pool's operation timeout. `Unavailable`.
    OperationTimeout,
    /// The statement lost a race (40001, 55P03, 40P01). `Contended`.
    Contended,
    /// SQLSTATE 53000 raised as `DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED` (migration 0013). `Refused`.
    RefusedPutCapacity,
    /// SQLSTATE 53000 raised as `DRAIN_METADATA_CAPACITY` (migrations 0026/0030). `Refused`.
    RefusedMetadataCapacity,
    /// SQLSTATE 53000 under any other message. `Refused`.
    RefusedCapacityOther,
    /// SQLSTATE 57014: the `SET LOCAL statement_timeout` fired. `Refused`.
    RefusedStatementTimeout,
    /// Any other SQLSTATE, a raised authority refusal included. `Refused`.
    RefusedOther,
    /// `DRAIN_METADATA_UNDERFLOW`. `MetadataUnderflow`.
    MetadataUnderflow,
    /// The statement failed with no SQLSTATE, so its outcome is unknown. `Unavailable`.
    StatementUnknown,
    /// `COMMIT` lost a race and rolled back. `Contended`.
    CommitContended,
    /// `COMMIT` failed otherwise and may have committed. `Unavailable`.
    CommitUnknown,
}

impl DrainFailureCause {
    pub const ALL: [Self; 13] = [
        Self::PoolAcquire,
        Self::Session,
        Self::OperationTimeout,
        Self::Contended,
        Self::RefusedPutCapacity,
        Self::RefusedMetadataCapacity,
        Self::RefusedCapacityOther,
        Self::RefusedStatementTimeout,
        Self::RefusedOther,
        Self::MetadataUnderflow,
        Self::StatementUnknown,
        Self::CommitContended,
        Self::CommitUnknown,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::PoolAcquire => "unavailable_pool",
            Self::Session => "unavailable_session",
            Self::OperationTimeout => "unavailable_timeout",
            Self::Contended => "contended",
            Self::RefusedPutCapacity => "refused_put_capacity",
            Self::RefusedMetadataCapacity => "refused_metadata_capacity",
            Self::RefusedCapacityOther => "refused_capacity_other",
            Self::RefusedStatementTimeout => "refused_statement_timeout",
            Self::RefusedOther => "refused_other",
            Self::MetadataUnderflow => "metadata_underflow",
            Self::StatementUnknown => "unavailable_statement",
            Self::CommitContended => "commit_contended",
            Self::CommitUnknown => "commit_unknown",
        }
    }
}

/// The cause of a failed statement, from its SQLSTATE and raised message. Mirrors
/// [`statement_error_of`]: the [`DrainError`] each cause documents is exactly what that function
/// returns for the same inputs.
pub fn statement_failure_cause(
    code: Option<&SqlState>,
    message: Option<&str>,
) -> DrainFailureCause {
    if message == Some("DRAIN_METADATA_UNDERFLOW") {
        return DrainFailureCause::MetadataUnderflow;
    }
    match code {
        None => DrainFailureCause::StatementUnknown,
        Some(code) if is_contention(code) => DrainFailureCause::Contended,
        Some(code) if *code == SqlState::INSUFFICIENT_RESOURCES => match message {
            Some("DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED") => {
                DrainFailureCause::RefusedPutCapacity
            }
            Some("DRAIN_METADATA_CAPACITY") => DrainFailureCause::RefusedMetadataCapacity,
            _ => DrainFailureCause::RefusedCapacityOther,
        },
        Some(code) if *code == SqlState::QUERY_CANCELED => {
            DrainFailureCause::RefusedStatementTimeout
        }
        Some(_) => DrainFailureCause::RefusedOther,
    }
}

/// The cause of a failed `COMMIT`. Mirrors [`commit_error`].
pub fn commit_failure_cause(code: Option<&SqlState>) -> DrainFailureCause {
    match code {
        Some(code) if is_contention(code) => DrainFailureCause::CommitContended,
        _ => DrainFailureCause::CommitUnknown,
    }
}

/// A closed label for the authority procedure a drain statement calls. Matched against this
/// crate's own static SQL, so the label set is the arms below.
pub fn drain_procedure_label(sql: &str) -> &'static str {
    const PROCEDURES: [(&str, &str); 14] = [
        ("drain_reserve_v1", "reserve"),
        ("drain_policy_read_v1", "policy_read"),
        ("drain_check_ready_v1", "check_ready"),
        ("drain_observe_v1", "observe"),
        ("drain_cleanup_candidates_v1", "cleanup_candidates"),
        ("drain_cleanup_claim_v2", "cleanup_claim"),
        ("drain_cleanup_unlease_v1", "cleanup_unlease"),
        ("drain_cleanup_release_v1", "cleanup_release"),
        ("drain_cleanup_compact_v2", "cleanup_compact"),
        ("drain_policy_publish_v1", "policy_publish"),
        ("drain_policy_verify_v1", "policy_verify"),
        ("drain_policy_rotate_v1", "policy_rotate"),
        ("cell_schema_revision_v1", "schema_revision"),
        ("drain_", "other_drain"),
    ];
    PROCEDURES
        .iter()
        .find(|(needle, _)| sql.contains(needle))
        .map_or("other", |(_, label)| label)
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
    /// Custody rows a policy rotation superseded that still wait for compaction or for their
    /// post-fence rescan (migration 0029). Each still holds a metadata row.
    pub superseded_pending: u64,
    /// Every byte and file a reservation ever charged to the spool ledger (migration 0030). They
    /// only grow, so their growth between two reads is what was charged in between.
    pub charged_bytes: u64,
    pub charged_files: u64,
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
            superseded_pending: u64::try_from(
                r.try_get::<_, i64>(4)
                    .map_err(|_error| DrainError::Invalid)?,
            )
            .map_err(|_error| DrainError::Invalid)?,
            charged_bytes: r
                .try_get::<_, &str>(5)
                .map_err(|_error| DrainError::Invalid)?
                .parse()
                .map_err(|_error| DrainError::Invalid)?,
            charged_files: r
                .try_get::<_, &str>(6)
                .map_err(|_error| DrainError::Invalid)?
                .parse()
                .map_err(|_error| DrainError::Invalid)?,
        })
    }

    /// All SQL goes through bounded serializable transactions. An uncertain response
    /// preserves the caller's descriptor; no retry creates a replacement identity.
    pub(crate) async fn query(
        &self,
        sql: &str,
        values: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Row>, DrainError> {
        self.query_at(IsolationLevel::Serializable, sql, values)
            .await
    }

    /// [`DrainClient::query`] at a chosen isolation level. Only the cleanup candidates lease runs
    /// below `SERIALIZABLE`; see `drain_spool.rs`.
    pub(crate) async fn query_at(
        &self,
        isolation: IsolationLevel,
        sql: &str,
        values: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Row>, DrainError> {
        let failed = |cause: DrainFailureCause, error: DrainError| {
            crate::metrics::record_drain_authority_failure(
                drain_procedure_label(sql),
                cause.label(),
            );
            error
        };
        let mut lease =
            self.pool.acquire().await.map_err(|_error| {
                failed(DrainFailureCause::PoolAcquire, DrainError::Unavailable)
            })?;
        let operation = tokio::time::timeout(self.pool.operation_timeout(), async {
            let session = || failed(DrainFailureCause::Session, DrainError::Unavailable);
            let client = lease.client().map_err(|_error| session())?;
            let tx = client
                .build_transaction()
                .isolation_level(isolation)
                .start()
                .await
                .map_err(|_error| session())?;
            tx.batch_execute(&self.pool.bounded_execution_preamble())
                .await
                .map_err(|_error| session())?;
            let rows = tx.query(sql, values).await.map_err(|e| {
                let message = e.as_db_error().map(|db| db.message());
                failed(
                    statement_failure_cause(e.code(), message),
                    statement_error_of(&e),
                )
            })?;
            tx.commit()
                .await
                .map_err(|e| failed(commit_failure_cause(e.code()), commit_error(e.code())))?;
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
                Err(failed(
                    DrainFailureCause::OperationTimeout,
                    DrainError::Unavailable,
                ))
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

    /// Refuse write-behind on a cell that lacks the spool metadata true-up (CR-038 D5).
    ///
    /// The runtime readback 0019 carries cannot see migrations after 0024, so without this a binary
    /// would run the spool on an un-upgraded cell with no prevention, which is how a cell wedges. An
    /// absent marker names the fix; a marker naming any other revision fails closed.
    pub async fn verify_schema_revision(&self) -> Result<(), DrainError> {
        let rows = self
            .query(
                "SELECT pg_catalog.to_regprocedure('object_store_retention.cell_schema_revision_v1()') IS NOT NULL",
                &[],
            )
            .await?;
        let present: bool = rows
            .first()
            .ok_or(DrainError::Invalid)?
            .try_get(0)
            .map_err(|_error| DrainError::Invalid)?;
        if !present {
            return Err(DrainError::SchemaUpgradeRequired);
        }
        let rows = self
            .query(
                "SELECT object_store_retention.cell_schema_revision_v1()",
                &[],
            )
            .await?;
        let revision: i32 = rows
            .first()
            .ok_or(DrainError::Invalid)?
            .try_get(0)
            .map_err(|_error| DrainError::Invalid)?;
        // An older marker is a known state `cell-schema-install upgrade` moves forward, so it
        // names that fix. A newer one is a later installer's cell.
        match revision.cmp(&CELL_SCHEMA_REVISION) {
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Less => Err(DrainError::SchemaUpgradeRequired),
            std::cmp::Ordering::Greater => Err(DrainError::SchemaUnknown),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_row_race_is_contention_not_a_refusal() {
        for code in [
            SqlState::T_R_SERIALIZATION_FAILURE,
            SqlState::LOCK_NOT_AVAILABLE,
            SqlState::T_R_DEADLOCK_DETECTED,
        ] {
            assert_eq!(statement_error(Some(&code)), DrainError::Contended);
            assert_eq!(commit_error(Some(&code)), DrainError::Contended);
        }
    }

    #[test]
    fn other_sqlstates_keep_their_existing_meaning() {
        // A raised exception (P0001) and a statement timeout are the authority's own answer.
        for code in [
            SqlState::RAISE_EXCEPTION,
            SqlState::QUERY_CANCELED,
            SqlState::NO_DATA_FOUND,
        ] {
            assert_eq!(statement_error(Some(&code)), DrainError::Refused);
            assert_eq!(commit_error(Some(&code)), DrainError::Unavailable);
        }
        assert_eq!(statement_error(None), DrainError::Unavailable);
        assert_eq!(commit_error(None), DrainError::Unavailable);
    }

    const PUT_CAPACITY: &str = "DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED";
    const METADATA_CAPACITY: &str = "DRAIN_METADATA_CAPACITY";
    const UNDERFLOW: &str = "DRAIN_METADATA_UNDERFLOW";

    /// The `DrainError` each cause documents on its own doc comment.
    fn documented_error(cause: DrainFailureCause) -> DrainError {
        use DrainFailureCause as C;
        match cause {
            C::PoolAcquire
            | C::Session
            | C::OperationTimeout
            | C::StatementUnknown
            | C::CommitUnknown => DrainError::Unavailable,
            C::Contended | C::CommitContended => DrainError::Contended,
            C::RefusedPutCapacity
            | C::RefusedMetadataCapacity
            | C::RefusedCapacityOther
            | C::RefusedStatementTimeout
            | C::RefusedOther => DrainError::Refused,
            C::MetadataUnderflow => DrainError::MetadataUnderflow,
        }
    }

    #[test]
    fn drain_failure_cause_labels_are_thirteen_distinct_exact_literals() {
        let expected = [
            "unavailable_pool",
            "unavailable_session",
            "unavailable_timeout",
            "contended",
            "refused_put_capacity",
            "refused_metadata_capacity",
            "refused_capacity_other",
            "refused_statement_timeout",
            "refused_other",
            "metadata_underflow",
            "unavailable_statement",
            "commit_contended",
            "commit_unknown",
        ];
        assert_eq!(DrainFailureCause::ALL.len(), 13);
        let labels: Vec<&str> = DrainFailureCause::ALL.iter().map(|c| c.label()).collect();
        assert_eq!(labels, expected, "ALL order and labels are pinned");
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 13, "labels must be distinct");
        // ALL covers every variant exactly once: no duplicates by value.
        for (i, a) in DrainFailureCause::ALL.iter().enumerate() {
            for b in &DrainFailureCause::ALL[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// Every branch of `statement_failure_cause`, with the `DrainError` the live
    /// `statement_error` returns for the same SQLSTATE where the message does not decide it.
    #[test]
    fn statement_failure_cause_table_covers_every_branch() {
        use DrainFailureCause as C;
        let serial = SqlState::T_R_SERIALIZATION_FAILURE;
        let lock = SqlState::LOCK_NOT_AVAILABLE;
        let dead = SqlState::T_R_DEADLOCK_DETECTED;
        let capacity = SqlState::INSUFFICIENT_RESOURCES;
        let cancel = SqlState::QUERY_CANCELED;
        let raise = SqlState::RAISE_EXCEPTION;
        let table: [(Option<&SqlState>, Option<&str>, DrainFailureCause); 16] = [
            // The underflow message wins over every code, including none and contention.
            (None, Some(UNDERFLOW), C::MetadataUnderflow),
            (Some(&raise), Some(UNDERFLOW), C::MetadataUnderflow),
            (Some(&serial), Some(UNDERFLOW), C::MetadataUnderflow),
            (Some(&capacity), Some(UNDERFLOW), C::MetadataUnderflow),
            // No code: outcome unknown, whatever the message.
            (None, None, C::StatementUnknown),
            (None, Some(PUT_CAPACITY), C::StatementUnknown),
            // Contention, message ignored.
            (Some(&serial), None, C::Contended),
            (Some(&lock), Some("anything"), C::Contended),
            (Some(&dead), Some(PUT_CAPACITY), C::Contended),
            // 53000 splits by message.
            (Some(&capacity), Some(PUT_CAPACITY), C::RefusedPutCapacity),
            (
                Some(&capacity),
                Some(METADATA_CAPACITY),
                C::RefusedMetadataCapacity,
            ),
            (
                Some(&capacity),
                Some("OTHER_CAPACITY"),
                C::RefusedCapacityOther,
            ),
            (Some(&capacity), None, C::RefusedCapacityOther),
            // A message that only contains the exact one does not match.
            (
                Some(&capacity),
                Some("DRAIN_METADATA_CAPACITY "),
                C::RefusedCapacityOther,
            ),
            // Statement timeout and everything else.
            (
                Some(&cancel),
                Some(PUT_CAPACITY),
                C::RefusedStatementTimeout,
            ),
            (Some(&raise), Some(PUT_CAPACITY), C::RefusedOther),
        ];
        for (code, message, expected) in table {
            assert_eq!(
                statement_failure_cause(code, message),
                expected,
                "code {:?} message {message:?}",
                code.map(SqlState::code)
            );
        }
    }

    #[test]
    fn commit_failure_cause_splits_contention_from_unknown() {
        for code in [
            SqlState::T_R_SERIALIZATION_FAILURE,
            SqlState::LOCK_NOT_AVAILABLE,
            SqlState::T_R_DEADLOCK_DETECTED,
        ] {
            assert_eq!(
                commit_failure_cause(Some(&code)),
                DrainFailureCause::CommitContended
            );
        }
        for code in [SqlState::RAISE_EXCEPTION, SqlState::QUERY_CANCELED] {
            assert_eq!(
                commit_failure_cause(Some(&code)),
                DrainFailureCause::CommitUnknown
            );
        }
        assert_eq!(commit_failure_cause(None), DrainFailureCause::CommitUnknown);
    }

    /// The cause a statement or commit failure is recorded under documents the `DrainError` the
    /// caller receives. `statement_error_of` needs a real `tokio_postgres::Error` (unconstructible
    /// here), so it is compared through its two parts: `statement_error` for the SQLSTATE and the
    /// underflow literal, pinned by source scan, for the message.
    #[test]
    fn recorded_cause_agrees_with_the_drain_error_the_caller_gets() {
        let codes = [
            None,
            Some(SqlState::T_R_SERIALIZATION_FAILURE),
            Some(SqlState::LOCK_NOT_AVAILABLE),
            Some(SqlState::T_R_DEADLOCK_DETECTED),
            Some(SqlState::INSUFFICIENT_RESOURCES),
            Some(SqlState::QUERY_CANCELED),
            Some(SqlState::RAISE_EXCEPTION),
            Some(SqlState::NO_DATA_FOUND),
        ];
        let messages = [
            None,
            Some(PUT_CAPACITY),
            Some(METADATA_CAPACITY),
            Some("OTHER"),
        ];
        for code in &codes {
            for message in messages {
                let cause = statement_failure_cause(code.as_ref(), message);
                assert_eq!(
                    documented_error(cause),
                    statement_error(code.as_ref()),
                    "statement code {:?} message {message:?} cause {}",
                    code.as_ref().map(SqlState::code),
                    cause.label()
                );
            }
            let cause = commit_failure_cause(code.as_ref());
            assert_eq!(
                documented_error(cause),
                commit_error(code.as_ref()),
                "commit code {:?} cause {}",
                code.as_ref().map(SqlState::code),
                cause.label()
            );
        }
        // The message arm: both the cause and the live error key on the same exact literal.
        assert_eq!(
            documented_error(statement_failure_cause(None, Some(UNDERFLOW))),
            DrainError::MetadataUnderflow
        );
        let source = include_str!("drain_policy.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            production.contains("db.message() == \"DRAIN_METADATA_UNDERFLOW\""),
            "statement_error_of must keep keying on the underflow message the cause also keys on"
        );
        assert!(production.contains("message == Some(\"DRAIN_METADATA_UNDERFLOW\")"));
    }

    /// The raised messages the 53000 split keys on must still be what the migrations raise.
    #[test]
    fn capacity_split_messages_match_the_migrations() {
        for (file, message) in [
            (
                include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql"),
                PUT_CAPACITY,
            ),
            (
                include_str!("../migrations/0026_object_store_dispatch_drain_policy.sql"),
                METADATA_CAPACITY,
            ),
            (
                include_str!("../migrations/0030_object_store_dispatch_drain_charge_counters.sql"),
                METADATA_CAPACITY,
            ),
            (
                include_str!("../migrations/0028_object_store_dispatch_drain_metadata_true_up.sql"),
                UNDERFLOW,
            ),
        ] {
            assert!(
                file.contains(&format!("RAISE EXCEPTION '{message}'")),
                "{message} is no longer raised by its migration"
            );
        }
    }

    #[test]
    fn drain_procedure_label_names_each_documented_procedure() {
        let table = [
            (
                "SELECT object_store_retention.drain_reserve_v1($1::text::jsonb,$2,$3)",
                "reserve",
            ),
            (
                "SELECT * FROM object_store_retention.drain_policy_read_v1($1,$2,$3,$4)",
                "policy_read",
            ),
            (
                "SELECT * FROM object_store_retention.drain_check_ready_v1($1,$2,$3,$4,$5)",
                "check_ready",
            ),
            (
                "SELECT * FROM object_store_retention.drain_observe_v1($1,$2)",
                "observe",
            ),
            (
                "SELECT spool FROM object_store_retention.drain_cleanup_candidates_v1($1,$2,$3)",
                "cleanup_candidates",
            ),
            (
                "SELECT * FROM object_store_retention.drain_cleanup_claim_v2($1)",
                "cleanup_claim",
            ),
            (
                "SELECT object_store_retention.drain_cleanup_unlease_v1($1)",
                "cleanup_unlease",
            ),
            (
                "SELECT object_store_retention.drain_cleanup_release_v1($1,$2)",
                "cleanup_release",
            ),
            (
                "SELECT object_store_retention.drain_cleanup_compact_v2($1,$2)",
                "cleanup_compact",
            ),
            (
                "SELECT object_store_retention.drain_policy_publish_v1($1::text::jsonb,$2,$3)",
                "policy_publish",
            ),
            (
                "SELECT object_store_retention.drain_policy_verify_v1($1::text::jsonb,$2,$3)",
                "policy_verify",
            ),
            (
                "SELECT object_store_retention.drain_policy_rotate_v1($1::text::jsonb,$2,$3,$4,$5)",
                "policy_rotate",
            ),
            (
                "SELECT object_store_retention.cell_schema_revision_v1()",
                "schema_revision",
            ),
            // A drain procedure this table does not know falls to the drain bucket, then other.
            (
                "SELECT object_store_retention.drain_future_v9($1)",
                "other_drain",
            ),
            ("SELECT 1", "other"),
            ("", "other"),
        ];
        for (sql, label) in table {
            assert_eq!(drain_procedure_label(sql), label, "{sql}");
        }
    }

    /// Every real SQL literal in the drain client and the spool cleanup client that calls a drain
    /// procedure must get a specific label, so a renamed procedure (`_v3`) cannot silently fall
    /// into `other_drain` and merge two procedures' failure counts.
    #[test]
    fn every_real_drain_sql_literal_gets_a_specific_procedure_label() {
        let mut checked = 0usize;
        for source in [
            include_str!("drain_policy.rs"),
            include_str!("drain_spool.rs"),
        ] {
            let production = source.split("#[cfg(test)]").next().unwrap_or(source);
            for line in production.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                let Some(start) = trimmed.find("\"SELECT ") else {
                    continue;
                };
                let rest = &trimmed[start + 1..];
                let Some(end) = rest.find('"') else { continue };
                let sql = &rest[..end];
                if !sql.contains("object_store_retention.") {
                    continue;
                }
                let label = drain_procedure_label(sql);
                assert!(
                    label != "other" && label != "other_drain",
                    "drain SQL has no specific procedure label: {sql}"
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 12,
            "expected the real call sites, found {checked}"
        );
    }
}

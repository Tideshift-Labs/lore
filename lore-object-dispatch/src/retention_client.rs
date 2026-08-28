// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-dark mTLS maintenance client for the independent retention authority.
//!
//! This module is deliberately not referenced by the RPC service, server composition, provider
//! adapters, or loreserver. It accepts only closed planner decisions for mutations and reconciles
//! prune commit ambiguity through immutable v2 receipts.

use std::fmt;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio::sync::Mutex;
use tokio_postgres::IsolationLevel;
use tokio_postgres::Row;
use tokio_postgres::config::Host;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::ToSql;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

use crate::CanonicalObjectStoreCompactReceipt;
use crate::OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID;
use crate::ObjectStoreCompactPruneBackupCoverage;
use crate::ObjectStoreCompactPruneCandidate;
use crate::ObjectStoreCompactPruneDecision;
use crate::ObjectStoreCompactPruneInput;
use crate::ObjectStoreCompactPruneWatermark;
use crate::ObjectStoreCompactReceiptDecision;
use crate::ObjectStoreFullRecordOwnership;
use crate::ObjectStoreFullToCompactDecision;
use crate::ObjectStoreFullToCompactInput;
use crate::ObjectStoreFullToCompactLifecycle;
use crate::ObjectStoreFullToCompactNextCounters;
use crate::ObjectStoreFullToCompactPolicy;
use crate::ObjectStoreFullToCompactScope;
use crate::ObjectStoreRecordStorageCounter;
use crate::RETENTION_MUTATIONS_API_REVISION_V1;
use crate::RETENTION_PRUNE_RECEIPTS_API_REVISION_V2;
use crate::RETENTION_READBACK_API_REVISION_V1;
use crate::decide_object_store_compact_prune;
use crate::decide_object_store_full_to_compact;

const REQUIRED_MUTATION_RETRY_ATTEMPTS: u8 = 3;
const FIRST_MUTATION_RETRY_DELAY: Duration = Duration::from_millis(25);
const SECOND_MUTATION_RETRY_DELAY: Duration = Duration::from_millis(100);
const MUTATION_ISOLATION_LEVEL: IsolationLevel = IsolationLevel::Serializable;

const READ_TRANSFER_SQL: &str = "SELECT
  (r).state,
  ((r).full_record).logical_request_id, ((r).full_record).attempt_id,
  ((r).full_record).provider_boundary_id, ((r).full_record).authenticated_cell_id,
  ((r).full_record).authenticated_tenant_id, ((r).full_record).source_authority_blake3,
  ((r).full_record).full_record_rows::text, ((r).full_record).full_record_bytes::text,
  ((r).full_record).full_record_concurrency::text,
  ((r).full_record).ownership_revision::text,
  ((r).full_record).closure_committed_at_unix_ms,
  ((r).full_record).created_at_unix_ms,
  ((r).compact_record).compact_sequence::text,
  ((r).compact_record).logical_request_id, ((r).compact_record).attempt_id,
  ((r).compact_record).provider_boundary_id, ((r).compact_record).authenticated_cell_id,
  ((r).compact_record).authenticated_tenant_id,
  ((r).compact_record).source_authority_blake3,
  ((r).compact_record).compact_receipt_bytes, ((r).compact_record).compact_blake3,
  ((r).compact_record).compact_rows::text, ((r).compact_record).compact_bytes::text,
  ((r).compact_record).compact_concurrency::text,
  ((r).compact_record).compaction_fingerprint,
  ((r).compact_record).transfer_fingerprint,
  ((r).compact_record).compacted_at_unix_ms,
  ((r).compact_record).compact_prune_after_unix_ms,
  (r).compact_sequence_high_water::text, (r).compact_sequence_revision::text,
  ((r).global_counter).scope_kind, ((r).global_counter).scope_id,
  ((r).global_counter).full_record_rows::text,
  ((r).global_counter).full_record_bytes::text,
  ((r).global_counter).compact_rows::text, ((r).global_counter).compact_bytes::text,
  ((r).global_counter).counter_revision::text,
  ((r).cell_counter).scope_kind, ((r).cell_counter).scope_id,
  ((r).cell_counter).full_record_rows::text, ((r).cell_counter).full_record_bytes::text,
  ((r).cell_counter).compact_rows::text, ((r).cell_counter).compact_bytes::text,
  ((r).cell_counter).counter_revision::text,
  ((r).tenant_counter).scope_kind, ((r).tenant_counter).scope_id,
  ((r).tenant_counter).full_record_rows::text,
  ((r).tenant_counter).full_record_bytes::text,
  ((r).tenant_counter).compact_rows::text, ((r).tenant_counter).compact_bytes::text,
  ((r).tenant_counter).counter_revision::text
FROM (SELECT object_store_retention.object_store_retention_read_transfer_v1($1, $2, $3) AS r) q";

const READ_PRUNE_SQL: &str = "SELECT
  (r).state,
  ((r).compact_record).compact_sequence::text,
  ((r).compact_record).logical_request_id, ((r).compact_record).attempt_id,
  ((r).compact_record).provider_boundary_id, ((r).compact_record).authenticated_cell_id,
  ((r).compact_record).authenticated_tenant_id,
  ((r).compact_record).source_authority_blake3,
  ((r).compact_record).compact_receipt_bytes, ((r).compact_record).compact_blake3,
  ((r).compact_record).compact_rows::text, ((r).compact_record).compact_bytes::text,
  ((r).compact_record).compact_concurrency::text,
  ((r).compact_record).compaction_fingerprint,
  ((r).compact_record).transfer_fingerprint,
  ((r).compact_record).compacted_at_unix_ms,
  ((r).compact_record).compact_prune_after_unix_ms,
  ((r).prune_receipt).compact_sequence::text,
  ((r).prune_receipt).logical_request_id, ((r).prune_receipt).attempt_id,
  ((r).prune_receipt).provider_boundary_id,
  ((r).prune_receipt).authenticated_cell_id,
  ((r).prune_receipt).authenticated_tenant_id,
  ((r).prune_receipt).compact_blake3,
  ((r).prune_receipt).compact_rows::text,
  ((r).prune_receipt).compact_bytes::text,
  ((r).prune_receipt).compact_concurrency::text,
  ((r).prune_receipt).prune_fingerprint,
  ((r).prune_receipt).backup_revision,
  ((r).prune_receipt).backup_manifest_blake3,
  ((r).prune_receipt).durable_covered_through_compact_sequence::text,
  ((r).prune_receipt).restore_verified_through_compact_sequence::text,
  ((r).prune_receipt).backup_observed_at_unix_ms,
  ((r).prune_receipt).pruned_at_unix_ms,
  ((r).watermark).pruned_through_compact_sequence::text,
  ((r).watermark).watermark_revision::text,
  ((r).watermark).last_prune_fingerprint,
  ((r).watermark).last_compact_blake3,
  ((r).watermark).last_pruned_at_unix_ms,
  ((r).watermark).last_backup_revision,
  ((r).watermark).last_backup_manifest_blake3,
  ((r).global_counter).scope_kind, ((r).global_counter).scope_id,
  ((r).global_counter).full_record_rows::text,
  ((r).global_counter).full_record_bytes::text,
  ((r).global_counter).compact_rows::text, ((r).global_counter).compact_bytes::text,
  ((r).global_counter).counter_revision::text,
  ((r).cell_counter).scope_kind, ((r).cell_counter).scope_id,
  ((r).cell_counter).full_record_rows::text, ((r).cell_counter).full_record_bytes::text,
  ((r).cell_counter).compact_rows::text, ((r).cell_counter).compact_bytes::text,
  ((r).cell_counter).counter_revision::text,
  ((r).tenant_counter).scope_kind, ((r).tenant_counter).scope_id,
  ((r).tenant_counter).full_record_rows::text,
  ((r).tenant_counter).full_record_bytes::text,
  ((r).tenant_counter).compact_rows::text, ((r).tenant_counter).compact_bytes::text,
  ((r).tenant_counter).counter_revision::text,
  (((r).prune_receipt).post_watermark).pruned_through_compact_sequence::text,
  (((r).prune_receipt).post_watermark).watermark_revision::text,
  (((r).prune_receipt).post_watermark).last_prune_fingerprint,
  (((r).prune_receipt).post_watermark).last_compact_blake3,
  (((r).prune_receipt).post_watermark).last_pruned_at_unix_ms,
  (((r).prune_receipt).post_watermark).last_backup_revision,
  (((r).prune_receipt).post_watermark).last_backup_manifest_blake3,
  (((r).prune_receipt).post_global_counter).scope_kind,
  (((r).prune_receipt).post_global_counter).scope_id,
  (((r).prune_receipt).post_global_counter).full_record_rows::text,
  (((r).prune_receipt).post_global_counter).full_record_bytes::text,
  (((r).prune_receipt).post_global_counter).compact_rows::text,
  (((r).prune_receipt).post_global_counter).compact_bytes::text,
  (((r).prune_receipt).post_global_counter).counter_revision::text,
  (((r).prune_receipt).post_cell_counter).scope_kind,
  (((r).prune_receipt).post_cell_counter).scope_id,
  (((r).prune_receipt).post_cell_counter).full_record_rows::text,
  (((r).prune_receipt).post_cell_counter).full_record_bytes::text,
  (((r).prune_receipt).post_cell_counter).compact_rows::text,
  (((r).prune_receipt).post_cell_counter).compact_bytes::text,
  (((r).prune_receipt).post_cell_counter).counter_revision::text,
  (((r).prune_receipt).post_tenant_counter).scope_kind,
  (((r).prune_receipt).post_tenant_counter).scope_id,
  (((r).prune_receipt).post_tenant_counter).full_record_rows::text,
  (((r).prune_receipt).post_tenant_counter).full_record_bytes::text,
  (((r).prune_receipt).post_tenant_counter).compact_rows::text,
  (((r).prune_receipt).post_tenant_counter).compact_bytes::text,
  (((r).prune_receipt).post_tenant_counter).counter_revision::text,
  (r).database_now_unix_ms
FROM (SELECT object_store_retention.object_store_retention_read_prune_v2(
  $1, $2::text::object_store_retention.uint64
) AS r) q";

const APPLY_TRANSFER_SQL: &str = "SELECT
  (m).result_code,
  ((m).compact_record).compact_sequence::text,
  ((m).compact_record).logical_request_id, ((m).compact_record).attempt_id,
  ((m).compact_record).provider_boundary_id,
  ((m).compact_record).authenticated_cell_id,
  ((m).compact_record).authenticated_tenant_id,
  ((m).compact_record).source_authority_blake3,
  ((m).compact_record).compact_receipt_bytes, ((m).compact_record).compact_blake3,
  ((m).compact_record).compact_rows::text, ((m).compact_record).compact_bytes::text,
  ((m).compact_record).compact_concurrency::text,
  ((m).compact_record).compaction_fingerprint,
  ((m).compact_record).transfer_fingerprint,
  ((m).compact_record).compacted_at_unix_ms,
  ((m).compact_record).compact_prune_after_unix_ms,
  ((m).schema_state).compact_sequence_high_water::text,
  ((m).schema_state).compact_sequence_revision::text,
  ((m).global_counter).scope_kind, ((m).global_counter).scope_id,
  ((m).global_counter).full_record_rows::text,
  ((m).global_counter).full_record_bytes::text,
  ((m).global_counter).compact_rows::text, ((m).global_counter).compact_bytes::text,
  ((m).global_counter).counter_revision::text,
  ((m).cell_counter).scope_kind, ((m).cell_counter).scope_id,
  ((m).cell_counter).full_record_rows::text, ((m).cell_counter).full_record_bytes::text,
  ((m).cell_counter).compact_rows::text, ((m).cell_counter).compact_bytes::text,
  ((m).cell_counter).counter_revision::text,
  ((m).tenant_counter).scope_kind, ((m).tenant_counter).scope_id,
  ((m).tenant_counter).full_record_rows::text,
  ((m).tenant_counter).full_record_bytes::text,
  ((m).tenant_counter).compact_rows::text, ((m).tenant_counter).compact_bytes::text,
  ((m).tenant_counter).counter_revision::text
FROM (SELECT object_store_retention.object_store_retention_apply_transfer_v1(
  $1, $2, $3, $4, $5, $6, $7,
  $8::text::object_store_retention.uint64,
  $9::text::object_store_retention.uint64,
  $10::text::object_store_retention.uint64,
  $11::text::object_store_retention.uint64,
  $12::text::object_store_retention.uint64,
  $13::text::object_store_retention.uint64,
  $14, $15, $16, $17, $18, $19
) AS m) q";

const APPLY_PRUNE_SQL: &str = "SELECT
  (m).result_code,
  ((m).prune_receipt).compact_sequence::text,
  ((m).prune_receipt).logical_request_id, ((m).prune_receipt).attempt_id,
  ((m).prune_receipt).provider_boundary_id,
  ((m).prune_receipt).authenticated_cell_id,
  ((m).prune_receipt).authenticated_tenant_id,
  ((m).prune_receipt).compact_blake3,
  ((m).prune_receipt).compact_rows::text,
  ((m).prune_receipt).compact_bytes::text,
  ((m).prune_receipt).compact_concurrency::text,
  ((m).prune_receipt).prune_fingerprint,
  ((m).prune_receipt).backup_revision,
  ((m).prune_receipt).backup_manifest_blake3,
  ((m).prune_receipt).durable_covered_through_compact_sequence::text,
  ((m).prune_receipt).restore_verified_through_compact_sequence::text,
  ((m).prune_receipt).backup_observed_at_unix_ms,
  ((m).prune_receipt).pruned_at_unix_ms,
  (((m).prune_receipt).post_watermark).pruned_through_compact_sequence::text,
  (((m).prune_receipt).post_watermark).watermark_revision::text,
  (((m).prune_receipt).post_watermark).last_prune_fingerprint,
  (((m).prune_receipt).post_watermark).last_compact_blake3,
  (((m).prune_receipt).post_watermark).last_pruned_at_unix_ms,
  (((m).prune_receipt).post_watermark).last_backup_revision,
  (((m).prune_receipt).post_watermark).last_backup_manifest_blake3,
  (((m).prune_receipt).post_global_counter).scope_kind,
  (((m).prune_receipt).post_global_counter).scope_id,
  (((m).prune_receipt).post_global_counter).full_record_rows::text,
  (((m).prune_receipt).post_global_counter).full_record_bytes::text,
  (((m).prune_receipt).post_global_counter).compact_rows::text,
  (((m).prune_receipt).post_global_counter).compact_bytes::text,
  (((m).prune_receipt).post_global_counter).counter_revision::text,
  (((m).prune_receipt).post_cell_counter).scope_kind,
  (((m).prune_receipt).post_cell_counter).scope_id,
  (((m).prune_receipt).post_cell_counter).full_record_rows::text,
  (((m).prune_receipt).post_cell_counter).full_record_bytes::text,
  (((m).prune_receipt).post_cell_counter).compact_rows::text,
  (((m).prune_receipt).post_cell_counter).compact_bytes::text,
  (((m).prune_receipt).post_cell_counter).counter_revision::text,
  (((m).prune_receipt).post_tenant_counter).scope_kind,
  (((m).prune_receipt).post_tenant_counter).scope_id,
  (((m).prune_receipt).post_tenant_counter).full_record_rows::text,
  (((m).prune_receipt).post_tenant_counter).full_record_bytes::text,
  (((m).prune_receipt).post_tenant_counter).compact_rows::text,
  (((m).prune_receipt).post_tenant_counter).compact_bytes::text,
  (((m).prune_receipt).post_tenant_counter).counter_revision::text
FROM (SELECT object_store_retention.object_store_retention_apply_prune_v2(
  $1, $2::text::object_store_retention.uint64, $3, $4,
  $5::text::object_store_retention.uint64,
  $6::text::object_store_retention.uint64,
  $7::text::object_store_retention.uint64,
  $8::text::object_store_retention.uint64,
  $9, $10,
  $11::text::object_store_retention.uint64,
  $12::text::object_store_retention.uint64, $13
) AS m) q";

#[derive(Clone)]
pub struct RetentionTlsConfig {
    pub postgres_url: String,
    pub root_ca_pem: String,
    pub client_certificate_chain_pem: String,
    pub private_key_pem: String,
    pub connect_timeout: Duration,
    pub statement_timeout: Duration,
    pub lock_timeout: Duration,
    pub max_retry_attempts: u8,
}

impl fmt::Debug for RetentionTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetentionTlsConfig")
            .field("postgres_url", &"<redacted>")
            .field("root_ca_pem", &"<redacted>")
            .field("client_certificate_chain_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("lock_timeout", &self.lock_timeout)
            .field("max_retry_attempts", &self.max_retry_attempts)
            .finish()
    }
}

impl RetentionTlsConfig {
    pub fn validate(&self) -> Result<(), RetentionError> {
        self.connection_material().map(|_| ())
    }

    fn connection_material(
        &self,
    ) -> Result<(tokio_postgres::Config, MakeRustlsConnect), RetentionError> {
        validate_duration(self.connect_timeout, "connect timeout must be positive")?;
        validate_duration(
            self.statement_timeout,
            "statement timeout must be a positive whole-millisecond value",
        )?;
        validate_duration(
            self.lock_timeout,
            "lock timeout must be a positive whole-millisecond value",
        )?;
        self.statement_timeout
            .checked_add(self.lock_timeout)
            .ok_or(RetentionError::InvalidConfiguration(
                "combined operation timeout is too large",
            ))?;
        if self.max_retry_attempts != REQUIRED_MUTATION_RETRY_ATTEMPTS {
            return Err(RetentionError::InvalidConfiguration(
                "retention mutation retry attempts must equal three",
            ));
        }
        let postgres = self
            .postgres_url
            .parse::<tokio_postgres::Config>()
            .map_err(|_| RetentionError::InvalidConfiguration("invalid PostgreSQL URL"))?;
        if postgres.get_ssl_mode() != SslMode::Require {
            return Err(RetentionError::InvalidConfiguration(
                "retention PostgreSQL requires sslmode=require",
            ));
        }
        let [Host::Tcp(host)] = postgres.get_hosts() else {
            return Err(RetentionError::InvalidConfiguration(
                "retention PostgreSQL requires exactly one TCP DNS host",
            ));
        };
        if host.parse::<IpAddr>().is_ok() || !is_dns_name(host) {
            return Err(RetentionError::InvalidConfiguration(
                "retention PostgreSQL host must be a DNS name",
            ));
        }
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(RetentionError::InvalidConfiguration(
                "retention PostgreSQL URL requires user and database",
            ));
        }
        if postgres.get_user() != Some("object_dispatch_retention_maintenance") {
            return Err(RetentionError::InvalidConfiguration(
                "retention PostgreSQL user must be the exact maintenance identity",
            ));
        }
        let mut roots = RootCertStore::empty();
        let mut root_reader = Cursor::new(self.root_ca_pem.as_bytes());
        let mut root_count = 0usize;
        for certificate in rustls_pemfile::certs(&mut root_reader) {
            let certificate = certificate
                .map_err(|_| RetentionError::InvalidTlsMaterial("invalid root CA PEM"))?;
            roots
                .add(certificate)
                .map_err(|_| RetentionError::InvalidTlsMaterial("unusable root CA certificate"))?;
            root_count = root_count.saturating_add(1);
        }
        if root_count == 0 {
            return Err(RetentionError::InvalidTlsMaterial(
                "root CA bundle is empty",
            ));
        }
        let mut certificate_reader = Cursor::new(self.client_certificate_chain_pem.as_bytes());
        let certificates = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RetentionError::InvalidTlsMaterial("invalid client certificate PEM"))?;
        if certificates.is_empty() {
            return Err(RetentionError::InvalidTlsMaterial(
                "client certificate chain is empty",
            ));
        }
        let mut key_reader = Cursor::new(self.private_key_pem.as_bytes());
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|_| RetentionError::InvalidTlsMaterial("invalid client private key PEM"))?
            .ok_or(RetentionError::InvalidTlsMaterial(
                "client private key is empty",
            ))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| RetentionError::InvalidTlsMaterial("unsupported TLS protocol set"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, private_key)
            .map_err(|_| {
                RetentionError::InvalidTlsMaterial("client certificate and key do not match")
            })?;
        Ok((postgres, MakeRustlsConnect::new(tls)))
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RetentionError {
    #[error("invalid retention connection configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid retention TLS material: {0}")]
    InvalidTlsMaterial(&'static str),
    #[error("retention database connection timed out")]
    ConnectTimeout,
    #[error("retention database operation timed out")]
    OperationTimeout,
    #[error("retention database operation failed")]
    Postgres { transient: bool },
    #[error("retention mutation retry budget exhausted")]
    RetryExhausted,
    #[error("retention mutation commit outcome is ambiguous")]
    AmbiguousCommit,
    #[error("invalid retention authority response: {0}")]
    InvalidResponse(&'static str),
    #[error("retention planner decision does not match its authoritative snapshot")]
    PlannerMismatch,
}

impl RetentionError {
    fn postgres(error: tokio_postgres::Error) -> Self {
        Self::Postgres {
            transient: postgres_error_is_transient(&error),
        }
    }

    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::ConnectTimeout
                | Self::OperationTimeout
                | Self::Postgres { transient: true }
                | Self::RetryExhausted
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionFullRecordSnapshot {
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub ownership: ObjectStoreFullRecordOwnership,
    pub ownership_revision: u64,
    pub closure_committed_at_unix_ms: i64,
    pub created_at_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionCompactRecordSnapshot {
    pub compact_sequence: u64,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub source_authority_blake3: [u8; 32],
    pub compact_receipt_bytes: Vec<u8>,
    pub compact_blake3: [u8; 32],
    pub compact_rows: u64,
    pub compact_bytes: u64,
    pub compact_concurrency: u64,
    pub compaction_fingerprint: [u8; 32],
    pub transfer_fingerprint: [u8; 32],
    pub compacted_at_unix_ms: i64,
    pub compact_prune_after_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionTransferState {
    FullOwned,
    CompactInstalled,
    Absent,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionTransferSnapshot {
    pub state: RetentionTransferState,
    pub full_record: Option<RetentionFullRecordSnapshot>,
    pub compact_record: Option<RetentionCompactRecordSnapshot>,
    pub compact_sequence_high_water: u64,
    pub compact_sequence_revision: u64,
    pub global_counter: ObjectStoreRecordStorageCounter,
    pub cell_counter: Option<ObjectStoreRecordStorageCounter>,
    pub tenant_counter: Option<ObjectStoreRecordStorageCounter>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPruneReceiptSnapshot {
    pub compact_sequence: u64,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub compact_blake3: [u8; 32],
    pub compact_rows: u64,
    pub compact_bytes: u64,
    pub compact_concurrency: u64,
    pub prune_fingerprint: [u8; 32],
    pub backup_revision: String,
    pub backup_manifest_blake3: [u8; 32],
    pub durable_covered_through_compact_sequence: u64,
    pub restore_verified_through_compact_sequence: u64,
    pub backup_observed_at_unix_ms: i64,
    pub pruned_at_unix_ms: i64,
    pub post_watermark: ObjectStoreCompactPruneWatermark,
    pub post_counters: ObjectStoreFullToCompactNextCounters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPruneState {
    CompactInstalled,
    Pruned,
    AbsentUnproven,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPruneSnapshot {
    pub state: RetentionPruneState,
    pub compact_record: Option<RetentionCompactRecordSnapshot>,
    pub prune_receipt: Option<RetentionPruneReceiptSnapshot>,
    pub watermark: ObjectStoreCompactPruneWatermark,
    pub global_counter: ObjectStoreRecordStorageCounter,
    pub cell_counter: Option<ObjectStoreRecordStorageCounter>,
    pub tenant_counter: Option<ObjectStoreRecordStorageCounter>,
    pub database_now_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionTransferMutationResult {
    pub result_code: String,
    pub compact_record: RetentionCompactRecordSnapshot,
    pub compact_sequence_high_water: u64,
    pub compact_sequence_revision: u64,
    pub next_counters: ObjectStoreFullToCompactNextCounters,
}

struct RetentionSession {
    client: tokio_postgres::Client,
    _connection_task: AbortOnDropHandle<()>,
}

pub struct RetentionMaintenanceClient {
    config: RetentionTlsConfig,
    session: Mutex<RetentionSession>,
    statement_timeout_ms: u64,
    lock_timeout_ms: u64,
    operation_timeout: Duration,
}

impl RetentionMaintenanceClient {
    pub async fn connect(config: &RetentionTlsConfig) -> Result<Self, RetentionError> {
        let session = Self::connect_session(config).await?;
        Ok(Self {
            config: config.clone(),
            session: Mutex::new(session),
            statement_timeout_ms: millis(config.statement_timeout)?,
            lock_timeout_ms: millis(config.lock_timeout)?,
            operation_timeout: config
                .statement_timeout
                .checked_add(config.lock_timeout)
                .ok_or(RetentionError::InvalidConfiguration(
                    "combined operation timeout is too large",
                ))?,
        })
    }

    async fn connect_session(
        config: &RetentionTlsConfig,
    ) -> Result<RetentionSession, RetentionError> {
        let (postgres, tls) = config.connection_material()?;
        let (client, connection) =
            tokio::time::timeout(config.connect_timeout, postgres.connect(tls))
                .await
                .map_err(|_| RetentionError::ConnectTimeout)?
                .map_err(RetentionError::postgres)?;
        let connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "object-store-retention-postgres",
            async move {
                if connection.await.is_err() {
                    tracing::error!("object-store retention PostgreSQL connection ended");
                }
            }
        ));
        Ok(RetentionSession {
            client,
            _connection_task: connection_task,
        })
    }

    async fn reconnect(&self) -> Result<(), RetentionError> {
        let replacement = Self::connect_session(&self.config).await?;
        *self.session.lock().await = replacement;
        Ok(())
    }

    async fn apply_timeouts(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
    ) -> Result<(), tokio_postgres::Error> {
        transaction
            .batch_execute(&format!(
                "SET LOCAL statement_timeout = '{}ms'; SET LOCAL lock_timeout = '{}ms';",
                self.statement_timeout_ms, self.lock_timeout_ms
            ))
            .await
    }

    pub async fn read_transfer(
        &self,
        logical_request_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<RetentionTransferSnapshot, RetentionError> {
        match tokio::time::timeout(
            self.operation_timeout,
            self.read_transfer_once(logical_request_id, attempt_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let _ = self.reconnect().await;
                Err(RetentionError::OperationTimeout)
            }
        }
    }

    async fn read_transfer_once(
        &self,
        logical_request_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<RetentionTransferSnapshot, RetentionError> {
        let mut session = self.session.lock().await;
        let transaction = session
            .client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(RetentionError::postgres)?;
        self.apply_timeouts(&transaction)
            .await
            .map_err(RetentionError::postgres)?;
        let row = transaction
            .query_one(
                READ_TRANSFER_SQL,
                &[
                    &RETENTION_READBACK_API_REVISION_V1,
                    &logical_request_id,
                    &attempt_id,
                ],
            )
            .await
            .map_err(RetentionError::postgres)?;
        let result = parse_transfer_snapshot(&row)?;
        transaction
            .commit()
            .await
            .map_err(RetentionError::postgres)?;
        Ok(result)
    }

    pub async fn read_prune(
        &self,
        compact_sequence: u64,
    ) -> Result<RetentionPruneSnapshot, RetentionError> {
        if compact_sequence == 0 {
            return Err(RetentionError::InvalidConfiguration(
                "compact sequence must be positive",
            ));
        }
        match tokio::time::timeout(
            self.operation_timeout,
            self.read_prune_once(compact_sequence),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let _ = self.reconnect().await;
                Err(RetentionError::OperationTimeout)
            }
        }
    }

    async fn read_prune_once(
        &self,
        compact_sequence: u64,
    ) -> Result<RetentionPruneSnapshot, RetentionError> {
        let compact_sequence = compact_sequence.to_string();
        let mut session = self.session.lock().await;
        let transaction = session
            .client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(RetentionError::postgres)?;
        self.apply_timeouts(&transaction)
            .await
            .map_err(RetentionError::postgres)?;
        let row = transaction
            .query_one(
                READ_PRUNE_SQL,
                &[&RETENTION_PRUNE_RECEIPTS_API_REVISION_V2, &compact_sequence],
            )
            .await
            .map_err(RetentionError::postgres)?;
        let result = parse_prune_snapshot(&row)?;
        transaction
            .commit()
            .await
            .map_err(RetentionError::postgres)?;
        Ok(result)
    }

    pub async fn apply_transfer(
        &self,
        snapshot: &RetentionTransferSnapshot,
        compact_plan: &ObjectStoreCompactReceiptDecision,
        policy: &ObjectStoreFullToCompactPolicy,
        decision: &ObjectStoreFullToCompactDecision,
    ) -> Result<RetentionTransferMutationResult, RetentionError> {
        let ObjectStoreFullToCompactDecision::ApplyFullToCompact {
            transfer_fingerprint,
            expected_source_authority_blake3,
            expected_counter_revisions,
            next_counters,
            compact,
            ..
        } = decision
        else {
            return Err(RetentionError::PlannerMismatch);
        };
        let full = snapshot
            .full_record
            .as_ref()
            .filter(|_| snapshot.state == RetentionTransferState::FullOwned)
            .ok_or(RetentionError::PlannerMismatch)?;
        let cell = snapshot
            .cell_counter
            .as_ref()
            .ok_or(RetentionError::PlannerMismatch)?;
        let tenant = snapshot
            .tenant_counter
            .as_ref()
            .ok_or(RetentionError::PlannerMismatch)?;
        let compact_value = compact.value();
        let lifecycle = ObjectStoreFullToCompactLifecycle::FullOwned {
            source_authority_blake3: full.ownership.source_authority_blake3,
        };
        let recomputed = decide_object_store_full_to_compact(&ObjectStoreFullToCompactInput {
            compact_plan,
            full_ownership: &full.ownership,
            global_counter: &snapshot.global_counter,
            cell_counter: cell,
            tenant_counter: tenant,
            policy,
            lifecycle: &lifecycle,
        })
        .map_err(|_| RetentionError::PlannerMismatch)?;
        if full.ownership.source_authority_blake3 != *expected_source_authority_blake3
            || recomputed != *decision
            || expected_counter_revisions.global != snapshot.global_counter.counter_revision
            || expected_counter_revisions.cell != cell.counter_revision
            || expected_counter_revisions.tenant != tenant.counter_revision
            || next_counters.global.scope != ObjectStoreFullToCompactScope::Global
            || next_counters.global.scope_id != OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID
            || compact_value.provider_boundary_id != full.ownership.provider_boundary_id
            || compact_value.authenticated_cell_id != full.ownership.authenticated_cell_id
            || compact_value.authenticated_tenant_id != full.ownership.authenticated_tenant_id
            || compact_value.logical_request_id != full.logical_request_id.to_string()
            || compact_value.attempt_id != full.attempt_id.to_string()
            || compact.canonical_bytes().is_empty()
            || compact.compact_blake3() != &compact_value.compact_blake3
            || !canonical_bytes_match_digest(compact.canonical_bytes(), compact.compact_blake3())
        {
            return Err(RetentionError::PlannerMismatch);
        }
        let expected_sequence = snapshot
            .compact_sequence_high_water
            .checked_add(1)
            .ok_or(RetentionError::PlannerMismatch)?;
        let expected_sequence_revision = snapshot
            .compact_sequence_revision
            .checked_add(1)
            .ok_or(RetentionError::PlannerMismatch)?;
        let expected_ownership_revision = full.ownership_revision.to_string();
        let sequence_high_water = snapshot.compact_sequence_high_water.to_string();
        let sequence_revision = snapshot.compact_sequence_revision.to_string();
        let global_revision = expected_counter_revisions.global.to_string();
        let cell_revision = expected_counter_revisions.cell.to_string();
        let tenant_revision = expected_counter_revisions.tenant.to_string();

        let prepared = PreparedTransfer {
            full,
            compact,
            transfer_fingerprint,
            next_counters,
            expected_sequence,
            expected_sequence_revision,
            expected_ownership_revision,
            sequence_high_water,
            sequence_revision,
            global_revision,
            cell_revision,
            tenant_revision,
        };
        for attempt in 1..=REQUIRED_MUTATION_RETRY_ATTEMPTS {
            let attempt_result = tokio::time::timeout(
                self.operation_timeout,
                self.run_transfer_attempt(&prepared, attempt),
            )
            .await;
            let outcome = match attempt_result {
                Ok(outcome) => outcome,
                Err(_) => {
                    if self.reconnect().await.is_err() {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    let readback = self
                        .read_transfer(full.logical_request_id, full.attempt_id)
                        .await
                        .map_err(|_| RetentionError::AmbiguousCommit)?;
                    if let Some(adopted) = transfer_adoption_from_readback(&readback, &prepared) {
                        return Ok(adopted);
                    }
                    if readback.state != RetentionTransferState::FullOwned
                        || attempt == REQUIRED_MUTATION_RETRY_ATTEMPTS
                    {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    MutationAttempt::Retry(
                        retry_delay_for_attempt(attempt).ok_or(RetentionError::AmbiguousCommit)?,
                    )
                }
            };
            match outcome {
                MutationAttempt::Committed(result) => return Ok(result),
                MutationAttempt::Retry(delay) => {
                    tokio::time::sleep(delay).await;
                }
                MutationAttempt::Reconcile(precommit) => {
                    if self.reconnect().await.is_err() {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    let readback = self
                        .read_transfer(full.logical_request_id, full.attempt_id)
                        .await
                        .map_err(|_| RetentionError::AmbiguousCommit)?;
                    if transfer_readback_matches(&readback, &precommit) {
                        return Ok(precommit);
                    }
                    if readback.state != RetentionTransferState::FullOwned
                        || attempt == REQUIRED_MUTATION_RETRY_ATTEMPTS
                    {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    tokio::time::sleep(
                        retry_delay_for_attempt(attempt).ok_or(RetentionError::AmbiguousCommit)?,
                    )
                    .await;
                }
                MutationAttempt::Error(error) => return Err(error),
            }
        }
        Err(RetentionError::RetryExhausted)
    }

    pub async fn apply_prune(
        &self,
        snapshot: &RetentionPruneSnapshot,
        compact: &CanonicalObjectStoreCompactReceipt,
        backup: &ObjectStoreCompactPruneBackupCoverage,
        decision: &ObjectStoreCompactPruneDecision,
    ) -> Result<RetentionPruneReceiptSnapshot, RetentionError> {
        let ObjectStoreCompactPruneDecision::ApplyCompactPrune {
            prune_fingerprint,
            expected_compact_blake3,
            expected_watermark_revision,
            expected_counter_revisions,
            next_watermark,
            next_counters,
        } = decision
        else {
            return Err(RetentionError::PlannerMismatch);
        };
        let installed = snapshot
            .compact_record
            .as_ref()
            .filter(|_| snapshot.state == RetentionPruneState::CompactInstalled)
            .ok_or(RetentionError::PlannerMismatch)?;
        let cell = snapshot
            .cell_counter
            .as_ref()
            .ok_or(RetentionError::PlannerMismatch)?;
        let tenant = snapshot
            .tenant_counter
            .as_ref()
            .ok_or(RetentionError::PlannerMismatch)?;
        let value = compact.value();
        let database_now_unix_ms = snapshot.database_now_unix_ms;
        let recomputed = decide_object_store_compact_prune(&ObjectStoreCompactPruneInput {
            candidate: ObjectStoreCompactPruneCandidate::CompactInstalled {
                compact_sequence: installed.compact_sequence,
                compact,
            },
            watermark: &snapshot.watermark,
            backup_coverage: backup,
            database_now_unix_ms,
            global_counter: &snapshot.global_counter,
            cell_counter: cell,
            tenant_counter: tenant,
        })
        .map_err(|_| RetentionError::PlannerMismatch)?;
        if installed.compact_receipt_bytes != compact.canonical_bytes()
            || recomputed != *decision
            || installed.compact_blake3 != *compact.compact_blake3()
            || installed.compact_blake3 != *expected_compact_blake3
            || installed.logical_request_id.to_string() != value.logical_request_id
            || installed.attempt_id.to_string() != value.attempt_id
            || installed.provider_boundary_id != value.provider_boundary_id
            || installed.authenticated_cell_id != value.authenticated_cell_id
            || installed.authenticated_tenant_id != value.authenticated_tenant_id
            || installed.compaction_fingerprint != value.compaction_fingerprint
            || installed.compacted_at_unix_ms != value.compacted_at_unix_ms
            || installed.compact_prune_after_unix_ms != value.compact_prune_after_unix_ms
            || *expected_watermark_revision != snapshot.watermark.watermark_revision
            || expected_counter_revisions.global != snapshot.global_counter.counter_revision
            || expected_counter_revisions.cell != cell.counter_revision
            || expected_counter_revisions.tenant != tenant.counter_revision
            || next_watermark.pruned_through_compact_sequence != installed.compact_sequence
            || next_watermark.watermark_revision
                != expected_watermark_revision
                    .checked_add(1)
                    .ok_or(RetentionError::PlannerMismatch)?
            || next_watermark.last_prune_fingerprint != Some(*prune_fingerprint)
            || next_watermark.last_compact_blake3 != Some(*expected_compact_blake3)
            || next_watermark.last_backup_revision.as_deref() != Some(&backup.backup_revision)
            || next_watermark.last_backup_manifest_blake3 != Some(backup.backup_manifest_blake3)
        {
            return Err(RetentionError::PlannerMismatch);
        }
        let prepared = PreparedPrune {
            installed,
            compact,
            backup,
            prune_fingerprint,
            expected_compact_blake3,
            next_watermark,
            next_counters,
            compact_sequence: installed.compact_sequence.to_string(),
            watermark_revision: expected_watermark_revision.to_string(),
            global_revision: expected_counter_revisions.global.to_string(),
            cell_revision: expected_counter_revisions.cell.to_string(),
            tenant_revision: expected_counter_revisions.tenant.to_string(),
            durable_coverage: backup.durable_covered_through_compact_sequence.to_string(),
            restore_coverage: backup.restore_verified_through_compact_sequence.to_string(),
        };
        for attempt in 1..=REQUIRED_MUTATION_RETRY_ATTEMPTS {
            let attempt_result = tokio::time::timeout(
                self.operation_timeout,
                self.run_prune_attempt(&prepared, attempt),
            )
            .await;
            let outcome = match attempt_result {
                Ok(outcome) => outcome,
                Err(_) => {
                    if self.reconnect().await.is_err() {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    let readback = self
                        .read_prune(installed.compact_sequence)
                        .await
                        .map_err(|_| RetentionError::AmbiguousCommit)?;
                    if let Some(receipt) = readback
                        .prune_receipt
                        .filter(|receipt| prune_result_matches(receipt, &prepared))
                    {
                        return Ok(receipt);
                    }
                    if readback.state != RetentionPruneState::CompactInstalled
                        || attempt == REQUIRED_MUTATION_RETRY_ATTEMPTS
                    {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    MutationAttempt::Retry(
                        retry_delay_for_attempt(attempt).ok_or(RetentionError::AmbiguousCommit)?,
                    )
                }
            };
            match outcome {
                MutationAttempt::Committed(result) => return Ok(result),
                MutationAttempt::Retry(delay) => tokio::time::sleep(delay).await,
                MutationAttempt::Reconcile(precommit) => {
                    if self.reconnect().await.is_err() {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    let readback = self
                        .read_prune(installed.compact_sequence)
                        .await
                        .map_err(|_| RetentionError::AmbiguousCommit)?;
                    if readback.prune_receipt.as_ref() == Some(&precommit) {
                        return Ok(precommit);
                    }
                    if readback.state != RetentionPruneState::CompactInstalled
                        || attempt == REQUIRED_MUTATION_RETRY_ATTEMPTS
                    {
                        return Err(RetentionError::AmbiguousCommit);
                    }
                    tokio::time::sleep(
                        retry_delay_for_attempt(attempt).ok_or(RetentionError::AmbiguousCommit)?,
                    )
                    .await;
                }
                MutationAttempt::Error(error) => return Err(error),
            }
        }
        Err(RetentionError::RetryExhausted)
    }

    async fn run_transfer_attempt(
        &self,
        prepared: &PreparedTransfer<'_>,
        attempt: u8,
    ) -> MutationAttempt<RetentionTransferMutationResult> {
        let mut session = self.session.lock().await;
        let transaction = match session
            .client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
        {
            Ok(transaction) => transaction,
            Err(error) => return mutation_query_failure(error, attempt),
        };
        if let Err(error) = self.apply_timeouts(&transaction).await {
            return mutation_query_failure(error, attempt);
        }
        let value = prepared.compact.value();
        let params: &[&(dyn ToSql + Sync)] = &[
            &RETENTION_MUTATIONS_API_REVISION_V1,
            &prepared.full.logical_request_id,
            &prepared.full.attempt_id,
            &prepared.full.ownership.provider_boundary_id,
            &prepared.full.ownership.authenticated_cell_id,
            &prepared.full.ownership.authenticated_tenant_id,
            &&prepared.full.ownership.source_authority_blake3[..],
            &prepared.expected_ownership_revision,
            &prepared.sequence_high_water,
            &prepared.sequence_revision,
            &prepared.global_revision,
            &prepared.cell_revision,
            &prepared.tenant_revision,
            &prepared.compact.canonical_bytes(),
            &&value.compact_blake3[..],
            &&value.compaction_fingerprint[..],
            &&prepared.transfer_fingerprint[..],
            &value.compacted_at_unix_ms,
            &value.compact_prune_after_unix_ms,
        ];
        let row = match transaction.query_one(APPLY_TRANSFER_SQL, params).await {
            Ok(row) => row,
            Err(error) => return mutation_query_failure(error, attempt),
        };
        let result = match parse_transfer_mutation(&row) {
            Ok(result) if transfer_result_matches(&result, prepared) => result,
            Ok(_) => return MutationAttempt::Error(RetentionError::PlannerMismatch),
            Err(error) => return MutationAttempt::Error(error),
        };
        match transaction.commit().await {
            Ok(()) => MutationAttempt::Committed(result),
            Err(error) if error.is_closed() => MutationAttempt::Reconcile(result),
            Err(error) => mutation_query_failure(error, attempt),
        }
    }

    async fn run_prune_attempt(
        &self,
        prepared: &PreparedPrune<'_>,
        attempt: u8,
    ) -> MutationAttempt<RetentionPruneReceiptSnapshot> {
        let mut session = self.session.lock().await;
        let transaction = match session
            .client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
        {
            Ok(transaction) => transaction,
            Err(error) => return mutation_query_failure(error, attempt),
        };
        if let Err(error) = self.apply_timeouts(&transaction).await {
            return mutation_query_failure(error, attempt);
        }
        let params: &[&(dyn ToSql + Sync)] = &[
            &RETENTION_PRUNE_RECEIPTS_API_REVISION_V2,
            &prepared.compact_sequence,
            &&prepared.expected_compact_blake3[..],
            &&prepared.prune_fingerprint[..],
            &prepared.watermark_revision,
            &prepared.global_revision,
            &prepared.cell_revision,
            &prepared.tenant_revision,
            &prepared.backup.backup_revision,
            &&prepared.backup.backup_manifest_blake3[..],
            &prepared.durable_coverage,
            &prepared.restore_coverage,
            &prepared.backup.observed_at_unix_ms,
        ];
        let row = match transaction.query_one(APPLY_PRUNE_SQL, params).await {
            Ok(row) => row,
            Err(error) => return mutation_query_failure(error, attempt),
        };
        let result = match parse_prune_mutation(&row) {
            Ok(result) if prune_result_matches(&result, prepared) => result,
            Ok(_) => return MutationAttempt::Error(RetentionError::PlannerMismatch),
            Err(error) => return MutationAttempt::Error(error),
        };
        match transaction.commit().await {
            Ok(()) => MutationAttempt::Committed(result),
            Err(error) if error.is_closed() => MutationAttempt::Reconcile(result),
            Err(error) => mutation_query_failure(error, attempt),
        }
    }
}

struct PreparedTransfer<'a> {
    full: &'a RetentionFullRecordSnapshot,
    compact: &'a CanonicalObjectStoreCompactReceipt,
    transfer_fingerprint: &'a [u8; 32],
    next_counters: &'a ObjectStoreFullToCompactNextCounters,
    expected_sequence: u64,
    expected_sequence_revision: u64,
    expected_ownership_revision: String,
    sequence_high_water: String,
    sequence_revision: String,
    global_revision: String,
    cell_revision: String,
    tenant_revision: String,
}

struct PreparedPrune<'a> {
    installed: &'a RetentionCompactRecordSnapshot,
    compact: &'a CanonicalObjectStoreCompactReceipt,
    backup: &'a ObjectStoreCompactPruneBackupCoverage,
    prune_fingerprint: &'a [u8; 32],
    expected_compact_blake3: &'a [u8; 32],
    next_watermark: &'a ObjectStoreCompactPruneWatermark,
    next_counters: &'a ObjectStoreFullToCompactNextCounters,
    compact_sequence: String,
    watermark_revision: String,
    global_revision: String,
    cell_revision: String,
    tenant_revision: String,
    durable_coverage: String,
    restore_coverage: String,
}

enum MutationAttempt<T> {
    Committed(T),
    Retry(Duration),
    Reconcile(T),
    Error(RetentionError),
}

fn mutation_query_failure<T>(error: tokio_postgres::Error, attempt: u8) -> MutationAttempt<T> {
    if let Some(delay) = retry_delay(&error, attempt) {
        MutationAttempt::Retry(delay)
    } else if postgres_error_is_retryable_mutation(&error) {
        MutationAttempt::Error(RetentionError::RetryExhausted)
    } else {
        MutationAttempt::Error(RetentionError::postgres(error))
    }
}

fn validate_duration(value: Duration, message: &'static str) -> Result<(), RetentionError> {
    if value.is_zero()
        || value.as_millis() == 0
        || !value.subsec_nanos().is_multiple_of(1_000_000)
        || u64::try_from(value.as_millis()).is_err()
    {
        return Err(RetentionError::InvalidConfiguration(message));
    }
    Ok(())
}

fn millis(value: Duration) -> Result<u64, RetentionError> {
    u64::try_from(value.as_millis())
        .map_err(|_| RetentionError::InvalidConfiguration("timeout is too large"))
}

fn is_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn postgres_error_is_transient(error: &tokio_postgres::Error) -> bool {
    error.is_closed()
        || error.as_db_error().is_some_and(|database_error| {
            matches!(
                database_error.code().code(),
                "40001" | "40P01" | "55P03" | "57014"
            )
        })
}

fn postgres_error_is_retryable_mutation(error: &tokio_postgres::Error) -> bool {
    error
        .as_db_error()
        .is_some_and(|database_error| matches!(database_error.code().code(), "40001" | "40P01"))
}

fn retry_delay(error: &tokio_postgres::Error, attempt: u8) -> Option<Duration> {
    postgres_error_is_retryable_mutation(error)
        .then(|| retry_delay_for_attempt(attempt))
        .flatten()
}

fn retry_delay_for_attempt(attempt: u8) -> Option<Duration> {
    match attempt {
        1 => Some(FIRST_MUTATION_RETRY_DELAY),
        2 => Some(SECOND_MUTATION_RETRY_DELAY),
        _ => None,
    }
}

fn valid_identity(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn validate_full_projection(value: &RetentionFullRecordSnapshot) -> Result<(), RetentionError> {
    let ownership = &value.ownership;
    if !valid_identity(&ownership.provider_boundary_id, 1024)
        || !valid_identity(&ownership.authenticated_cell_id, 1024)
        || !valid_identity(&ownership.authenticated_tenant_id, 1024)
        || ownership.logical_request_id != value.logical_request_id.to_string()
        || ownership.attempt_id != value.attempt_id.to_string()
        || ownership.rows != 1
        || ownership.bytes == 0
        || ownership.concurrency != 0
        || value.ownership_revision == 0
        || value.created_at_unix_ms < 0
        || value.closure_committed_at_unix_ms < value.created_at_unix_ms
    {
        return Err(RetentionError::InvalidResponse("full record projection"));
    }
    Ok(())
}

fn validate_compact_projection(
    value: &RetentionCompactRecordSnapshot,
) -> Result<(), RetentionError> {
    if value.compact_sequence == 0
        || !valid_identity(&value.provider_boundary_id, 1024)
        || !valid_identity(&value.authenticated_cell_id, 1024)
        || !valid_identity(&value.authenticated_tenant_id, 1024)
        || value.compact_rows != 1
        || value.compact_bytes == 0
        || value.compact_concurrency != 0
        || value.compacted_at_unix_ms < 0
        || value.compact_prune_after_unix_ms < value.compacted_at_unix_ms
        || usize::try_from(value.compact_bytes).ok() != Some(value.compact_receipt_bytes.len())
        || !canonical_bytes_match_digest(&value.compact_receipt_bytes, &value.compact_blake3)
    {
        return Err(RetentionError::InvalidResponse("compact record projection"));
    }
    Ok(())
}

fn validate_watermark_projection(
    value: &ObjectStoreCompactPruneWatermark,
) -> Result<(), RetentionError> {
    if value.watermark_revision == 0 {
        return Err(RetentionError::InvalidResponse("watermark projection"));
    }
    let present = [
        value.last_prune_fingerprint.is_some(),
        value.last_compact_blake3.is_some(),
        value.last_pruned_at_unix_ms.is_some(),
        value.last_backup_revision.is_some(),
        value.last_backup_manifest_blake3.is_some(),
    ];
    if (value.pruned_through_compact_sequence == 0 && present.into_iter().any(|field| field))
        || (value.pruned_through_compact_sequence > 0
            && (present.into_iter().any(|field| !field)
                || value.last_pruned_at_unix_ms.is_some_and(|time| time < 0)
                || value
                    .last_backup_revision
                    .as_deref()
                    .is_none_or(|revision| !valid_identity(revision, u32::MAX as usize))))
    {
        return Err(RetentionError::InvalidResponse("watermark projection"));
    }
    Ok(())
}

fn validate_counter_projection(
    value: &ObjectStoreRecordStorageCounter,
) -> Result<(), RetentionError> {
    if value.counter_revision == 0
        || !valid_identity(&value.scope_id, 1024)
        || match value.scope {
            ObjectStoreFullToCompactScope::Global => {
                value.scope_id != OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID
            }
            ObjectStoreFullToCompactScope::Cell | ObjectStoreFullToCompactScope::Tenant => {
                value.scope_id == OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID
            }
        }
    {
        return Err(RetentionError::InvalidResponse("counter projection"));
    }
    Ok(())
}

fn validate_scoped_counters(
    global: &ObjectStoreRecordStorageCounter,
    cell: Option<&ObjectStoreRecordStorageCounter>,
    tenant: Option<&ObjectStoreRecordStorageCounter>,
    expected_cell_id: &str,
    expected_tenant_id: &str,
) -> Result<(), RetentionError> {
    let (Some(cell), Some(tenant)) = (cell, tenant) else {
        return Err(RetentionError::InvalidResponse("scoped counter projection"));
    };
    if global.scope != ObjectStoreFullToCompactScope::Global
        || cell.scope != ObjectStoreFullToCompactScope::Cell
        || tenant.scope != ObjectStoreFullToCompactScope::Tenant
        || cell.scope_id != expected_cell_id
        || tenant.scope_id != expected_tenant_id
        || [cell, tenant].into_iter().any(|child| {
            child.full_record_rows > global.full_record_rows
                || child.full_record_bytes > global.full_record_bytes
                || child.compact_rows > global.compact_rows
                || child.compact_bytes > global.compact_bytes
        })
    {
        return Err(RetentionError::InvalidResponse("scoped counter projection"));
    }
    Ok(())
}

fn validate_prune_receipt_projection(
    value: &RetentionPruneReceiptSnapshot,
) -> Result<(), RetentionError> {
    if value.compact_sequence == 0
        || !valid_identity(&value.provider_boundary_id, 1024)
        || !valid_identity(&value.authenticated_cell_id, 1024)
        || !valid_identity(&value.authenticated_tenant_id, 1024)
        || value.compact_rows != 1
        || value.compact_bytes == 0
        || value.compact_concurrency != 0
        || !valid_identity(&value.backup_revision, u32::MAX as usize)
        || value.restore_verified_through_compact_sequence
            > value.durable_covered_through_compact_sequence
        || value.restore_verified_through_compact_sequence < value.compact_sequence
        || value.durable_covered_through_compact_sequence < value.compact_sequence
        || value.backup_observed_at_unix_ms < 0
        || value.pruned_at_unix_ms < 0
        || value.post_watermark.pruned_through_compact_sequence != value.compact_sequence
        || value.post_watermark.last_prune_fingerprint != Some(value.prune_fingerprint)
        || value.post_watermark.last_compact_blake3 != Some(value.compact_blake3)
        || value.post_watermark.last_pruned_at_unix_ms != Some(value.pruned_at_unix_ms)
        || value.post_watermark.last_backup_revision.as_deref()
            != Some(value.backup_revision.as_str())
        || value.post_watermark.last_backup_manifest_blake3 != Some(value.backup_manifest_blake3)
    {
        return Err(RetentionError::InvalidResponse("prune receipt projection"));
    }
    validate_watermark_projection(&value.post_watermark)?;
    validate_scoped_counters(
        &value.post_counters.global,
        Some(&value.post_counters.cell),
        Some(&value.post_counters.tenant),
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
    )
}

fn parse_u64(value: Option<String>, field: &'static str) -> Result<u64, RetentionError> {
    let value = value.ok_or(RetentionError::InvalidResponse(field))?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| RetentionError::InvalidResponse(field))?;
    if parsed.to_string() != value {
        return Err(RetentionError::InvalidResponse(field));
    }
    Ok(parsed)
}

fn parse_digest(value: Option<Vec<u8>>, field: &'static str) -> Result<[u8; 32], RetentionError> {
    value
        .ok_or(RetentionError::InvalidResponse(field))?
        .try_into()
        .map_err(|_| RetentionError::InvalidResponse(field))
}

fn canonical_bytes_match_digest(bytes: &[u8], digest: &[u8; 32]) -> bool {
    if bytes.len() <= 32 {
        return false;
    }
    let (preimage, trailing) = bytes.split_at(bytes.len() - 32);
    trailing == digest && blake3::hash(preimage).as_bytes() == digest
}

fn parse_watermark(
    row: &Row,
    start: usize,
) -> Result<ObjectStoreCompactPruneWatermark, RetentionError> {
    let watermark = ObjectStoreCompactPruneWatermark {
        pruned_through_compact_sequence: parse_u64(row.try_get(start).ok(), "watermark sequence")?,
        watermark_revision: parse_u64(row.try_get(start + 1).ok(), "watermark revision")?,
        last_prune_fingerprint: optional_digest(
            row.try_get(start + 2).ok(),
            "last prune fingerprint",
        )?,
        last_compact_blake3: optional_digest(row.try_get(start + 3).ok(), "last compact digest")?,
        last_pruned_at_unix_ms: row
            .try_get(start + 4)
            .map_err(|_| RetentionError::InvalidResponse("last pruned time"))?,
        last_backup_revision: row
            .try_get(start + 5)
            .map_err(|_| RetentionError::InvalidResponse("last backup revision"))?,
        last_backup_manifest_blake3: optional_digest(
            row.try_get(start + 6).ok(),
            "last backup digest",
        )?,
    };
    validate_watermark_projection(&watermark)?;
    Ok(watermark)
}

fn optional_digest(
    value: Option<Vec<u8>>,
    field: &'static str,
) -> Result<Option<[u8; 32]>, RetentionError> {
    value
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| RetentionError::InvalidResponse(field))
        })
        .transpose()
}

fn parse_counter(
    row: &Row,
    start: usize,
) -> Result<Option<ObjectStoreRecordStorageCounter>, RetentionError> {
    let scope_kind: Option<i16> = row
        .try_get(start)
        .map_err(|_| RetentionError::InvalidResponse("counter scope kind"))?;
    let Some(scope_kind) = scope_kind else {
        return Ok(None);
    };
    let scope = match scope_kind {
        1 => ObjectStoreFullToCompactScope::Global,
        2 => ObjectStoreFullToCompactScope::Cell,
        3 => ObjectStoreFullToCompactScope::Tenant,
        _ => return Err(RetentionError::InvalidResponse("counter scope kind")),
    };
    let counter = ObjectStoreRecordStorageCounter {
        scope,
        scope_id: row
            .try_get(start + 1)
            .map_err(|_| RetentionError::InvalidResponse("counter scope id"))?,
        full_record_rows: parse_u64(row.try_get(start + 2).ok(), "counter full rows")?,
        full_record_bytes: parse_u64(row.try_get(start + 3).ok(), "counter full bytes")?,
        compact_rows: parse_u64(row.try_get(start + 4).ok(), "counter compact rows")?,
        compact_bytes: parse_u64(row.try_get(start + 5).ok(), "counter compact bytes")?,
        counter_revision: parse_u64(row.try_get(start + 6).ok(), "counter revision")?,
    };
    validate_counter_projection(&counter)?;
    Ok(Some(counter))
}

fn parse_compact(
    row: &Row,
    start: usize,
) -> Result<Option<RetentionCompactRecordSnapshot>, RetentionError> {
    let sequence: Option<String> = row
        .try_get(start)
        .map_err(|_| RetentionError::InvalidResponse("compact sequence"))?;
    let Some(sequence) = sequence else {
        return Ok(None);
    };
    let compact_receipt_bytes: Vec<u8> = row
        .try_get(start + 7)
        .map_err(|_| RetentionError::InvalidResponse("compact receipt"))?;
    let compact_bytes = parse_u64(row.try_get(start + 10).ok(), "compact bytes")?;
    let compact_blake3 = parse_digest(row.try_get(start + 8).ok(), "compact digest")?;
    if usize::try_from(compact_bytes).ok() != Some(compact_receipt_bytes.len())
        || !canonical_bytes_match_digest(&compact_receipt_bytes, &compact_blake3)
    {
        return Err(RetentionError::InvalidResponse("compact byte length"));
    }
    let compact = RetentionCompactRecordSnapshot {
        compact_sequence: sequence
            .parse()
            .map_err(|_| RetentionError::InvalidResponse("compact sequence"))?,
        logical_request_id: row
            .try_get(start + 1)
            .map_err(|_| RetentionError::InvalidResponse("compact request id"))?,
        attempt_id: row
            .try_get(start + 2)
            .map_err(|_| RetentionError::InvalidResponse("compact attempt id"))?,
        provider_boundary_id: row
            .try_get(start + 3)
            .map_err(|_| RetentionError::InvalidResponse("compact boundary"))?,
        authenticated_cell_id: row
            .try_get(start + 4)
            .map_err(|_| RetentionError::InvalidResponse("compact cell"))?,
        authenticated_tenant_id: row
            .try_get(start + 5)
            .map_err(|_| RetentionError::InvalidResponse("compact tenant"))?,
        source_authority_blake3: parse_digest(
            row.try_get(start + 6).ok(),
            "compact source digest",
        )?,
        compact_receipt_bytes,
        compact_blake3,
        compact_rows: parse_u64(row.try_get(start + 9).ok(), "compact rows")?,
        compact_bytes,
        compact_concurrency: parse_u64(row.try_get(start + 11).ok(), "compact concurrency")?,
        compaction_fingerprint: parse_digest(
            row.try_get(start + 12).ok(),
            "compaction fingerprint",
        )?,
        transfer_fingerprint: parse_digest(row.try_get(start + 13).ok(), "transfer fingerprint")?,
        compacted_at_unix_ms: row
            .try_get(start + 14)
            .map_err(|_| RetentionError::InvalidResponse("compacted time"))?,
        compact_prune_after_unix_ms: row
            .try_get(start + 15)
            .map_err(|_| RetentionError::InvalidResponse("prune floor"))?,
    };
    validate_compact_projection(&compact)?;
    Ok(Some(compact))
}

fn parse_transfer_snapshot(row: &Row) -> Result<RetentionTransferSnapshot, RetentionError> {
    let state_text: String = row
        .try_get(0)
        .map_err(|_| RetentionError::InvalidResponse("transfer state"))?;
    let full_request: Option<Uuid> = row
        .try_get(1)
        .map_err(|_| RetentionError::InvalidResponse("full request id"))?;
    let full_record = if let Some(logical_request_id) = full_request {
        let attempt_id = row
            .try_get(2)
            .map_err(|_| RetentionError::InvalidResponse("full attempt id"))?;
        let provider_boundary_id = row
            .try_get(3)
            .map_err(|_| RetentionError::InvalidResponse("full boundary"))?;
        let authenticated_cell_id = row
            .try_get(4)
            .map_err(|_| RetentionError::InvalidResponse("full cell"))?;
        let authenticated_tenant_id = row
            .try_get(5)
            .map_err(|_| RetentionError::InvalidResponse("full tenant"))?;
        let full = RetentionFullRecordSnapshot {
            logical_request_id,
            attempt_id,
            ownership: ObjectStoreFullRecordOwnership {
                provider_boundary_id,
                authenticated_cell_id,
                authenticated_tenant_id,
                logical_request_id: logical_request_id.to_string(),
                attempt_id: attempt_id.to_string(),
                source_authority_blake3: parse_digest(row.try_get(6).ok(), "full source digest")?,
                rows: parse_u64(row.try_get(7).ok(), "full rows")?,
                bytes: parse_u64(row.try_get(8).ok(), "full bytes")?,
                concurrency: parse_u64(row.try_get(9).ok(), "full concurrency")?,
            },
            ownership_revision: parse_u64(row.try_get(10).ok(), "ownership revision")?,
            closure_committed_at_unix_ms: row
                .try_get(11)
                .map_err(|_| RetentionError::InvalidResponse("closure time"))?,
            created_at_unix_ms: row
                .try_get(12)
                .map_err(|_| RetentionError::InvalidResponse("created time"))?,
        };
        validate_full_projection(&full)?;
        Some(full)
    } else {
        None
    };
    let compact_record = parse_compact(row, 13)?;
    let state = match state_text.as_str() {
        "FULL_OWNED" => RetentionTransferState::FullOwned,
        "COMPACT_INSTALLED" => RetentionTransferState::CompactInstalled,
        "ABSENT" => RetentionTransferState::Absent,
        "CONFLICT" => RetentionTransferState::Conflict,
        _ => return Err(RetentionError::InvalidResponse("transfer state")),
    };
    let global_counter =
        parse_counter(row, 31)?.ok_or(RetentionError::InvalidResponse("global counter"))?;
    let cell_counter = parse_counter(row, 38)?;
    let tenant_counter = parse_counter(row, 45)?;
    let valid_shape = match state {
        RetentionTransferState::FullOwned => {
            full_record.is_some()
                && compact_record.is_none()
                && cell_counter.is_some()
                && tenant_counter.is_some()
        }
        RetentionTransferState::CompactInstalled => {
            full_record.is_none()
                && compact_record.is_some()
                && cell_counter.is_some()
                && tenant_counter.is_some()
        }
        RetentionTransferState::Absent => {
            full_record.is_none()
                && compact_record.is_none()
                && cell_counter.is_none()
                && tenant_counter.is_none()
        }
        RetentionTransferState::Conflict => {
            full_record.is_none()
                && compact_record.is_none()
                && cell_counter.is_none()
                && tenant_counter.is_none()
        }
    };
    if !valid_shape {
        return Err(RetentionError::InvalidResponse("transfer projection shape"));
    }
    if let Some(record) = full_record.as_ref() {
        validate_scoped_counters(
            &global_counter,
            cell_counter.as_ref(),
            tenant_counter.as_ref(),
            &record.ownership.authenticated_cell_id,
            &record.ownership.authenticated_tenant_id,
        )?;
    }
    if let Some(record) = compact_record.as_ref() {
        if record.compact_sequence > parse_u64(row.try_get(29).ok(), "sequence high water")? {
            return Err(RetentionError::InvalidResponse(
                "compact sequence high water",
            ));
        }
        validate_scoped_counters(
            &global_counter,
            cell_counter.as_ref(),
            tenant_counter.as_ref(),
            &record.authenticated_cell_id,
            &record.authenticated_tenant_id,
        )?;
    }
    Ok(RetentionTransferSnapshot {
        state,
        full_record,
        compact_record,
        compact_sequence_high_water: parse_u64(row.try_get(29).ok(), "sequence high water")?,
        compact_sequence_revision: parse_u64(row.try_get(30).ok(), "sequence revision")?,
        global_counter,
        cell_counter,
        tenant_counter,
    })
}

fn parse_prune_snapshot(row: &Row) -> Result<RetentionPruneSnapshot, RetentionError> {
    let state_text: String = row
        .try_get(0)
        .map_err(|_| RetentionError::InvalidResponse("prune state"))?;
    let compact_record = parse_compact(row, 1)?;
    let receipt_sequence: Option<String> = row
        .try_get(17)
        .map_err(|_| RetentionError::InvalidResponse("receipt sequence"))?;
    let watermark = parse_watermark(row, 34)?;
    let global_counter =
        parse_counter(row, 41)?.ok_or(RetentionError::InvalidResponse("global counter"))?;
    let cell_counter = parse_counter(row, 48)?;
    let tenant_counter = parse_counter(row, 55)?;
    let prune_receipt = receipt_sequence
        .map(|sequence| {
            let post_watermark = parse_watermark(row, 62)?;
            let post_counters = ObjectStoreFullToCompactNextCounters {
                global: parse_counter(row, 69)?
                    .ok_or(RetentionError::InvalidResponse("receipt global counter"))?,
                cell: parse_counter(row, 76)?
                    .ok_or(RetentionError::InvalidResponse("receipt cell counter"))?,
                tenant: parse_counter(row, 83)?
                    .ok_or(RetentionError::InvalidResponse("receipt tenant counter"))?,
            };
            Ok(RetentionPruneReceiptSnapshot {
                compact_sequence: sequence
                    .parse()
                    .map_err(|_| RetentionError::InvalidResponse("receipt sequence"))?,
                logical_request_id: row
                    .try_get(18)
                    .map_err(|_| RetentionError::InvalidResponse("receipt request id"))?,
                attempt_id: row
                    .try_get(19)
                    .map_err(|_| RetentionError::InvalidResponse("receipt attempt id"))?,
                provider_boundary_id: row
                    .try_get(20)
                    .map_err(|_| RetentionError::InvalidResponse("receipt boundary"))?,
                authenticated_cell_id: row
                    .try_get(21)
                    .map_err(|_| RetentionError::InvalidResponse("receipt cell"))?,
                authenticated_tenant_id: row
                    .try_get(22)
                    .map_err(|_| RetentionError::InvalidResponse("receipt tenant"))?,
                compact_blake3: parse_digest(row.try_get(23).ok(), "receipt compact digest")?,
                compact_rows: parse_u64(row.try_get(24).ok(), "receipt compact rows")?,
                compact_bytes: parse_u64(row.try_get(25).ok(), "receipt compact bytes")?,
                compact_concurrency: parse_u64(
                    row.try_get(26).ok(),
                    "receipt compact concurrency",
                )?,
                prune_fingerprint: parse_digest(row.try_get(27).ok(), "receipt prune fingerprint")?,
                backup_revision: row
                    .try_get(28)
                    .map_err(|_| RetentionError::InvalidResponse("receipt backup revision"))?,
                backup_manifest_blake3: parse_digest(
                    row.try_get(29).ok(),
                    "receipt backup digest",
                )?,
                durable_covered_through_compact_sequence: parse_u64(
                    row.try_get(30).ok(),
                    "receipt durable coverage",
                )?,
                restore_verified_through_compact_sequence: parse_u64(
                    row.try_get(31).ok(),
                    "receipt restore coverage",
                )?,
                backup_observed_at_unix_ms: row
                    .try_get(32)
                    .map_err(|_| RetentionError::InvalidResponse("receipt backup time"))?,
                pruned_at_unix_ms: row
                    .try_get(33)
                    .map_err(|_| RetentionError::InvalidResponse("receipt prune time"))?,
                post_watermark,
                post_counters,
            })
        })
        .transpose()?;
    let state = match state_text.as_str() {
        "COMPACT_INSTALLED" => RetentionPruneState::CompactInstalled,
        "PRUNED" => RetentionPruneState::Pruned,
        "ABSENT_UNPROVEN" => RetentionPruneState::AbsentUnproven,
        _ => return Err(RetentionError::InvalidResponse("prune state")),
    };
    let valid_shape = match state {
        RetentionPruneState::CompactInstalled => {
            compact_record.is_some()
                && prune_receipt.is_none()
                && cell_counter.is_some()
                && tenant_counter.is_some()
        }
        RetentionPruneState::Pruned => {
            compact_record.is_none()
                && prune_receipt.is_some()
                && cell_counter.is_some()
                && tenant_counter.is_some()
        }
        RetentionPruneState::AbsentUnproven => {
            compact_record.is_none()
                && prune_receipt.is_none()
                && cell_counter.is_none()
                && tenant_counter.is_none()
        }
    };
    if !valid_shape {
        return Err(RetentionError::InvalidResponse("prune projection shape"));
    }
    if let Some(record) = compact_record.as_ref() {
        validate_scoped_counters(
            &global_counter,
            cell_counter.as_ref(),
            tenant_counter.as_ref(),
            &record.authenticated_cell_id,
            &record.authenticated_tenant_id,
        )?;
    }
    if let Some(receipt) = prune_receipt.as_ref() {
        validate_prune_receipt_projection(receipt)?;
    }
    let database_now_unix_ms = row
        .try_get(90)
        .map_err(|_| RetentionError::InvalidResponse("prune database time"))?;
    if database_now_unix_ms < 0 {
        return Err(RetentionError::InvalidResponse("prune database time"));
    }
    Ok(RetentionPruneSnapshot {
        state,
        compact_record,
        prune_receipt,
        watermark,
        global_counter,
        cell_counter,
        tenant_counter,
        database_now_unix_ms,
    })
}

fn parse_transfer_mutation(row: &Row) -> Result<RetentionTransferMutationResult, RetentionError> {
    let result_code: String = row
        .try_get(0)
        .map_err(|_| RetentionError::InvalidResponse("transfer result code"))?;
    if !matches!(result_code.as_str(), "APPLIED" | "REPLAY") {
        return Err(RetentionError::InvalidResponse("transfer result code"));
    }
    let compact_record =
        parse_compact(row, 1)?.ok_or(RetentionError::InvalidResponse("transfer compact record"))?;
    let global = parse_counter(row, 19)?
        .ok_or(RetentionError::InvalidResponse("transfer global counter"))?;
    let cell =
        parse_counter(row, 26)?.ok_or(RetentionError::InvalidResponse("transfer cell counter"))?;
    let tenant = parse_counter(row, 33)?
        .ok_or(RetentionError::InvalidResponse("transfer tenant counter"))?;
    Ok(RetentionTransferMutationResult {
        result_code,
        compact_record,
        compact_sequence_high_water: parse_u64(
            row.try_get(17).ok(),
            "transfer sequence high water",
        )?,
        compact_sequence_revision: parse_u64(row.try_get(18).ok(), "transfer sequence revision")?,
        next_counters: ObjectStoreFullToCompactNextCounters {
            global,
            cell,
            tenant,
        },
    })
}

fn transfer_result_matches(
    result: &RetentionTransferMutationResult,
    prepared: &PreparedTransfer<'_>,
) -> bool {
    let value = prepared.compact.value();
    result.compact_sequence_high_water == prepared.expected_sequence
        && result.compact_sequence_revision == prepared.expected_sequence_revision
        && result.next_counters == *prepared.next_counters
        && result.compact_record.compact_sequence == prepared.expected_sequence
        && result.compact_record.logical_request_id == prepared.full.logical_request_id
        && result.compact_record.attempt_id == prepared.full.attempt_id
        && result.compact_record.provider_boundary_id == value.provider_boundary_id
        && result.compact_record.authenticated_cell_id == value.authenticated_cell_id
        && result.compact_record.authenticated_tenant_id == value.authenticated_tenant_id
        && result.compact_record.source_authority_blake3
            == prepared.full.ownership.source_authority_blake3
        && result.compact_record.compact_receipt_bytes == prepared.compact.canonical_bytes()
        && result.compact_record.compact_blake3 == value.compact_blake3
        && result.compact_record.compaction_fingerprint == value.compaction_fingerprint
        && result.compact_record.transfer_fingerprint == *prepared.transfer_fingerprint
        && result.compact_record.compacted_at_unix_ms == value.compacted_at_unix_ms
        && result.compact_record.compact_prune_after_unix_ms == value.compact_prune_after_unix_ms
}

fn transfer_readback_matches(
    readback: &RetentionTransferSnapshot,
    precommit: &RetentionTransferMutationResult,
) -> bool {
    readback.state == RetentionTransferState::CompactInstalled
        && readback.compact_record.as_ref() == Some(&precommit.compact_record)
        && readback.compact_sequence_high_water >= precommit.compact_sequence_high_water
        && readback.compact_sequence_revision >= precommit.compact_sequence_revision
}

fn transfer_adoption_from_readback(
    readback: &RetentionTransferSnapshot,
    prepared: &PreparedTransfer<'_>,
) -> Option<RetentionTransferMutationResult> {
    let compact_record = readback.compact_record.clone()?;
    let candidate = RetentionTransferMutationResult {
        result_code: "APPLIED".to_string(),
        compact_record,
        compact_sequence_high_water: prepared.expected_sequence,
        compact_sequence_revision: prepared.expected_sequence_revision,
        next_counters: prepared.next_counters.clone(),
    };
    (readback.state == RetentionTransferState::CompactInstalled
        && transfer_result_matches(&candidate, prepared))
    .then_some(candidate)
}

fn parse_prune_mutation(row: &Row) -> Result<RetentionPruneReceiptSnapshot, RetentionError> {
    let result_code: String = row
        .try_get(0)
        .map_err(|_| RetentionError::InvalidResponse("prune result code"))?;
    if !matches!(result_code.as_str(), "APPLIED" | "REPLAY") {
        return Err(RetentionError::InvalidResponse("prune result code"));
    }
    let watermark = parse_watermark(row, 18)?;
    let global =
        parse_counter(row, 25)?.ok_or(RetentionError::InvalidResponse("prune global counter"))?;
    let cell =
        parse_counter(row, 32)?.ok_or(RetentionError::InvalidResponse("prune cell counter"))?;
    let tenant =
        parse_counter(row, 39)?.ok_or(RetentionError::InvalidResponse("prune tenant counter"))?;
    let receipt = RetentionPruneReceiptSnapshot {
        compact_sequence: parse_u64(row.try_get(1).ok(), "prune receipt sequence")?,
        logical_request_id: row
            .try_get(2)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt request id"))?,
        attempt_id: row
            .try_get(3)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt attempt id"))?,
        provider_boundary_id: row
            .try_get(4)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt boundary"))?,
        authenticated_cell_id: row
            .try_get(5)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt cell"))?,
        authenticated_tenant_id: row
            .try_get(6)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt tenant"))?,
        compact_blake3: parse_digest(row.try_get(7).ok(), "prune receipt compact digest")?,
        compact_rows: parse_u64(row.try_get(8).ok(), "prune receipt compact rows")?,
        compact_bytes: parse_u64(row.try_get(9).ok(), "prune receipt compact bytes")?,
        compact_concurrency: parse_u64(row.try_get(10).ok(), "prune receipt compact concurrency")?,
        prune_fingerprint: parse_digest(row.try_get(11).ok(), "prune receipt fingerprint")?,
        backup_revision: row
            .try_get(12)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt backup revision"))?,
        backup_manifest_blake3: parse_digest(row.try_get(13).ok(), "prune receipt backup digest")?,
        durable_covered_through_compact_sequence: parse_u64(
            row.try_get(14).ok(),
            "prune receipt durable coverage",
        )?,
        restore_verified_through_compact_sequence: parse_u64(
            row.try_get(15).ok(),
            "prune receipt restore coverage",
        )?,
        backup_observed_at_unix_ms: row
            .try_get(16)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt backup time"))?,
        pruned_at_unix_ms: row
            .try_get(17)
            .map_err(|_| RetentionError::InvalidResponse("prune receipt prune time"))?,
        post_watermark: watermark,
        post_counters: ObjectStoreFullToCompactNextCounters {
            global,
            cell,
            tenant,
        },
    };
    validate_prune_receipt_projection(&receipt)?;
    Ok(receipt)
}

fn prune_result_matches(
    result: &RetentionPruneReceiptSnapshot,
    prepared: &PreparedPrune<'_>,
) -> bool {
    let planned_time = prepared.next_watermark.last_pruned_at_unix_ms.unwrap_or(-1);
    let mut normalized_watermark = result.post_watermark.clone();
    normalized_watermark.last_pruned_at_unix_ms = Some(planned_time);
    result.compact_sequence == prepared.installed.compact_sequence
        && result.logical_request_id == prepared.installed.logical_request_id
        && result.attempt_id == prepared.installed.attempt_id
        && result.provider_boundary_id == prepared.installed.provider_boundary_id
        && result.authenticated_cell_id == prepared.installed.authenticated_cell_id
        && result.authenticated_tenant_id == prepared.installed.authenticated_tenant_id
        && result.compact_blake3 == *prepared.expected_compact_blake3
        && result.compact_rows == 1
        && result.compact_bytes
            == u64::try_from(prepared.compact.canonical_bytes().len()).unwrap_or(u64::MAX)
        && result.compact_concurrency == 0
        && result.prune_fingerprint == *prepared.prune_fingerprint
        && result.backup_revision == prepared.backup.backup_revision
        && result.backup_manifest_blake3 == prepared.backup.backup_manifest_blake3
        && result.durable_covered_through_compact_sequence
            == prepared.backup.durable_covered_through_compact_sequence
        && result.restore_verified_through_compact_sequence
            == prepared.backup.restore_verified_through_compact_sequence
        && result.backup_observed_at_unix_ms == prepared.backup.observed_at_unix_ms
        && result.pruned_at_unix_ms == result.post_watermark.last_pruned_at_unix_ms.unwrap_or(-1)
        && result.pruned_at_unix_ms >= planned_time
        && result.pruned_at_unix_ms >= prepared.installed.compact_prune_after_unix_ms
        && result.pruned_at_unix_ms >= prepared.backup.observed_at_unix_ms
        && normalized_watermark == *prepared.next_watermark
        && result.post_counters == *prepared.next_counters
}

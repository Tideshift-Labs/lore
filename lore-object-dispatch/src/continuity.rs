// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Direct mTLS client for the independent object-dispatch continuity database.
//!
//! The connector deliberately has no plaintext, opportunistic TLS, native-root, password-only, or
//! insecure-verifier mode. PostgreSQL verifies the client identity and maps it to one boundary role;
//! rustls verifies the server DNS name against the explicitly provisioned continuity root CA.

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
use tokio_postgres::types::PgLsn;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const API_REVISION: &str = "object-store-authority-continuity-v1";
const MUTATION_ISOLATION_LEVEL: IsolationLevel = IsolationLevel::Serializable;
const MAX_ARCHIVE_PROOF_BYTES: usize = 1_048_576;
const BEGIN_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms \
    FROM object_store_continuity.object_store_continuity_begin_v1(\
      $1, $2::text::object_store_continuity.uint64, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
      $13::text::object_store_continuity.uint64, $14::text::object_store_continuity.uint64, \
      $15::text::object_store_continuity.uint64, $16\
    )";
const GET_BY_TOKEN_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_get_by_token_v1($1, $2, $3)";
const MARK_BOUND_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_bound_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13\
    )";
const MARK_COMPLETED_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_completed_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15\
    )";
const MARK_NO_LOCAL_EFFECT_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_no_local_effect_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16\
    )";
const QUARANTINE_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_quarantine_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15\
    )";
const MARK_AMBIGUOUS_DISPATCH_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_ambiguous_dispatch_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15\
    )";
const PREPARE_ADJUDICATION_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_prepare_adjudication_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16\
    )";
const COMPLETE_ADJUDICATION_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_complete_adjudication_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
      $16, $17, $18, $19\
    )";
const RECORD_SNAPSHOT_SQL: &str = "SELECT accepted_snapshot_id, \
    accepted_through_continuity_seq::text, accepted_manifest_blake3, \
    accepted_coverage_blake3, recorded_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_record_snapshot_v1(\
      $1, $2, $3, $4::text::object_store_continuity.uint64, \
      $5::text::object_store_continuity.uint64, $6, $7, \
      $8::text::object_store_continuity.uint64, $9, $10, $11, $12, \
      $13::text::object_store_continuity.uint64\
    )";
const RELEASE_SHADOW_OWNERSHIP_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_release_shadow_ownership_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
      $15, $16, $17\
    )";
const READ_RECONCILIATION_STATE_SQL: &str = "SELECT current_authority_epoch::text, \
    continuity_seq_high_water::text, owned_rows::text, owned_bytes::text, \
    owned_concurrency::text, latest_snapshot_id, latest_snapshot_through_continuity_seq::text, \
    latest_snapshot_manifest_blake3 FROM \
    object_store_continuity.object_store_continuity_read_reconciliation_state_v1(\
      $1, $2, $3::text::object_store_continuity.uint64\
    )";
const READ_EPOCH_SQL: &str = "SELECT authority_epoch::text, continuity_seq_high_water::text FROM \
    object_store_continuity.object_store_continuity_read_epoch_v1($1, $2)";
const ALLOCATE_EPOCH_SQL: &str = "SELECT authority_epoch::text, continuity_seq_high_water::text FROM \
    object_store_continuity.object_store_continuity_allocate_epoch_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )";
const READ_SHADOW_RELEASE_RECEIPT_SQL: &str = "SELECT receipt_provider_boundary_id, \
    receipt_authority_epoch::text, receipt_continuity_seq::text, receipt_continuity_token_id, \
    release_id, receipt_blake3, released_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )";
const ARCHIVE_PRUNE_SQL: &str = "SELECT accepted_start_sequence::text, \
    accepted_end_sequence::text, accepted_row_count::text, prune_commit_sequence::text, \
    accepted_interval_blake3 FROM \
    object_store_continuity.object_store_continuity_archive_prune_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9\
    )";

/// Connection material for one continuity boundary identity.
///
/// The custom [`Debug`] implementation never prints the URL or PEM material because each can carry
/// credentials. Callers should obtain the PEM values from the deployment secret provider and keep
/// them in memory only.
#[derive(Clone)]
pub struct ContinuityTlsConfig {
    pub postgres_url: String,
    pub root_ca_pem: String,
    pub client_certificate_chain_pem: String,
    pub private_key_pem: String,
    pub connect_timeout: Duration,
}

impl fmt::Debug for ContinuityTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuityTlsConfig")
            .field("postgres_url", &"<redacted>")
            .field("root_ca_pem", &"<redacted>")
            .field("client_certificate_chain_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl ContinuityTlsConfig {
    /// Validate the fail-closed connection contract without opening a socket.
    pub fn validate(&self) -> Result<(), ContinuityError> {
        self.connection_material().map(|_| ())
    }

    fn connection_material(
        &self,
    ) -> Result<(tokio_postgres::Config, MakeRustlsConnect), ContinuityError> {
        if self.connect_timeout.is_zero() {
            return Err(ContinuityError::InvalidConfiguration(
                "connect timeout must be positive",
            ));
        }
        let postgres = self
            .postgres_url
            .parse::<tokio_postgres::Config>()
            .map_err(|_| ContinuityError::InvalidConfiguration("invalid PostgreSQL URL"))?;
        if postgres.get_ssl_mode() != SslMode::Require {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL requires sslmode=require",
            ));
        }
        let [Host::Tcp(host)] = postgres.get_hosts() else {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL requires exactly one TCP DNS host",
            ));
        };
        if host.parse::<IpAddr>().is_ok() || !is_dns_name(host) {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL host must be a DNS name",
            ));
        }
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL URL requires user and database",
            ));
        }

        let mut roots = RootCertStore::empty();
        let mut root_reader = Cursor::new(self.root_ca_pem.as_bytes());
        let mut root_count = 0usize;
        for certificate in rustls_pemfile::certs(&mut root_reader) {
            let certificate = certificate
                .map_err(|_| ContinuityError::InvalidTlsMaterial("invalid root CA PEM"))?;
            roots
                .add(certificate)
                .map_err(|_| ContinuityError::InvalidTlsMaterial("unusable root CA certificate"))?;
            root_count = root_count.saturating_add(1);
        }
        if root_count == 0 {
            return Err(ContinuityError::InvalidTlsMaterial(
                "root CA bundle is empty",
            ));
        }

        let mut certificate_reader = Cursor::new(self.client_certificate_chain_pem.as_bytes());
        let certificates = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ContinuityError::InvalidTlsMaterial("invalid client certificate PEM"))?;
        if certificates.is_empty() {
            return Err(ContinuityError::InvalidTlsMaterial(
                "client certificate chain is empty",
            ));
        }
        let mut key_reader = Cursor::new(self.private_key_pem.as_bytes());
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|_| ContinuityError::InvalidTlsMaterial("invalid client private key PEM"))?
            .ok_or(ContinuityError::InvalidTlsMaterial(
                "client private key is empty",
            ))?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| ContinuityError::InvalidTlsMaterial("unsupported TLS protocol set"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, private_key)
            .map_err(|_| {
                ContinuityError::InvalidTlsMaterial("client certificate and key do not match")
            })?;
        Ok((postgres, MakeRustlsConnect::new(tls)))
    }
}

/// Closed failure surface for the continuity client. Messages intentionally omit dynamic
/// connection strings, PEM bodies, SQL parameter values, and server diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum ContinuityError {
    #[error("invalid continuity connection configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid continuity TLS material: {0}")]
    InvalidTlsMaterial(&'static str),
    #[error("continuity database connection timed out")]
    ConnectTimeout,
    #[error("continuity database operation failed")]
    Postgres { transient: bool },
    #[error("invalid continuity procedure result: {0}")]
    InvalidResponse(&'static str),
}

impl ContinuityError {
    fn postgres(error: tokio_postgres::Error) -> Self {
        Self::Postgres {
            transient: postgres_error_is_transient(&error),
        }
    }

    /// Whether retrying against the same deployment revision can be safe after backoff.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::ConnectTimeout => true,
            Self::Postgres { transient } => *transient,
            Self::InvalidConfiguration(_)
            | Self::InvalidTlsMaterial(_)
            | Self::InvalidResponse(_) => false,
        }
    }
}

/// Immutable input to the gapless continuity-intent allocation procedure.
pub struct BeginIntentRequest {
    pub provider_boundary_id: String,
    pub expected_authority_epoch: u64,
    pub continuity_token_id: Uuid,
    pub intent_kind: ContinuityIntentKind,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub operation_quota_class: String,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub selected_fingerprint: [u8; 32],
    pub continuity_policy_revision: String,
    pub quota_bytes: u64,
    pub quota_rows: u64,
    pub quota_concurrency: u64,
    pub retention_deadline_unix_ms: i64,
}

/// Exact identity that every runtime transition re-presents to prevent cross-request adoption.
pub struct ContinuityIntentIdentity {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub intent_kind: ContinuityIntentKind,
    pub selected_fingerprint: [u8; 32],
}

/// Local durable binding transition from external INTENT to BOUND.
pub struct MarkBoundRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub local_binding_blake3: [u8; 32],
}

/// Terminal transition after the exact local result is durable.
pub struct MarkCompletedRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub local_binding_blake3: [u8; 32],
    pub terminal_evidence_blake3: [u8; 32],
}

/// Decisive no-local-effect transition with its exact quota-release basis.
pub struct MarkNoLocalEffectRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub terminal_evidence_blake3: [u8; 32],
    pub release_id: Uuid,
    pub release_basis_id: String,
    pub release_basis_blake3: [u8; 32],
}

/// Exact stored state and binding evidence accepted by a quarantine transition.
pub enum QuarantinePriorState {
    Intent,
    Bound { local_binding_blake3: [u8; 32] },
}

impl QuarantinePriorState {
    fn as_sql(&self) -> &'static str {
        match self {
            Self::Intent => "INTENT",
            Self::Bound { .. } => "BOUND",
        }
    }

    fn local_binding_blake3(&self) -> Option<&[u8]> {
        match self {
            Self::Intent => None,
            Self::Bound {
                local_binding_blake3,
            } => Some(local_binding_blake3),
        }
    }
}

/// Reconciler transition that preserves ownership while making ambiguity explicit.
pub struct QuarantineRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub prior_state: QuarantinePriorState,
    pub terminal_evidence_blake3: [u8; 32],
}

/// Reconciler transition from BOUND to explicit possible-provider-dispatch ambiguity.
pub struct MarkAmbiguousDispatchRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub local_binding_blake3: [u8; 32],
    pub terminal_evidence_blake3: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityAdjudicationKind {
    NoLocalEffect,
    NoDispatch,
}

impl ContinuityAdjudicationKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::NoLocalEffect => "NO_LOCAL_EFFECT",
            Self::NoDispatch => "NO_DISPATCH",
        }
    }

    fn prepared_prior_state_sql(self) -> &'static str {
        match self {
            Self::NoLocalEffect => "QUARANTINED",
            Self::NoDispatch => "AMBIGUOUS_DISPATCH",
        }
    }

    fn final_state_sql(self) -> &'static str {
        match self {
            Self::NoLocalEffect => "ADJUDICATED_NO_LOCAL_EFFECT",
            Self::NoDispatch => "ADJUDICATED_NO_DISPATCH",
        }
    }
}

/// First half of authenticated two-step adjudication. Ownership remains reserved.
pub struct PrepareAdjudicationRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub adjudication_kind: ContinuityAdjudicationKind,
    pub local_binding_blake3: Option<[u8; 32]>,
    pub terminal_evidence_blake3: [u8; 32],
}

/// Final adjudication evidence and exact release basis.
pub struct CompleteAdjudicationRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub adjudication_kind: ContinuityAdjudicationKind,
    pub local_binding_blake3: Option<[u8; 32]>,
    pub terminal_evidence_blake3: [u8; 32],
    pub release_id: Uuid,
    pub release_basis_id: String,
    pub release_basis_blake3: [u8; 32],
}

/// Exact local durability evidence accepted into one monotonic continuity snapshot.
pub struct RecordSnapshotRequest {
    pub snapshot_id: Uuid,
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub through_continuity_seq: u64,
    pub authority_lsn: u64,
    pub manifest_blake3: [u8; 32],
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub local_binding_blake3: [u8; 32],
    pub local_state_blake3: [u8; 32],
    pub local_quota_ownership_blake3: [u8; 32],
    pub local_counter_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSnapshotResult {
    pub accepted_snapshot_id: Uuid,
    pub accepted_through_continuity_seq: u64,
    pub accepted_manifest_blake3: [u8; 32],
    pub accepted_coverage_blake3: [u8; 32],
    pub recorded_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoveredReleaseState {
    Bound,
    Completed,
}

impl CoveredReleaseState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Bound => "BOUND",
            Self::Completed => "COMPLETED",
        }
    }

    fn as_state(self) -> ContinuityState {
        match self {
            Self::Bound => ContinuityState::Bound,
            Self::Completed => ContinuityState::Completed,
        }
    }
}

/// Release request bound to an exact accepted snapshot coverage receipt.
pub struct ReleaseShadowOwnershipRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub expected_state: CoveredReleaseState,
    pub snapshot_id: Uuid,
    pub expected_manifest_blake3: [u8; 32],
    pub expected_coverage_blake3: [u8; 32],
    pub release_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationSnapshot {
    pub snapshot_id: Uuid,
    pub through_continuity_seq: u64,
    pub manifest_blake3: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationState {
    pub current_authority_epoch: u64,
    pub continuity_seq_high_water: u64,
    pub owned_rows: u64,
    pub owned_bytes: u64,
    pub owned_concurrency: u64,
    pub latest_snapshot: Option<ReconciliationSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuityEpochState {
    pub authority_epoch: u64,
    pub continuity_seq_high_water: u64,
}

/// Compare-and-swap allocation of a strictly newer drained boundary epoch.
pub struct AllocateEpochRequest {
    pub provider_boundary_id: String,
    pub expected_current_epoch: u64,
    pub next_epoch: u64,
    pub epoch_namespace_blake3: [u8; 32],
}

/// Exact released-token identity used for least-privilege receipt readback.
pub struct ReadShadowReleaseReceiptRequest {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowReleaseReceipt {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub release_id: Uuid,
    pub receipt_blake3: [u8; 32],
    pub released_at_unix_ms: i64,
}

/// Exact terminal detail and local-dependency proof accepted for bounded archive/prune.
pub struct ArchivePruneRequest {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub expected_row_blake3: [u8; 32],
    pub expected_release_receipt_blake3: [u8; 32],
    pub archive_proof_bytes: Vec<u8>,
    pub archive_proof_blake3: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivePruneResult {
    pub accepted_start_sequence: u64,
    pub accepted_end_sequence: u64,
    pub accepted_row_count: u64,
    pub prune_commit_sequence: u64,
    pub accepted_interval_blake3: [u8; 32],
}

/// Server-derived result projection shared by continuity mutation and read procedures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuityProcedureResult {
    pub result_code: ContinuityResultCode,
    pub state: ContinuityState,
    pub ownership_state: ContinuityOwnershipState,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub row_blake3: [u8; 32],
    pub external_committed_at_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContinuityTokenLookup {
    Found(ContinuityProcedureResult),
    NotFound {
        continuity_token_id: Uuid,
        observed_at_unix_ms: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityResultCode {
    Created,
    Found,
    Replay,
    Updated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityState {
    Intent,
    Bound,
    Completed,
    NoLocalEffect,
    Quarantined,
    AmbiguousDispatch,
    AdjudicationPrepared,
    AdjudicatedNoLocalEffect,
    AdjudicatedNoDispatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityOwnershipState {
    ShadowReserved,
    OwnershipReleased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityIntentKind {
    UuidAdmission,
    DispatchCas,
}

impl ContinuityIntentKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::UuidAdmission => "UUID_ADMISSION",
            Self::DispatchCas => "DISPATCH_CAS",
        }
    }
}

/// One direct connection to the independent continuity authority.
pub struct ContinuityClient {
    client: Mutex<tokio_postgres::Client>,
    _connection_task: AbortOnDropHandle<()>,
}

impl ContinuityClient {
    /// Connect with mandatory server-name verification and client-certificate authentication.
    pub async fn connect(config: &ContinuityTlsConfig) -> Result<Self, ContinuityError> {
        let (postgres, tls) = config.connection_material()?;
        let connected = tokio::time::timeout(config.connect_timeout, postgres.connect(tls))
            .await
            .map_err(|_| ContinuityError::ConnectTimeout)?
            .map_err(ContinuityError::postgres)?;
        let (client, connection) = connected;
        let connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "object-store-continuity-postgres",
            async move {
                if connection.await.is_err() {
                    tracing::error!("object-store continuity PostgreSQL connection ended");
                }
            }
        ));
        Ok(Self {
            client: Mutex::new(client),
            _connection_task: connection_task,
        })
    }

    /// Allocate or replay an exact intent in a serializable read-write transaction.
    pub async fn begin(
        &self,
        request: &BeginIntentRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        if request.expected_authority_epoch == 0 {
            return Err(ContinuityError::InvalidConfiguration(
                "expected authority epoch must be positive",
            ));
        }
        if request.provider_boundary_id.is_empty()
            || request.authenticated_cell_id.is_empty()
            || request.authenticated_tenant_id.is_empty()
            || request.operation_quota_class.is_empty()
            || request.continuity_policy_revision.is_empty()
        {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity begin text must be nonempty",
            ));
        }
        if request.retention_deadline_unix_ms < 0 {
            return Err(ContinuityError::InvalidConfiguration(
                "retention deadline must be nonnegative",
            ));
        }
        let expected_authority_epoch = request.expected_authority_epoch.to_string();
        let quota_bytes = request.quota_bytes.to_string();
        let quota_rows = request.quota_rows.to_string();
        let quota_concurrency = request.quota_concurrency.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                BEGIN_SQL,
                &[
                    &API_REVISION,
                    &expected_authority_epoch,
                    &request.continuity_token_id,
                    &request.provider_boundary_id,
                    &request.intent_kind.as_sql(),
                    &request.authenticated_cell_id,
                    &request.authenticated_tenant_id,
                    &request.logical_request_id,
                    &request.attempt_id,
                    &&request.selected_fingerprint[..],
                    &request.continuity_policy_revision,
                    &request.operation_quota_class,
                    &quota_rows,
                    &quota_bytes,
                    &quota_concurrency,
                    &request.retention_deadline_unix_ms,
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_begin_result(&result, request)?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Read an exact token through the boundary-authorized SECURITY DEFINER surface.
    pub async fn get_by_token(
        &self,
        provider_boundary_id: &str,
        continuity_token_id: Uuid,
    ) -> Result<ContinuityTokenLookup, ContinuityError> {
        let client = self.client.lock().await;
        let row = client
            .query_one(
                GET_BY_TOKEN_SQL,
                &[&API_REVISION, &provider_boundary_id, &continuity_token_id],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_token_lookup(&row)?;
        if let ContinuityTokenLookup::Found(found) = &result {
            validate_lookup_result(found)?;
        }
        let returned_token = match &result {
            ContinuityTokenLookup::Found(found) => found.continuity_token_id,
            ContinuityTokenLookup::NotFound {
                continuity_token_id,
                ..
            } => *continuity_token_id,
        };
        if returned_token != continuity_token_id {
            return Err(ContinuityError::InvalidResponse(
                "token lookup returned a different token",
            ));
        }
        Ok(result)
    }

    /// Bind an external intent to its exact durable local request state.
    pub async fn mark_bound(
        &self,
        request: &MarkBoundRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                MARK_BOUND_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &&request.local_binding_blake3[..],
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_transition_result(
            &result,
            &request.identity,
            ContinuityState::Bound,
            ContinuityOwnershipState::ShadowReserved,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Record exact terminal evidence while retaining shadow ownership for snapshot coverage.
    pub async fn mark_completed(
        &self,
        request: &MarkCompletedRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                MARK_COMPLETED_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &&request.local_binding_blake3[..],
                    &&request.terminal_evidence_blake3[..],
                    &"BOUND",
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_transition_result(
            &result,
            &request.identity,
            ContinuityState::Completed,
            ContinuityOwnershipState::ShadowReserved,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Close an intent that provably produced no local effect and release its shadow ownership.
    pub async fn mark_no_local_effect(
        &self,
        request: &MarkNoLocalEffectRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        validate_release_basis_id(&request.release_basis_id)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                MARK_NO_LOCAL_EFFECT_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &&request.terminal_evidence_blake3[..],
                    &request.release_id,
                    &request.release_basis_id,
                    &&request.release_basis_blake3[..],
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_transition_result(
            &result,
            &request.identity,
            ContinuityState::NoLocalEffect,
            ContinuityOwnershipState::OwnershipReleased,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Preserve shadow ownership while recording an exact INTENT or BOUND quarantine.
    pub async fn quarantine(
        &self,
        request: &QuarantineRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let local_binding = request.prior_state.local_binding_blake3();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                QUARANTINE_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &request.prior_state.as_sql(),
                    &local_binding,
                    &&request.terminal_evidence_blake3[..],
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_transition_result(
            &result,
            &request.identity,
            ContinuityState::Quarantined,
            ContinuityOwnershipState::ShadowReserved,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Preserve shadow ownership while recording a BOUND dispatch as externally ambiguous.
    pub async fn mark_ambiguous_dispatch(
        &self,
        request: &MarkAmbiguousDispatchRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                MARK_AMBIGUOUS_DISPATCH_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &&request.local_binding_blake3[..],
                    &&request.terminal_evidence_blake3[..],
                    &"BOUND",
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_transition_result(
            &result,
            &request.identity,
            ContinuityState::AmbiguousDispatch,
            ContinuityOwnershipState::ShadowReserved,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Prepare a typed adjudication while retaining shadow ownership.
    pub async fn prepare_adjudication(
        &self,
        request: &PrepareAdjudicationRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        validate_adjudication_binding(
            request.adjudication_kind,
            request.local_binding_blake3.as_ref(),
        )?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let local_binding = request
            .local_binding_blake3
            .as_ref()
            .map(|digest| &digest[..]);
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                PREPARE_ADJUDICATION_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &request.adjudication_kind.prepared_prior_state_sql(),
                    &local_binding,
                    &&request.terminal_evidence_blake3[..],
                    &request.adjudication_kind.as_sql(),
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_transition_result(
            &result,
            &request.identity,
            ContinuityState::AdjudicationPrepared,
            ContinuityOwnershipState::ShadowReserved,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Complete a prepared adjudication and release its exact shadow ownership once.
    pub async fn complete_adjudication(
        &self,
        request: &CompleteAdjudicationRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        validate_adjudication_binding(
            request.adjudication_kind,
            request.local_binding_blake3.as_ref(),
        )?;
        validate_release_basis_id(&request.release_basis_id)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let local_binding = request
            .local_binding_blake3
            .as_ref()
            .map(|digest| &digest[..]);
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                COMPLETE_ADJUDICATION_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &local_binding,
                    &&request.terminal_evidence_blake3[..],
                    &request.adjudication_kind.as_sql(),
                    &request.adjudication_kind.final_state_sql(),
                    &request.release_id,
                    &request.release_basis_id,
                    &&request.release_basis_blake3[..],
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        let expected_state = match request.adjudication_kind {
            ContinuityAdjudicationKind::NoLocalEffect => ContinuityState::AdjudicatedNoLocalEffect,
            ContinuityAdjudicationKind::NoDispatch => ContinuityState::AdjudicatedNoDispatch,
        };
        validate_transition_result(
            &result,
            &request.identity,
            expected_state,
            ContinuityOwnershipState::OwnershipReleased,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Record exact local durability coverage without installing or deriving local evidence.
    pub async fn record_snapshot(
        &self,
        request: &RecordSnapshotRequest,
    ) -> Result<RecordSnapshotResult, ContinuityError> {
        if request.provider_boundary_id.is_empty()
            || request.authority_epoch == 0
            || request.continuity_seq == 0
            || request.through_continuity_seq < request.continuity_seq
        {
            return Err(ContinuityError::InvalidConfiguration(
                "snapshot identity and coverage must be valid",
            ));
        }
        let epoch = request.authority_epoch.to_string();
        let through_sequence = request.through_continuity_seq.to_string();
        let sequence = request.continuity_seq.to_string();
        let counter_revision = request.local_counter_revision.to_string();
        let authority_lsn = PgLsn::from(request.authority_lsn);
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                RECORD_SNAPSHOT_SQL,
                &[
                    &API_REVISION,
                    &request.snapshot_id,
                    &request.provider_boundary_id,
                    &epoch,
                    &through_sequence,
                    &authority_lsn,
                    &&request.manifest_blake3[..],
                    &sequence,
                    &request.continuity_token_id,
                    &&request.local_binding_blake3[..],
                    &&request.local_state_blake3[..],
                    &&request.local_quota_ownership_blake3[..],
                    &counter_revision,
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_snapshot_result(&row)?;
        if result.accepted_snapshot_id != request.snapshot_id
            || result.accepted_through_continuity_seq != request.through_continuity_seq
            || result.accepted_manifest_blake3 != request.manifest_blake3
        {
            return Err(ContinuityError::InvalidResponse(
                "snapshot result identity is inconsistent",
            ));
        }
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Release BOUND or COMPLETED ownership only from exact accepted snapshot coverage.
    pub async fn release_shadow_ownership(
        &self,
        request: &ReleaseShadowOwnershipRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                RELEASE_SHADOW_OWNERSHIP_SQL,
                &[
                    &API_REVISION,
                    &request.identity.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.identity.continuity_token_id,
                    &request.identity.authenticated_cell_id,
                    &request.identity.authenticated_tenant_id,
                    &request.identity.logical_request_id,
                    &request.identity.attempt_id,
                    &request.identity.intent_kind.as_sql(),
                    &&request.identity.selected_fingerprint[..],
                    &&request.expected_prior_row_blake3[..],
                    &request.expected_state.as_sql(),
                    &request.snapshot_id,
                    &&request.expected_manifest_blake3[..],
                    &&request.expected_coverage_blake3[..],
                    &request.release_id,
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
        validate_transition_result(
            &result,
            &request.identity,
            request.expected_state.as_state(),
            ContinuityOwnershipState::OwnershipReleased,
        )?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Read one boundary's exact current reconciliation counters and latest snapshot.
    pub async fn read_reconciliation_state(
        &self,
        provider_boundary_id: &str,
        authority_epoch: u64,
    ) -> Result<Option<ReconciliationState>, ContinuityError> {
        if provider_boundary_id.is_empty() || authority_epoch == 0 {
            return Err(ContinuityError::InvalidConfiguration(
                "reconciliation identity must be valid",
            ));
        }
        let epoch = authority_epoch.to_string();
        let client = self.client.lock().await;
        let row = client
            .query_opt(
                READ_RECONCILIATION_STATE_SQL,
                &[&API_REVISION, &provider_boundary_id, &epoch],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        row.map(|row| {
            let state = parse_reconciliation_state(&row)?;
            if state.current_authority_epoch != authority_epoch {
                return Err(ContinuityError::InvalidResponse(
                    "reconciliation epoch is inconsistent",
                ));
            }
            Ok(state)
        })
        .transpose()
    }

    /// Read the current epoch and its gapless continuity sequence high-water.
    pub async fn read_epoch(
        &self,
        provider_boundary_id: &str,
    ) -> Result<Option<ContinuityEpochState>, ContinuityError> {
        if provider_boundary_id.is_empty() {
            return Err(ContinuityError::InvalidConfiguration(
                "provider boundary ID must be nonempty",
            ));
        }
        let client = self.client.lock().await;
        client
            .query_opt(READ_EPOCH_SQL, &[&API_REVISION, &provider_boundary_id])
            .await
            .map_err(ContinuityError::postgres)?
            .map(|row| parse_epoch_state(&row))
            .transpose()
    }

    /// Allocate a strictly newer epoch only after the authority proves the current epoch drained.
    pub async fn allocate_epoch(
        &self,
        request: &AllocateEpochRequest,
    ) -> Result<ContinuityEpochState, ContinuityError> {
        if request.provider_boundary_id.is_empty()
            || request.expected_current_epoch == 0
            || request.next_epoch <= request.expected_current_epoch
        {
            return Err(ContinuityError::InvalidConfiguration(
                "epoch allocation identity and ordering must be valid",
            ));
        }
        let expected_current_epoch = request.expected_current_epoch.to_string();
        let next_epoch = request.next_epoch.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                ALLOCATE_EPOCH_SQL,
                &[
                    &API_REVISION,
                    &request.provider_boundary_id,
                    &expected_current_epoch,
                    &next_epoch,
                    &&request.epoch_namespace_blake3[..],
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_epoch_state(&row)?;
        if result.authority_epoch != request.next_epoch || result.continuity_seq_high_water != 0 {
            return Err(ContinuityError::InvalidResponse(
                "allocated epoch result is inconsistent",
            ));
        }
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }

    /// Read one exact canonical shadow-release receipt without granting table access.
    pub async fn read_shadow_release_receipt(
        &self,
        request: &ReadShadowReleaseReceiptRequest,
    ) -> Result<Option<ShadowReleaseReceipt>, ContinuityError> {
        if request.provider_boundary_id.is_empty()
            || request.authority_epoch == 0
            || request.continuity_seq == 0
        {
            return Err(ContinuityError::InvalidConfiguration(
                "shadow release receipt identity must be valid",
            ));
        }
        let epoch = request.authority_epoch.to_string();
        let sequence = request.continuity_seq.to_string();
        let client = self.client.lock().await;
        let row = client
            .query_opt(
                READ_SHADOW_RELEASE_RECEIPT_SQL,
                &[
                    &API_REVISION,
                    &request.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.continuity_token_id,
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        row.map(|row| {
            let receipt = parse_shadow_release_receipt(&row)?;
            if receipt.provider_boundary_id != request.provider_boundary_id
                || receipt.authority_epoch != request.authority_epoch
                || receipt.continuity_seq != request.continuity_seq
                || receipt.continuity_token_id != request.continuity_token_id
            {
                return Err(ContinuityError::InvalidResponse(
                    "shadow release receipt identity is inconsistent",
                ));
            }
            Ok(receipt)
        })
        .transpose()
    }

    /// Replace one exact eligible terminal detail row with its bounded authenticated interval.
    pub async fn archive_prune(
        &self,
        request: &ArchivePruneRequest,
    ) -> Result<ArchivePruneResult, ContinuityError> {
        validate_archive_prune_request(request)?;
        let epoch = request.authority_epoch.to_string();
        let sequence = request.continuity_seq.to_string();
        let mut client = self.client.lock().await;
        let transaction = client
            .build_transaction()
            .isolation_level(MUTATION_ISOLATION_LEVEL)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .query_one(
                ARCHIVE_PRUNE_SQL,
                &[
                    &API_REVISION,
                    &request.provider_boundary_id,
                    &epoch,
                    &sequence,
                    &request.continuity_token_id,
                    &&request.expected_row_blake3[..],
                    &&request.expected_release_receipt_blake3[..],
                    &&request.archive_proof_bytes[..],
                    &&request.archive_proof_blake3[..],
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_archive_prune_result(&row)?;
        validate_archive_prune_result_for_sequence(&result, request.continuity_seq)?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }
}

fn validate_begin_result(
    result: &ContinuityProcedureResult,
    request: &BeginIntentRequest,
) -> Result<(), ContinuityError> {
    match result.result_code {
        ContinuityResultCode::Created
            if result.state == ContinuityState::Intent
                && result.ownership_state == ContinuityOwnershipState::ShadowReserved => {}
        ContinuityResultCode::Replay if valid_state_ownership_pair(result) => {}
        ContinuityResultCode::Created | ContinuityResultCode::Replay => {
            return Err(ContinuityError::InvalidResponse(
                "begin result state is inconsistent",
            ));
        }
        ContinuityResultCode::Found | ContinuityResultCode::Updated => {
            return Err(ContinuityError::InvalidResponse(
                "begin result code is unsupported",
            ));
        }
    }
    if result.authority_epoch != request.expected_authority_epoch
        || result.continuity_token_id != request.continuity_token_id
    {
        return Err(ContinuityError::InvalidResponse(
            "begin result identity is inconsistent",
        ));
    }
    Ok(())
}

fn valid_state_ownership_pair(result: &ContinuityProcedureResult) -> bool {
    match result.state {
        ContinuityState::Intent
        | ContinuityState::Quarantined
        | ContinuityState::AmbiguousDispatch
        | ContinuityState::AdjudicationPrepared => {
            result.ownership_state == ContinuityOwnershipState::ShadowReserved
        }
        ContinuityState::NoLocalEffect
        | ContinuityState::AdjudicatedNoLocalEffect
        | ContinuityState::AdjudicatedNoDispatch => {
            result.ownership_state == ContinuityOwnershipState::OwnershipReleased
        }
        ContinuityState::Bound | ContinuityState::Completed => true,
    }
}

fn validate_lookup_result(result: &ContinuityProcedureResult) -> Result<(), ContinuityError> {
    if result.result_code != ContinuityResultCode::Found {
        return Err(ContinuityError::InvalidResponse(
            "token lookup result code is unsupported",
        ));
    }
    Ok(())
}

fn validate_transition_result(
    result: &ContinuityProcedureResult,
    identity: &ContinuityIntentIdentity,
    expected_state: ContinuityState,
    expected_ownership: ContinuityOwnershipState,
) -> Result<(), ContinuityError> {
    if !matches!(
        result.result_code,
        ContinuityResultCode::Updated | ContinuityResultCode::Replay
    ) {
        return Err(ContinuityError::InvalidResponse(
            "transition result code is unsupported",
        ));
    }
    if result.state != expected_state || result.ownership_state != expected_ownership {
        return Err(ContinuityError::InvalidResponse(
            "transition result state is inconsistent",
        ));
    }
    if result.authority_epoch != identity.authority_epoch
        || result.continuity_seq != identity.continuity_seq
        || result.continuity_token_id != identity.continuity_token_id
    {
        return Err(ContinuityError::InvalidResponse(
            "transition result identity is inconsistent",
        ));
    }
    Ok(())
}

fn validate_adjudication_binding(
    kind: ContinuityAdjudicationKind,
    local_binding_blake3: Option<&[u8; 32]>,
) -> Result<(), ContinuityError> {
    match (kind, local_binding_blake3) {
        (ContinuityAdjudicationKind::NoLocalEffect, None)
        | (ContinuityAdjudicationKind::NoDispatch, Some(_)) => Ok(()),
        (ContinuityAdjudicationKind::NoLocalEffect, Some(_)) => {
            Err(ContinuityError::InvalidConfiguration(
                "no-local-effect adjudication forbids a local binding",
            ))
        }
        (ContinuityAdjudicationKind::NoDispatch, None) => {
            Err(ContinuityError::InvalidConfiguration(
                "no-dispatch adjudication requires a local binding",
            ))
        }
    }
}

fn validate_release_basis_id(release_basis_id: &str) -> Result<(), ContinuityError> {
    if release_basis_id.is_empty() {
        return Err(ContinuityError::InvalidConfiguration(
            "release basis ID must be nonempty",
        ));
    }
    Ok(())
}

fn validate_identity(identity: &ContinuityIntentIdentity) -> Result<(), ContinuityError> {
    if identity.authority_epoch == 0 || identity.continuity_seq == 0 {
        return Err(ContinuityError::InvalidConfiguration(
            "authority epoch and continuity sequence must be positive",
        ));
    }
    if identity.provider_boundary_id.is_empty()
        || identity.authenticated_cell_id.is_empty()
        || identity.authenticated_tenant_id.is_empty()
    {
        return Err(ContinuityError::InvalidConfiguration(
            "continuity intent identity text must be nonempty",
        ));
    }
    Ok(())
}

fn parse_snapshot_result(row: &Row) -> Result<RecordSnapshotResult, ContinuityError> {
    let recorded_at_unix_ms = row
        .try_get::<_, i64>(4)
        .map_err(|_| ContinuityError::InvalidResponse("snapshot time is not bigint"))?;
    if recorded_at_unix_ms < 0 {
        return Err(ContinuityError::InvalidResponse(
            "snapshot time must be nonnegative",
        ));
    }
    Ok(RecordSnapshotResult {
        accepted_snapshot_id: row
            .try_get(0)
            .map_err(|_| ContinuityError::InvalidResponse("snapshot ID is not UUID"))?,
        accepted_through_continuity_seq: parse_u64_text(row, 1)?,
        accepted_manifest_blake3: parse_digest(
            row.try_get(2)
                .map_err(|_| ContinuityError::InvalidResponse("manifest digest is not bytea"))?,
        )?,
        accepted_coverage_blake3: parse_digest(
            row.try_get(3)
                .map_err(|_| ContinuityError::InvalidResponse("coverage digest is not bytea"))?,
        )?,
        recorded_at_unix_ms,
    })
}

fn parse_reconciliation_state(row: &Row) -> Result<ReconciliationState, ContinuityError> {
    let current_authority_epoch = parse_u64_text(row, 0)?;
    if current_authority_epoch == 0 {
        return Err(ContinuityError::InvalidResponse(
            "authority epoch must be positive",
        ));
    }
    let snapshot_id = row
        .try_get::<_, Option<Uuid>>(5)
        .map_err(|_| ContinuityError::InvalidResponse("latest snapshot ID is not nullable UUID"))?;
    let snapshot_sequence = row.try_get::<_, Option<String>>(6).map_err(|_| {
        ContinuityError::InvalidResponse("latest snapshot sequence is not nullable text")
    })?;
    let snapshot_digest = row.try_get::<_, Option<Vec<u8>>>(7).map_err(|_| {
        ContinuityError::InvalidResponse("latest snapshot digest is not nullable bytea")
    })?;
    let latest_snapshot = match (snapshot_id, snapshot_sequence, snapshot_digest) {
        (None, None, None) => None,
        (Some(snapshot_id), Some(sequence), Some(digest)) => {
            let through_continuity_seq = parse_u64_text_value(&sequence)?;
            if through_continuity_seq == 0 {
                return Err(ContinuityError::InvalidResponse(
                    "latest snapshot sequence must be positive",
                ));
            }
            Some(ReconciliationSnapshot {
                snapshot_id,
                through_continuity_seq,
                manifest_blake3: parse_digest(digest)?,
            })
        }
        _ => {
            return Err(ContinuityError::InvalidResponse(
                "latest snapshot evidence is partially null",
            ));
        }
    };
    Ok(ReconciliationState {
        current_authority_epoch,
        continuity_seq_high_water: parse_u64_text(row, 1)?,
        owned_rows: parse_u64_text(row, 2)?,
        owned_bytes: parse_u64_text(row, 3)?,
        owned_concurrency: parse_u64_text(row, 4)?,
        latest_snapshot,
    })
}

fn parse_epoch_state(row: &Row) -> Result<ContinuityEpochState, ContinuityError> {
    let authority_epoch = parse_u64_text(row, 0)?;
    if authority_epoch == 0 {
        return Err(ContinuityError::InvalidResponse(
            "authority epoch must be positive",
        ));
    }
    Ok(ContinuityEpochState {
        authority_epoch,
        continuity_seq_high_water: parse_u64_text(row, 1)?,
    })
}

fn parse_shadow_release_receipt(row: &Row) -> Result<ShadowReleaseReceipt, ContinuityError> {
    let released_at_unix_ms = row
        .try_get::<_, i64>(6)
        .map_err(|_| ContinuityError::InvalidResponse("release receipt time is invalid"))?;
    if released_at_unix_ms < 0 {
        return Err(ContinuityError::InvalidResponse(
            "release receipt time must be nonnegative",
        ));
    }
    Ok(ShadowReleaseReceipt {
        provider_boundary_id: row
            .try_get(0)
            .map_err(|_| ContinuityError::InvalidResponse("release receipt boundary is invalid"))?,
        authority_epoch: parse_u64_text(row, 1)?,
        continuity_seq: parse_u64_text(row, 2)?,
        continuity_token_id: row
            .try_get(3)
            .map_err(|_| ContinuityError::InvalidResponse("release receipt token is invalid"))?,
        release_id: row
            .try_get(4)
            .map_err(|_| ContinuityError::InvalidResponse("release receipt ID is invalid"))?,
        receipt_blake3: parse_digest(
            row.try_get(5).map_err(|_| {
                ContinuityError::InvalidResponse("release receipt digest is invalid")
            })?,
        )?,
        released_at_unix_ms,
    })
}

fn parse_archive_prune_result(row: &Row) -> Result<ArchivePruneResult, ContinuityError> {
    let result = ArchivePruneResult {
        accepted_start_sequence: parse_u64_text(row, 0)?,
        accepted_end_sequence: parse_u64_text(row, 1)?,
        accepted_row_count: parse_u64_text(row, 2)?,
        prune_commit_sequence: parse_u64_text(row, 3)?,
        accepted_interval_blake3: parse_digest(row.try_get(4).map_err(|_| {
            ContinuityError::InvalidResponse("archive interval digest is invalid")
        })?)?,
    };
    validate_archive_prune_result(&result)?;
    Ok(result)
}

fn validate_archive_prune_request(request: &ArchivePruneRequest) -> Result<(), ContinuityError> {
    if request.provider_boundary_id.is_empty()
        || request.authority_epoch == 0
        || request.continuity_seq == 0
        || request.archive_proof_bytes.is_empty()
        || request.archive_proof_bytes.len() > MAX_ARCHIVE_PROOF_BYTES
    {
        return Err(ContinuityError::InvalidConfiguration(
            "archive identity and proof must be valid",
        ));
    }
    Ok(())
}

fn validate_archive_prune_result(result: &ArchivePruneResult) -> Result<(), ContinuityError> {
    let expected_row_count = result
        .accepted_end_sequence
        .checked_sub(result.accepted_start_sequence)
        .and_then(|width| width.checked_add(1));
    if result.accepted_start_sequence == 0
        || result.accepted_end_sequence == 0
        || result.accepted_row_count == 0
        || result.prune_commit_sequence == 0
        || expected_row_count != Some(result.accepted_row_count)
    {
        return Err(ContinuityError::InvalidResponse(
            "archive interval result is inconsistent",
        ));
    }
    Ok(())
}

fn validate_archive_prune_result_for_sequence(
    result: &ArchivePruneResult,
    requested_sequence: u64,
) -> Result<(), ContinuityError> {
    if requested_sequence < result.accepted_start_sequence
        || requested_sequence > result.accepted_end_sequence
    {
        return Err(ContinuityError::InvalidResponse(
            "archive result does not cover the requested sequence",
        ));
    }
    Ok(())
}

fn parse_procedure_result(row: &Row) -> Result<ContinuityProcedureResult, ContinuityError> {
    let authority_epoch = parse_u64_text(row, 3)?;
    let continuity_seq = parse_u64_text(row, 4)?;
    if authority_epoch == 0 || continuity_seq == 0 {
        return Err(ContinuityError::InvalidResponse(
            "authority epoch and continuity sequence must be positive",
        ));
    }
    let digest = row
        .try_get::<_, Vec<u8>>(6)
        .map_err(|_| ContinuityError::InvalidResponse("row digest is not bytea"))?;
    let row_blake3 = parse_digest(digest)?;
    let committed_at = row
        .try_get::<_, i64>(7)
        .map_err(|_| ContinuityError::InvalidResponse("commit time is not bigint"))?;
    if committed_at < 0 {
        return Err(ContinuityError::InvalidResponse(
            "commit time must be nonnegative",
        ));
    }
    Ok(ContinuityProcedureResult {
        result_code: parse_result_code(&required_text(row, 0, "result code is missing")?)?,
        state: parse_state(&required_text(row, 1, "state is missing")?)?,
        ownership_state: parse_ownership_state(&required_text(
            row,
            2,
            "ownership state is missing",
        )?)?,
        authority_epoch,
        continuity_seq,
        continuity_token_id: row
            .try_get(5)
            .map_err(|_| ContinuityError::InvalidResponse("continuity token is not UUID"))?,
        row_blake3,
        external_committed_at_unix_ms: committed_at,
    })
}

fn parse_token_lookup(row: &Row) -> Result<ContinuityTokenLookup, ContinuityError> {
    let result_code = required_text(row, 0, "result code is missing")?;
    if result_code != "NOT_FOUND" {
        return parse_procedure_result(row).map(ContinuityTokenLookup::Found);
    }
    let state = row
        .try_get::<_, Option<String>>(1)
        .map_err(|_| ContinuityError::InvalidResponse("not-found state is not nullable text"))?;
    let ownership = row.try_get::<_, Option<String>>(2).map_err(|_| {
        ContinuityError::InvalidResponse("not-found ownership is not nullable text")
    })?;
    let authority_epoch = row.try_get::<_, Option<String>>(3).map_err(|_| {
        ContinuityError::InvalidResponse("not-found authority epoch is not nullable text")
    })?;
    let continuity_seq = row.try_get::<_, Option<String>>(4).map_err(|_| {
        ContinuityError::InvalidResponse("not-found continuity sequence is not nullable text")
    })?;
    let row_blake3 = row.try_get::<_, Option<Vec<u8>>>(6).map_err(|_| {
        ContinuityError::InvalidResponse("not-found row digest is not nullable bytea")
    })?;
    let observed_at_unix_ms = row
        .try_get::<_, i64>(7)
        .map_err(|_| ContinuityError::InvalidResponse("not-found time is not bigint"))?;
    validate_not_found_shape(
        state.as_deref(),
        ownership.as_deref(),
        authority_epoch.as_deref(),
        continuity_seq.as_deref(),
        row_blake3.as_deref(),
        observed_at_unix_ms,
    )?;
    Ok(ContinuityTokenLookup::NotFound {
        continuity_token_id: row
            .try_get(5)
            .map_err(|_| ContinuityError::InvalidResponse("continuity token is not UUID"))?,
        observed_at_unix_ms,
    })
}

fn validate_not_found_shape(
    state: Option<&str>,
    ownership: Option<&str>,
    authority_epoch: Option<&str>,
    continuity_seq: Option<&str>,
    row_blake3: Option<&[u8]>,
    observed_at_unix_ms: i64,
) -> Result<(), ContinuityError> {
    if state.is_some()
        || ownership.is_some()
        || authority_epoch.is_some()
        || continuity_seq.is_some()
        || row_blake3.is_some()
    {
        return Err(ContinuityError::InvalidResponse(
            "not-found result carries stored-row evidence",
        ));
    }
    if observed_at_unix_ms < 0 {
        return Err(ContinuityError::InvalidResponse(
            "not-found time must be nonnegative",
        ));
    }
    Ok(())
}

fn required_text(
    row: &Row,
    index: usize,
    message: &'static str,
) -> Result<String, ContinuityError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| ContinuityError::InvalidResponse(message))?;
    if value.is_empty() {
        return Err(ContinuityError::InvalidResponse(message));
    }
    Ok(value)
}

fn parse_result_code(value: &str) -> Result<ContinuityResultCode, ContinuityError> {
    match value {
        "CREATED" => Ok(ContinuityResultCode::Created),
        "FOUND" => Ok(ContinuityResultCode::Found),
        "REPLAY" => Ok(ContinuityResultCode::Replay),
        "UPDATED" => Ok(ContinuityResultCode::Updated),
        _ => Err(ContinuityError::InvalidResponse(
            "result code is unsupported",
        )),
    }
}

fn parse_state(value: &str) -> Result<ContinuityState, ContinuityError> {
    match value {
        "INTENT" => Ok(ContinuityState::Intent),
        "BOUND" => Ok(ContinuityState::Bound),
        "COMPLETED" => Ok(ContinuityState::Completed),
        "NO_LOCAL_EFFECT" => Ok(ContinuityState::NoLocalEffect),
        "QUARANTINED" => Ok(ContinuityState::Quarantined),
        "AMBIGUOUS_DISPATCH" => Ok(ContinuityState::AmbiguousDispatch),
        "ADJUDICATION_PREPARED" => Ok(ContinuityState::AdjudicationPrepared),
        "ADJUDICATED_NO_LOCAL_EFFECT" => Ok(ContinuityState::AdjudicatedNoLocalEffect),
        "ADJUDICATED_NO_DISPATCH" => Ok(ContinuityState::AdjudicatedNoDispatch),
        _ => Err(ContinuityError::InvalidResponse("state is unsupported")),
    }
}

fn parse_ownership_state(value: &str) -> Result<ContinuityOwnershipState, ContinuityError> {
    match value {
        "SHADOW_RESERVED" => Ok(ContinuityOwnershipState::ShadowReserved),
        "OWNERSHIP_RELEASED" => Ok(ContinuityOwnershipState::OwnershipReleased),
        _ => Err(ContinuityError::InvalidResponse(
            "ownership state is unsupported",
        )),
    }
}

fn parse_u64_text(row: &Row, index: usize) -> Result<u64, ContinuityError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| ContinuityError::InvalidResponse("uint64 field is not text"))?;
    parse_u64_text_value(&value)
}

fn parse_u64_text_value(value: &str) -> Result<u64, ContinuityError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ContinuityError::InvalidResponse("uint64 field is out of range"))?;
    if value != parsed.to_string() {
        return Err(ContinuityError::InvalidResponse(
            "uint64 field is not canonical decimal text",
        ));
    }
    Ok(parsed)
}

fn parse_digest(value: Vec<u8>) -> Result<[u8; 32], ContinuityError> {
    value
        .try_into()
        .map_err(|_| ContinuityError::InvalidResponse("row digest is not 32 bytes"))
}

fn is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    host.split('.').all(|label| {
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
    postgres_error_shape_is_transient(
        error.is_closed(),
        error
            .as_db_error()
            .map(|database_error| database_error.code().code()),
    )
}

fn postgres_error_shape_is_transient(is_closed: bool, sqlstate: Option<&str>) -> bool {
    if is_closed {
        return true;
    }
    let Some(code) = sqlstate else {
        return false;
    };
    code.starts_with("08")
        || code.starts_with("40")
        || code.starts_with("53")
        || code == "57P01"
        || code == "57P03"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> ContinuityIntentIdentity {
        ContinuityIntentIdentity {
            provider_boundary_id: "boundary-a".to_string(),
            authority_epoch: 7,
            continuity_seq: 11,
            continuity_token_id: Uuid::from_u128(13),
            authenticated_cell_id: "cell-a".to_string(),
            authenticated_tenant_id: "tenant-a".to_string(),
            logical_request_id: Uuid::from_u128(17),
            attempt_id: Uuid::from_u128(19),
            intent_kind: ContinuityIntentKind::DispatchCas,
            selected_fingerprint: [0x21; 32],
        }
    }

    fn sample_result(identity: &ContinuityIntentIdentity) -> ContinuityProcedureResult {
        ContinuityProcedureResult {
            result_code: ContinuityResultCode::Updated,
            state: ContinuityState::Quarantined,
            ownership_state: ContinuityOwnershipState::ShadowReserved,
            authority_epoch: identity.authority_epoch,
            continuity_seq: identity.continuity_seq,
            continuity_token_id: identity.continuity_token_id,
            row_blake3: [0x51; 32],
            external_committed_at_unix_ms: 23,
        }
    }

    fn sample_archive_prune_request() -> ArchivePruneRequest {
        ArchivePruneRequest {
            provider_boundary_id: "boundary-live-test".to_string(),
            authority_epoch: 7,
            continuity_seq: 11,
            continuity_token_id: Uuid::from_u128(23),
            expected_row_blake3: [0x31; 32],
            expected_release_receipt_blake3: [0x41; 32],
            archive_proof_bytes: vec![0x51],
            archive_proof_blake3: [0x61; 32],
        }
    }

    fn sample_archive_prune_result() -> ArchivePruneResult {
        ArchivePruneResult {
            accepted_start_sequence: 10,
            accepted_end_sequence: 12,
            accepted_row_count: 3,
            prune_commit_sequence: 5,
            accepted_interval_blake3: [0x71; 32],
        }
    }

    fn normalized_embedded_migration() -> String {
        std::str::from_utf8(crate::schema::CONTINUITY_MIGRATION_V1)
            .expect("embedded migration must remain UTF-8 SQL")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn client_procedure_signatures_match_the_embedded_migration() {
        let migration = normalized_embedded_migration();
        for signature in [
            "CREATE FUNCTION object_store_continuity.object_store_continuity_get_by_token_v1( \
             api_revision text, provider_boundary_id text, continuity_token_id uuid )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_begin_v1( \
             api_revision text, expected_current_epoch object_store_continuity.uint64, \
             continuity_token_id uuid, provider_boundary_id text, intent_kind text, \
             authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid, \
             attempt_id uuid, selected_fingerprint bytea, expected_policy_revision text, \
             operation_quota_class text, requested_rows object_store_continuity.uint64, \
             requested_bytes object_store_continuity.uint64, requested_concurrency \
             object_store_continuity.uint64, retention_deadline_unix_ms bigint )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_bound_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_completed_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, expected_prior_state text DEFAULT 'BOUND' )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_no_local_effect_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, terminal_evidence_blake3 bytea, release_id uuid, \
             release_basis_id text, release_basis_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_quarantine_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, expected_prior_state text, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_ambiguous_dispatch_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, expected_prior_state text DEFAULT 'BOUND' )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_prepare_adjudication_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, expected_prior_state text, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, adjudication_kind text )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_complete_adjudication_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, adjudication_kind text, final_state text, \
             release_id uuid, release_basis_id text, release_basis_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_record_snapshot_v1( \
             api_revision text, snapshot_id uuid, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, through_continuity_seq object_store_continuity.uint64, \
             authority_lsn pg_lsn, manifest_blake3 bytea, continuity_seq \
             object_store_continuity.uint64, continuity_token_id uuid, local_binding_blake3 bytea, \
             local_state_blake3 bytea, local_quota_ownership_blake3 bytea, \
             local_counter_revision object_store_continuity.uint64 )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_release_shadow_ownership_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, expected_state text, snapshot_id uuid, \
             expected_manifest_blake3 bytea, expected_coverage_blake3 bytea, release_id uuid )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_reconciliation_state_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64 )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_epoch_v1( \
             api_revision text, provider_boundary_id text )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_allocate_epoch_v1( \
             api_revision text, provider_boundary_id text, expected_current_epoch \
             object_store_continuity.uint64, next_epoch object_store_continuity.uint64, \
             epoch_namespace_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1( \
             api_revision text, requested_provider_boundary_id text, requested_authority_epoch \
             object_store_continuity.uint64, requested_continuity_seq \
             object_store_continuity.uint64, requested_continuity_token_id uuid )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_archive_prune_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, expected_row_blake3 bytea, \
             expected_release_receipt_blake3 bytea, archive_proof_bytes bytea, \
             archive_proof_blake3 bytea )",
        ] {
            assert!(
                migration.contains(signature),
                "embedded migration is missing client procedure signature: {signature}"
            );
        }
    }

    #[test]
    fn begin_query_calls_only_the_versioned_procedure_with_numeric_u64_parameters() {
        assert_eq!(
            BEGIN_SQL,
            "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms \
    FROM object_store_continuity.object_store_continuity_begin_v1(\
      $1, $2::text::object_store_continuity.uint64, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
      $13::text::object_store_continuity.uint64, $14::text::object_store_continuity.uint64, \
      $15::text::object_store_continuity.uint64, $16\
    )"
        );
        assert_eq!(
            BEGIN_SQL
                .matches("::text::object_store_continuity.uint64")
                .count(),
            4
        );
        assert!(!BEGIN_SQL.contains("::bigint"));
    }

    #[test]
    fn token_read_query_calls_only_the_versioned_boundary_authorized_procedure() {
        assert_eq!(
            GET_BY_TOKEN_SQL,
            "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_get_by_token_v1($1, $2, $3)"
        );
    }

    #[test]
    fn transition_queries_call_only_versioned_procedures_with_numeric_u64_identity() {
        for (query, procedure, last_parameter) in [
            (
                MARK_BOUND_SQL,
                "object_store_continuity_mark_bound_v1",
                "$13",
            ),
            (
                MARK_COMPLETED_SQL,
                "object_store_continuity_mark_completed_v1",
                "$15",
            ),
            (
                MARK_NO_LOCAL_EFFECT_SQL,
                "object_store_continuity_mark_no_local_effect_v1",
                "$16",
            ),
        ] {
            assert!(
                query.contains(&format!("object_store_continuity.{procedure}(")),
                "query did not call {procedure}: {query}"
            );
            assert_eq!(
                query
                    .matches("::text::object_store_continuity.uint64")
                    .count(),
                2,
                "query: {query}"
            );
            assert!(query.contains(last_parameter), "query: {query}");
            assert!(!query.contains("::bigint"), "query: {query}");
            assert_eq!(query.matches("SELECT").count(), 1, "query: {query}");
        }
    }

    #[test]
    fn reconciler_queries_match_the_frozen_procedure_arity_and_numeric_identity() {
        const RESULT_PROJECTION: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM";
        for (query, procedure, parameter_count) in [
            (QUARANTINE_SQL, "object_store_continuity_quarantine_v1", 15),
            (
                MARK_AMBIGUOUS_DISPATCH_SQL,
                "object_store_continuity_mark_ambiguous_dispatch_v1",
                15,
            ),
            (
                PREPARE_ADJUDICATION_SQL,
                "object_store_continuity_prepare_adjudication_v1",
                16,
            ),
            (
                COMPLETE_ADJUDICATION_SQL,
                "object_store_continuity_complete_adjudication_v1",
                19,
            ),
        ] {
            assert!(
                query.starts_with(RESULT_PROJECTION),
                "query does not present the complete procedure-result projection: {query}"
            );
            assert!(
                query.contains(&format!("object_store_continuity.{procedure}(")),
                "query did not call {procedure}: {query}"
            );
            assert_eq!(
                query
                    .matches("::text::object_store_continuity.uint64")
                    .count(),
                2,
                "query: {query}"
            );
            assert!(
                query.contains(&format!("${parameter_count}")),
                "query does not present all {parameter_count} parameters: {query}"
            );
            assert!(!query.contains(&format!("${}", parameter_count + 1)));
            assert!(!query.contains("::bigint"), "query: {query}");
            assert_eq!(query.matches("SELECT").count(), 1, "query: {query}");
        }
    }

    #[test]
    fn snapshot_release_and_read_queries_pin_arity_and_uint64_transfer() {
        for (query, procedure, parameter_count, uint64_casts) in [
            (
                RECORD_SNAPSHOT_SQL,
                "object_store_continuity_record_snapshot_v1",
                13,
                4,
            ),
            (
                RELEASE_SHADOW_OWNERSHIP_SQL,
                "object_store_continuity_release_shadow_ownership_v1",
                17,
                2,
            ),
            (
                READ_RECONCILIATION_STATE_SQL,
                "object_store_continuity_read_reconciliation_state_v1",
                3,
                1,
            ),
            (
                READ_EPOCH_SQL,
                "object_store_continuity_read_epoch_v1",
                2,
                0,
            ),
            (
                ALLOCATE_EPOCH_SQL,
                "object_store_continuity_allocate_epoch_v1",
                5,
                2,
            ),
            (
                READ_SHADOW_RELEASE_RECEIPT_SQL,
                "object_store_continuity_read_shadow_release_receipt_v1",
                5,
                2,
            ),
        ] {
            assert!(
                query.contains(&format!("object_store_continuity.{procedure}(")),
                "query did not call {procedure}: {query}"
            );
            assert_eq!(
                query
                    .matches("::text::object_store_continuity.uint64")
                    .count(),
                uint64_casts,
                "query: {query}"
            );
            assert!(
                query.contains(&format!("${parameter_count}")),
                "query: {query}"
            );
            assert!(!query.contains(&format!("${}", parameter_count + 1)));
            assert!(!query.contains("::bigint"), "query: {query}");
            assert_eq!(query.matches("SELECT").count(), 1, "query: {query}");
        }
        assert_eq!(CoveredReleaseState::Bound.as_sql(), "BOUND");
        assert_eq!(CoveredReleaseState::Completed.as_sql(), "COMPLETED");
    }

    #[test]
    fn epoch_allocation_query_and_migration_pin_drained_cas_reset_semantics() {
        assert_eq!(
            ALLOCATE_EPOCH_SQL,
            "SELECT authority_epoch::text, continuity_seq_high_water::text FROM \
    object_store_continuity.object_store_continuity_allocate_epoch_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )"
        );
        let migration = normalized_embedded_migration();
        for invariant in [
            "PERFORM object_store_continuity.assert_serializable_write_v1(); PERFORM object_store_continuity.assert_reconciler_v1();",
            "IF next_epoch <= expected_current_epoch OR octet_length(epoch_namespace_blake3) <> 32 THEN RAISE EXCEPTION 'INVALID_NEXT_EPOCH' USING ERRCODE = '22023'; END IF;",
            "AND intent.state NOT IN ('COMPLETED', 'NO_LOCAL_EFFECT', 'ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH')",
            "RAISE EXCEPTION 'EPOCH_CAS_OR_DRAIN_FAILED' USING ERRCODE = '40001';",
            "current_authority_epoch = next_epoch, continuity_seq_high_water = 0, epoch_namespace_blake3 = object_store_continuity_allocate_epoch_v1.epoch_namespace_blake3",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded epoch allocation lost invariant: {invariant}"
            );
        }
    }

    #[test]
    fn release_receipt_read_pins_exact_projection_canonical_validation_and_reconciler_auth() {
        assert_eq!(
            READ_SHADOW_RELEASE_RECEIPT_SQL,
            "SELECT receipt_provider_boundary_id, \
    receipt_authority_epoch::text, receipt_continuity_seq::text, receipt_continuity_token_id, \
    release_id, receipt_blake3, released_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )"
        );
        let migration = normalized_embedded_migration();
        for invariant in [
            "PERFORM object_store_continuity.assert_api_revision_v1(api_revision); PERFORM object_store_continuity.assert_reconciler_v1();",
            "WHERE receipt.provider_boundary_id = requested_provider_boundary_id AND receipt.authority_epoch = requested_authority_epoch AND receipt.continuity_seq = requested_continuity_seq AND receipt.continuity_token_id = requested_continuity_token_id; IF NOT FOUND THEN RETURN; END IF;",
            "PERFORM object_store_continuity.assert_blake3_v1(release_preimage, stored.receipt_blake3);",
            "IF stored.canonical_receipt_bytes IS DISTINCT FROM release_preimage || stored.receipt_blake3 THEN RAISE EXCEPTION 'SHADOW_RELEASE_RECEIPT_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000'; END IF;",
            "object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid)",
            "TO object_dispatch_continuity_reconciler;",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded release-receipt read lost invariant: {invariant}"
            );
        }
    }

    #[test]
    fn archive_prune_query_and_migration_pin_bounded_reconciler_contract() {
        assert_eq!(
            ARCHIVE_PRUNE_SQL,
            "SELECT accepted_start_sequence::text, \
    accepted_end_sequence::text, accepted_row_count::text, prune_commit_sequence::text, \
    accepted_interval_blake3 FROM \
    object_store_continuity.object_store_continuity_archive_prune_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9\
    )"
        );
        assert_eq!(
            ARCHIVE_PRUNE_SQL
                .matches("::text::object_store_continuity.uint64")
                .count(),
            2
        );
        assert!(!ARCHIVE_PRUNE_SQL.contains("$10"));
        assert!(!ARCHIVE_PRUNE_SQL.contains("::bigint"));

        let migration = normalized_embedded_migration();
        for invariant in [
            "PERFORM object_store_continuity.assert_api_revision_v1(api_revision); PERFORM object_store_continuity.assert_serializable_write_v1(); PERFORM object_store_continuity.assert_reconciler_v1();",
            "IF octet_length(expected_row_blake3) <> 32 OR octet_length(expected_release_receipt_blake3) <> 32 THEN RAISE EXCEPTION 'ARCHIVE_EXPECTED_DIGEST_INVALID' USING ERRCODE = '22023'; END IF;",
            "PERFORM object_store_continuity.assert_archive_eligibility_v1( archive_proof_bytes, archive_proof_blake3, stored, release_value.receipt_blake3 );",
            "accepted_start_sequence := merged.start_sequence; accepted_end_sequence := merged.end_sequence; accepted_row_count := merged.row_count; accepted_interval_blake3 := merged.interval_blake3; RETURN NEXT;",
            "object_store_continuity.object_store_continuity_archive_prune_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, bytea, bytea, bytea, bytea)",
            "TO object_dispatch_continuity_reconciler;",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded archive/prune contract lost invariant: {invariant}"
            );
        }
    }

    #[test]
    fn archive_prune_request_accepts_nonempty_identity_and_bounded_proof() {
        let mut request = sample_archive_prune_request();
        request.archive_proof_bytes = vec![0x51; MAX_ARCHIVE_PROOF_BYTES];

        validate_archive_prune_request(&request)
            .expect("an exact maximum-sized archive proof must remain admissible");
    }

    #[test]
    fn archive_prune_request_rejects_missing_identity_and_unbounded_proof() {
        let mut invalid_requests = Vec::new();
        let mut empty_boundary = sample_archive_prune_request();
        empty_boundary.provider_boundary_id.clear();
        invalid_requests.push(empty_boundary);
        let mut zero_epoch = sample_archive_prune_request();
        zero_epoch.authority_epoch = 0;
        invalid_requests.push(zero_epoch);
        let mut zero_sequence = sample_archive_prune_request();
        zero_sequence.continuity_seq = 0;
        invalid_requests.push(zero_sequence);
        let mut empty_proof = sample_archive_prune_request();
        empty_proof.archive_proof_bytes.clear();
        invalid_requests.push(empty_proof);
        let mut oversized_proof = sample_archive_prune_request();
        oversized_proof.archive_proof_bytes = vec![0x51; MAX_ARCHIVE_PROOF_BYTES + 1];
        invalid_requests.push(oversized_proof);

        for request in invalid_requests {
            assert!(matches!(
                validate_archive_prune_request(&request),
                Err(ContinuityError::InvalidConfiguration(
                    "archive identity and proof must be valid"
                ))
            ));
        }
    }

    #[test]
    fn archive_prune_result_accepts_exact_nonzero_interval_and_digest() {
        let result = sample_archive_prune_result();

        validate_archive_prune_result(&result)
            .expect("a contiguous nonzero archive interval must validate");
        assert_eq!(result.accepted_interval_blake3, [0x71; 32]);
    }

    #[test]
    fn archive_prune_result_rejects_zero_reversed_and_count_mismatch_shapes() {
        let mut invalid_results = Vec::new();
        let mut zero_start = sample_archive_prune_result();
        zero_start.accepted_start_sequence = 0;
        invalid_results.push(zero_start);
        let mut reversed = sample_archive_prune_result();
        reversed.accepted_start_sequence = 13;
        invalid_results.push(reversed);
        let mut count_mismatch = sample_archive_prune_result();
        count_mismatch.accepted_row_count = 2;
        invalid_results.push(count_mismatch);
        let mut zero_commit = sample_archive_prune_result();
        zero_commit.prune_commit_sequence = 0;
        invalid_results.push(zero_commit);

        for result in invalid_results {
            assert!(matches!(
                validate_archive_prune_result(&result),
                Err(ContinuityError::InvalidResponse(
                    "archive interval result is inconsistent"
                ))
            ));
        }
    }

    #[test]
    fn archive_prune_result_must_cover_the_requested_sequence() {
        let result = sample_archive_prune_result();
        validate_archive_prune_result_for_sequence(&result, 11)
            .expect("the requested sequence is covered by the accepted interval");
        for outside in [9, 13] {
            assert!(matches!(
                validate_archive_prune_result_for_sequence(&result, outside),
                Err(ContinuityError::InvalidResponse(
                    "archive result does not cover the requested sequence"
                ))
            ));
        }
    }

    #[test]
    fn reconciler_state_algebra_is_closed_and_pairs_adjudication_kind_with_final_state() {
        assert_eq!(QuarantinePriorState::Intent.as_sql(), "INTENT");
        assert_eq!(
            QuarantinePriorState::Bound {
                local_binding_blake3: [0x11; 32],
            }
            .as_sql(),
            "BOUND"
        );
        for (kind, prior_state, final_state) in [
            (
                ContinuityAdjudicationKind::NoLocalEffect,
                "QUARANTINED",
                "ADJUDICATED_NO_LOCAL_EFFECT",
            ),
            (
                ContinuityAdjudicationKind::NoDispatch,
                "AMBIGUOUS_DISPATCH",
                "ADJUDICATED_NO_DISPATCH",
            ),
        ] {
            assert_eq!(kind.prepared_prior_state_sql(), prior_state);
            assert_eq!(kind.final_state_sql(), final_state);
        }
    }

    #[test]
    fn quarantine_prior_state_preserves_only_bound_local_binding_evidence() {
        assert_eq!(QuarantinePriorState::Intent.local_binding_blake3(), None);
        let digest = [0xa5; 32];
        assert_eq!(
            QuarantinePriorState::Bound {
                local_binding_blake3: digest,
            }
            .local_binding_blake3(),
            Some(digest.as_slice())
        );
    }

    #[test]
    fn quarantine_request_requires_exact_terminal_evidence() {
        let request = QuarantineRequest {
            identity: sample_identity(),
            expected_prior_row_blake3: [0x31; 32],
            prior_state: QuarantinePriorState::Intent,
            terminal_evidence_blake3: [0x41; 32],
        };
        assert_eq!(request.terminal_evidence_blake3, [0x41; 32]);
        assert!(QUARANTINE_SQL.contains("$15"));
    }

    #[test]
    fn adjudication_kind_requires_its_exact_local_binding_shape() {
        let digest = [0x3c; 32];
        assert!(
            validate_adjudication_binding(ContinuityAdjudicationKind::NoLocalEffect, None).is_ok()
        );
        assert!(
            validate_adjudication_binding(ContinuityAdjudicationKind::NoDispatch, Some(&digest))
                .is_ok()
        );
        for (kind, binding) in [
            (ContinuityAdjudicationKind::NoLocalEffect, Some(&digest)),
            (ContinuityAdjudicationKind::NoDispatch, None),
        ] {
            assert!(matches!(
                validate_adjudication_binding(kind, binding),
                Err(ContinuityError::InvalidConfiguration(_))
            ));
        }
    }

    #[test]
    fn release_basis_validation_rejects_empty_ids_before_database_access() {
        assert!(validate_release_basis_id("release-basis:v1").is_ok());
        assert!(matches!(
            validate_release_basis_id(""),
            Err(ContinuityError::InvalidConfiguration(
                "release basis ID must be nonempty"
            ))
        ));
    }

    #[test]
    fn transition_result_validation_accepts_only_exact_identity_state_and_ownership() {
        let identity = sample_identity();
        let exact = sample_result(&identity);
        validate_transition_result(
            &exact,
            &identity,
            ContinuityState::Quarantined,
            ContinuityOwnershipState::ShadowReserved,
        )
        .expect("the exact transition result must validate");

        let mut replay = exact.clone();
        replay.result_code = ContinuityResultCode::Replay;
        validate_transition_result(
            &replay,
            &identity,
            ContinuityState::Quarantined,
            ContinuityOwnershipState::ShadowReserved,
        )
        .expect("an exact replay must validate");

        let mut wrong_identity = exact.clone();
        wrong_identity.continuity_seq += 1;
        let mut wrong_code = exact.clone();
        wrong_code.result_code = ContinuityResultCode::Found;
        let mut wrong_state = exact.clone();
        wrong_state.state = ContinuityState::AmbiguousDispatch;
        let mut wrong_ownership = exact;
        wrong_ownership.ownership_state = ContinuityOwnershipState::OwnershipReleased;
        for result in [wrong_identity, wrong_code, wrong_state, wrong_ownership] {
            assert!(matches!(
                validate_transition_result(
                    &result,
                    &identity,
                    ContinuityState::Quarantined,
                    ContinuityOwnershipState::ShadowReserved,
                ),
                Err(ContinuityError::InvalidResponse(_))
            ));
        }
    }

    #[test]
    fn begin_result_validation_accepts_current_row_replay_and_rejects_invalid_shapes() {
        let identity = sample_identity();
        let request = BeginIntentRequest {
            provider_boundary_id: identity.provider_boundary_id.clone(),
            expected_authority_epoch: identity.authority_epoch,
            continuity_token_id: identity.continuity_token_id,
            intent_kind: identity.intent_kind,
            authenticated_cell_id: identity.authenticated_cell_id.clone(),
            authenticated_tenant_id: identity.authenticated_tenant_id.clone(),
            operation_quota_class: "test".to_string(),
            logical_request_id: identity.logical_request_id,
            attempt_id: identity.attempt_id,
            selected_fingerprint: identity.selected_fingerprint,
            continuity_policy_revision: "policy-v1".to_string(),
            quota_bytes: 1,
            quota_rows: 1,
            quota_concurrency: 1,
            retention_deadline_unix_ms: 1,
        };
        let mut exact = sample_result(&identity);
        exact.result_code = ContinuityResultCode::Created;
        exact.state = ContinuityState::Intent;
        validate_begin_result(&exact, &request).expect("the exact begin result must validate");

        for (state, ownership_state) in [
            (
                ContinuityState::Intent,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::Bound,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::Bound,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::Completed,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::Completed,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::NoLocalEffect,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::Quarantined,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::AmbiguousDispatch,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::AdjudicationPrepared,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::AdjudicatedNoLocalEffect,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::AdjudicatedNoDispatch,
                ContinuityOwnershipState::OwnershipReleased,
            ),
        ] {
            let mut replay = exact.clone();
            replay.result_code = ContinuityResultCode::Replay;
            replay.state = state;
            replay.ownership_state = ownership_state;
            validate_begin_result(&replay, &request)
                .expect("begin replay must accept every closed stored-row state");
        }

        let mut wrong_identity = exact.clone();
        wrong_identity.continuity_token_id = Uuid::from_u128(29);
        let mut wrong_code = exact.clone();
        wrong_code.result_code = ContinuityResultCode::Updated;
        let mut wrong_state = exact.clone();
        wrong_state.state = ContinuityState::Bound;
        let mut wrong_ownership = exact.clone();
        wrong_ownership.ownership_state = ContinuityOwnershipState::OwnershipReleased;
        let mut wrong_replay_ownership = exact;
        wrong_replay_ownership.result_code = ContinuityResultCode::Replay;
        wrong_replay_ownership.state = ContinuityState::AdjudicatedNoDispatch;
        for result in [
            wrong_identity,
            wrong_code,
            wrong_state,
            wrong_ownership,
            wrong_replay_ownership,
        ] {
            assert!(matches!(
                validate_begin_result(&result, &request),
                Err(ContinuityError::InvalidResponse(_))
            ));
        }
    }

    #[test]
    fn token_lookup_result_validation_accepts_only_found() {
        let identity = sample_identity();
        let mut found = sample_result(&identity);
        found.result_code = ContinuityResultCode::Found;
        validate_lookup_result(&found).expect("FOUND must validate for token lookup");
        for result_code in [
            ContinuityResultCode::Created,
            ContinuityResultCode::Replay,
            ContinuityResultCode::Updated,
        ] {
            let mut invalid = found.clone();
            invalid.result_code = result_code;
            assert!(matches!(
                validate_lookup_result(&invalid),
                Err(ContinuityError::InvalidResponse(
                    "token lookup result code is unsupported"
                ))
            ));
        }
    }

    #[test]
    fn every_mutation_uses_the_serializable_isolation_contract() {
        assert!(matches!(
            MUTATION_ISOLATION_LEVEL,
            IsolationLevel::Serializable
        ));
    }

    #[test]
    fn u64_max_has_an_exact_lossless_numeric_text_representation() {
        assert_eq!(u64::MAX.to_string(), "18446744073709551615");
        assert_eq!(
            parse_u64_text_value("18446744073709551615")
                .expect("u64 max must survive the NUMERIC text projection"),
            u64::MAX
        );
    }

    #[test]
    fn uint64_result_parser_rejects_negative_overflow_and_noncanonical_numbers() {
        for value in ["-1", "18446744073709551616", " 1", "1 ", "1.0", ""] {
            let error = parse_u64_text_value(value)
                .expect_err("an invalid uint64 text projection must fail closed");
            assert!(
                matches!(
                    error,
                    ContinuityError::InvalidResponse("uint64 field is out of range")
                ),
                "unexpected error for {value:?}: {error}"
            );
        }
        for value in ["+1", "01"] {
            let error = parse_u64_text_value(value)
                .expect_err("a noncanonical uint64 text projection must fail closed");
            assert!(
                matches!(
                    error,
                    ContinuityError::InvalidResponse("uint64 field is not canonical decimal text")
                ),
                "unexpected error for {value:?}: {error}"
            );
        }
    }

    #[test]
    fn digest_parser_accepts_exactly_32_bytes() {
        assert_eq!(
            parse_digest(vec![0x5a; 32]).expect("a 32-byte BLAKE3 digest must parse"),
            [0x5a; 32]
        );
        for digest in [vec![0x5a; 31], vec![0x5a; 33]] {
            let error = parse_digest(digest).expect_err("a non-32-byte digest must fail closed");
            assert!(
                matches!(
                    error,
                    ContinuityError::InvalidResponse("row digest is not 32 bytes")
                ),
                "unexpected digest error: {error}"
            );
        }
    }

    #[test]
    fn result_code_parser_accepts_only_the_frozen_allowlist() {
        for (text, expected) in [
            ("CREATED", ContinuityResultCode::Created),
            ("FOUND", ContinuityResultCode::Found),
            ("REPLAY", ContinuityResultCode::Replay),
            ("UPDATED", ContinuityResultCode::Updated),
        ] {
            assert_eq!(
                parse_result_code(text).expect("allowlisted result code must parse"),
                expected
            );
        }
        for text in ["", "created", "DELETED", " CREATED"] {
            assert!(matches!(
                parse_result_code(text),
                Err(ContinuityError::InvalidResponse(
                    "result code is unsupported"
                ))
            ));
        }
    }

    #[test]
    fn state_parser_accepts_only_the_frozen_allowlist() {
        for (text, expected) in [
            ("INTENT", ContinuityState::Intent),
            ("BOUND", ContinuityState::Bound),
            ("COMPLETED", ContinuityState::Completed),
            ("NO_LOCAL_EFFECT", ContinuityState::NoLocalEffect),
            ("QUARANTINED", ContinuityState::Quarantined),
            ("AMBIGUOUS_DISPATCH", ContinuityState::AmbiguousDispatch),
            (
                "ADJUDICATION_PREPARED",
                ContinuityState::AdjudicationPrepared,
            ),
            (
                "ADJUDICATED_NO_LOCAL_EFFECT",
                ContinuityState::AdjudicatedNoLocalEffect,
            ),
            (
                "ADJUDICATED_NO_DISPATCH",
                ContinuityState::AdjudicatedNoDispatch,
            ),
        ] {
            assert_eq!(
                parse_state(text).expect("allowlisted continuity state must parse"),
                expected
            );
        }
        for text in ["", "intent", "RELEASED", " INTENT"] {
            assert!(matches!(
                parse_state(text),
                Err(ContinuityError::InvalidResponse("state is unsupported"))
            ));
        }
    }

    #[test]
    fn ownership_parser_accepts_only_the_frozen_allowlist() {
        assert_eq!(
            parse_ownership_state("SHADOW_RESERVED").expect("shadow ownership state must parse"),
            ContinuityOwnershipState::ShadowReserved
        );
        assert_eq!(
            parse_ownership_state("OWNERSHIP_RELEASED")
                .expect("released ownership state must parse"),
            ContinuityOwnershipState::OwnershipReleased
        );
        for text in ["", "shadow_reserved", "OWNED", " SHADOW_RESERVED"] {
            assert!(matches!(
                parse_ownership_state(text),
                Err(ContinuityError::InvalidResponse(
                    "ownership state is unsupported"
                ))
            ));
        }
    }

    #[test]
    fn not_found_shape_accepts_only_null_stored_evidence_and_nonnegative_time() {
        validate_not_found_shape(None, None, None, None, None, 0)
            .expect("the migration's exact nullable absence shape must parse");
        validate_not_found_shape(None, None, None, None, None, i64::MAX)
            .expect("a nonnegative observation time must parse");

        let digest = [0x5a; 32];
        for result in [
            validate_not_found_shape(Some("INTENT"), None, None, None, None, 0),
            validate_not_found_shape(None, Some("SHADOW_RESERVED"), None, None, None, 0),
            validate_not_found_shape(None, None, Some("1"), None, None, 0),
            validate_not_found_shape(None, None, None, Some("1"), None, 0),
            validate_not_found_shape(None, None, None, None, Some(&digest), 0),
        ] {
            assert!(matches!(
                result,
                Err(ContinuityError::InvalidResponse(
                    "not-found result carries stored-row evidence"
                ))
            ));
        }

        assert!(matches!(
            validate_not_found_shape(None, None, None, None, None, -1),
            Err(ContinuityError::InvalidResponse(
                "not-found time must be nonnegative"
            ))
        ));
    }

    #[test]
    fn dns_validator_rejects_paths_addresses_and_invalid_labels() {
        for invalid in [
            "",
            "/var/run/postgresql",
            r"C:\postgres\socket",
            "::1",
            ".continuity.internal",
            "continuity.internal.",
            "continuity..internal",
            "-continuity.internal",
            "continuity-.internal",
            "continuity_internal",
            "contínuïty.internal",
        ] {
            assert!(
                !is_dns_name(invalid),
                "accepted invalid DNS name {invalid:?}"
            );
        }
        assert!(is_dns_name("continuity-1.internal"));
    }

    #[test]
    fn postgres_transience_is_a_closed_transport_and_sqlstate_set() {
        assert!(postgres_error_shape_is_transient(true, None));
        for sqlstate in ["08006", "40001", "40P01", "53000", "57P01", "57P03"] {
            assert!(
                postgres_error_shape_is_transient(false, Some(sqlstate)),
                "expected SQLSTATE {sqlstate} to be transient"
            );
        }
        for sqlstate in ["22003", "23505", "28000", "42601", "57P02", "XXXXX"] {
            assert!(
                !postgres_error_shape_is_transient(false, Some(sqlstate)),
                "expected SQLSTATE {sqlstate} to be permanent"
            );
        }
        assert!(!postgres_error_shape_is_transient(false, None));
    }

    #[test]
    fn client_level_errors_are_transient_only_when_the_contract_says_so() {
        assert!(ContinuityError::ConnectTimeout.is_transient());
        assert!(ContinuityError::Postgres { transient: true }.is_transient());
        assert!(!ContinuityError::Postgres { transient: false }.is_transient());
        assert!(
            !ContinuityError::InvalidConfiguration("test configuration failure").is_transient()
        );
        assert!(!ContinuityError::InvalidTlsMaterial("test TLS failure").is_transient());
        assert!(!ContinuityError::InvalidResponse("test response failure").is_transient());
    }

    #[test]
    fn postgres_error_rendering_and_source_chain_never_expose_driver_diagnostics() {
        let error = ContinuityError::Postgres { transient: true };
        assert_eq!(format!("{error}"), "continuity database operation failed");
        assert_eq!(format!("{error:?}"), "Postgres { transient: true }");
        assert!(std::error::Error::source(&error).is_none());
    }
}

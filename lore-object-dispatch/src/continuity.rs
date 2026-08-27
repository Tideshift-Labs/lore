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
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const API_REVISION: &str = "object-store-authority-continuity-v1";
const MUTATION_ISOLATION_LEVEL: IsolationLevel = IsolationLevel::Serializable;
const BEGIN_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms \
    FROM object_store_continuity.object_store_continuity_begin_v1(\
      $1, $2, $3::object_store_continuity.uint64, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
      $13::object_store_continuity.uint64, $14::object_store_continuity.uint64, \
      $15::object_store_continuity.uint64, $16\
    )";
const GET_BY_TOKEN_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_get_by_token_v1($1, $2, $3)";
const MARK_BOUND_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_bound_v1(\
      $1, $2, $3::object_store_continuity.uint64, \
      $4::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13\
    )";
const MARK_COMPLETED_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_completed_v1(\
      $1, $2, $3::object_store_continuity.uint64, \
      $4::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15\
    )";
const MARK_NO_LOCAL_EFFECT_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_no_local_effect_v1(\
      $1, $2, $3::object_store_continuity.uint64, \
      $4::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16\
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
    pub external_created_at_unix_ms: i64,
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
        if request.external_created_at_unix_ms < 0 {
            return Err(ContinuityError::InvalidConfiguration(
                "external creation time must be nonnegative",
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
                    &request.provider_boundary_id,
                    &expected_authority_epoch,
                    &request.continuity_token_id,
                    &request.intent_kind.as_sql(),
                    &request.authenticated_cell_id,
                    &request.authenticated_tenant_id,
                    &request.operation_quota_class,
                    &request.logical_request_id,
                    &request.attempt_id,
                    &&request.selected_fingerprint[..],
                    &request.continuity_policy_revision,
                    &quota_bytes,
                    &quota_rows,
                    &quota_concurrency,
                    &request.external_created_at_unix_ms,
                ],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        let result = parse_procedure_result(&row)?;
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
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        let client = self.client.lock().await;
        let row = client
            .query_one(
                GET_BY_TOKEN_SQL,
                &[&API_REVISION, &provider_boundary_id, &continuity_token_id],
            )
            .await
            .map_err(ContinuityError::postgres)?;
        parse_procedure_result(&row)
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
        if request.release_basis_id.is_empty() {
            return Err(ContinuityError::InvalidConfiguration(
                "release basis ID must be nonempty",
            ));
        }
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
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }
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

    #[test]
    fn begin_query_calls_only_the_versioned_procedure_with_numeric_u64_parameters() {
        assert_eq!(
            BEGIN_SQL,
            "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms \
    FROM object_store_continuity.object_store_continuity_begin_v1(\
      $1, $2, $3::object_store_continuity.uint64, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
      $13::object_store_continuity.uint64, $14::object_store_continuity.uint64, $15::object_store_continuity.uint64, $16\
    )"
        );
        assert_eq!(
            BEGIN_SQL
                .matches("::object_store_continuity.uint64")
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
                query.matches("::object_store_continuity.uint64").count(),
                2,
                "query: {query}"
            );
            assert!(query.contains(last_parameter), "query: {query}");
            assert!(!query.contains("::bigint"), "query: {query}");
            assert_eq!(query.matches("SELECT").count(), 1, "query: {query}");
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

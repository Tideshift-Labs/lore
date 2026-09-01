// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! The typed cell-authority client (WP-114 CD-3).
//!
//! CR-033 D1 makes the retained PostgreSQL procedures in the cell database *the* dispatch
//! authority. This module is the only typed path to them: 0013's `ReservePut` admission, 0015's
//! non-final upload progress, 0017's `SPOOL_READY` transition, 0020's maintenance-only participant
//! enrollment and runtime-only dispatcher registration, and 0019's runtime-callable installed-layer
//! readback.
//!
//! Three properties hold across every call.
//!
//! **Closed decoding.** Each procedure declares a closed set of `result_code` values. An
//! unrecognized code is [`DispatchAuthorityError::UnrecognizedResultCode`], never a silent default
//! and never folded into a neighbouring meaning. Every raised condition maps through one closed
//! classification table; an unrecognized SQLSTATE fails closed as
//! [`DispatchAuthorityError::AuthorityUnavailable`].
//!
//! **The bounded-execution envelope, verbatim (CR-033 D1).** Every transaction sets
//! `SET LOCAL statement_timeout` and `lock_timeout`. Read-only transactions are never retried.
//! Mutations run at exactly three attempts, retry only `40001` and `40P01` after 25 ms then 100 ms,
//! and release the pooled session before sleeping. Transport ambiguity around `COMMIT` is resolved
//! by reconnect plus the operation-specific authoritative read.
//!
//! **Redaction.** No connection string, PEM, PostgreSQL diagnostic, parameter value, identifier, or
//! boundary id reaches `Display`, `Debug`, `Error::source`, tracing, or a detached task's log.
//!
//! The module is source-dark. It opens no provider route, installs no schema, and is not wired into
//! loreserver composition.

use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio_postgres::Row;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::dispatch_pool::DispatchLease;
use crate::dispatch_pool::DispatchPoolError;
use crate::dispatch_pool::DispatchPoolRole;
use crate::dispatch_pool::DispatchRuntimePool;

/// 0013's frozen API revision.
pub const RESERVE_PUT_API_REVISION_V1: &str = "object-store-dispatch-reserve-put-v1";
/// 0015's frozen API revision.
pub const PUT_UPLOAD_PROGRESS_API_REVISION_V1: &str =
    "object-store-dispatch-put-upload-progress-v1";
/// 0017's frozen API revision.
pub const PUT_SPOOL_READY_API_REVISION_V1: &str = "object-store-dispatch-put-spool-ready-v1";
/// 0020's frozen API revision, shared by enrollment and registration.
pub const DISPATCHER_REGISTRATION_API_REVISION_V1: &str =
    "object-store-dispatch-dispatcher-registration-v1";
/// 0019's frozen API revision, used by the runtime-callable installed-layer readback.
pub const DISPATCHER_IDENTITY_API_REVISION_V1: &str =
    "object-store-dispatch-dispatcher-identity-provisioning-v1";

/// Exactly three attempts: retry after the first two, never after the last (CR-033 D1).
const MUTATION_RETRY_SCHEDULE: [Option<Duration>; 3] = [
    Some(Duration::from_millis(25)),
    Some(Duration::from_millis(100)),
    None,
];

const RESERVE_PUT_SQL: &str = "SELECT
  (r).result_code,
  (r).spool_object_id,
  (r).logical_request_id,
  (r).attempt_id,
  (r).upload_id,
  ((r).upload_fence)::text,
  (r).admission_clock_unix_ms,
  (r).expires_at_unix_ms,
  (r).reserve_put_ack_canonical_bytes,
  (r).reserve_put_ack_blake3
FROM (SELECT object_store_retention.object_store_dispatch_reserve_put_v1(
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
  $11::text::object_store_retention.uint64, $12, $13, $14,
  $15::text::object_store_retention.uint64, $16, $17, $18,
  $19::text::object_store_retention.uint64, $20, $21, $22,
  $23::text::object_store_retention.uint64,
  $24::text::object_store_retention.uint64,
  $25::text::object_store_retention.uint64,
  $26::text::object_store_retention.uint64,
  $27::text::object_store_retention.uint64,
  $28::text::object_store_retention.uint64,
  $29::text::object_store_retention.uint64,
  $30::text::object_store_retention.uint64,
  $31::text::object_store_retention.uint64,
  $32::text::object_store_retention.uint64,
  $33::text::object_store_retention.uint64,
  $34::text::object_store_retention.uint64,
  $35::text::object_store_retention.uint64,
  $36::text::object_store_retention.uint64,
  $37::text::object_store_retention.uint64,
  $38::text::object_store_retention.uint64,
  $39::text::object_store_retention.uint64,
  $40::text::object_store_retention.uint64,
  $41::text::object_store_retention.uint64,
  $42::text::object_store_retention.uint64,
  $43, $44, $45
) AS r) q";

const PUT_UPLOAD_PROGRESS_SQL: &str = "SELECT
  (r).result_code,
  (r).spool_object_id,
  (r).logical_request_id,
  (r).attempt_id,
  (r).upload_id,
  ((r).upload_fence)::text,
  ((r).committed_prefix_bytes)::text,
  ((r).committed_prefix_chunks)::text,
  ((r).spool_revision)::text,
  (r).record_blake3
FROM (SELECT object_store_retention.object_store_dispatch_put_upload_progress_v1(
  $1, $2, $3, $4, $5, $6, $7, $8,
  $9::text::object_store_retention.uint64,
  $10::text::object_store_retention.uint64,
  $11::text::object_store_retention.uint64,
  $12, $13, $14
) AS r) q";

const PUT_SPOOL_READY_SQL: &str = "SELECT
  (r).result_code,
  (r).spool_object_id,
  (r).logical_request_id,
  (r).attempt_id,
  (r).upload_id,
  ((r).upload_fence)::text,
  (r).durable_handle,
  ((r).committed_size)::text,
  (r).committed_blake3,
  (r).ready_at_unix_ms,
  (r).reserve_put_ack_canonical_bytes,
  (r).reserve_put_ack_blake3,
  ((r).spool_revision)::text,
  (r).record_blake3
FROM (SELECT object_store_retention.object_store_dispatch_put_spool_ready_v1(
  $1, $2, $3, $4, $5, $6, $7, $8,
  $9::text::object_store_retention.uint64,
  $10::text::object_store_retention.uint64,
  $11::text::object_store_retention.uint64,
  $12, $13, $14, $15, $16, $17
) AS r) q";

const ENROLL_PARTICIPANT_SQL: &str = "SELECT
  (r).result_code,
  (r).provider_boundary_id,
  (r).dispatcher_id
FROM (SELECT object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(
  $1, $2, $3, $4
) AS r) q";

const REGISTER_DISPATCHER_SQL: &str = "SELECT
  (r).result_code,
  (r).dispatcher_id,
  ((r).lease_generation)::text,
  (r).provider_boundary_id,
  (r).service_instance_id,
  ((r).dispatcher_fence)::text,
  (r).state,
  (r).record_blake3
FROM (SELECT object_store_retention.object_store_dispatch_register_dispatcher_v1(
  $1, $2,
  $3::text::object_store_retention.uint64,
  $4,
  $5::text::object_store_retention.uint64,
  $6::text::object_store_retention.uint64,
  $7,
  $8::text::object_store_retention.uint64,
  $9, $10, $11, $12, $13
) AS r) q";

const DISPATCHER_IDENTITY_READ_STATE_SQL: &str = "SELECT
  (r).result_code,
  (r).retention_schema_revision,
  (r).retention_migration_blake3,
  ((r).retention_install_revision)::text,
  (r).retention_installed_at_unix_ms,
  (r).local_authority_schema_revision,
  (r).local_authority_migration_blake3,
  ((r).local_authority_install_revision)::text,
  (r).local_authority_installed_at_unix_ms,
  (r).put_reservation_schema_revision,
  (r).put_reservation_migration_blake3,
  ((r).put_reservation_install_revision)::text,
  (r).put_reservation_installed_at_unix_ms,
  (r).dispatcher_identity_schema_revision,
  (r).dispatcher_identity_migration_blake3,
  ((r).dispatcher_identity_install_revision)::text,
  (r).dispatcher_identity_installed_at_unix_ms
FROM (SELECT object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(
  $1
) AS r) q";

/// Why a cell-authority call refused, or could not be completed.
///
/// Every variant is a fixed shape. None carries a connection string, a PEM, a PostgreSQL
/// diagnostic, a parameter value, an identifier, or a boundary id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DispatchAuthorityError {
    #[error("dispatch pool could not supply a cell database session")]
    Pool(#[from] DispatchPoolError),
    #[error("dispatch pool identity is not the one this client requires")]
    WrongPoolRole,
    #[error("cell authority refused this session's role")]
    Unauthorized,
    #[error("cell authority does not implement the requested API revision")]
    UnsupportedApiRevision,
    #[error("cell authority schema is absent, incomplete, or drifted")]
    SchemaUnavailable,
    #[error("cell authority rejected an argument")]
    InvalidArgument,
    #[error("cell authority could not form a valid canonical record from this call's inputs")]
    CanonicalRecordInvalid,
    /// The cell database's `public.blake3` provider is absent or returned an unusable digest. A
    /// deployment prerequisite, not schema drift and not a caller error.
    #[error("cell authority's BLAKE3 digest provider is unavailable or unusable")]
    DigestProviderUnavailable,
    /// A supplied UUIDv7's embedded timestamp is outside the window the authority admits against
    /// its own clock. Distinct from a malformed identifier: the identifier is well formed.
    #[error("supplied identifier's timestamp is outside the cell authority's admission window")]
    IdentifierTimestampOutOfRange,
    #[error("cell authority reservation is expired or unknown")]
    ExpiredOrUnknown,
    #[error("cell authority reservation deadline has passed")]
    ReservationExpired,
    #[error("cell authority admission capacity is exhausted")]
    CapacityExhausted,
    #[error("cell authority quota state is unavailable")]
    QuotaUnavailable,
    #[error("cell authority counter would overflow")]
    CounterOverflow,
    #[error("cell authority clock or deadline arithmetic is invalid")]
    TimeInvalid,
    #[error("cell authority holds a conflicting record under this identity")]
    ReplayConflict,
    #[error("cell authority's stored record does not match this call")]
    StoredRecordMismatch,
    #[error("cell authority's stored state is not usable")]
    StoredStateInvalid,
    #[error("upload is already closed")]
    UploadClosed,
    #[error("upload stream identity does not match the reservation")]
    UploadStreamIdentityMismatch,
    #[error("upload chunk index is not the next one")]
    ChunkGap,
    #[error("dispatcher lease generation is not monotonic")]
    GenerationNotMonotonic,
    #[error("dispatcher participant key is not enrolled")]
    ParticipantAuthenticationRequired,
    #[error("dispatcher participant enrollment state is not usable")]
    ParticipantStateInvalid,
    #[error("dispatcher participant key digest is not a 32-byte BLAKE3 digest")]
    ParticipantKeyDigestInvalid,
    #[error("cell authority requires a serializable read-write transaction")]
    SerializableTransactionRequired,
    #[error("cell authority returned a result code this client does not recognize")]
    UnrecognizedResultCode,
    #[error("cell authority response is not usable: {0}")]
    InvalidAuthorityResponse(&'static str),
    #[error("cell authority mutation retry budget is exhausted")]
    RetryExhausted,
    #[error("cell authority operation exceeded its bounded execution envelope")]
    OperationTimeout,
    #[error("cell authority commit outcome could not be resolved")]
    AmbiguousCommit,
    /// The cell database refused a new connection because the instance is at `max_connections`.
    /// Named rather than folded into [`Self::AuthorityUnavailable`] because this is exactly the
    /// failure the per-replica connection budget exists to prevent, and the learning that budget
    /// cites records it being misdiagnosed three times over precisely because it arrived generic.
    #[error("cell database has no connection slots left")]
    ConnectionSlotsExhausted,
    #[error("cell authority is unavailable")]
    AuthorityUnavailable,
}

impl DispatchAuthorityError {
    /// Whether a caller may reasonably try the same call again later.
    ///
    /// [`Self::AmbiguousCommit`] is deliberately **not** transient: the client already tried to
    /// resolve it and could not, so whether the effect landed is unknown and a blind retry is the
    /// caller's decision, not this type's recommendation.
    pub const fn is_transient(self) -> bool {
        matches!(
            self,
            Self::Pool(DispatchPoolError::ConnectTimeout)
                | Self::Pool(DispatchPoolError::ConnectFailed)
                | Self::Pool(DispatchPoolError::PoolExhausted)
                | Self::OperationTimeout
                | Self::RetryExhausted
                | Self::AuthorityUnavailable
                | Self::ConnectionSlotsExhausted
                | Self::CapacityExhausted
        )
    }
}

/// How an accepted call reached its result.
///
/// The four arms keep provable states apart. `Applied` and `Replayed` are what the authority
/// reported on a call whose commit was observed. The two `AfterAmbiguousCommit` arms are what a
/// resolution proved about a commit whose transport outcome was unknown: the authority's own record
/// showed the earlier attempt had committed, or showed it had not and this re-issue applied the
/// effect. A commit that could not be resolved is [`DispatchAuthorityError::AmbiguousCommit`] and
/// never one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchDisposition {
    /// The authority created or applied this call's effect during this call.
    Applied,
    /// The identical call was already applied; the authority replayed its stored projection.
    Replayed,
    /// A commit with an unknown transport outcome was re-issued, and the authority proved the
    /// earlier attempt had committed.
    ReplayedAfterAmbiguousCommit,
    /// A commit with an unknown transport outcome was re-issued, and the authority proved the
    /// earlier attempt had **not** committed. This re-issue applied the effect.
    AppliedAfterAmbiguousCommit,
}

impl DispatchDisposition {
    const fn after_ambiguity(self) -> Self {
        match self {
            Self::Applied | Self::AppliedAfterAmbiguousCommit => Self::AppliedAfterAmbiguousCommit,
            Self::Replayed | Self::ReplayedAfterAmbiguousCommit => {
                Self::ReplayedAfterAmbiguousCommit
            }
        }
    }
}

/// An accepted authority result and how it was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchAccepted<T> {
    pub disposition: DispatchDisposition,
    pub value: T,
}

// ---------------------------------------------------------------------------------------------
// Request and outcome types
// ---------------------------------------------------------------------------------------------

/// The identity every PUT-path call binds to. Redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct PutStreamIdentity {
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub upload_id: Uuid,
    pub upload_fence: u64,
}

impl fmt::Debug for PutStreamIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutStreamIdentity")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("authenticated_cell_id", &"[REDACTED]")
            .field("authenticated_tenant_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("upload_id", &"[REDACTED]")
            .field("upload_fence", &"[REDACTED]")
            .finish()
    }
}

/// The quota envelope 0013 admits a reservation against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservePutQuotaScope {
    pub max_bytes: u64,
    pub max_rows: u64,
    pub max_concurrency: u64,
    pub low_water_bytes: u64,
    pub low_water_rows: u64,
    pub low_water_concurrency: u64,
}

/// The three text and record bounds 0013, 0015 and 0017 enforce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchRecordLimits {
    pub maximum_identity_bytes: i32,
    pub maximum_boundary_token_bytes: i32,
    pub maximum_record_bytes: i32,
}

/// One 0013 `ReservePut` admission.
#[derive(Clone, PartialEq, Eq)]
pub struct ReservePutRequest {
    pub protocol_revision: String,
    pub policy_revision: String,
    pub identity: PutStreamIdentity,
    pub spool_object_id: Uuid,
    pub boundary_blake3: [u8; 32],
    pub boundary_token: String,
    pub observation_binding_blake3: [u8; 32],
    pub expected_size: u64,
    pub expected_blake3: [u8; 32],
    pub put_reservation_fingerprint: [u8; 32],
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub reservation_deadline_unix_ms: i64,
    pub allocation_hard_expiry_unix_ms: i64,
    pub prepared_ttl_ms: i64,
    pub max_chunk_bytes: u64,
    pub quota_revision: u64,
    pub global_quota: ReservePutQuotaScope,
    pub cell_quota: ReservePutQuotaScope,
    pub tenant_quota: ReservePutQuotaScope,
    pub limits: DispatchRecordLimits,
}

impl fmt::Debug for ReservePutRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservePutRequest")
            .field("protocol_revision", &"[REDACTED]")
            .field("policy_revision", &"[REDACTED]")
            .field("identity", &self.identity)
            .field("spool_object_id", &"[REDACTED]")
            .field("boundary_blake3", &"[REDACTED]")
            .field("boundary_token", &"[REDACTED]")
            .field("observation_binding_blake3", &"[REDACTED]")
            .field("expected_size", &"[REDACTED]")
            .field("expected_blake3", &"[REDACTED]")
            .field("put_reservation_fingerprint", &"[REDACTED]")
            .field("allocation_revision", &"[REDACTED]")
            .field("allocation_fence", &"[REDACTED]")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// 0013's projected reservation.
#[derive(Clone, PartialEq, Eq)]
pub struct ReservePutOutcome {
    pub spool_object_id: Uuid,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub upload_id: Uuid,
    pub upload_fence: u64,
    pub admission_clock_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub reserve_put_ack_canonical_bytes: Vec<u8>,
    pub reserve_put_ack_blake3: [u8; 32],
}

impl fmt::Debug for ReservePutOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservePutOutcome")
            .field("spool_object_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("upload_id", &"[REDACTED]")
            .field("upload_fence", &"[REDACTED]")
            .field("admission_clock_unix_ms", &self.admission_clock_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("reserve_put_ack_canonical_bytes", &"[REDACTED]")
            .field("reserve_put_ack_blake3", &"[REDACTED]")
            .finish()
    }
}

/// One 0015 non-final upload-progress step.
#[derive(Clone, PartialEq, Eq)]
pub struct PutUploadProgressRequest {
    pub protocol_revision: String,
    pub identity: PutStreamIdentity,
    pub chunk_index: u64,
    pub fsynced_prefix_bytes: u64,
    pub limits: DispatchRecordLimits,
}

impl fmt::Debug for PutUploadProgressRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutUploadProgressRequest")
            .field("protocol_revision", &"[REDACTED]")
            .field("identity", &self.identity)
            .field("chunk_index", &"[REDACTED]")
            .field("fsynced_prefix_bytes", &"[REDACTED]")
            .field("limits", &self.limits)
            .finish()
    }
}

/// 0015's projected progress row.
#[derive(Clone, PartialEq, Eq)]
pub struct PutUploadProgressOutcome {
    pub spool_object_id: Uuid,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub upload_id: Uuid,
    pub upload_fence: u64,
    pub committed_prefix_bytes: u64,
    pub committed_prefix_chunks: u64,
    pub spool_revision: u64,
    pub record_blake3: [u8; 32],
}

impl fmt::Debug for PutUploadProgressOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutUploadProgressOutcome")
            .field("spool_object_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("upload_id", &"[REDACTED]")
            .field("upload_fence", &"[REDACTED]")
            .field("committed_prefix_bytes", &"[REDACTED]")
            .field("committed_prefix_chunks", &"[REDACTED]")
            .field("spool_revision", &"[REDACTED]")
            .field("record_blake3", &"[REDACTED]")
            .finish()
    }
}

/// One 0017 `SPOOL_READY` transition.
///
/// The caller asserts the complete body is already durable at `durable_handle`. This client neither
/// derives nor inspects a path, and performs no filesystem write, fsync, or rename.
#[derive(Clone, PartialEq, Eq)]
pub struct PutSpoolReadyRequest {
    pub protocol_revision: String,
    pub identity: PutStreamIdentity,
    pub final_chunk_index: u64,
    pub fsynced_body_size: u64,
    pub fsynced_body_blake3: [u8; 32],
    pub durable_handle: String,
    pub maximum_identity_bytes: i32,
    pub maximum_boundary_token_bytes: i32,
    pub maximum_durable_handle_bytes: i32,
    pub maximum_record_bytes: i32,
}

impl fmt::Debug for PutSpoolReadyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutSpoolReadyRequest")
            .field("protocol_revision", &"[REDACTED]")
            .field("identity", &self.identity)
            .field("final_chunk_index", &"[REDACTED]")
            .field("fsynced_body_size", &"[REDACTED]")
            .field("fsynced_body_blake3", &"[REDACTED]")
            .field("durable_handle", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// 0017's projected ready row.
#[derive(Clone, PartialEq, Eq)]
pub struct PutSpoolReadyOutcome {
    pub spool_object_id: Uuid,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub upload_id: Uuid,
    pub upload_fence: u64,
    pub durable_handle: String,
    pub committed_size: u64,
    pub committed_blake3: [u8; 32],
    pub ready_at_unix_ms: i64,
    pub reserve_put_ack_canonical_bytes: Vec<u8>,
    pub reserve_put_ack_blake3: [u8; 32],
    pub spool_revision: u64,
    pub record_blake3: [u8; 32],
}

impl fmt::Debug for PutSpoolReadyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutSpoolReadyOutcome")
            .field("spool_object_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("upload_id", &"[REDACTED]")
            .field("upload_fence", &"[REDACTED]")
            .field("durable_handle", &"[REDACTED]")
            .field("committed_size", &"[REDACTED]")
            .field("committed_blake3", &"[REDACTED]")
            .field("ready_at_unix_ms", &self.ready_at_unix_ms)
            .field("reserve_put_ack_canonical_bytes", &"[REDACTED]")
            .field("reserve_put_ack_blake3", &"[REDACTED]")
            .field("spool_revision", &"[REDACTED]")
            .field("record_blake3", &"[REDACTED]")
            .finish()
    }
}

/// One 0020 maintenance-only participant enrollment.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollParticipantRequest {
    pub provider_boundary_id: String,
    pub dispatcher_id: String,
    pub participant_key_blake3: [u8; 32],
}

impl fmt::Debug for EnrollParticipantRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollParticipantRequest")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("dispatcher_id", &"[REDACTED]")
            .field("participant_key_blake3", &"[REDACTED]")
            .finish()
    }
}

/// 0020's projected enrollment row.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollParticipantOutcome {
    pub provider_boundary_id: String,
    pub dispatcher_id: String,
}

impl fmt::Debug for EnrollParticipantOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollParticipantOutcome")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("dispatcher_id", &"[REDACTED]")
            .finish()
    }
}

/// One 0020 runtime-only dispatcher registration.
///
/// The runtime proves possession of its enrolled participant key and never supplies either identity
/// column itself; the authority mints `provider_boundary_id` and `dispatcher_id` from the enrolled
/// participant row.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisterDispatcherRequest {
    /// The 32-byte enrolled participant secret. Never logged, never rendered.
    pub participant_key: [u8; 32],
    pub next_generation: u64,
    pub service_instance_id: String,
    pub dispatcher_fence: u64,
    pub authority_revision: u64,
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub provider_credential_revision: String,
    pub acquired_at_unix_ms: i64,
    pub renewed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub state_changed_at_unix_ms: i64,
}

impl fmt::Debug for RegisterDispatcherRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisterDispatcherRequest")
            .field("participant_key", &"[REDACTED]")
            .field("next_generation", &"[REDACTED]")
            .field("service_instance_id", &"[REDACTED]")
            .field("dispatcher_fence", &"[REDACTED]")
            .field("authority_revision", &"[REDACTED]")
            .field("allocation_revision", &"[REDACTED]")
            .field("allocation_fence", &"[REDACTED]")
            .field("provider_credential_revision", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// 0020's projected dispatcher row.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisterDispatcherOutcome {
    pub dispatcher_id: String,
    pub lease_generation: u64,
    pub provider_boundary_id: String,
    pub service_instance_id: String,
    pub dispatcher_fence: u64,
    pub state: i16,
    pub record_blake3: [u8; 32],
}

impl fmt::Debug for RegisterDispatcherOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisterDispatcherOutcome")
            .field("dispatcher_id", &"[REDACTED]")
            .field("lease_generation", &"[REDACTED]")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("service_instance_id", &"[REDACTED]")
            .field("dispatcher_fence", &"[REDACTED]")
            .field("state", &self.state)
            .field("record_blake3", &"[REDACTED]")
            .finish()
    }
}

/// One installed schema layer's identity tuple, as 0019's readback reports it.
#[derive(Clone, PartialEq, Eq)]
pub struct InstalledLayerIdentity {
    pub schema_revision: String,
    pub migration_blake3: [u8; 32],
    pub install_revision: u64,
    pub installed_at_unix_ms: i64,
}

impl fmt::Debug for InstalledLayerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledLayerIdentity")
            .field("schema_revision", &self.schema_revision)
            .field("migration_blake3", &"[REDACTED]")
            .field("install_revision", &self.install_revision)
            .field("installed_at_unix_ms", &self.installed_at_unix_ms)
            .finish()
    }
}

/// 0019's runtime-callable readiness signal: every installed layer's identity tuple.
///
/// It answers "is every layer installed at the artifact identity this cell expects, and is D8's
/// participant constraint the one in force". It does **not** attest the live PostgreSQL catalog;
/// that is the out-of-band attester's job, and the attester is migrator-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatcherIdentityState {
    pub retention: InstalledLayerIdentity,
    pub local_authority: InstalledLayerIdentity,
    pub put_reservation: InstalledLayerIdentity,
    pub dispatcher_identity: InstalledLayerIdentity,
}

// ---------------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------------

/// The runtime-identity client: 0013, 0015, 0017, 0020's registration, and 0019's readback.
#[derive(Debug)]
pub struct DispatchRuntimeClient {
    pool: DispatchRuntimePool,
}

impl DispatchRuntimeClient {
    /// Refuses a pool that does not connect as the runtime role, so a maintenance credential cannot
    /// be routed into a runtime mutation.
    pub fn new(pool: DispatchRuntimePool) -> Result<Self, DispatchAuthorityError> {
        if pool.role() != DispatchPoolRole::Runtime {
            return Err(DispatchAuthorityError::WrongPoolRole);
        }
        Ok(Self { pool })
    }

    /// 0013: admit one PUT reservation.
    pub async fn reserve_put(
        &self,
        request: &ReservePutRequest,
    ) -> Result<DispatchAccepted<ReservePutOutcome>, DispatchAuthorityError> {
        run_mutation(&self.pool, &PreparedReservePut::new(request)).await
    }

    /// 0015: record one non-final upload chunk's fsynced prefix.
    pub async fn put_upload_progress(
        &self,
        request: &PutUploadProgressRequest,
    ) -> Result<DispatchAccepted<PutUploadProgressOutcome>, DispatchAuthorityError> {
        run_mutation(&self.pool, &PreparedPutUploadProgress::new(request)).await
    }

    /// 0017: record the already-durable body and move the spool object to `SPOOL_READY`.
    pub async fn put_spool_ready(
        &self,
        request: &PutSpoolReadyRequest,
    ) -> Result<DispatchAccepted<PutSpoolReadyOutcome>, DispatchAuthorityError> {
        run_mutation(&self.pool, &PreparedPutSpoolReady::new(request)).await
    }

    /// 0020: register this replica's dispatcher generation against its enrolled participant key.
    pub async fn register_dispatcher(
        &self,
        request: &RegisterDispatcherRequest,
    ) -> Result<DispatchAccepted<RegisterDispatcherOutcome>, DispatchAuthorityError> {
        run_mutation(&self.pool, &PreparedRegisterDispatcher::new(request)).await
    }

    /// 0019: read every installed layer's identity tuple.
    ///
    /// Read-only, and therefore **never retried**: a read that fails is reported, not repeated.
    pub async fn read_dispatcher_identity_state(
        &self,
    ) -> Result<DispatcherIdentityState, DispatchAuthorityError> {
        let api = DISPATCHER_IDENTITY_API_REVISION_V1;
        let params: [&(dyn ToSql + Sync); 1] = [&api];
        // `read_once` applies the envelope to the transaction and leaves acquisition to the pool's
        // own timeouts, so there is no second wall-clock wrapper here.
        let row = read_once(&self.pool, DISPATCHER_IDENTITY_READ_STATE_SQL, &params).await?;
        decode_dispatcher_identity_state(&row)
    }
}

/// The maintenance-identity client: 0020's participant enrollment, and nothing else.
#[derive(Debug)]
pub struct DispatchMaintenanceClient {
    pool: DispatchRuntimePool,
}

impl DispatchMaintenanceClient {
    /// Refuses a pool that does not connect as the maintenance role.
    pub fn new(pool: DispatchRuntimePool) -> Result<Self, DispatchAuthorityError> {
        if pool.role() != DispatchPoolRole::Maintenance {
            return Err(DispatchAuthorityError::WrongPoolRole);
        }
        Ok(Self { pool })
    }

    /// 0020: enrol one dispatcher participant slot and its key digest.
    pub async fn enroll_dispatcher_participant(
        &self,
        request: &EnrollParticipantRequest,
    ) -> Result<DispatchAccepted<EnrollParticipantOutcome>, DispatchAuthorityError> {
        run_mutation(&self.pool, &PreparedEnrollParticipant::new(request)).await
    }
}

// ---------------------------------------------------------------------------------------------
// The bounded-execution envelope
// ---------------------------------------------------------------------------------------------

/// A mutation with its parameters already converted to what `tokio-postgres` can bind.
trait PreparedMutation {
    type Outcome;

    fn statement(&self) -> &'static str;
    fn bind(&self) -> Vec<&(dyn ToSql + Sync)>;
    /// Closed decoding, including binding the projection to the submitted identity.
    fn decode(&self, row: &Row) -> Result<DispatchAccepted<Self::Outcome>, DispatchAuthorityError>;
}

enum AttemptOutcome<T> {
    /// The transaction committed and the authority's response decoded.
    Committed(DispatchAccepted<T>),
    /// PostgreSQL proved the transaction aborted for a retryable reason.
    Retryable,
    /// A refusal, on a transaction that provably did not commit.
    Refused(DispatchAuthorityError),
    /// `COMMIT` produced no SQLSTATE, so durability cannot be proved from this attempt alone.
    AmbiguousCommit,
}

async fn run_mutation<M: PreparedMutation>(
    pool: &DispatchRuntimePool,
    prepared: &M,
) -> Result<DispatchAccepted<M::Outcome>, DispatchAuthorityError> {
    // Once any attempt's commit has been left unresolved, no later attempt can restore certainty
    // about *this* call unless it commits: a refusal may be refusing precisely because the earlier
    // attempt committed. So the flag makes every non-committed terminal outcome ambiguous from
    // then on, and a commit is reported with an `AfterAmbiguousCommit` disposition.
    let mut ambiguity_seen = false;
    for retry_delay in MUTATION_RETRY_SCHEDULE {
        match mutate_once(pool, prepared).await {
            AttemptOutcome::Committed(accepted) => {
                return Ok(DispatchAccepted {
                    disposition: if ambiguity_seen {
                        accepted.disposition.after_ambiguity()
                    } else {
                        accepted.disposition
                    },
                    value: accepted.value,
                });
            }
            AttemptOutcome::Refused(_) if ambiguity_seen => {
                return Err(DispatchAuthorityError::AmbiguousCommit);
            }
            AttemptOutcome::Refused(error) => return Err(error),
            // CR-033 D1's resolution step - reconnect plus the operation-specific authoritative
            // read - is folded into this same budget rather than given a second one. For all five
            // procedures the authoritative read *is* re-issuing the identical call, so the next
            // attempt performs it: the ambiguous attempt's session was poisoned, and a `REPLAY`
            // proves the earlier attempt committed while `CREATED`/`APPLIED` proves it did not.
            // Keeping it in this loop is what holds the envelope's "exactly three attempts": a
            // separate resolution budget would let one logical mutation reach six.
            AttemptOutcome::AmbiguousCommit => {
                ambiguity_seen = true;
                match retry_delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => return Err(DispatchAuthorityError::AmbiguousCommit),
                }
            }
            AttemptOutcome::Retryable => match retry_delay {
                // The session is already back in the pool: `mutate_once` releases its lease before
                // returning, so a bounded pool is never held idle across the backoff.
                Some(delay) => tokio::time::sleep(delay).await,
                None if ambiguity_seen => return Err(DispatchAuthorityError::AmbiguousCommit),
                None => return Err(DispatchAuthorityError::RetryExhausted),
            },
        }
    }
    if ambiguity_seen {
        return Err(DispatchAuthorityError::AmbiguousCommit);
    }
    Err(DispatchAuthorityError::RetryExhausted)
}

/// One serializable attempt, bounded by `statement_timeout + lock_timeout`. The lease is always
/// released or poisoned before this returns.
///
/// The wall-clock bound covers the transaction only, not the pool acquisition ahead of it, which
/// carries its own `acquire_timeout` and `connect_timeout`.
async fn mutate_once<M: PreparedMutation>(
    pool: &DispatchRuntimePool,
    prepared: &M,
) -> AttemptOutcome<M::Outcome> {
    let mut lease = match pool.acquire().await {
        Ok(lease) => lease,
        Err(error) => return AttemptOutcome::Refused(DispatchAuthorityError::Pool(error)),
    };
    // Set the instant `COMMIT` is written to the wire. A wall-clock timeout that fires before that
    // is a transaction this client provably never asked the database to commit, so it is a plain
    // refusal; only a timeout with `COMMIT` in flight is genuinely ambiguous. Folding both into
    // ambiguity would report an unresolvable outcome for a case the client can prove.
    let commit_sent = AtomicBool::new(false);
    let bounded = tokio::time::timeout(
        pool.operation_timeout(),
        mutate_on_lease(pool, prepared, &mut lease, &commit_sent),
    )
    .await;
    let outcome = match bounded {
        Ok(outcome) => outcome,
        Err(_) => {
            let ambiguous = commit_sent.load(Ordering::SeqCst);
            // Either way the session was abandoned with a transaction open on it, so it is closed
            // rather than returned to the pool.
            lease.poison();
            return if ambiguous {
                AttemptOutcome::AmbiguousCommit
            } else {
                AttemptOutcome::Refused(DispatchAuthorityError::OperationTimeout)
            };
        }
    };
    match outcome {
        // A poisoned connection is closed rather than returned: after an unresolved COMMIT the
        // server-side state of that session is not known.
        AttemptOutcome::AmbiguousCommit => {
            lease.poison();
            AttemptOutcome::AmbiguousCommit
        }
        other => {
            lease.release().await;
            other
        }
    }
}

async fn mutate_on_lease<M: PreparedMutation>(
    pool: &DispatchRuntimePool,
    prepared: &M,
    lease: &mut DispatchLease<'_>,
    commit_sent: &AtomicBool,
) -> AttemptOutcome<M::Outcome> {
    let preamble = pool.bounded_execution_preamble();
    let client = match lease.client() {
        Ok(client) => client,
        Err(error) => return AttemptOutcome::Refused(DispatchAuthorityError::Pool(error)),
    };
    let transaction = match client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .await
    {
        Ok(transaction) => transaction,
        Err(error) => return classify_precommit(&error),
    };
    if let Err(error) = transaction.batch_execute(&preamble).await {
        return classify_precommit(&error);
    }
    let row = match transaction
        .query_one(prepared.statement(), &prepared.bind())
        .await
    {
        Ok(row) => row,
        Err(error) => return classify_precommit(&error),
    };
    let accepted = match prepared.decode(&row) {
        Ok(accepted) => accepted,
        // Decoding refused before COMMIT, so nothing durable happened. Roll back explicitly; a lost
        // ROLLBACK cannot make an uncommitted transaction commit.
        Err(error) => {
            let _ = transaction.rollback().await;
            return AttemptOutcome::Refused(error);
        }
    };
    commit_sent.store(true, Ordering::SeqCst);
    match transaction.commit().await {
        Ok(()) => AttemptOutcome::Committed(accepted),
        Err(error) => classify_commit(&error),
    }
}

/// One read-only transaction. Never retried.
///
/// Acquisition sits outside the bounded-execution envelope, as it does on the mutation path: the
/// envelope bounds the transaction, while the pool carries its own `acquire_timeout` and
/// `connect_timeout`. Folding acquisition in would report provable pool exhaustion as a timeout.
async fn read_once(
    pool: &DispatchRuntimePool,
    statement: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Row, DispatchAuthorityError> {
    let preamble = pool.bounded_execution_preamble();
    let mut lease = pool.acquire().await.map_err(DispatchAuthorityError::Pool)?;
    let bounded = tokio::time::timeout(
        pool.operation_timeout(),
        read_on_lease(&mut lease, &preamble, statement, params),
    )
    .await;
    match bounded {
        Ok(result) => {
            lease.release().await;
            result
        }
        Err(_) => {
            // The read transaction was abandoned mid-flight, so its session is closed rather than
            // returned. A read is never retried, so this is terminal.
            lease.poison();
            Err(DispatchAuthorityError::OperationTimeout)
        }
    }
}

async fn read_on_lease(
    lease: &mut DispatchLease<'_>,
    preamble: &str,
    statement: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Row, DispatchAuthorityError> {
    let client = lease.client().map_err(DispatchAuthorityError::Pool)?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|error| refusal_of(&error))?;
    transaction
        .batch_execute(preamble)
        .await
        .map_err(|error| refusal_of(&error))?;
    let row = transaction
        .query_one(statement, params)
        .await
        .map_err(|error| refusal_of(&error))?;
    transaction
        .commit()
        .await
        .map_err(|error| refusal_of(&error))?;
    Ok(row)
}

// ---------------------------------------------------------------------------------------------
// Closed retry classification
// ---------------------------------------------------------------------------------------------

/// A failure before `COMMIT` was sent. Nothing durable happened, so no arm here is ambiguous.
fn classify_precommit<T>(error: &tokio_postgres::Error) -> AttemptOutcome<T> {
    match classify(error) {
        Classification::Retryable => AttemptOutcome::Retryable,
        Classification::Refusal(refusal) => AttemptOutcome::Refused(refusal),
    }
}

/// A failure reported by `COMMIT`.
///
/// A SQLSTATE at `COMMIT` is PostgreSQL proving the transaction aborted, so it keeps its own arm
/// rather than being folded into the ambiguous one. Only a `COMMIT` with **no** SQLSTATE - a
/// transport loss - is ambiguous, and that one is resolved rather than reported.
fn classify_commit<T>(error: &tokio_postgres::Error) -> AttemptOutcome<T> {
    if error.code().is_none() {
        return AttemptOutcome::AmbiguousCommit;
    }
    classify_precommit(error)
}

fn refusal_of(error: &tokio_postgres::Error) -> DispatchAuthorityError {
    match classify(error) {
        // A read-only transaction is never retried, so a retryable class is reported as
        // unavailability rather than silently repeated.
        Classification::Retryable => DispatchAuthorityError::AuthorityUnavailable,
        Classification::Refusal(refusal) => refusal,
    }
}

enum Classification {
    Retryable,
    Refusal(DispatchAuthorityError),
}

/// The one closed classification table.
///
/// Order matters. `40001` and `40P01` are checked first and are the **only** retryable classes, per
/// CR-033 D1. That deliberately includes 0015's `DISPATCH_PUT_UPLOAD_PROGRESS_CONFLICT` and 0017's
/// `DISPATCH_PUT_SPOOL_READY_CONFLICT`, which the procedures raise *as* `40001` precisely so a
/// caller treats them as serialization conflicts.
fn classify(error: &tokio_postgres::Error) -> Classification {
    let Some(database_error) = error.as_db_error() else {
        // No SQLSTATE and no server response: the statement never completed, so no COMMIT was sent.
        return Classification::Refusal(DispatchAuthorityError::AuthorityUnavailable);
    };
    let code = database_error.code();
    if code == &SqlState::T_R_SERIALIZATION_FAILURE || code == &SqlState::T_R_DEADLOCK_DETECTED {
        return Classification::Retryable;
    }
    if let Some(refusal) = refusal_for_condition(database_error.message()) {
        return Classification::Refusal(refusal);
    }
    Classification::Refusal(refusal_for_sqlstate(code))
}

/// The closed set of conditions the retained procedures raise, by their frozen message literal.
///
/// The literals are fixed strings written into the migration artifacts, not parameter values, so
/// matching on them discloses nothing. Nothing from the diagnostic is retained past this function.
fn refusal_for_condition(message: &str) -> Option<DispatchAuthorityError> {
    let refusal = match message {
        "DISPATCH_RUNTIME_UNAUTHORIZED"
        | "DISPATCH_MAINTENANCE_AUTHORIZATION_REQUIRED"
        | "DISPATCH_DISPATCHER_IDENTITY_READER_AUTHORIZATION_REQUIRED" => {
            DispatchAuthorityError::Unauthorized
        }
        "UNSUPPORTED_DISPATCH_RESERVE_PUT_API_REVISION"
        | "UNSUPPORTED_DISPATCH_PUT_UPLOAD_PROGRESS_API_REVISION"
        | "UNSUPPORTED_DISPATCH_PUT_SPOOL_READY_API_REVISION"
        | "UNSUPPORTED_DISPATCH_DISPATCHER_REGISTRATION_API_REVISION"
        | "UNSUPPORTED_DISPATCH_DISPATCHER_IDENTITY_API_REVISION" => {
            DispatchAuthorityError::UnsupportedApiRevision
        }
        "DISPATCH_RESERVE_PUT_SCHEMA_UNAVAILABLE"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_SCHEMA_UNAVAILABLE"
        | "DISPATCH_PUT_SPOOL_READY_SCHEMA_UNAVAILABLE"
        | "DISPATCH_RESERVE_PUT_UNAVAILABLE"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_UNAVAILABLE"
        | "DISPATCH_PUT_SPOOL_READY_UNAVAILABLE"
        | "DISPATCH_DISPATCHER_IDENTITY_UNAVAILABLE"
        | "DISPATCH_DISPATCHER_IDENTITY_CATALOG_MISMATCH" => {
            DispatchAuthorityError::SchemaUnavailable
        }
        "DISPATCH_RESERVE_PUT_INVALID_ARGUMENT"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_INVALID_ARGUMENT"
        | "DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_RESULT_INVALID"
        | "DISPATCH_PUT_SPOOL_READY_RESULT_INVALID" => DispatchAuthorityError::InvalidArgument,
        // The canonical-record helpers the mutations call. The inputs are well formed as SQL but
        // cannot be encoded into a record the schema can store.
        "LOCAL_DISPATCHER_REGISTRATION_RECORD_INVALID"
        | "LOCAL_RESERVE_PUT_ACK_INVALID"
        | "LOCAL_PUT_RESERVED_RECORD_INVALID"
        | "LOCAL_PUT_SPOOL_READY_RECORD_INVALID"
        | "LOCAL_QUOTA_CHILD_INVALID"
        | "LOCAL_PUT_SPOOL_READY_CHILD_INVALID"
        | "LOCAL_CANONICAL_TEXT_INVALID"
        | "LOCAL_CANONICAL_BYTES_INVALID"
        | "LOCAL_CANONICAL_U8_INVALID"
        | "LOCAL_CANONICAL_U32_INVALID"
        | "LOCAL_CANONICAL_RECORD_TOO_LARGE" => DispatchAuthorityError::CanonicalRecordInvalid,
        "LOCAL_BLAKE3_PROVIDER_UNAVAILABLE" | "LOCAL_BLAKE3_PROVIDER_INVALID_RESULT" => {
            DispatchAuthorityError::DigestProviderUnavailable
        }
        "INVALID_UUIDV7" => DispatchAuthorityError::InvalidArgument,
        "UUIDV7_TIMESTAMP_TOO_FAR_IN_FUTURE" => {
            DispatchAuthorityError::IdentifierTimestampOutOfRange
        }
        "EXPIRED_OR_UNKNOWN" => DispatchAuthorityError::ExpiredOrUnknown,
        "DISPATCH_RESERVE_PUT_EXPIRED" => DispatchAuthorityError::ReservationExpired,
        "DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED" => DispatchAuthorityError::CapacityExhausted,
        "DISPATCH_RESERVE_PUT_QUOTA_UNAVAILABLE" => DispatchAuthorityError::QuotaUnavailable,
        "DISPATCH_RESERVE_PUT_COUNTER_OVERFLOW"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_COUNTER_OVERFLOW"
        | "DISPATCH_PUT_SPOOL_READY_COUNTER_OVERFLOW" => DispatchAuthorityError::CounterOverflow,
        "DISPATCH_RESERVE_PUT_TIME_OVERFLOW"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_TIME_INVALID"
        | "DISPATCH_PUT_SPOOL_READY_TIME_INVALID" => DispatchAuthorityError::TimeInvalid,
        "DISPATCH_RESERVE_PUT_REPLAY_CONFLICT"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_REPLAY_CONFLICT"
        | "DISPATCH_PUT_SPOOL_READY_REPLAY_CONFLICT"
        | "DISPATCH_DISPATCHER_REGISTRATION_REPLAY_CONFLICT"
        | "DISPATCH_DISPATCHER_PARTICIPANT_ENROLLMENT_CONFLICT" => {
            DispatchAuthorityError::ReplayConflict
        }
        // The two ACK mismatches belong here, not with the caller-input refusals: the reachable
        // site is the replay path, where the authority recomputes the ACK from the *stored* row
        // (0013:110 feeds `stored.*`) and finds it disagrees. That is a stored-record problem, and
        // naming it a caller derivation error would send an operator looking at the wrong thing.
        "DISPATCH_RESERVED_PUT_STORED_RECORD_MISMATCH"
        | "DISPATCH_DISPATCHER_REGISTRATION_STORED_RECORD_MISMATCH"
        | "LOCAL_PUT_RESERVATION_ACK_MISMATCH"
        | "LOCAL_PUT_SPOOL_READY_ACK_MISMATCH" => DispatchAuthorityError::StoredRecordMismatch,
        "DISPATCH_RESERVED_PUT_STORED_STATE_INVALID"
        | "DISPATCH_PUT_UPLOAD_PROGRESS_STORED_STATE_INVALID"
        | "DISPATCH_PUT_SPOOL_READY_STORED_STATE_INVALID"
        | "DISPATCH_DISPATCHER_REGISTRATION_STORED_STATE_INVALID" => {
            DispatchAuthorityError::StoredStateInvalid
        }
        "UPLOAD_CLOSED" => DispatchAuthorityError::UploadClosed,
        "UPLOAD_STREAM_IDENTITY_MISMATCH" => DispatchAuthorityError::UploadStreamIdentityMismatch,
        "DISPATCH_PUT_UPLOAD_CHUNK_GAP" => DispatchAuthorityError::ChunkGap,
        "DISPATCH_DISPATCHER_GENERATION_NOT_MONOTONIC" => {
            DispatchAuthorityError::GenerationNotMonotonic
        }
        "DISPATCH_DISPATCHER_PARTICIPANT_AUTHENTICATION_REQUIRED" => {
            DispatchAuthorityError::ParticipantAuthenticationRequired
        }
        "DISPATCH_DISPATCHER_PARTICIPANT_STATE_INVALID" => {
            DispatchAuthorityError::ParticipantStateInvalid
        }
        "DISPATCH_DISPATCHER_PARTICIPANT_KEY_DIGEST_INVALID" => {
            DispatchAuthorityError::ParticipantKeyDigestInvalid
        }
        "SERIALIZABLE_READ_WRITE_TRANSACTION_REQUIRED" => {
            DispatchAuthorityError::SerializableTransactionRequired
        }
        _ => return None,
    };
    Some(refusal)
}

/// The fallback for a SQLSTATE whose condition this client does not recognize. Fails closed.
fn refusal_for_sqlstate(code: &SqlState) -> DispatchAuthorityError {
    if code == &SqlState::INSUFFICIENT_PRIVILEGE {
        DispatchAuthorityError::Unauthorized
    } else if code == &SqlState::INVALID_PARAMETER_VALUE {
        DispatchAuthorityError::InvalidArgument
    } else if code == &SqlState::UNIQUE_VIOLATION {
        DispatchAuthorityError::ReplayConflict
    } else if code == &SqlState::NUMERIC_VALUE_OUT_OF_RANGE {
        DispatchAuthorityError::CounterOverflow
    } else if code == &SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE {
        DispatchAuthorityError::SchemaUnavailable
    } else if code == &SqlState::TOO_MANY_CONNECTIONS {
        DispatchAuthorityError::ConnectionSlotsExhausted
    } else if code == &SqlState::INSUFFICIENT_RESOURCES {
        DispatchAuthorityError::CapacityExhausted
    } else if code == &SqlState::INVALID_TRANSACTION_STATE {
        DispatchAuthorityError::SerializableTransactionRequired
    } else if code == &SqlState::QUERY_CANCELED || code == &SqlState::LOCK_NOT_AVAILABLE {
        // The envelope's own `SET LOCAL statement_timeout` and `lock_timeout` aborting the
        // statement. Reported as what it is rather than as generic unavailability.
        DispatchAuthorityError::OperationTimeout
    } else {
        DispatchAuthorityError::AuthorityUnavailable
    }
}

// ---------------------------------------------------------------------------------------------
// Closed result-code decoding
// ---------------------------------------------------------------------------------------------

/// 0013's and 0020's closed result codes.
const CREATED_OR_REPLAY: [&str; 2] = ["CREATED", "REPLAY"];
/// 0015's and 0017's closed result codes.
const APPLIED_OR_REPLAY: [&str; 2] = ["APPLIED", "REPLAY"];
/// 0019's readback's one closed result code.
const READ_ONLY_RESULT_CODE: &str = "READ";

/// Decode a `result_code` against a closed two-value set. Anything else is a refusal.
fn disposition_of(
    row: &Row,
    accepted: [&str; 2],
) -> Result<DispatchDisposition, DispatchAuthorityError> {
    let code: &str = row
        .try_get(0)
        .map_err(|_| DispatchAuthorityError::InvalidAuthorityResponse("result_code is not text"))?;
    if code == accepted[0] {
        Ok(DispatchDisposition::Applied)
    } else if code == accepted[1] {
        Ok(DispatchDisposition::Replayed)
    } else {
        Err(DispatchAuthorityError::UnrecognizedResultCode)
    }
}

fn text(row: &Row, index: usize) -> Result<String, DispatchAuthorityError> {
    row.try_get::<_, String>(index)
        .map_err(|_| DispatchAuthorityError::InvalidAuthorityResponse("expected a text column"))
}

fn uuid(row: &Row, index: usize) -> Result<Uuid, DispatchAuthorityError> {
    row.try_get::<_, Uuid>(index)
        .map_err(|_| DispatchAuthorityError::InvalidAuthorityResponse("expected a uuid column"))
}

fn int8(row: &Row, index: usize) -> Result<i64, DispatchAuthorityError> {
    row.try_get::<_, i64>(index)
        .map_err(|_| DispatchAuthorityError::InvalidAuthorityResponse("expected a bigint column"))
}

fn int2(row: &Row, index: usize) -> Result<i16, DispatchAuthorityError> {
    row.try_get::<_, i16>(index)
        .map_err(|_| DispatchAuthorityError::InvalidAuthorityResponse("expected a smallint column"))
}

fn bytes(row: &Row, index: usize) -> Result<Vec<u8>, DispatchAuthorityError> {
    row.try_get::<_, Vec<u8>>(index)
        .map_err(|_| DispatchAuthorityError::InvalidAuthorityResponse("expected a bytea column"))
}

fn digest(row: &Row, index: usize) -> Result<[u8; 32], DispatchAuthorityError> {
    let raw = bytes(row, index)?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
        DispatchAuthorityError::InvalidAuthorityResponse("expected a 32-byte BLAKE3 digest")
    })
}

/// The `uint64` domain is transferred as text so no value is narrowed through `bigint`.
fn uint64(row: &Row, index: usize) -> Result<u64, DispatchAuthorityError> {
    text(row, index)?.parse().map_err(|_| {
        DispatchAuthorityError::InvalidAuthorityResponse("expected a canonical uint64 in text")
    })
}

fn require(condition: bool, what: &'static str) -> Result<(), DispatchAuthorityError> {
    if condition {
        Ok(())
    } else {
        Err(DispatchAuthorityError::InvalidAuthorityResponse(what))
    }
}

fn decode_dispatcher_identity_state(
    row: &Row,
) -> Result<DispatcherIdentityState, DispatchAuthorityError> {
    let code: &str = row
        .try_get(0)
        .map_err(|_| DispatchAuthorityError::InvalidAuthorityResponse("result_code is not text"))?;
    if code != READ_ONLY_RESULT_CODE {
        return Err(DispatchAuthorityError::UnrecognizedResultCode);
    }
    let layer = |base: usize| -> Result<InstalledLayerIdentity, DispatchAuthorityError> {
        Ok(InstalledLayerIdentity {
            schema_revision: text(row, base)?,
            migration_blake3: digest(row, base + 1)?,
            install_revision: uint64(row, base + 2)?,
            installed_at_unix_ms: int8(row, base + 3)?,
        })
    };
    Ok(DispatcherIdentityState {
        retention: layer(1)?,
        local_authority: layer(5)?,
        put_reservation: layer(9)?,
        dispatcher_identity: layer(13)?,
    })
}

// ---------------------------------------------------------------------------------------------
// Prepared parameter conversion
// ---------------------------------------------------------------------------------------------

struct PreparedReservePut<'a> {
    request: &'a ReservePutRequest,
    api: &'static str,
    boundary_blake3: Vec<u8>,
    observation_binding_blake3: Vec<u8>,
    expected_blake3: Vec<u8>,
    put_reservation_fingerprint: Vec<u8>,
    upload_fence: String,
    expected_size: String,
    allocation_fence: String,
    max_chunk_bytes: String,
    quota_revision: String,
    quotas: [String; 18],
}

impl<'a> PreparedReservePut<'a> {
    fn new(request: &'a ReservePutRequest) -> Self {
        // 0013's eighteen quota bounds, written out in the exact order the procedure declares them
        // rather than filled by a loop over the three scopes. A loop hides which scope landed in
        // which position: swapping two scopes inside it changes what the cell admits against, and
        // no ordering check upstream or downstream can see it. Spelled out, the order is pinned by
        // `every_bound_value_sits_at_the_position_the_migration_declares_for_its_name`.
        let quotas: [String; 18] = [
            request.global_quota.max_bytes.to_string(),
            request.global_quota.max_rows.to_string(),
            request.global_quota.max_concurrency.to_string(),
            request.global_quota.low_water_bytes.to_string(),
            request.global_quota.low_water_rows.to_string(),
            request.global_quota.low_water_concurrency.to_string(),
            request.cell_quota.max_bytes.to_string(),
            request.cell_quota.max_rows.to_string(),
            request.cell_quota.max_concurrency.to_string(),
            request.cell_quota.low_water_bytes.to_string(),
            request.cell_quota.low_water_rows.to_string(),
            request.cell_quota.low_water_concurrency.to_string(),
            request.tenant_quota.max_bytes.to_string(),
            request.tenant_quota.max_rows.to_string(),
            request.tenant_quota.max_concurrency.to_string(),
            request.tenant_quota.low_water_bytes.to_string(),
            request.tenant_quota.low_water_rows.to_string(),
            request.tenant_quota.low_water_concurrency.to_string(),
        ];
        Self {
            request,
            api: RESERVE_PUT_API_REVISION_V1,
            boundary_blake3: request.boundary_blake3.to_vec(),
            observation_binding_blake3: request.observation_binding_blake3.to_vec(),
            expected_blake3: request.expected_blake3.to_vec(),
            put_reservation_fingerprint: request.put_reservation_fingerprint.to_vec(),
            upload_fence: request.identity.upload_fence.to_string(),
            expected_size: request.expected_size.to_string(),
            allocation_fence: request.allocation_fence.to_string(),
            max_chunk_bytes: request.max_chunk_bytes.to_string(),
            quota_revision: request.quota_revision.to_string(),
            quotas,
        }
    }
}

impl PreparedMutation for PreparedReservePut<'_> {
    type Outcome = ReservePutOutcome;

    fn statement(&self) -> &'static str {
        RESERVE_PUT_SQL
    }

    fn bind(&self) -> Vec<&(dyn ToSql + Sync)> {
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![
            &self.api,
            &self.request.protocol_revision,
            &self.request.policy_revision,
            &self.request.identity.provider_boundary_id,
            &self.request.identity.authenticated_cell_id,
            &self.request.identity.authenticated_tenant_id,
            &self.request.spool_object_id,
            &self.request.identity.logical_request_id,
            &self.request.identity.attempt_id,
            &self.request.identity.upload_id,
            &self.upload_fence,
            &self.boundary_blake3,
            &self.request.boundary_token,
            &self.observation_binding_blake3,
            &self.expected_size,
            &self.expected_blake3,
            &self.put_reservation_fingerprint,
            &self.request.allocation_revision,
            &self.allocation_fence,
            &self.request.reservation_deadline_unix_ms,
            &self.request.allocation_hard_expiry_unix_ms,
            &self.request.prepared_ttl_ms,
            &self.max_chunk_bytes,
            &self.quota_revision,
        ];
        for value in &self.quotas {
            params.push(value);
        }
        params.push(&self.request.limits.maximum_identity_bytes);
        params.push(&self.request.limits.maximum_boundary_token_bytes);
        params.push(&self.request.limits.maximum_record_bytes);
        params
    }

    fn decode(&self, row: &Row) -> Result<DispatchAccepted<Self::Outcome>, DispatchAuthorityError> {
        let disposition = disposition_of(row, CREATED_OR_REPLAY)?;
        let value = ReservePutOutcome {
            spool_object_id: uuid(row, 1)?,
            logical_request_id: uuid(row, 2)?,
            attempt_id: uuid(row, 3)?,
            upload_id: uuid(row, 4)?,
            upload_fence: uint64(row, 5)?,
            admission_clock_unix_ms: int8(row, 6)?,
            expires_at_unix_ms: int8(row, 7)?,
            reserve_put_ack_canonical_bytes: bytes(row, 8)?,
            reserve_put_ack_blake3: digest(row, 9)?,
        };
        // Bind the projection to the descriptor this call submitted. A replay that names another
        // reservation is a different writer's record, not this call's result.
        require(
            value.spool_object_id == self.request.spool_object_id
                && value.logical_request_id == self.request.identity.logical_request_id
                && value.attempt_id == self.request.identity.attempt_id
                && value.upload_id == self.request.identity.upload_id
                && value.upload_fence == self.request.identity.upload_fence,
            "reservation projection does not bind the submitted descriptor",
        )?;
        require(
            !value.reserve_put_ack_canonical_bytes.is_empty(),
            "reservation projection carries an empty ACK",
        )?;
        Ok(DispatchAccepted { disposition, value })
    }
}

struct PreparedPutUploadProgress<'a> {
    request: &'a PutUploadProgressRequest,
    api: &'static str,
    upload_fence: String,
    chunk_index: String,
    fsynced_prefix_bytes: String,
}

impl<'a> PreparedPutUploadProgress<'a> {
    fn new(request: &'a PutUploadProgressRequest) -> Self {
        Self {
            request,
            api: PUT_UPLOAD_PROGRESS_API_REVISION_V1,
            upload_fence: request.identity.upload_fence.to_string(),
            chunk_index: request.chunk_index.to_string(),
            fsynced_prefix_bytes: request.fsynced_prefix_bytes.to_string(),
        }
    }
}

impl PreparedMutation for PreparedPutUploadProgress<'_> {
    type Outcome = PutUploadProgressOutcome;

    fn statement(&self) -> &'static str {
        PUT_UPLOAD_PROGRESS_SQL
    }

    fn bind(&self) -> Vec<&(dyn ToSql + Sync)> {
        vec![
            &self.api,
            &self.request.protocol_revision,
            &self.request.identity.provider_boundary_id,
            &self.request.identity.authenticated_cell_id,
            &self.request.identity.authenticated_tenant_id,
            &self.request.identity.logical_request_id,
            &self.request.identity.attempt_id,
            &self.request.identity.upload_id,
            &self.upload_fence,
            &self.chunk_index,
            &self.fsynced_prefix_bytes,
            &self.request.limits.maximum_identity_bytes,
            &self.request.limits.maximum_boundary_token_bytes,
            &self.request.limits.maximum_record_bytes,
        ]
    }

    fn decode(&self, row: &Row) -> Result<DispatchAccepted<Self::Outcome>, DispatchAuthorityError> {
        let disposition = disposition_of(row, APPLIED_OR_REPLAY)?;
        let value = PutUploadProgressOutcome {
            spool_object_id: uuid(row, 1)?,
            logical_request_id: uuid(row, 2)?,
            attempt_id: uuid(row, 3)?,
            upload_id: uuid(row, 4)?,
            upload_fence: uint64(row, 5)?,
            committed_prefix_bytes: uint64(row, 6)?,
            committed_prefix_chunks: uint64(row, 7)?,
            spool_revision: uint64(row, 8)?,
            record_blake3: digest(row, 9)?,
        };
        require(
            value.logical_request_id == self.request.identity.logical_request_id
                && value.attempt_id == self.request.identity.attempt_id
                && value.upload_id == self.request.identity.upload_id
                && value.upload_fence == self.request.identity.upload_fence,
            "progress projection does not bind the submitted stream identity",
        )?;
        // The authority commits the prefix this call named; a projection short of it would let a
        // caller believe a chunk was recorded that was not.
        require(
            value.committed_prefix_bytes >= self.request.fsynced_prefix_bytes,
            "progress projection reports a shorter prefix than the call supplied",
        )?;
        Ok(DispatchAccepted { disposition, value })
    }
}

struct PreparedPutSpoolReady<'a> {
    request: &'a PutSpoolReadyRequest,
    api: &'static str,
    upload_fence: String,
    final_chunk_index: String,
    fsynced_body_size: String,
    fsynced_body_blake3: Vec<u8>,
}

impl<'a> PreparedPutSpoolReady<'a> {
    fn new(request: &'a PutSpoolReadyRequest) -> Self {
        Self {
            request,
            api: PUT_SPOOL_READY_API_REVISION_V1,
            upload_fence: request.identity.upload_fence.to_string(),
            final_chunk_index: request.final_chunk_index.to_string(),
            fsynced_body_size: request.fsynced_body_size.to_string(),
            fsynced_body_blake3: request.fsynced_body_blake3.to_vec(),
        }
    }
}

impl PreparedMutation for PreparedPutSpoolReady<'_> {
    type Outcome = PutSpoolReadyOutcome;

    fn statement(&self) -> &'static str {
        PUT_SPOOL_READY_SQL
    }

    fn bind(&self) -> Vec<&(dyn ToSql + Sync)> {
        vec![
            &self.api,
            &self.request.protocol_revision,
            &self.request.identity.provider_boundary_id,
            &self.request.identity.authenticated_cell_id,
            &self.request.identity.authenticated_tenant_id,
            &self.request.identity.logical_request_id,
            &self.request.identity.attempt_id,
            &self.request.identity.upload_id,
            &self.upload_fence,
            &self.final_chunk_index,
            &self.fsynced_body_size,
            &self.fsynced_body_blake3,
            &self.request.durable_handle,
            &self.request.maximum_identity_bytes,
            &self.request.maximum_boundary_token_bytes,
            &self.request.maximum_durable_handle_bytes,
            &self.request.maximum_record_bytes,
        ]
    }

    fn decode(&self, row: &Row) -> Result<DispatchAccepted<Self::Outcome>, DispatchAuthorityError> {
        let disposition = disposition_of(row, APPLIED_OR_REPLAY)?;
        let value = PutSpoolReadyOutcome {
            spool_object_id: uuid(row, 1)?,
            logical_request_id: uuid(row, 2)?,
            attempt_id: uuid(row, 3)?,
            upload_id: uuid(row, 4)?,
            upload_fence: uint64(row, 5)?,
            durable_handle: text(row, 6)?,
            committed_size: uint64(row, 7)?,
            committed_blake3: digest(row, 8)?,
            ready_at_unix_ms: int8(row, 9)?,
            reserve_put_ack_canonical_bytes: bytes(row, 10)?,
            reserve_put_ack_blake3: digest(row, 11)?,
            spool_revision: uint64(row, 12)?,
            record_blake3: digest(row, 13)?,
        };
        require(
            value.logical_request_id == self.request.identity.logical_request_id
                && value.attempt_id == self.request.identity.attempt_id
                && value.upload_id == self.request.identity.upload_id
                && value.upload_fence == self.request.identity.upload_fence,
            "ready projection does not bind the submitted stream identity",
        )?;
        // The ready row is what a later reader trusts for the durable body. It must be the body
        // this call asserted, at the handle this call named.
        require(
            value.durable_handle == self.request.durable_handle
                && value.committed_size == self.request.fsynced_body_size
                && value.committed_blake3 == self.request.fsynced_body_blake3,
            "ready projection does not carry the asserted durable body",
        )?;
        require(
            !value.reserve_put_ack_canonical_bytes.is_empty(),
            "ready projection carries an empty ACK",
        )?;
        Ok(DispatchAccepted { disposition, value })
    }
}

struct PreparedEnrollParticipant<'a> {
    request: &'a EnrollParticipantRequest,
    api: &'static str,
    participant_key_blake3: Vec<u8>,
}

impl<'a> PreparedEnrollParticipant<'a> {
    fn new(request: &'a EnrollParticipantRequest) -> Self {
        Self {
            request,
            api: DISPATCHER_REGISTRATION_API_REVISION_V1,
            participant_key_blake3: request.participant_key_blake3.to_vec(),
        }
    }
}

impl PreparedMutation for PreparedEnrollParticipant<'_> {
    type Outcome = EnrollParticipantOutcome;

    fn statement(&self) -> &'static str {
        ENROLL_PARTICIPANT_SQL
    }

    fn bind(&self) -> Vec<&(dyn ToSql + Sync)> {
        vec![
            &self.api,
            &self.request.provider_boundary_id,
            &self.request.dispatcher_id,
            &self.participant_key_blake3,
        ]
    }

    fn decode(&self, row: &Row) -> Result<DispatchAccepted<Self::Outcome>, DispatchAuthorityError> {
        let disposition = disposition_of(row, CREATED_OR_REPLAY)?;
        let value = EnrollParticipantOutcome {
            provider_boundary_id: text(row, 1)?,
            dispatcher_id: text(row, 2)?,
        };
        require(
            value.provider_boundary_id == self.request.provider_boundary_id
                && value.dispatcher_id == self.request.dispatcher_id,
            "enrollment projection does not bind the submitted participant slot",
        )?;
        Ok(DispatchAccepted { disposition, value })
    }
}

struct PreparedRegisterDispatcher<'a> {
    request: &'a RegisterDispatcherRequest,
    api: &'static str,
    participant_key: Vec<u8>,
    next_generation: String,
    dispatcher_fence: String,
    authority_revision: String,
    allocation_fence: String,
}

impl<'a> PreparedRegisterDispatcher<'a> {
    fn new(request: &'a RegisterDispatcherRequest) -> Self {
        Self {
            request,
            api: DISPATCHER_REGISTRATION_API_REVISION_V1,
            participant_key: request.participant_key.to_vec(),
            next_generation: request.next_generation.to_string(),
            dispatcher_fence: request.dispatcher_fence.to_string(),
            authority_revision: request.authority_revision.to_string(),
            allocation_fence: request.allocation_fence.to_string(),
        }
    }
}

impl PreparedMutation for PreparedRegisterDispatcher<'_> {
    type Outcome = RegisterDispatcherOutcome;

    fn statement(&self) -> &'static str {
        REGISTER_DISPATCHER_SQL
    }

    fn bind(&self) -> Vec<&(dyn ToSql + Sync)> {
        vec![
            &self.api,
            &self.participant_key,
            &self.next_generation,
            &self.request.service_instance_id,
            &self.dispatcher_fence,
            &self.authority_revision,
            &self.request.allocation_revision,
            &self.allocation_fence,
            &self.request.provider_credential_revision,
            &self.request.acquired_at_unix_ms,
            &self.request.renewed_at_unix_ms,
            &self.request.expires_at_unix_ms,
            &self.request.state_changed_at_unix_ms,
        ]
    }

    fn decode(&self, row: &Row) -> Result<DispatchAccepted<Self::Outcome>, DispatchAuthorityError> {
        let disposition = disposition_of(row, CREATED_OR_REPLAY)?;
        let value = RegisterDispatcherOutcome {
            dispatcher_id: text(row, 1)?,
            lease_generation: uint64(row, 2)?,
            provider_boundary_id: text(row, 3)?,
            service_instance_id: text(row, 4)?,
            dispatcher_fence: uint64(row, 5)?,
            state: int2(row, 6)?,
            record_blake3: digest(row, 7)?,
        };
        // `dispatcher_id` and `provider_boundary_id` are database-minted from the enrolled
        // participant row, so they are not compared against a submitted value. Everything the call
        // did supply is.
        require(
            value.lease_generation == self.request.next_generation
                && value.service_instance_id == self.request.service_instance_id
                && value.dispatcher_fence == self.request.dispatcher_fence,
            "registration projection does not bind the submitted lease",
        )?;
        require(
            !value.dispatcher_id.is_empty() && !value.provider_boundary_id.is_empty(),
            "registration projection carries an empty minted identity",
        )?;
        Ok(DispatchAccepted { disposition, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_two_sqlstates_are_retryable_and_they_win_over_the_condition_table() {
        // 0015 and 0017 raise their CONFLICT conditions *as* 40001 on purpose. The classification
        // must treat them as serialization conflicts, not as a named refusal.
        for condition in [
            "DISPATCH_PUT_UPLOAD_PROGRESS_CONFLICT",
            "DISPATCH_PUT_SPOOL_READY_CONFLICT",
        ] {
            assert!(refusal_for_condition(condition).is_none(), "{condition}");
        }
    }

    #[test]
    fn every_frozen_condition_maps_to_a_distinct_named_refusal() {
        assert_eq!(
            refusal_for_condition("DISPATCH_RUNTIME_UNAUTHORIZED"),
            Some(DispatchAuthorityError::Unauthorized)
        );
        assert_eq!(
            refusal_for_condition("EXPIRED_OR_UNKNOWN"),
            Some(DispatchAuthorityError::ExpiredOrUnknown)
        );
        assert_eq!(
            refusal_for_condition("DISPATCH_RESERVE_PUT_EXPIRED"),
            Some(DispatchAuthorityError::ReservationExpired)
        );
        assert_eq!(
            refusal_for_condition("DISPATCH_PUT_UPLOAD_CHUNK_GAP"),
            Some(DispatchAuthorityError::ChunkGap)
        );
        assert_eq!(refusal_for_condition("SOMETHING_ELSE"), None);
    }

    #[test]
    fn an_unrecognized_sqlstate_fails_closed_as_unavailable() {
        assert_eq!(
            refusal_for_sqlstate(&SqlState::CONNECTION_FAILURE),
            DispatchAuthorityError::AuthorityUnavailable
        );
        assert_eq!(
            refusal_for_sqlstate(&SqlState::INSUFFICIENT_PRIVILEGE),
            DispatchAuthorityError::Unauthorized
        );
    }

    #[test]
    fn connection_exhaustion_is_named_and_kept_apart_from_admission_capacity() {
        // 53300 is the instance out of connection slots - the failure the per-replica budget
        // exists to prevent. 53000 is the authority refusing an admission. Folding them together
        // would repeat the misdiagnosis the cited learning records.
        assert_eq!(
            refusal_for_sqlstate(&SqlState::TOO_MANY_CONNECTIONS),
            DispatchAuthorityError::ConnectionSlotsExhausted
        );
        assert_eq!(
            refusal_for_sqlstate(&SqlState::INSUFFICIENT_RESOURCES),
            DispatchAuthorityError::CapacityExhausted
        );
        assert!(DispatchAuthorityError::ConnectionSlotsExhausted.is_transient());
    }

    #[test]
    fn the_retry_schedule_is_exactly_three_attempts_at_25_then_100_milliseconds() {
        assert_eq!(
            MUTATION_RETRY_SCHEDULE,
            [
                Some(Duration::from_millis(25)),
                Some(Duration::from_millis(100)),
                None
            ]
        );
    }

    #[test]
    fn ambiguity_resolution_preserves_which_side_committed() {
        assert_eq!(
            DispatchDisposition::Applied.after_ambiguity(),
            DispatchDisposition::AppliedAfterAmbiguousCommit
        );
        assert_eq!(
            DispatchDisposition::Replayed.after_ambiguity(),
            DispatchDisposition::ReplayedAfterAmbiguousCommit
        );
    }

    #[test]
    fn ambiguous_commit_is_not_advertised_as_transient() {
        assert!(!DispatchAuthorityError::AmbiguousCommit.is_transient());
        assert!(DispatchAuthorityError::AuthorityUnavailable.is_transient());
        assert!(!DispatchAuthorityError::ReplayConflict.is_transient());
    }
}
